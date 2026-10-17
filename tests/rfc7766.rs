//! RFC 7766, DNS Transport over TCP - Implementation Requirements.
//! <https://rfc-annotations.research.icann.org/rfc7766.html>

use std::assert_matches;
use std::io::ErrorKind;
use std::time::{Duration, Instant};

use crate::common::*;
use hickory_proto::rr::rdata::A;
use hickory_proto::rr::{RData, RecordType};
use insta::assert_snapshot;
use proptest::prelude::*;
use rstest::rstest;
use sansio_dns::{Event, Resolver, Transmit};

/// Start a query, answer it with TC set over UDP, and return the TCP transmit.
fn switch_to_tcp(resolver: &mut Resolver, now: Instant) -> Transmit {
    let sent = start_distinct(resolver, now);
    let mut truncated = reply(&sent);
    truncated.metadata.truncation = true;
    resolver.handle_datagram(udp(&sent), S1, &encode(&truncated), now);
    resolver.poll_transmit().unwrap()
}

/// Query `name` and answer it with TC set over UDP; return the TCP transmit.
fn truncate(trace: &mut Trace, name: &str) -> Transmit {
    trace.query(name, RecordType::A);
    let sent = trace.last();
    trace.answer(&sent, &truncated(reply(&sent)));
    trace.last()
}

/// §5: a truncated UDP response is retried over TCP, to the same server.
mod section_5 {
    use super::*;

    #[rstest]
    fn truncation_retries_the_same_query_over_tcp(mut trace: Trace) {
        trace.query("example.com.", RecordType::A);
        let sent = trace.last();

        trace.answer(&sent, &truncated(reply(&sent)));

        assert_eq!(trace.last().payload, frame(&sent.payload));
        assert_snapshot!(trace, @"
        t=0s query q0 example.com. A
          -> S1 udp q0: example.com. A
          next t=2s
        t=0s <- S1 udp q0: example.com. A: NoError, 1 answer, TC
          -> S1 connect c0: example.com. A
          next t=2s
        ");
    }

    /// Once on TCP, a UDP answer could only be spoofed or late; ignore it.
    #[rstest]
    fn udp_answer_after_switch_is_ignored(mut resolver: Resolver) {
        let now = Instant::now();
        let sent = start(&mut resolver, now);
        let mut truncated = reply(&sent);
        truncated.metadata.truncation = true;
        resolver.handle_datagram(udp(&sent), S1, &encode(&truncated), now);

        resolver.handle_datagram(udp(&sent), S1, &encode(&reply(&sent)), now);

        assert!(resolver.poll_event().is_none());
    }

    #[rstest]
    fn truncated_answer_over_tcp_is_used(mut resolver: Resolver) {
        let now = Instant::now();
        let tcp = switch_to_tcp(&mut resolver, now);
        let mut answer = reply(&tcp);
        answer.metadata.truncation = true;

        resolver.handle_stream_data(conn(&tcp), &frame(&encode(&answer)), now);

        assert!(is_response(resolver.poll_event()));
    }

    /// Lose each connection the query is sent over with `lose`, until it
    /// runs out of attempts.
    fn lose_every_attempt(trace: &mut Trace, lose: impl Fn(&mut Trace, &Transmit)) {
        let mut attempt = Some(truncate(trace, "example.com."));
        while let Some(tcp) = attempt {
            lose(trace, &tcp);
            attempt = trace.sent().last().cloned();
        }
    }

    // A failed TCP attempt moves to the next server and stays on TCP: the
    // answer is known not to fit in UDP. Out of attempts, the query fails
    // with what happened to the last one.

    #[rstest]
    fn closed_connections_move_on_over_tcp_then_fail(mut trace: Trace) {
        lose_every_attempt(&mut trace, Trace::close);

        assert_snapshot!(trace, @"
        t=0s query q0 example.com. A
          -> S1 udp q0: example.com. A
          next t=2s
        t=0s <- S1 udp q0: example.com. A: NoError, 1 answer, TC
          -> S1 connect c0: example.com. A
          next t=2s
        t=0s c0 closed
          -> S2 connect c1: example.com. A
          next t=2s
        t=0s c1 closed
          -> S1 connect c2: example.com. A
          next t=4s
        t=0s c2 closed
          -> S2 connect c3: example.com. A
          next t=4s
        t=0s c3 closed
          => q0 Failed ConnectionClosed
          next none
        ");
    }

    #[rstest]
    fn refused_connections_move_on_over_tcp_then_fail(mut trace: Trace) {
        lose_every_attempt(&mut trace, |trace, tcp| {
            trace.error(tcp, ErrorKind::ConnectionRefused);
        });

        assert_snapshot!(trace, @"
        t=0s query q0 example.com. A
          -> S1 udp q0: example.com. A
          next t=2s
        t=0s <- S1 udp q0: example.com. A: NoError, 1 answer, TC
          -> S1 connect c0: example.com. A
          next t=2s
        t=0s c0 error ConnectionRefused
          -> S2 connect c1: example.com. A
          next t=2s
        t=0s c1 error ConnectionRefused
          -> S1 connect c2: example.com. A
          next t=4s
        t=0s c2 error ConnectionRefused
          -> S2 connect c3: example.com. A
          next t=4s
        t=0s c3 error ConnectionRefused
          => q0 Failed Io(ConnectionRefused)
          next none
        ");
    }

    #[rstest]
    fn timed_out_tcp_attempts_move_on_over_tcp_then_fail(mut trace: Trace) {
        truncate(&mut trace, "example.com.");

        trace.timeouts();

        assert_snapshot!(trace, @"
        t=0s query q0 example.com. A
          -> S1 udp q0: example.com. A
          next t=2s
        t=0s <- S1 udp q0: example.com. A: NoError, 1 answer, TC
          -> S1 connect c0: example.com. A
          next t=2s
        t=2s timeout
          -> S1 close c0
          -> S2 connect c1: example.com. A
          next t=4s
        t=4s timeout
          -> S2 close c1
          -> S1 connect c2: example.com. A
          next t=8s
        t=8s timeout
          -> S1 close c2
          -> S2 connect c3: example.com. A
          next t=12s
        t=12s timeout
          => q0 Failed Timeout
          -> S2 close c3
          next none
        ");
    }
}

/// §8: messages on a TCP connection carry a two-byte length prefix and may
/// arrive split across reads in any way.
mod section_8 {
    use super::*;

    proptest! {
        #[test]
        fn answer_in_any_chunking_completes(cuts in prop::collection::vec(any::<prop::sample::Index>(), 0..8)) {
            let mut r = resolver();
            let now = Instant::now();
            let tcp = switch_to_tcp(&mut r, now);
            let bytes = frame(&encode(&reply(&tcp)));
            let mut cuts: Vec<usize> = cuts.iter().map(|c| c.index(bytes.len() + 1)).collect();
            cuts.extend([0, bytes.len()]);
            cuts.sort_unstable();

            cuts.windows(2)
                .for_each(|w| r.handle_stream_data(conn(&tcp), &bytes[w[0]..w[1]], now));

            let Some(Event::Response { response, .. }) = r.poll_event() else {
                panic!("expected a response");
            };
            prop_assert_eq!(&response.answers[0].data, &RData::A(A(ADDR)));
        }
    }

    /// Half a message from a connection that was then replaced must not
    /// corrupt the framing on the new connection.
    #[rstest]
    fn partial_message_from_replaced_connection_is_discarded(mut resolver: Resolver) {
        let now = Instant::now();
        let first = switch_to_tcp(&mut resolver, now);
        resolver.handle_stream_data(conn(&first), &[0, 40, 1, 2], now);
        resolver.handle_stream_closed(conn(&first), now);
        let second = resolver.poll_transmit().unwrap();

        resolver.handle_stream_data(conn(&second), &frame(&encode(&reply(&second))), now);

        assert!(is_response(resolver.poll_event()));
    }

    /// A message that doesn't answer the query is skipped, and a later one
    /// in the same read still counts.
    #[rstest]
    fn non_matching_message_on_stream_is_skipped(mut resolver: Resolver) {
        let now = Instant::now();
        let tcp = switch_to_tcp(&mut resolver, now);
        let mut wrong = reply(&tcp);
        wrong.metadata.id = wrong.metadata.id.wrapping_add(1);
        let bytes = [frame(&encode(&wrong)), frame(&encode(&reply(&tcp)))].concat();

        resolver.handle_stream_data(conn(&tcp), &bytes, now);

        assert!(is_response(resolver.poll_event()));
    }
}

/// §6.2.1: further queries to a server reuse its open connection, several
/// at a time.
mod section_6_2_1 {
    use super::*;

    #[rstest]
    fn second_query_shares_the_connection(mut trace: Trace) {
        truncate(&mut trace, "a.example.");
        truncate(&mut trace, "b.example.");

        assert_snapshot!(trace, @"
        t=0s query q0 a.example. A
          -> S1 udp q0: a.example. A
          next t=2s
        t=0s <- S1 udp q0: a.example. A: NoError, 1 answer, TC
          -> S1 connect c0: a.example. A
          next t=2s
        t=0s query q1 b.example. A
          -> S1 udp q1: b.example. A
          next t=2s
        t=0s <- S1 udp q1: b.example. A: NoError, 1 answer, TC
          -> S1 write c0: b.example. A
          next t=2s
        ");
    }

    /// §6.2.1.1: answers on a shared connection may come in any order.
    #[rstest]
    fn answers_in_any_order_complete_their_queries(mut resolver: Resolver) {
        let now = Instant::now();
        let first = switch_to_tcp(&mut resolver, now);
        let second = switch_to_tcp(&mut resolver, now);
        let bytes = [
            frame(&encode(&reply(&second))),
            frame(&encode(&reply(&first))),
        ]
        .concat();

        resolver.handle_stream_data(conn(&first), &bytes, now);

        assert!(is_response(resolver.poll_event()));
        assert!(is_response(resolver.poll_event()));
    }

    // When a shared connection fails, all its queries move on, and share a
    // new connection to the next server.

    #[rstest]
    fn closed_connection_moves_all_queries_to_one_new_connection(mut trace: Trace) {
        let first = truncate(&mut trace, "a.example.");
        truncate(&mut trace, "b.example.");

        trace.close(&first);

        assert_snapshot!(trace, @"
        t=0s query q0 a.example. A
          -> S1 udp q0: a.example. A
          next t=2s
        t=0s <- S1 udp q0: a.example. A: NoError, 1 answer, TC
          -> S1 connect c0: a.example. A
          next t=2s
        t=0s query q1 b.example. A
          -> S1 udp q1: b.example. A
          next t=2s
        t=0s <- S1 udp q1: b.example. A: NoError, 1 answer, TC
          -> S1 write c0: b.example. A
          next t=2s
        t=0s c0 closed
          -> S2 connect c1: a.example. A
          -> S2 write c1: b.example. A
          next t=2s
        ");
    }

    #[rstest]
    fn reset_connection_moves_all_queries_to_one_new_connection(mut trace: Trace) {
        let first = truncate(&mut trace, "a.example.");
        truncate(&mut trace, "b.example.");

        trace.error(&first, ErrorKind::ConnectionReset);

        assert_snapshot!(trace, @"
        t=0s query q0 a.example. A
          -> S1 udp q0: a.example. A
          next t=2s
        t=0s <- S1 udp q0: a.example. A: NoError, 1 answer, TC
          -> S1 connect c0: a.example. A
          next t=2s
        t=0s query q1 b.example. A
          -> S1 udp q1: b.example. A
          next t=2s
        t=0s <- S1 udp q1: b.example. A: NoError, 1 answer, TC
          -> S1 write c0: b.example. A
          next t=2s
        t=0s c0 error ConnectionReset
          -> S2 connect c1: a.example. A
          -> S2 write c1: b.example. A
          next t=2s
        ");
    }

    #[rstest]
    fn timed_out_connection_moves_all_queries_to_one_new_connection(mut trace: Trace) {
        truncate(&mut trace, "a.example.");
        truncate(&mut trace, "b.example.");

        trace.timeout();

        assert_snapshot!(trace, @"
        t=0s query q0 a.example. A
          -> S1 udp q0: a.example. A
          next t=2s
        t=0s <- S1 udp q0: a.example. A: NoError, 1 answer, TC
          -> S1 connect c0: a.example. A
          next t=2s
        t=0s query q1 b.example. A
          -> S1 udp q1: b.example. A
          next t=2s
        t=0s <- S1 udp q1: b.example. A: NoError, 1 answer, TC
          -> S1 write c0: b.example. A
          next t=2s
        t=2s timeout
          -> S1 close c0
          -> S2 connect c1: a.example. A
          -> S2 write c1: b.example. A
          next t=4s
        ");
    }
}

/// A query that times out on a stream suggests a dead connection: it is
/// closed. Only the late query moves on to its next attempt; the others on
/// the connection try the same server again, keeping their deadlines.
mod stream_timeout {
    use super::*;

    #[rstest]
    fn closes_the_connection_and_moves_only_the_late_query_on(mut trace: Trace) {
        truncate(&mut trace, "a.example.");
        trace.at(Duration::from_secs(1));
        truncate(&mut trace, "b.example.");

        trace.timeout_at(Duration::from_secs(2));

        assert_snapshot!(trace, @"
        t=0s query q0 a.example. A
          -> S1 udp q0: a.example. A
          next t=2s
        t=0s <- S1 udp q0: a.example. A: NoError, 1 answer, TC
          -> S1 connect c0: a.example. A
          next t=2s
        t=1s query q1 b.example. A
          -> S1 udp q1: b.example. A
          next t=2s
        t=1s <- S1 udp q1: b.example. A: NoError, 1 answer, TC
          -> S1 write c0: b.example. A
          next t=2s
        t=2s timeout
          -> S1 close c0
          -> S2 connect c1: a.example. A
          -> S1 connect c2: b.example. A
          next t=3s
        ");
    }

    /// A query moved off one timed-out connection uses up its attempt when a
    /// neighbour times out on the next one too.
    #[rstest]
    fn moves_a_query_for_free_only_once(mut trace: Trace) {
        truncate(&mut trace, "a.example.");
        trace.at(Duration::from_millis(500));
        truncate(&mut trace, "b.example.");
        trace.at(Duration::from_secs(1));
        truncate(&mut trace, "c.example.");
        trace.timeout_at(Duration::from_secs(2));

        trace.timeout_at(Duration::from_millis(2500));

        assert_snapshot!(trace, @"
        t=0s query q0 a.example. A
          -> S1 udp q0: a.example. A
          next t=2s
        t=0s <- S1 udp q0: a.example. A: NoError, 1 answer, TC
          -> S1 connect c0: a.example. A
          next t=2s
        t=0.5s query q1 b.example. A
          -> S1 udp q1: b.example. A
          next t=2s
        t=0.5s <- S1 udp q1: b.example. A: NoError, 1 answer, TC
          -> S1 write c0: b.example. A
          next t=2s
        t=1s query q2 c.example. A
          -> S1 udp q2: c.example. A
          next t=2s
        t=1s <- S1 udp q2: c.example. A: NoError, 1 answer, TC
          -> S1 write c0: c.example. A
          next t=2s
        t=2s timeout
          -> S1 close c0
          -> S2 connect c1: a.example. A
          -> S1 connect c2: b.example. A
          -> S1 write c2: c.example. A
          next t=2.5s
        t=2.5s timeout
          -> S1 close c2
          -> S2 write c1: b.example. A
          -> S2 write c1: c.example. A
          next t=4s
        ");
    }

    /// A query still waiting keeps its connection open past the idle timeout.
    #[test]
    fn busy_connection_is_not_idle() {
        let mut config = sansio_dns::Config::new(S1, [S2]);
        config.timeout = Duration::from_secs(30);
        let mut resolver = Resolver::new(config);
        let now = Instant::now();
        switch_to_tcp(&mut resolver, now);

        resolver.handle_timeout(now + Duration::from_secs(10));

        assert!(resolver.poll_transmit().is_none());
    }
}

/// A connection that has answered and then goes away was most likely closed
/// by the server for being idle (§6.2.3), so its queries try the same server
/// again once without using up an attempt.
mod lost_connection {
    use super::*;

    /// A query written to a connection that already answered another one.
    fn on_working_connection(trace: &mut Trace) -> Transmit {
        let first = truncate(trace, "a.example.");
        trace.answer(&first, &reply(&first));
        assert_matches!(trace.events(), [Event::Response { .. }]);
        truncate(trace, "b.example.")
    }

    fn reset(trace: &mut Trace, tcp: &Transmit) {
        trace.error(tcp, ErrorKind::ConnectionReset);
    }

    #[rstest]
    #[case::closed(Trace::close)]
    #[case::reset(reset)]
    fn query_is_resent_to_the_same_server(
        mut trace: Trace,
        #[case] lose: fn(&mut Trace, &Transmit),
    ) {
        let second = on_working_connection(&mut trace);

        lose(&mut trace, &second);

        assert_matches!(trace.sent(), [resent] if is_connect(resent) && resent.destination == S1);
    }

    /// The new connection answers too before it goes away, so only the
    /// query's own flag stops a second free resend.
    #[rstest]
    fn only_once(mut trace: Trace) {
        let second = on_working_connection(&mut trace);
        trace.close(&second);
        let resent = trace.last();
        let third = truncate(&mut trace, "c.example.");
        trace.answer(&third, &reply(&third));

        trace.close(&resent);

        assert_snapshot!(trace, @"
        t=0s query q0 a.example. A
          -> S1 udp q0: a.example. A
          next t=2s
        t=0s <- S1 udp q0: a.example. A: NoError, 1 answer, TC
          -> S1 connect c0: a.example. A
          next t=2s
        t=0s <- S1 c0: a.example. A: NoError, 1 answer
          => q0 Response a.example. A: NoError, 1 answer
          next t=10s
        t=0s query q1 b.example. A
          -> S1 udp q1: b.example. A
          next t=2s
        t=0s <- S1 udp q1: b.example. A: NoError, 1 answer, TC
          -> S1 write c0: b.example. A
          next t=2s
        t=0s c0 closed
          -> S1 connect c1: b.example. A
          next t=2s
        t=0s query q2 c.example. A
          -> S1 udp q2: c.example. A
          next t=2s
        t=0s <- S1 udp q2: c.example. A: NoError, 1 answer, TC
          -> S1 write c1: c.example. A
          next t=2s
        t=0s <- S1 c1: c.example. A: NoError, 1 answer
          => q2 Response c.example. A: NoError, 1 answer
          next t=2s
        t=0s c1 closed
          -> S2 connect c2: b.example. A
          next t=2s
        ");
    }

    #[rstest]
    fn uses_up_no_attempt(mut trace: Trace) {
        let second = on_working_connection(&mut trace);
        trace.close(&second);

        while let Some(attempt) = trace.sent().last().cloned() {
            trace.close(&attempt);
        }

        assert_snapshot!(trace, @"
        t=0s query q0 a.example. A
          -> S1 udp q0: a.example. A
          next t=2s
        t=0s <- S1 udp q0: a.example. A: NoError, 1 answer, TC
          -> S1 connect c0: a.example. A
          next t=2s
        t=0s <- S1 c0: a.example. A: NoError, 1 answer
          => q0 Response a.example. A: NoError, 1 answer
          next t=10s
        t=0s query q1 b.example. A
          -> S1 udp q1: b.example. A
          next t=2s
        t=0s <- S1 udp q1: b.example. A: NoError, 1 answer, TC
          -> S1 write c0: b.example. A
          next t=2s
        t=0s c0 closed
          -> S1 connect c1: b.example. A
          next t=2s
        t=0s c1 closed
          -> S2 connect c2: b.example. A
          next t=2s
        t=0s c2 closed
          -> S1 connect c3: b.example. A
          next t=4s
        t=0s c3 closed
          -> S2 connect c4: b.example. A
          next t=4s
        t=0s c4 closed
          => q1 Failed ConnectionClosed
          next none
        ");
    }

    #[rstest]
    fn gives_the_resent_query_a_new_deadline(mut trace: Trace) {
        let second = on_working_connection(&mut trace);
        trace.at(Duration::from_millis(1500));

        trace.close(&second);

        assert_snapshot!(trace, @"
        t=0s query q0 a.example. A
          -> S1 udp q0: a.example. A
          next t=2s
        t=0s <- S1 udp q0: a.example. A: NoError, 1 answer, TC
          -> S1 connect c0: a.example. A
          next t=2s
        t=0s <- S1 c0: a.example. A: NoError, 1 answer
          => q0 Response a.example. A: NoError, 1 answer
          next t=10s
        t=0s query q1 b.example. A
          -> S1 udp q1: b.example. A
          next t=2s
        t=0s <- S1 udp q1: b.example. A: NoError, 1 answer, TC
          -> S1 write c0: b.example. A
          next t=2s
        t=1.5s c0 closed
          -> S1 connect c1: b.example. A
          next t=3.5s
        ");
    }

    #[rstest]
    fn not_for_a_connection_that_never_answered(mut resolver: Resolver) {
        let now = Instant::now();
        let tcp = switch_to_tcp(&mut resolver, now);

        resolver.handle_stream_closed(conn(&tcp), now);

        assert_eq!(resolver.poll_transmit().unwrap().destination, S2);
    }
}

/// §6.2.3: an idle connection is closed after the idle timeout, and not
/// while queries are still waiting on it.
mod section_6_2_3 {
    use super::*;

    #[rstest]
    fn idle_connection_is_closed(mut trace: Trace) {
        let tcp = truncate(&mut trace, "example.com.");
        trace.answer(&tcp, &reply(&tcp));

        trace.timeout();

        assert_snapshot!(trace, @"
        t=0s query q0 example.com. A
          -> S1 udp q0: example.com. A
          next t=2s
        t=0s <- S1 udp q0: example.com. A: NoError, 1 answer, TC
          -> S1 connect c0: example.com. A
          next t=2s
        t=0s <- S1 c0: example.com. A: NoError, 1 answer
          => q0 Response example.com. A: NoError, 1 answer
          next t=10s
        t=10s timeout
          -> S1 close c0
          next none
        ");
    }

    /// Without this, a query that waited longer than the idle timeout would
    /// leave a deadline that has already passed.
    #[test]
    fn idle_time_starts_when_the_last_query_is_cancelled() {
        let mut config = config();
        config.timeout = Duration::from_secs(30);
        let mut trace = Trace::new(Resolver::new(config));
        let q0 = trace.query("example.com.", RecordType::A);
        let sent = trace.last();
        trace.answer(&sent, &truncated(reply(&sent)));
        trace.at(Duration::from_secs(15));
        trace.cancel(q0);

        trace.timeout();

        assert_snapshot!(trace, @"
        t=0s query q0 example.com. A
          -> S1 udp q0: example.com. A
          next t=30s
        t=0s <- S1 udp q0: example.com. A: NoError, 1 answer, TC
          -> S1 connect c0: example.com. A
          next t=30s
        t=15s cancel q0
          next t=25s
        t=25s timeout
          -> S1 close c0
          next none
        ");
    }
}
