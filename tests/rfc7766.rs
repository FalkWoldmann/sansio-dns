//! RFC 7766, DNS Transport over TCP - Implementation Requirements.
//! <https://rfc-annotations.research.icann.org/rfc7766.html>

use std::assert_matches;
use std::collections::BTreeSet;
use std::io::ErrorKind;
use std::net::Ipv4Addr;
use std::num::NonZeroUsize;
use std::time::{Duration, Instant};

use crate::common::*;
use hickory_proto::op::{Message, ResponseCode};
use hickory_proto::rr::rdata::A;
use hickory_proto::rr::{DNSClass, Name, RData, Record, RecordType};
use insta::assert_snapshot;
use proptest::prelude::*;
use rstest::rstest;
use sansio_dns::{Config, Event, Resolver, Transmit, Transport};

/// Start a query and return its transmit on a stream: answer it with TC
/// set over UDP, unless it went straight to an open connection.
fn switch_to_tcp(resolver: &mut Resolver, now: Instant) -> Transmit {
    let sent = start_distinct(resolver, now);
    if !matches!(sent.transport, Transport::Udp(_)) {
        return sent;
    }
    let mut truncated = reply(&sent);
    truncated.metadata.truncation = true;
    resolver.handle_datagram(udp(&sent), S1, &encode(&truncated), now);
    resolver.poll_transmit().unwrap()
}

/// Query `name` and return what it sent.
fn ask(trace: &mut Trace, name: &str) -> Transmit {
    trace.query(name, RecordType::A);
    trace.last()
}

/// Answer the datagram `sent` with TC set, and return the transmit that
/// sends the query again over TCP.
fn to_tcp(trace: &mut Trace, sent: &Transmit) -> Transmit {
    trace.answer(sent, &truncated(reply(sent)));
    trace.last()
}

/// Query `name` over UDP and answer it with TC set; return the TCP transmit.
/// With a connection to the server open, the query goes straight to it.
fn truncate(trace: &mut Trace, name: &str) -> Transmit {
    let sent = ask(trace, name);
    match sent.transport {
        Transport::Udp(_) => to_tcp(trace, &sent),
        _ => sent,
    }
}

/// Query each of `names` over UDP before any connection is open, then
/// answer each with TC set, so all of them go over TCP for good: the first
/// opens the connection and the others are written to it.
fn truncate_all<const N: usize>(trace: &mut Trace, names: [&str; N]) -> [Transmit; N] {
    let sent = names.map(|name| ask(trace, name));
    sent.map(|sent| to_tcp(trace, &sent))
}

/// §5: a truncated UDP response is retried over TCP, to the same server, as
/// RFC 1123 §6.1.3.2 asks, and the query stays on TCP. An open connection
/// to a server carries every query to it.
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

    /// "If the resolver already has an open TCP connection to the server,
    /// it SHOULD reuse this connection": a new query skips UDP.
    #[rstest]
    fn new_query_goes_to_the_open_connection(mut trace: Trace) {
        truncate(&mut trace, "a.example.");

        trace.query("b.example.", RecordType::A);

        assert_snapshot!(trace, @"
        t=0s query q0 a.example. A
          -> S1 udp q0: a.example. A
          next t=2s
        t=0s <- S1 udp q0: a.example. A: NoError, 1 answer, TC
          -> S1 connect c0: a.example. A
          next t=2s
        t=0s query q1 b.example. A
          -> S1 write c0: b.example. A
          next t=2s
        ");
    }

    /// The same for a later attempt: a query that got no answer from `S1`
    /// over UDP sends its next attempt on the connection open to `S2`.
    #[test]
    fn retry_goes_to_the_open_connection() {
        let mut config = config();
        config.failure_memory = Duration::ZERO;
        let mut trace = Trace::new(Resolver::new(config));
        trace.query("a.example.", RecordType::A);
        trace.timeout();
        let retry = trace.last();
        let tcp = to_tcp(&mut trace, &retry);
        trace.answer(&tcp, &reply(&tcp));
        trace.query("b.example.", RecordType::A);

        trace.timeout();

        assert_snapshot!(trace, @"
        t=0s query q0 a.example. A
          -> S1 udp q0: a.example. A
          next t=2s
        t=2s timeout
          -> S2 udp q0: a.example. A
          next t=4s
        t=2s <- S2 udp q0: a.example. A: NoError, 1 answer, TC
          -> S2 connect c0: a.example. A
          next t=4s
        t=2s <- S2 c0: a.example. A: NoError, 1 answer
          => q0 Response a.example. A: NoError, 1 answer
          next t=12s
        t=2s query q1 b.example. A
          -> S1 udp q1: b.example. A
          next t=4s
        t=4s timeout
          -> S2 write c0: b.example. A
          next t=6s
        ");
    }

    /// A query that went over a stream only because a connection was open
    /// goes back to UDP once there is none: only a truncated answer keeps
    /// it on TCP.
    #[rstest]
    fn query_on_a_connection_by_chance_goes_back_to_udp(mut trace: Trace) {
        let first = truncate(&mut trace, "a.example.");
        trace.answer(&first, &reply(&first));
        let second = ask(&mut trace, "b.example.");

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
          -> S1 write c0: b.example. A
          next t=2s
        t=0s c0 closed
          -> S1 udp q1: b.example. A
          next t=2s
        ");
    }
}

/// §6.2.1: further queries to a server reuse its open connection, several
/// at a time, and no two of them outstanding on it share a message ID.
mod section_6_2_1 {
    use super::*;

    #[rstest]
    fn second_query_shares_the_connection(mut trace: Trace) {
        truncate_all(&mut trace, ["a.example.", "b.example."]);

        assert_snapshot!(trace, @"
        t=0s query q0 a.example. A
          -> S1 udp q0: a.example. A
          next t=2s
        t=0s query q1 b.example. A
          -> S1 udp q1: b.example. A
          next t=2s
        t=0s <- S1 udp q0: a.example. A: NoError, 1 answer, TC
          -> S1 connect c0: a.example. A
          next t=2s
        t=0s <- S1 udp q1: b.example. A: NoError, 1 answer, TC
          -> S1 write c0: b.example. A
          next t=2s
        ");
    }

    /// "clients MUST NOT reuse the DNS Message ID of an in-flight query on
    /// that connection": a cancelled query's request is still in flight
    /// until its answer comes, so new queries avoid its ID too. With 256
    /// cancelled queries, the most a connection holds, the 3000 random IDs
    /// that follow would collide with one of them about twelve times if
    /// they only avoided the pending ones.
    #[rstest]
    fn cancelled_queries_keep_their_ids_on_the_connection(mut resolver: Resolver) {
        let now = Instant::now();
        switch_to_tcp(&mut resolver, now);
        let mut ids = BTreeSet::new();

        for n in 0..3256 {
            let name = Name::from_ascii(format!("id{n}.example.")).unwrap();
            let query = resolver.query(name, RecordType::A, now).unwrap();
            let sent = resolver.poll_transmit().unwrap();
            assert_matches!(sent.transport, Transport::TcpWrite(_));
            assert!(ids.insert(decode(&sent).metadata.id), "ID reused");
            if n < 256 {
                resolver.cancel(query, now);
            }
        }
    }

    /// A server that never answers some queries on a busy connection, which
    /// never goes idle, can't make their reserved IDs pile up: the
    /// connection is closed when a 257th request would be left on it
    /// unanswered, which frees them (§6.2.4 lets either end close a
    /// connection under unusual conditions). The query still on it is sent
    /// again over a new connection.
    #[rstest]
    fn connection_closes_before_unanswered_requests_pile_up(mut resolver: Resolver) {
        let now = Instant::now();
        let waiting = switch_to_tcp(&mut resolver, now);
        let queries: Vec<_> = (0..257)
            .map(|n| {
                let name = Name::from_ascii(format!("gone{n}.example.")).unwrap();
                let query = resolver.query(name, RecordType::A, now).unwrap();
                let sent = resolver.poll_transmit().unwrap();
                assert_eq!(sent.transport, Transport::TcpWrite(conn(&waiting)));
                query
            })
            .collect();
        let (last, kept) = queries.split_last().unwrap();
        for query in kept {
            resolver.cancel(*query, now);
        }
        assert_eq!(resolver.poll_transmit(), None);

        resolver.cancel(*last, now);

        let close = resolver.poll_transmit().unwrap();
        assert_eq!(close.transport, Transport::TcpClose(conn(&waiting)));
        let resent = resolver.poll_transmit().unwrap();
        assert!(is_connect(&resent) && resent.destination == S1);
        assert_eq!(decode(&resent).metadata.id, decode(&waiting).metadata.id);
    }
}

/// §6.2.2: at most one connection to each server. When it fails, all its
/// queries move on, and share one new connection to the next server.
mod section_6_2_2 {
    use super::*;

    #[rstest]
    fn closed_connection_moves_all_queries_to_one_new_connection(mut trace: Trace) {
        let [first, _] = truncate_all(&mut trace, ["a.example.", "b.example."]);

        trace.close(&first);

        assert_snapshot!(trace, @"
        t=0s query q0 a.example. A
          -> S1 udp q0: a.example. A
          next t=2s
        t=0s query q1 b.example. A
          -> S1 udp q1: b.example. A
          next t=2s
        t=0s <- S1 udp q0: a.example. A: NoError, 1 answer, TC
          -> S1 connect c0: a.example. A
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
        let [first, _] = truncate_all(&mut trace, ["a.example.", "b.example."]);

        trace.error(&first, ErrorKind::ConnectionReset);

        assert_snapshot!(trace, @"
        t=0s query q0 a.example. A
          -> S1 udp q0: a.example. A
          next t=2s
        t=0s query q1 b.example. A
          -> S1 udp q1: b.example. A
          next t=2s
        t=0s <- S1 udp q0: a.example. A: NoError, 1 answer, TC
          -> S1 connect c0: a.example. A
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
        truncate_all(&mut trace, ["a.example.", "b.example."]);

        trace.timeout();

        assert_snapshot!(trace, @"
        t=0s query q0 a.example. A
          -> S1 udp q0: a.example. A
          next t=2s
        t=0s query q1 b.example. A
          -> S1 udp q1: b.example. A
          next t=2s
        t=0s <- S1 udp q0: a.example. A: NoError, 1 answer, TC
          -> S1 connect c0: a.example. A
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

/// §6.2.3: an idle connection is closed after the idle timeout, and not
/// while queries are still waiting on it. Only writes and complete
/// responses count as activity.
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

    /// A driver that stops closes its connections through `shutdown`, which
    /// forgets the queries still waiting on them.
    #[rstest]
    fn shutdown_closes_every_connection(mut trace: Trace) {
        let tcp = truncate(&mut trace, "example.com.");
        trace.answer(&tcp, &reply(&tcp));
        trace.query("example.org.", RecordType::A);

        trace.shutdown();

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
        t=0s query q1 example.org. A
          -> S1 write c0: example.org. A
          next t=2s
        t=0s shutdown
          -> S1 close c0
          next none
        ");
    }

    /// A server that trickles bytes can't keep an idle connection open.
    #[rstest]
    fn partial_message_does_not_keep_the_connection_open(mut trace: Trace) {
        let tcp = truncate(&mut trace, "example.com.");
        trace.answer(&tcp, &reply(&tcp));
        trace.at(Duration::from_secs(5));

        let answer = frame(&encode(&reply(&tcp)));
        trace.stream_bytes(&tcp, &answer[..10], "the first 10 bytes of an answer");

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
        t=5s <- S1 c0: the first 10 bytes of an answer
          next t=10s
        ");
    }

    /// A cancelled query's request is still outstanding on the connection
    /// (RFC 7766 §3's idle needs "no outstanding responses"): the idle
    /// time starts at the deadline the query had.
    #[test]
    fn cancelled_query_keeps_the_connection_busy_until_its_deadline() {
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
          next t=40s
        t=40s timeout
          -> S1 close c0
          next none
        ");
    }

    /// Its answer ends the wait early: the connection is idle from then.
    #[test]
    fn answer_to_a_cancelled_query_starts_the_idle_time() {
        let mut config = config();
        config.timeout = Duration::from_secs(30);
        let mut trace = Trace::new(Resolver::new(config));
        let q0 = trace.query("example.com.", RecordType::A);
        let sent = trace.last();
        let tcp = to_tcp(&mut trace, &sent);
        trace.at(Duration::from_secs(15));
        trace.cancel(q0);
        trace.at(Duration::from_secs(20));
        trace.answer(&tcp, &reply(&tcp));

        trace.timeout();

        assert_snapshot!(trace, @"
        t=0s query q0 example.com. A
          -> S1 udp q0: example.com. A
          next t=30s
        t=0s <- S1 udp q0: example.com. A: NoError, 1 answer, TC
          -> S1 connect c0: example.com. A
          next t=30s
        t=15s cancel q0
          next t=40s
        t=20s <- S1 c0: example.com. A: NoError, 1 answer
          next t=30s
        t=30s timeout
          -> S1 close c0
          next none
        ");
    }
}

/// §6.2.4: "DNS clients SHOULD retry unanswered queries if the connection
/// closes before receiving all outstanding responses". A connection that
/// has answered and then goes away was most likely closed by the server for
/// being idle (§6.2.3), or after as many queries as it serves on one
/// connection (RFC 9210 §4.2), so its queries try the same server again
/// without using up an attempt: whenever it answered something after the
/// query was written, and otherwise once per query.
mod section_6_2_4 {
    use super::*;

    /// A query written to a connection that already answered another one,
    /// which keeps it on TCP: it got a truncated answer before.
    fn on_working_connection(trace: &mut Trace) -> Transmit {
        let a = ask(trace, "a.example.");
        let b = ask(trace, "b.example.");
        let first = to_tcp(trace, &a);
        trace.answer(&first, &reply(&first));
        assert_matches!(trace.events(), [Event::Response { .. }]);
        to_tcp(trace, &b)
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
        t=0s query q1 b.example. A
          -> S1 udp q1: b.example. A
          next t=2s
        t=0s <- S1 udp q0: a.example. A: NoError, 1 answer, TC
          -> S1 connect c0: a.example. A
          next t=2s
        t=0s <- S1 c0: a.example. A: NoError, 1 answer
          => q0 Response a.example. A: NoError, 1 answer
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

    /// A server that answers one query per connection and then closes it
    /// gets every pipelined query answered, without attempts used up: each
    /// close follows an answer to something written no later than the
    /// queries still waiting. RFC 9520 §3.1 still bounds it: the fourth
    /// query, sent to `S1` three times over TCP, moves on to `S2`.
    #[rstest]
    fn again_whenever_the_connection_answered_since(mut trace: Trace) {
        let mut sent = truncate_all(
            &mut trace,
            ["a.example.", "b.example.", "c.example.", "d.example."],
        )
        .to_vec();

        for _ in 0..3 {
            let first = sent.remove(0);
            trace.answer(&first, &reply(&first));
            trace.close(&first);
            sent = trace.sent().to_vec();
        }

        assert_snapshot!(trace, @"
        t=0s query q0 a.example. A
          -> S1 udp q0: a.example. A
          next t=2s
        t=0s query q1 b.example. A
          -> S1 udp q1: b.example. A
          next t=2s
        t=0s query q2 c.example. A
          -> S1 udp q2: c.example. A
          next t=2s
        t=0s query q3 d.example. A
          -> S1 udp q3: d.example. A
          next t=2s
        t=0s <- S1 udp q0: a.example. A: NoError, 1 answer, TC
          -> S1 connect c0: a.example. A
          next t=2s
        t=0s <- S1 udp q1: b.example. A: NoError, 1 answer, TC
          -> S1 write c0: b.example. A
          next t=2s
        t=0s <- S1 udp q2: c.example. A: NoError, 1 answer, TC
          -> S1 write c0: c.example. A
          next t=2s
        t=0s <- S1 udp q3: d.example. A: NoError, 1 answer, TC
          -> S1 write c0: d.example. A
          next t=2s
        t=0s <- S1 c0: a.example. A: NoError, 1 answer
          => q0 Response a.example. A: NoError, 1 answer
          next t=2s
        t=0s c0 closed
          -> S1 connect c1: b.example. A
          -> S1 write c1: c.example. A
          -> S1 write c1: d.example. A
          next t=2s
        t=0s <- S1 c1: b.example. A: NoError, 1 answer
          => q1 Response b.example. A: NoError, 1 answer
          next t=2s
        t=0s c1 closed
          -> S1 connect c2: c.example. A
          -> S1 write c2: d.example. A
          next t=2s
        t=0s <- S1 c2: c.example. A: NoError, 1 answer
          => q2 Response c.example. A: NoError, 1 answer
          next t=2s
        t=0s c2 closed
          -> S2 connect c3: d.example. A
          next t=2s
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
        t=0s query q1 b.example. A
          -> S1 udp q1: b.example. A
          next t=2s
        t=0s <- S1 udp q0: a.example. A: NoError, 1 answer, TC
          -> S1 connect c0: a.example. A
          next t=2s
        t=0s <- S1 c0: a.example. A: NoError, 1 answer
          => q0 Response a.example. A: NoError, 1 answer
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

    /// A connection that answered only before the query was written gives a
    /// free resend once per query: `b`, resent for free after losing `c1`,
    /// uses an attempt when it loses `c0` to `S2`, which had answered `d`
    /// before `b` was written there.
    #[rstest]
    fn once_per_query_for_a_connection_that_answered_before(mut trace: Trace) {
        let d = ask(&mut trace, "d.example.");
        trace.answer(&d, &with_code(reply(&d), ResponseCode::ServFail));
        let retried = trace.last();
        let other = to_tcp(&mut trace, &retried);
        trace.answer(&other, &reply(&other));
        let a = ask(&mut trace, "a.example.");
        let b = ask(&mut trace, "b.example.");
        let first = to_tcp(&mut trace, &a);
        trace.answer(&first, &reply(&first));
        let second = to_tcp(&mut trace, &b);
        trace.close(&second);
        let resent = trace.last();
        trace.close(&resent);
        let moved = trace.last();

        trace.close(&moved);

        assert_snapshot!(trace, @"
        t=0s query q0 d.example. A
          -> S1 udp q0: d.example. A
          next t=2s
        t=0s <- S1 udp q0: d.example. A: ServFail, 0 answers
          -> S2 udp q0: d.example. A
          next t=2s
        t=0s <- S2 udp q0: d.example. A: NoError, 1 answer, TC
          -> S2 connect c0: d.example. A
          next t=2s
        t=0s <- S2 c0: d.example. A: NoError, 1 answer
          => q0 Response d.example. A: NoError, 1 answer
          next t=10s
        t=0s query q1 a.example. A
          -> S1 udp q1: a.example. A
          next t=2s
        t=0s query q2 b.example. A
          -> S1 udp q2: b.example. A
          next t=2s
        t=0s <- S1 udp q1: a.example. A: NoError, 1 answer, TC
          -> S1 connect c1: a.example. A
          next t=2s
        t=0s <- S1 c1: a.example. A: NoError, 1 answer
          => q1 Response a.example. A: NoError, 1 answer
          next t=2s
        t=0s <- S1 udp q2: b.example. A: NoError, 1 answer, TC
          -> S1 write c1: b.example. A
          next t=2s
        t=0s c1 closed
          -> S1 connect c2: b.example. A
          next t=2s
        t=0s c2 closed
          -> S2 write c0: b.example. A
          next t=2s
        t=0s c0 closed
          -> S1 connect c3: b.example. A
          next t=4s
        ");
    }

    /// An answer to a query cancelled since shows the connection works as
    /// well as any other.
    #[rstest]
    fn answer_to_a_cancelled_query_counts(mut trace: Trace) {
        let a = ask(&mut trace, "a.example.");
        let q1 = trace.query("b.example.", RecordType::A);
        let b = trace.last();
        let first = to_tcp(&mut trace, &a);
        let second = to_tcp(&mut trace, &b);
        trace.cancel(q1);
        trace.answer(&second, &reply(&second));

        trace.close(&first);

        assert_snapshot!(trace, @"
        t=0s query q0 a.example. A
          -> S1 udp q0: a.example. A
          next t=2s
        t=0s query q1 b.example. A
          -> S1 udp q1: b.example. A
          next t=2s
        t=0s <- S1 udp q0: a.example. A: NoError, 1 answer, TC
          -> S1 connect c0: a.example. A
          next t=2s
        t=0s <- S1 udp q1: b.example. A: NoError, 1 answer, TC
          -> S1 write c0: b.example. A
          next t=2s
        t=0s cancel q1
          next t=2s
        t=0s <- S1 c0: b.example. A: NoError, 1 answer
          next t=2s
        t=0s c0 closed
          -> S1 connect c1: a.example. A
          next t=2s
        ");
    }
}

/// §7: answers on a connection may come in any order, and are matched to
/// the queries on it by message ID and, if they have one, question.
mod section_7 {
    use super::*;

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

    fn wrong_id(m: &mut Message) {
        m.metadata.id = m.metadata.id.wrapping_add(1);
    }
    fn wrong_name(m: &mut Message) {
        m.queries[0].set_name(Name::from_ascii("other.example.").unwrap());
    }
    fn wrong_type(m: &mut Message) {
        m.queries[0].set_query_type(RecordType::AAAA);
    }
    fn wrong_class(m: &mut Message) {
        m.queries[0].set_query_class(DNSClass::CH);
    }

    /// "If the response contains a question section, the client MUST match
    /// the QNAME, QCLASS, and QTYPE fields."
    #[rstest]
    #[case::id(wrong_id)]
    #[case::name(wrong_name)]
    #[case::record_type(wrong_type)]
    #[case::class(wrong_class)]
    fn mismatched_response_is_ignored(mut resolver: Resolver, #[case] tamper: fn(&mut Message)) {
        let now = Instant::now();
        let tcp = switch_to_tcp(&mut resolver, now);
        let mut forged = reply(&tcp);
        tamper(&mut forged);

        resolver.handle_stream_data(conn(&tcp), &frame(&encode(&forged)), now);

        assert!(resolver.poll_event().is_none());
        resolver.handle_stream_data(conn(&tcp), &frame(&encode(&reply(&tcp))), now);
        assert!(
            is_response(resolver.poll_event()),
            "genuine answer accepted"
        );
    }

    /// A response without a question section matches by message ID alone,
    /// as the question to answer. Over UDP it is dropped (RFC 5452 §9.1).
    #[rstest]
    fn response_without_a_question_matches_by_id(mut resolver: Resolver) {
        let now = Instant::now();
        let tcp = switch_to_tcp(&mut resolver, now);
        let mut answer = reply(&tcp);
        answer.queries.clear();

        resolver.handle_stream_data(conn(&tcp), &frame(&encode(&answer)), now);

        let Some(Event::Response { response, .. }) = resolver.poll_event() else {
            panic!("expected a response");
        };
        assert_eq!(response.queries, decode(&tcp).queries);
        assert_eq!(response.answers[0].data, RData::A(A(ADDR)));
    }

    /// So a server error without a question moves the query on at once,
    /// instead of after its deadline.
    #[rstest]
    fn server_error_without_a_question_moves_on(mut trace: Trace) {
        let tcp = truncate(&mut trace, "example.com.");
        let mut error = with_code(reply(&tcp), ResponseCode::ServFail);
        error.queries.clear();

        trace.answer(&tcp, &error);

        assert_snapshot!(trace, @"
        t=0s query q0 example.com. A
          -> S1 udp q0: example.com. A
          next t=2s
        t=0s <- S1 udp q0: example.com. A: NoError, 1 answer, TC
          -> S1 connect c0: example.com. A
          next t=2s
        t=0s <- S1 c0: no question: ServFail, 0 answers
          -> S2 connect c1: example.com. A
          next t=2s
        ");
    }
}

/// A query that times out on a stream moves on. If no response arrived on
/// its connection since it was written there, the connection looks dead:
/// it is closed, and the other queries on it try the same server again,
/// keeping their deadlines. Otherwise the server is only slow with this
/// query, and the connection stays.
mod stream_timeout {
    use super::*;

    #[rstest]
    fn closes_the_connection_and_moves_only_the_late_query_on(mut trace: Trace) {
        let a = ask(&mut trace, "a.example.");
        let b = ask(&mut trace, "b.example.");
        to_tcp(&mut trace, &a);
        trace.at(Duration::from_secs(1));
        to_tcp(&mut trace, &b);

        trace.timeout_at(Duration::from_secs(2));

        assert_snapshot!(trace, @"
        t=0s query q0 a.example. A
          -> S1 udp q0: a.example. A
          next t=2s
        t=0s query q1 b.example. A
          -> S1 udp q1: b.example. A
          next t=2s
        t=0s <- S1 udp q0: a.example. A: NoError, 1 answer, TC
          -> S1 connect c0: a.example. A
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
        let [a, b, c] = ["a.example.", "b.example.", "c.example."].map(|n| ask(&mut trace, n));
        to_tcp(&mut trace, &a);
        trace.at(Duration::from_millis(500));
        to_tcp(&mut trace, &b);
        trace.at(Duration::from_secs(1));
        to_tcp(&mut trace, &c);
        trace.timeout_at(Duration::from_secs(2));

        trace.timeout_at(Duration::from_millis(2500));

        assert_snapshot!(trace, @"
        t=0s query q0 a.example. A
          -> S1 udp q0: a.example. A
          next t=2s
        t=0s query q1 b.example. A
          -> S1 udp q1: b.example. A
          next t=2s
        t=0s query q2 c.example. A
          -> S1 udp q2: c.example. A
          next t=2s
        t=0s <- S1 udp q0: a.example. A: NoError, 1 answer, TC
          -> S1 connect c0: a.example. A
          next t=2s
        t=0.5s <- S1 udp q1: b.example. A: NoError, 1 answer, TC
          -> S1 write c0: b.example. A
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

    /// RFC 7766 §7 expects slow answers among pipelined ones. The late
    /// query moves on; its late answer is dropped, and the connection is
    /// idle from then.
    #[rstest]
    fn slow_answer_keeps_a_working_connection(mut trace: Trace) {
        let [first, second] = truncate_all(&mut trace, ["a.example.", "b.example."]);
        trace.at(Duration::from_secs(1));
        trace.answer(&second, &reply(&second));
        trace.timeout_at(Duration::from_secs(2));
        trace.at(Duration::from_secs(3));

        trace.answer(&first, &reply(&first));

        assert_snapshot!(trace, @"
        t=0s query q0 a.example. A
          -> S1 udp q0: a.example. A
          next t=2s
        t=0s query q1 b.example. A
          -> S1 udp q1: b.example. A
          next t=2s
        t=0s <- S1 udp q0: a.example. A: NoError, 1 answer, TC
          -> S1 connect c0: a.example. A
          next t=2s
        t=0s <- S1 udp q1: b.example. A: NoError, 1 answer, TC
          -> S1 write c0: b.example. A
          next t=2s
        t=1s <- S1 c0: b.example. A: NoError, 1 answer
          => q1 Response b.example. A: NoError, 1 answer
          next t=2s
        t=2s timeout
          -> S2 connect c1: a.example. A
          next t=4s
        t=3s <- S1 c0: a.example. A: NoError, 1 answer
          next t=4s
        ");
    }

    /// With one server, the next attempt goes back to the same connection,
    /// where the query is still outstanding: it waits for that answer
    /// instead of writing its message ID there a second time (§6.2.1).
    #[test]
    fn with_one_server_the_next_attempt_waits_on_the_connection() {
        let mut config = Config::new(S1, []);
        config.timeout = Duration::from_secs(2);
        config.attempts = NonZeroUsize::new(3).unwrap();
        let mut trace = Trace::new(Resolver::new(config));
        let [first, second] = truncate_all(&mut trace, ["a.example.", "b.example."]);
        trace.at(Duration::from_secs(1));
        trace.answer(&second, &reply(&second));
        trace.timeout_at(Duration::from_secs(2));
        trace.at(Duration::from_secs(5));

        trace.answer(&first, &reply(&first));

        assert_snapshot!(trace, @"
        t=0s query q0 a.example. A
          -> S1 udp q0: a.example. A
          next t=2s
        t=0s query q1 b.example. A
          -> S1 udp q1: b.example. A
          next t=2s
        t=0s <- S1 udp q0: a.example. A: NoError, 1 answer, TC
          -> S1 connect c0: a.example. A
          next t=2s
        t=0s <- S1 udp q1: b.example. A: NoError, 1 answer, TC
          -> S1 write c0: b.example. A
          next t=2s
        t=1s <- S1 c0: b.example. A: NoError, 1 answer
          => q1 Response b.example. A: NoError, 1 answer
          next t=2s
        t=2s timeout
          next t=6s
        t=5s <- S1 c0: a.example. A: NoError, 1 answer
          => q0 Response a.example. A: NoError, 1 answer
          next t=15s
        ");
    }

    /// Only responses after the next attempt took the request back show the
    /// connection still works: one that goes silent after answering
    /// another query is closed at that attempt's deadline, and the query is
    /// sent again.
    #[test]
    fn silent_connection_is_closed_when_the_next_attempt_times_out() {
        let mut config = Config::new(S1, []);
        config.timeout = Duration::from_secs(2);
        config.attempts = NonZeroUsize::new(3).unwrap();
        let mut trace = Trace::new(Resolver::new(config));
        let [_, second] = truncate_all(&mut trace, ["a.example.", "b.example."]);
        trace.at(Duration::from_secs(1));
        trace.answer(&second, &reply(&second));
        trace.timeout_at(Duration::from_secs(2));

        trace.timeout_at(Duration::from_secs(6));

        assert_snapshot!(trace, @"
        t=0s query q0 a.example. A
          -> S1 udp q0: a.example. A
          next t=2s
        t=0s query q1 b.example. A
          -> S1 udp q1: b.example. A
          next t=2s
        t=0s <- S1 udp q0: a.example. A: NoError, 1 answer, TC
          -> S1 connect c0: a.example. A
          next t=2s
        t=0s <- S1 udp q1: b.example. A: NoError, 1 answer, TC
          -> S1 write c0: b.example. A
          next t=2s
        t=1s <- S1 c0: b.example. A: NoError, 1 answer
          => q1 Response b.example. A: NoError, 1 answer
          next t=2s
        t=2s timeout
          next t=6s
        t=6s timeout
          -> S1 close c0
          -> S1 connect c1: a.example. A
          next t=14s
        ");
    }

    /// A query still waiting keeps its connection open past the idle timeout.
    #[test]
    fn busy_connection_is_not_idle() {
        let mut config = Config::new(S1, [S2]);
        config.timeout = Duration::from_secs(30);
        let mut resolver = Resolver::new(config);
        let now = Instant::now();
        switch_to_tcp(&mut resolver, now);

        resolver.handle_timeout(now + Duration::from_secs(10));

        assert!(resolver.poll_transmit().is_none());
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

        /// RFC 1035 §4.2.2: an answer near the 65535-octet limit, far larger
        /// than any read, is put together from its chunks too.
        #[test]
        fn large_answer_in_any_chunking_completes(cuts in prop::collection::vec(any::<prop::sample::Index>(), 0..32)) {
            let mut r = resolver();
            let now = Instant::now();
            let tcp = switch_to_tcp(&mut r, now);
            let mut answer = reply(&tcp);
            let name = answer.queries[0].name().clone();
            answer.answers = (0..4000u32)
                .map(|i| Record::from_rdata(name.clone(), 300, RData::A(A(Ipv4Addr::from(i)))))
                .collect();
            let message = encode(&answer);
            let sent = Message::from_vec(&message).unwrap().answers.len();
            let bytes = frame(&message);
            prop_assert!(bytes.len() > 60_000);
            let mut cuts: Vec<usize> = cuts.iter().map(|c| c.index(bytes.len() + 1)).collect();
            cuts.extend([0, bytes.len()]);
            cuts.sort_unstable();

            cuts.windows(2)
                .for_each(|w| r.handle_stream_data(conn(&tcp), &bytes[w[0]..w[1]], now));

            let Some(Event::Response { response, .. }) = r.poll_event() else {
                panic!("expected a response");
            };
            prop_assert_eq!(response.answers.len(), sent);
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
