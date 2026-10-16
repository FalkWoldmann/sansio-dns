//! RFC 7766, DNS Transport over TCP - Implementation Requirements.
//! <https://rfc-annotations.research.icann.org/rfc7766.html>

use std::assert_matches;
use std::io::ErrorKind;
use std::time::{Duration, Instant};

use crate::common::*;
use hickory_proto::rr::RData;
use hickory_proto::rr::rdata::A;
use proptest::prelude::*;
use rstest::rstest;
use sansio_dns::{ConnectionId, Error, Event, Resolver, Transmit, Transport};

/// Start a query, answer it with TC set over UDP, and return the TCP transmit.
fn switch_to_tcp(resolver: &mut Resolver, now: Instant) -> Transmit {
    let sent = start(resolver, now);
    let mut truncated = reply(&sent);
    truncated.metadata.truncation = true;
    resolver.handle_datagram(udp(&sent), S1, &encode(&truncated), now);
    resolver.poll_transmit().unwrap()
}

/// §5: a truncated UDP response is retried over TCP, to the same server.
mod section_5 {
    use super::*;

    #[rstest]
    fn truncation_retries_the_same_query_over_tcp(mut resolver: Resolver) {
        let now = Instant::now();
        let sent = start(&mut resolver, now);
        let mut truncated = reply(&sent);
        truncated.metadata.truncation = true;

        resolver.handle_datagram(udp(&sent), S1, &encode(&truncated), now);

        let tcp = resolver.poll_transmit().unwrap();
        assert!(is_connect(&tcp));
        assert_eq!(tcp.destination, S1);
        assert_eq!(tcp.payload, frame(&sent.payload));
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

    fn close(resolver: &mut Resolver, tcp: &Transmit, now: Instant) {
        resolver.handle_stream_closed(conn(tcp), now);
    }
    fn refuse(resolver: &mut Resolver, tcp: &Transmit, now: Instant) {
        resolver.handle_stream_error(conn(tcp), ErrorKind::ConnectionRefused, now);
    }
    fn time_out(resolver: &mut Resolver, _: &Transmit, _: Instant) {
        resolver.handle_timeout(resolver.poll_timeout().unwrap());
    }

    /// A failed TCP attempt moves to the next server and stays on TCP: the
    /// answer is known not to fit in UDP.
    #[rstest]
    #[case::connection_closed(close)]
    #[case::connection_failed(refuse)]
    #[case::timeout(time_out)]
    fn failed_tcp_attempt_retries_next_server_over_tcp(
        mut resolver: Resolver,
        #[case] fail: fn(&mut Resolver, &Transmit, Instant),
    ) {
        let now = Instant::now();
        let tcp = switch_to_tcp(&mut resolver, now);

        fail(&mut resolver, &tcp, now);

        let retry = std::iter::from_fn(|| resolver.poll_transmit())
            .find(is_connect)
            .unwrap();
        assert_eq!(retry.destination, S2);
    }

    #[rstest]
    #[case::closed(close, Error::ConnectionClosed)]
    #[case::failed(refuse, Error::Connection(ErrorKind::ConnectionRefused))]
    fn query_out_of_attempts_fails_with_the_last_connection_error(
        mut resolver: Resolver,
        #[case] fail: fn(&mut Resolver, &Transmit, Instant),
        #[case] expected: Error,
    ) {
        let now = Instant::now();
        let mut attempt = Some(switch_to_tcp(&mut resolver, now));

        while let Some(tcp) = attempt {
            fail(&mut resolver, &tcp, now);
            attempt = resolver.poll_transmit();
        }

        assert_matches!(
            resolver.poll_event(),
            Some(Event::Failed { error, .. }) if error == expected
        );
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
    fn second_query_shares_the_connection(mut resolver: Resolver) {
        let now = Instant::now();
        let first = switch_to_tcp(&mut resolver, now);
        let second = switch_to_tcp(&mut resolver, now);

        assert!(is_connect(&first));
        assert_matches!(second.transport, Transport::TcpWrite(c) if c == conn(&first));
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

    fn close(resolver: &mut Resolver, connection: ConnectionId, now: Instant) {
        resolver.handle_stream_closed(connection, now);
    }
    fn reset(resolver: &mut Resolver, connection: ConnectionId, now: Instant) {
        resolver.handle_stream_error(connection, ErrorKind::ConnectionReset, now);
    }
    fn time_out(resolver: &mut Resolver, _: ConnectionId, _: Instant) {
        resolver.handle_timeout(resolver.poll_timeout().unwrap());
    }

    /// When a shared connection fails, all its queries move on, and share
    /// a new connection to the next server.
    #[rstest]
    #[case::closed(close)]
    #[case::reset(reset)]
    #[case::timed_out(time_out)]
    fn failure_moves_all_queries_to_one_new_connection(
        mut resolver: Resolver,
        #[case] fail: fn(&mut Resolver, ConnectionId, Instant),
    ) {
        let now = Instant::now();
        let first = switch_to_tcp(&mut resolver, now);
        switch_to_tcp(&mut resolver, now);

        fail(&mut resolver, conn(&first), now);

        let next: Vec<Transmit> = std::iter::from_fn(|| resolver.poll_transmit())
            .filter(|t| !matches!(t.transport, Transport::TcpClose(_)))
            .collect();
        assert_eq!(next.len(), 2);
        assert!(next.iter().all(|t| t.destination == S2));
        assert!(is_connect(&next[0]));
        assert_matches!(next[1].transport, Transport::TcpWrite(c) if c == conn(&next[0]));
    }
}

/// A query that times out on a stream suggests a dead connection: it is
/// closed. Only the late query moves on to its next attempt; the others on
/// the connection try the same server again, keeping their deadlines.
mod stream_timeout {
    use super::*;

    #[rstest]
    fn closes_the_connection_and_moves_only_the_late_query_on(mut resolver: Resolver) {
        let now = Instant::now();
        let first = switch_to_tcp(&mut resolver, now);
        let later = now + Duration::from_secs(1);
        switch_to_tcp(&mut resolver, later);

        resolver.handle_timeout(now + Duration::from_secs(2));

        let sent: Vec<Transmit> = std::iter::from_fn(|| resolver.poll_transmit()).collect();
        assert_eq!(sent.len(), 3, "{sent:?}");
        assert_matches!(sent[0].transport, Transport::TcpClose(c) if c == conn(&first));
        assert!(is_connect(&sent[1]) && sent[1].destination == S2);
        assert!(is_connect(&sent[2]) && sent[2].destination == S1);
        assert_eq!(
            resolver.poll_timeout(),
            Some(later + Duration::from_secs(2))
        );
    }

    /// A query moved off one timed-out connection uses up its attempt when a
    /// neighbour times out on the next one too.
    #[rstest]
    fn moves_a_query_for_free_only_once(mut resolver: Resolver) {
        let now = Instant::now();
        switch_to_tcp(&mut resolver, now);
        switch_to_tcp(&mut resolver, now + Duration::from_millis(500));
        switch_to_tcp(&mut resolver, now + Duration::from_secs(1));
        resolver.handle_timeout(now + Duration::from_secs(2));
        let moved: Vec<Transmit> = std::iter::from_fn(|| resolver.poll_transmit()).collect();
        assert_eq!(
            moved.iter().filter(|t| t.destination == S1).count(),
            3,
            "{moved:?}"
        );

        resolver.handle_timeout(now + Duration::from_millis(2500));

        let sent: Vec<Transmit> = std::iter::from_fn(|| resolver.poll_transmit())
            .filter(|t| !matches!(t.transport, Transport::TcpClose(_)))
            .collect();
        assert_eq!(sent.len(), 2, "{sent:?}");
        assert!(sent.iter().all(|t| t.destination == S2));
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

    fn close(resolver: &mut Resolver, connection: ConnectionId, now: Instant) {
        resolver.handle_stream_closed(connection, now);
    }
    fn reset(resolver: &mut Resolver, connection: ConnectionId, now: Instant) {
        resolver.handle_stream_error(connection, ErrorKind::ConnectionReset, now);
    }

    /// A query written to a connection that already answered another one.
    fn on_working_connection(resolver: &mut Resolver, now: Instant) -> Transmit {
        let first = switch_to_tcp(resolver, now);
        resolver.handle_stream_data(conn(&first), &frame(&encode(&reply(&first))), now);
        assert!(is_response(resolver.poll_event()));
        switch_to_tcp(resolver, now)
    }

    #[rstest]
    #[case::closed(close)]
    #[case::reset(reset)]
    fn query_is_resent_to_the_same_server(
        mut resolver: Resolver,
        #[case] lose: fn(&mut Resolver, ConnectionId, Instant),
    ) {
        let now = Instant::now();
        let second = on_working_connection(&mut resolver, now);

        lose(&mut resolver, conn(&second), now);

        let resent = resolver.poll_transmit().unwrap();
        assert!(is_connect(&resent));
        assert_eq!(resent.destination, S1);
    }

    /// The new connection answers too before it goes away, so only the
    /// query's own flag stops a second free resend.
    #[rstest]
    fn only_once(mut resolver: Resolver) {
        let now = Instant::now();
        let second = on_working_connection(&mut resolver, now);
        resolver.handle_stream_closed(conn(&second), now);
        let resent = resolver.poll_transmit().unwrap();
        let third = switch_to_tcp(&mut resolver, now);
        assert_eq!(conn(&third), conn(&resent));
        resolver.handle_stream_data(conn(&third), &frame(&encode(&reply(&third))), now);
        assert!(is_response(resolver.poll_event()));

        resolver.handle_stream_closed(conn(&resent), now);

        assert_eq!(resolver.poll_transmit().unwrap().destination, S2);
    }

    #[rstest]
    fn uses_up_no_attempt(mut resolver: Resolver) {
        let now = Instant::now();
        let second = on_working_connection(&mut resolver, now);
        resolver.handle_stream_closed(conn(&second), now);

        let mut attempts = 0;
        while let Some(attempt) = resolver.poll_transmit() {
            attempts += 1;
            resolver.handle_stream_closed(conn(&attempt), now);
        }

        assert_eq!(attempts, 4, "all of Config::new(S1, [S2])'s attempts");
        assert_matches!(resolver.poll_event(), Some(Event::Failed { .. }));
    }

    #[rstest]
    fn gives_the_resent_query_a_new_deadline(mut resolver: Resolver) {
        let now = Instant::now();
        let second = on_working_connection(&mut resolver, now);
        let later = now + Duration::from_millis(1500);

        resolver.handle_stream_closed(conn(&second), later);

        assert_eq!(
            resolver.poll_timeout(),
            Some(later + Duration::from_secs(2))
        );
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
    fn idle_connection_is_closed(mut resolver: Resolver) {
        let now = Instant::now();
        let tcp = switch_to_tcp(&mut resolver, now);
        resolver.handle_stream_data(conn(&tcp), &frame(&encode(&reply(&tcp))), now);
        assert!(is_response(resolver.poll_event()));

        let deadline = resolver.poll_timeout().unwrap();
        assert_eq!(deadline - now, Duration::from_secs(10));
        resolver.handle_timeout(deadline);

        assert_matches!(
            resolver.poll_transmit().map(|t| t.transport),
            Some(Transport::TcpClose(c)) if c == conn(&tcp)
        );
        assert_eq!(resolver.poll_timeout(), None);
    }
}
