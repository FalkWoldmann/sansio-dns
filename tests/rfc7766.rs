//! RFC 7766, DNS Transport over TCP - Implementation Requirements.
//! <https://rfc-annotations.research.icann.org/rfc7766.html>

#![expect(
    clippy::disallowed_methods,
    clippy::indexing_slicing,
    clippy::unwrap_used,
    reason = "tests stand in for the driver, and helpers outside #[test] may panic"
)]

mod common;

use std::time::Instant;

use common::*;
use hickory_proto::rr::RData;
use hickory_proto::rr::rdata::A;
use proptest::prelude::*;
use rstest::rstest;
use sansio_dns::{Event, Resolver, Transmit, Transport};

/// Start a query, answer it with TC set over UDP, and return the TCP transmit.
fn switch_to_tcp(resolver: &mut Resolver, now: Instant) -> Transmit {
    let sent = start(resolver, now);
    let mut truncated = reply(&sent);
    truncated.metadata.truncation = true;
    resolver.handle_datagram(S1, &encode(&truncated), now);
    resolver.poll_transmit().unwrap()
}

/// §5: a truncated UDP response is retried over TCP, to the same server.
mod section_5 {
    use super::*;

    #[rstest]
    fn truncation_retries_the_same_query_over_tcp(mut resolver: Resolver) {
        let now = Instant::now();
        let udp = start(&mut resolver, now);
        let mut truncated = reply(&udp);
        truncated.metadata.truncation = true;

        resolver.handle_datagram(S1, &encode(&truncated), now);

        let tcp = resolver.poll_transmit().unwrap();
        assert_eq!(tcp.transport, Transport::Tcp);
        assert_eq!(tcp.destination, S1);
        assert_eq!(tcp.payload, frame(&udp.payload));
    }

    /// Once on TCP, a UDP answer could only be spoofed or late; ignore it.
    #[rstest]
    fn udp_answer_after_switch_is_ignored(mut resolver: Resolver) {
        let now = Instant::now();
        let tcp = switch_to_tcp(&mut resolver, now);

        resolver.handle_datagram(S1, &encode(&reply(&tcp)), now);

        assert!(resolver.poll_event().is_none());
    }

    #[rstest]
    fn truncated_answer_over_tcp_is_used(mut resolver: Resolver) {
        let now = Instant::now();
        let tcp = switch_to_tcp(&mut resolver, now);
        let mut answer = reply(&tcp);
        answer.metadata.truncation = true;

        resolver.handle_stream_data(tcp.query, &frame(&encode(&answer)), now);

        assert!(is_response(resolver.poll_event()));
    }

    fn close(resolver: &mut Resolver, tcp: &Transmit, now: Instant) {
        resolver.handle_stream_closed(tcp.query, now);
    }
    fn time_out(resolver: &mut Resolver, _: &Transmit, _: Instant) {
        resolver.handle_timeout(resolver.poll_timeout().unwrap());
    }

    /// A failed TCP attempt moves to the next server and stays on TCP: the
    /// answer is known not to fit in UDP.
    #[rstest]
    #[case::connection_closed(close)]
    #[case::timeout(time_out)]
    fn failed_tcp_attempt_retries_next_server_over_tcp(
        mut resolver: Resolver,
        #[case] fail: fn(&mut Resolver, &Transmit, Instant),
    ) {
        let now = Instant::now();
        let tcp = switch_to_tcp(&mut resolver, now);

        fail(&mut resolver, &tcp, now);

        let retry = resolver.poll_transmit().unwrap();
        assert_eq!(retry.transport, Transport::Tcp);
        assert_eq!(retry.destination, S2);
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
                .for_each(|w| r.handle_stream_data(tcp.query, &bytes[w[0]..w[1]], now));

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
        resolver.handle_stream_data(first.query, &[0, 40, 1, 2], now);
        resolver.handle_stream_closed(first.query, now);
        let second = resolver.poll_transmit().unwrap();

        resolver.handle_stream_data(second.query, &frame(&encode(&reply(&second))), now);

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

        resolver.handle_stream_data(tcp.query, &bytes, now);

        assert!(is_response(resolver.poll_event()));
    }
}
