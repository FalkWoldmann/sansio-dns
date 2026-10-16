//! RFC 6891, Extension Mechanisms for DNS (EDNS(0)).
//! <https://rfc-annotations.research.icann.org/rfc6891.html>

#![expect(
    clippy::disallowed_methods,
    clippy::indexing_slicing,
    clippy::unwrap_used,
    reason = "tests stand in for the driver, and helpers outside #[test] may panic"
)]

mod common;

use std::time::Instant;

use common::*;
use hickory_proto::op::ResponseCode;
use rstest::rstest;
use sansio_dns::Resolver;

/// §6.1.1 / §6.2.3: the query carries exactly one OPT record advertising a
/// payload size of at least 512 octets that avoids fragmentation.
mod section_6_2_3 {
    use super::*;

    #[rstest]
    fn query_advertises_a_safe_payload_size(mut resolver: Resolver) {
        let sent = decode(&start(&mut resolver, Instant::now()));
        let edns = sent.edns.expect("query carries OPT");
        assert_eq!(edns.max_payload(), 1232);
        assert_eq!(edns.version(), 0);
    }
}

/// §7 / §6.2.2: a server that doesn't implement EDNS answers FORMERR without
/// an OPT record; the requestor may retry without EDNS. FORMERR *with* OPT
/// means the server does speak EDNS, so it's an ordinary server error.
mod section_7 {
    use super::*;

    #[rstest]
    fn formerr_without_opt_retries_same_server_without_edns(mut resolver: Resolver) {
        let now = Instant::now();
        let sent = start(&mut resolver, now);
        let mut response = with_code(reply(&sent), ResponseCode::FormErr);
        response.edns = None;

        resolver.handle_datagram(udp(&sent), S1, &encode(&response), now);

        let retry = resolver.poll_transmit().unwrap();
        assert_eq!(retry.destination, S1);
        assert!(decode(&retry).edns.is_none());
        assert_eq!(decode(&retry).metadata.id, decode(&sent).metadata.id);
        resolver.handle_datagram(udp(&retry), S1, &encode(&reply(&retry)), now);
        assert!(is_response(resolver.poll_event()));
    }

    #[rstest]
    fn formerr_with_opt_fails_over(mut resolver: Resolver) {
        let now = Instant::now();
        let sent = start(&mut resolver, now);

        resolver.handle_datagram(
            udp(&sent),
            S1,
            &encode(&with_code(reply(&sent), ResponseCode::FormErr)),
            now,
        );

        let retry = resolver.poll_transmit().unwrap();
        assert_eq!(retry.destination, S2);
        assert!(decode(&retry).edns.is_some());
    }

    /// The downgrade happens once; FORMERR to the plain query is final for
    /// that server, so a broken server can't keep the query alive forever.
    #[rstest]
    fn edns_is_dropped_only_once(mut resolver: Resolver) {
        let now = Instant::now();
        let mut sent = start(&mut resolver, now);
        let mut destinations = Vec::new();
        for _ in 0..3 {
            let mut response = with_code(reply(&sent), ResponseCode::FormErr);
            response.edns = None;
            resolver.handle_datagram(udp(&sent), sent.destination, &encode(&response), now);
            let Some(next) = resolver.poll_transmit() else {
                break;
            };
            destinations.push(next.destination);
            sent = next;
        }

        assert_eq!(destinations, [S1, S2, S1]);
    }
}
