//! RFC 5452, Measures for Making DNS More Resilient against Forged Answers.
//! <https://rfc-annotations.research.icann.org/rfc5452.html>

mod common;

use std::collections::HashSet;
use std::net::SocketAddr;
use std::time::Instant;

use common::*;
use hickory_proto::op::{Message, Query};
use hickory_proto::rr::{DNSClass, Name, RecordType};
use proptest::prelude::*;
use rstest::rstest;
use sansio_dns::Resolver;

/// §9.1: a response MUST match the query's source and destination address,
/// port, ID, query name, class and type; otherwise it is invalid.
mod section_9_1 {
    use super::*;

    fn wrong_id(m: &mut Message) {
        m.metadata.id = m.metadata.id.wrapping_add(1);
    }
    fn wrong_name(m: &mut Message) {
        let q = &m.queries[0];
        m.queries[0] = Query::query(Name::from_ascii("example.net.").unwrap(), q.query_type());
    }
    fn wrong_type(m: &mut Message) {
        m.queries[0].set_query_type(RecordType::AAAA);
    }
    fn wrong_class(m: &mut Message) {
        m.queries[0].set_query_class(DNSClass::CH);
    }
    fn no_question(m: &mut Message) {
        m.queries.clear();
    }

    #[rstest]
    #[case::id(wrong_id)]
    #[case::name(wrong_name)]
    #[case::record_type(wrong_type)]
    #[case::class(wrong_class)]
    #[case::missing_question(no_question)]
    fn mismatched_response_is_invalid(mut resolver: Resolver, #[case] tamper: fn(&mut Message)) {
        let now = Instant::now();
        let sent = start(&mut resolver, now);
        let mut forged = reply(&sent);
        tamper(&mut forged);

        resolver.handle_datagram(S1, &encode(&forged), now);

        assert!(resolver.poll_event().is_none());
        resolver.handle_datagram(S1, &encode(&reply(&sent)), now);
        assert!(
            is_response(resolver.poll_event()),
            "genuine answer still accepted"
        );
    }

    #[rstest]
    #[case::other_server(S2)]
    #[case::other_port(SocketAddr::new(S1.ip(), 5353))]
    fn response_from_wrong_address_is_invalid(mut resolver: Resolver, #[case] from: SocketAddr) {
        let now = Instant::now();
        let sent = start(&mut resolver, now);

        resolver.handle_datagram(from, &encode(&reply(&sent)), now);

        assert!(resolver.poll_event().is_none());
    }

    /// After failing over, only the server currently asked may answer.
    #[rstest]
    fn late_answer_from_previous_server_is_invalid(mut resolver: Resolver) {
        let now = Instant::now();
        let first = start(&mut resolver, now);
        resolver.handle_timeout(resolver.poll_timeout().unwrap());
        assert_eq!(resolver.poll_transmit().unwrap().destination, S2);

        resolver.handle_datagram(S1, &encode(&reply(&first)), now);

        assert!(resolver.poll_event().is_none());
    }

    #[rstest]
    fn concurrent_queries_match_independently(mut resolver: Resolver) {
        let now = Instant::now();
        let a = start(&mut resolver, now);
        let b = start(&mut resolver, now);

        resolver.handle_datagram(S1, &encode(&reply(&b)), now);
        assert!(is_response(resolver.poll_event()));
        assert!(resolver.poll_timeout().is_some(), "a is still pending");
        resolver.handle_datagram(S1, &encode(&reply(&a)), now);
        assert!(is_response(resolver.poll_event()));
    }

    proptest! {
        /// Flipping any bit of the message ID makes the answer invalid.
        #[test]
        fn any_id_bit_flip_is_rejected(bit in 0u32..16) {
            let mut r = resolver();
            let now = Instant::now();
            let sent = start(&mut r, now);
            let mut forged = reply(&sent);
            forged.metadata.id ^= 1 << bit;

            r.handle_datagram(S1, &encode(&forged), now);

            prop_assert!(r.poll_event().is_none());
        }
    }
}

/// §4.6: once a response is accepted, later ones for the same query aren't.
mod section_4_6 {
    use super::*;

    #[rstest]
    fn first_matching_response_wins(mut resolver: Resolver) {
        let now = Instant::now();
        let sent = start(&mut resolver, now);
        let answer = encode(&reply(&sent));

        resolver.handle_datagram(S1, &answer, now);
        resolver.handle_datagram(S1, &answer, now);

        assert!(is_response(resolver.poll_event()));
        assert!(resolver.poll_event().is_none());
    }
}

/// §9.2: unpredictable IDs, and a separate source port per outstanding query.
mod section_9_2 {
    use super::*;

    /// Outstanding queries never share an ID, and each transmit names its
    /// query so the driver can give it its own socket.
    #[rstest]
    fn outstanding_queries_have_distinct_ids_and_handles(mut resolver: Resolver) {
        let now = Instant::now();
        let sent: Vec<_> = (0..512).map(|_| start(&mut resolver, now)).collect();

        let ids: HashSet<u16> = sent.iter().map(|t| decode(t).metadata.id).collect();
        let handles: HashSet<_> = sent.iter().map(|t| t.query).collect();
        assert_eq!(ids.len(), sent.len());
        assert_eq!(handles.len(), sent.len());
    }

    /// Not a randomness test, just a guard against a constant or counter ID.
    #[rstest]
    fn ids_are_not_sequential(mut resolver: Resolver) {
        let now = Instant::now();
        let ids: Vec<u16> = (0..64)
            .map(|_| decode(&start(&mut resolver, now)).metadata.id)
            .collect();
        assert!(ids.windows(2).any(|w| w[1] != w[0].wrapping_add(1)));
    }
}
