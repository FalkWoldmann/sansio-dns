//! RFC 1035, Domain Names - Implementation and Specification.
//! <https://rfc-annotations.research.icann.org/rfc1035.html>

use std::io::ErrorKind;
use std::time::{Duration, Instant};

use crate::common::*;
use hickory_proto::op::{MessageType, OpCode, Query, ResponseCode};
use hickory_proto::rr::rdata::A;
use hickory_proto::rr::{Name, RData, RecordType};
use insta::assert_snapshot;
use proptest::prelude::*;
use rstest::rstest;
use sansio_dns::{Error, Event, Resolver};
use std::assert_matches;

/// §2.3.3: name comparisons are case-insensitive, so a server that changes
/// the case of the question must still be matched.
mod section_2_3_3 {
    use super::*;

    proptest! {
        #[test]
        fn question_case_is_ignored(flips in proptest::collection::vec(any::<bool>(), 11)) {
            let mut r = resolver();
            let now = Instant::now();
            let sent = start(&mut r, now);
            let mut response = reply(&sent);
            let recased: String = "example.com"
                .chars()
                .zip(&flips)
                .map(|(c, &up)| if up { c.to_ascii_uppercase() } else { c })
                .collect();
            let name = Name::from_ascii(format!("{recased}.")).unwrap();
            let query = response.queries[0].clone();
            response.queries[0] = Query::query(name, query.query_type());

            r.handle_datagram(udp(&sent), S1, &encode(&response), now);

            prop_assert!(is_response(r.poll_event()));
        }
    }
}

/// §3.1 / §4.1.2: names on the wire are absolute, so `example.com` and
/// `example.com.` are the same question.
mod section_3_1 {
    use super::*;

    #[rstest]
    #[case::relative("example.com")]
    #[case::absolute("example.com.")]
    fn relative_and_absolute_names_resolve(mut resolver: Resolver, #[case] name: &str) {
        let now = Instant::now();
        let sent = start_name(&mut resolver, name, now);

        resolver.handle_datagram(udp(&sent), S1, &encode(&reply(&sent)), now);

        let Some(Event::Response { response, .. }) = resolver.poll_event() else {
            panic!("expected a response");
        };
        assert_eq!(response.answers[0].data, RData::A(A(ADDR)));
    }
}

/// §4.1.1: header fields of the query and their meaning in the response.
mod section_4_1_1 {
    use super::*;

    #[rstest]
    fn query_asks_for_recursion(mut resolver: Resolver) {
        let sent = decode(&start(&mut resolver, Instant::now()));
        assert_eq!(sent.metadata.message_type, MessageType::Query);
        assert_eq!(sent.metadata.op_code, OpCode::Query);
        assert!(sent.metadata.recursion_desired);
        assert_eq!(sent.queries.len(), 1);
    }

    /// RCODEs that are an answer about the name end the query.
    #[rstest]
    #[case::no_error(ResponseCode::NoError)]
    #[case::name_error(ResponseCode::NXDomain)]
    fn final_rcodes_complete_the_query(mut resolver: Resolver, #[case] code: ResponseCode) {
        let now = Instant::now();
        let sent = start(&mut resolver, now);

        resolver.handle_datagram(udp(&sent), S1, &encode(&with_code(reply(&sent), code)), now);

        let Some(Event::Response { response, .. }) = resolver.poll_event() else {
            panic!("expected a response");
        };
        assert_eq!(response.metadata.response_code, code);
        assert!(resolver.poll_transmit().is_none());
    }

    /// RCODEs that say this server can't answer move on to the next server.
    #[rstest]
    #[case::server_failure(ResponseCode::ServFail)]
    #[case::not_implemented(ResponseCode::NotImp)]
    #[case::refused(ResponseCode::Refused)]
    fn server_rcodes_fail_over(mut trace: Trace, #[case] code: ResponseCode) {
        trace.query("example.com.", RecordType::A);
        let sent = trace.last();
        trace.answer(&sent, &with_code(reply(&sent), code));
        let retry = trace.last();
        trace.answer(&retry, &reply(&retry));

        let trace = trace.to_string().replace(&format!("{code:?}"), "<code>");
        insta::allow_duplicates! {
            assert_snapshot!(trace, @"
            t=0s query q0 example.com. A
              -> S1 udp q0: example.com. A
              next t=2s
            t=0s <- S1 udp q0: example.com. A: <code>, 0 answers
              -> S2 udp q0: example.com. A
              next t=2s
            t=0s <- S2 udp q0: example.com. A: NoError, 1 answer
              => q0 Response example.com. A: NoError, 1 answer
              next none
            ");
        }
    }

    #[rstest]
    fn last_server_rcode_is_reported(
        #[values(ResponseCode::ServFail, ResponseCode::Refused)] code: ResponseCode,
    ) {
        let mut config = sansio_dns::Config::new(S1, []);
        config.attempts = std::num::NonZeroUsize::MIN;
        let mut r = Resolver::new(config);
        let now = Instant::now();
        let sent = start(&mut r, now);

        r.handle_datagram(udp(&sent), S1, &encode(&with_code(reply(&sent), code)), now);

        assert_matches!(
            r.poll_event(),
            Some(Event::Failed { error: Error::Server(c), .. }) if c == code
        );
    }
}

/// §4.2.1: a response that didn't fit in the datagram has TC set; the
/// query is retried over TCP (details in rfc7766.rs).
mod section_4_2_1 {
    use super::*;

    #[rstest]
    fn truncated_response_is_retried_over_tcp(mut trace: Trace) {
        trace.query("example.com.", RecordType::A);
        let sent = trace.last();

        trace.answer(&sent, &truncated(reply(&sent)));

        assert_snapshot!(trace, @"
        t=0s query q0 example.com. A
          -> S1 udp q0: example.com. A
          next t=2s
        t=0s <- S1 udp q0: example.com. A: NoError, 1 answer, TC
          -> S1 connect c0: example.com. A
          next t=2s
        ");
    }
}

/// §7.2: retransmit on timeout, cycling through the configured servers, and
/// keep track of how they did: new queries start after a server that
/// recently failed to answer.
mod section_7_2 {
    use super::*;

    #[rstest]
    fn timeouts_rotate_servers_then_fail(mut trace: Trace) {
        trace.query("example.com.", RecordType::A);

        trace.timeouts();

        assert_snapshot!(trace, @"
        t=0s query q0 example.com. A
          -> S1 udp q0: example.com. A
          next t=2s
        t=2s timeout
          -> S2 udp q0: example.com. A
          next t=4s
        t=4s timeout
          -> S1 udp q0: example.com. A
          next t=6s
        t=6s timeout
          -> S2 udp q0: example.com. A
          next t=8s
        t=8s timeout
          => q0 Failed Timeout
          next none
        ");
    }

    /// A datagram that can't be sent, say to a server of an address family
    /// the host has no route for, moves the query on without waiting out
    /// its deadline, and the last such error is the query's.
    #[rstest]
    fn unsendable_datagram_moves_on_at_once(mut trace: Trace) {
        trace.query("example.com.", RecordType::A);
        trace.at(Duration::from_millis(500));

        for _ in 0..4 {
            let sent = trace.last();
            trace.udp_error(&sent, ErrorKind::NetworkUnreachable);
        }

        assert_snapshot!(trace, @"
        t=0s query q0 example.com. A
          -> S1 udp q0: example.com. A
          next t=2s
        t=0.5s udp q0 to S1 error NetworkUnreachable
          -> S2 udp q0: example.com. A
          next t=2.5s
        t=0.5s udp q0 to S2 error NetworkUnreachable
          -> S1 udp q0: example.com. A
          next t=2.5s
        t=0.5s udp q0 to S1 error NetworkUnreachable
          -> S2 udp q0: example.com. A
          next t=2.5s
        t=0.5s udp q0 to S2 error NetworkUnreachable
          => q0 Failed Io(NetworkUnreachable)
          next none
        ");
    }

    /// A report about an attempt the query has moved on from is ignored:
    /// one to an earlier server, or one sent before switching to TCP.
    #[rstest]
    fn stale_udp_error_is_ignored(mut trace: Trace) {
        trace.query("example.com.", RecordType::A);
        let first = trace.last();
        trace.timeout();
        let second = trace.last();
        trace.udp_error(&first, ErrorKind::NetworkUnreachable);
        trace.answer(&second, &truncated(reply(&second)));
        trace.udp_error(&second, ErrorKind::NetworkUnreachable);

        assert_snapshot!(trace, @"
        t=0s query q0 example.com. A
          -> S1 udp q0: example.com. A
          next t=2s
        t=2s timeout
          -> S2 udp q0: example.com. A
          next t=4s
        t=2s udp q0 to S1 error NetworkUnreachable
          next t=4s
        t=2s <- S2 udp q0: example.com. A: NoError, 1 answer, TC
          -> S2 connect c0: example.com. A
          next t=4s
        t=2s udp q0 to S2 error NetworkUnreachable
          next t=4s
        ");
    }

    /// S1 times out, so queries in the next minute start at S2; after that,
    /// at S1 again.
    #[rstest]
    fn failed_server_is_tried_after_the_others(mut trace: Trace) {
        trace.query("a.example.", RecordType::A);
        trace.timeout();
        let sent = trace.last();
        trace.answer(&sent, &reply(&sent));
        trace.query("b.example.", RecordType::A);
        let sent = trace.last();
        trace.answer(&sent, &reply(&sent));
        trace.at(Duration::from_secs(62));
        trace.query("c.example.", RecordType::A);

        assert_snapshot!(trace, @"
        t=0s query q0 a.example. A
          -> S1 udp q0: a.example. A
          next t=2s
        t=2s timeout
          -> S2 udp q0: a.example. A
          next t=4s
        t=2s <- S2 udp q0: a.example. A: NoError, 1 answer
          => q0 Response a.example. A: NoError, 1 answer
          next none
        t=2s query q1 b.example. A
          -> S2 udp q1: b.example. A
          next t=4s
        t=2s <- S2 udp q1: b.example. A: NoError, 1 answer
          => q1 Response b.example. A: NoError, 1 answer
          next none
        t=62s query q2 c.example. A
          -> S1 udp q2: c.example. A
          next t=64s
        ");
    }

    /// An answer ends a failure early: S1 answers q1 after S2's SERVFAIL,
    /// which isn't a failure, so q2 starts at S1 again.
    #[rstest]
    fn answer_ends_the_failure(mut trace: Trace) {
        trace.query("a.example.", RecordType::A);
        trace.timeout();
        let sent = trace.last();
        trace.answer(&sent, &reply(&sent));
        trace.query("b.example.", RecordType::A);
        let sent = trace.last();
        trace.answer(&sent, &with_code(reply(&sent), ResponseCode::ServFail));
        let sent = trace.last();
        trace.answer(&sent, &reply(&sent));
        trace.query("c.example.", RecordType::A);

        assert_snapshot!(trace, @"
        t=0s query q0 a.example. A
          -> S1 udp q0: a.example. A
          next t=2s
        t=2s timeout
          -> S2 udp q0: a.example. A
          next t=4s
        t=2s <- S2 udp q0: a.example. A: NoError, 1 answer
          => q0 Response a.example. A: NoError, 1 answer
          next none
        t=2s query q1 b.example. A
          -> S2 udp q1: b.example. A
          next t=4s
        t=2s <- S2 udp q1: b.example. A: ServFail, 0 answers
          -> S1 udp q1: b.example. A
          next t=4s
        t=2s <- S1 udp q1: b.example. A: NoError, 1 answer
          => q1 Response b.example. A: NoError, 1 answer
          next none
        t=2s query q2 c.example. A
          -> S1 udp q2: c.example. A
          next t=4s
        ");
    }

    /// A server that answers with an error code is up, so it stays first.
    #[rstest]
    fn server_error_is_not_a_failure(mut trace: Trace) {
        trace.query("a.example.", RecordType::A);
        let sent = trace.last();
        trace.answer(&sent, &with_code(reply(&sent), ResponseCode::ServFail));
        trace.query("b.example.", RecordType::A);

        assert_snapshot!(trace, @"
        t=0s query q0 a.example. A
          -> S1 udp q0: a.example. A
          next t=2s
        t=0s <- S1 udp q0: a.example. A: ServFail, 0 answers
          -> S2 udp q0: a.example. A
          next t=2s
        t=0s query q1 b.example. A
          -> S1 udp q1: b.example. A
          next t=2s
        ");
    }

    #[test]
    fn zero_failure_memory_always_starts_at_the_first_server() {
        let mut config = sansio_dns::Config::new(S1, [S2]);
        config.failure_memory = Duration::ZERO;
        let mut trace = Trace::new(Resolver::new(config));
        trace.query("a.example.", RecordType::A);
        trace.timeout();
        trace.query("b.example.", RecordType::A);

        assert_eq!(trace.last().destination, S1);
    }

    #[rstest]
    fn retransmission_resends_the_same_question(mut resolver: Resolver) {
        let now = Instant::now();
        let first = start(&mut resolver, now);
        resolver.handle_timeout(resolver.poll_timeout().unwrap());
        assert_eq!(resolver.poll_transmit().unwrap().payload, first.payload);
    }

    #[test]
    fn timeout_too_large_for_instant_waits_forever() {
        let mut config = sansio_dns::Config::new(S1, []);
        config.timeout = Duration::MAX;
        let mut r = Resolver::new(config);
        let now = Instant::now();
        let sent = start(&mut r, now);

        assert_eq!(r.poll_timeout(), None);
        r.handle_datagram(udp(&sent), S1, &encode(&reply(&sent)), now);
        assert!(is_response(r.poll_event()));
    }
}

/// §7.3: a datagram that isn't a reply to our query is discarded.
mod section_7_3 {
    use super::*;

    #[rstest]
    fn a_query_is_not_a_response(mut resolver: Resolver) {
        let now = Instant::now();
        let sent = start(&mut resolver, now);
        let mut response = reply(&sent);
        response.metadata.message_type = MessageType::Query;

        resolver.handle_datagram(udp(&sent), S1, &encode(&response), now);

        assert!(resolver.poll_event().is_none());
    }

    #[rstest]
    fn opcode_must_match(mut resolver: Resolver) {
        let now = Instant::now();
        let sent = start(&mut resolver, now);
        let mut response = reply(&sent);
        response.metadata.op_code = OpCode::Status;

        resolver.handle_datagram(udp(&sent), S1, &encode(&response), now);

        assert!(resolver.poll_event().is_none());
    }

    proptest! {
        /// Arbitrary bytes never complete a query and never panic.
        #[test]
        fn garbage_is_discarded(data in proptest::collection::vec(any::<u8>(), 0..600)) {
            let mut r = resolver();
            let now = Instant::now();
            let sent = start(&mut r, now);
            r.handle_datagram(udp(&sent), S1, &data, now);
            prop_assert!(r.poll_event().is_none());
            prop_assert!(r.poll_timeout().is_some());
        }
    }
}
