//! RFC 1035, Domain Names - Implementation and Specification.
//! <https://rfc-annotations.research.icann.org/rfc1035.html>

use std::io::ErrorKind;
use std::num::NonZeroUsize;
use std::time::{Duration, Instant};

use crate::common::*;
use hickory_proto::op::{MessageType, OpCode, Query, ResponseCode};
use hickory_proto::rr::rdata::A;
use hickory_proto::rr::{Name, RData, RecordType};
use insta::assert_snapshot;
use proptest::prelude::*;
use rstest::rstest;
use sansio_dns::{Config, Error, Event, Resolver};
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

    /// Every other RCODE says this server can't answer: the query moves on
    /// to the next server (§7.2). That includes the codes 6 to 15 that were
    /// "reserved for future use" here, later assigned ones such as NOTAUTH,
    /// and extended RCODEs carried in OPT, such as BADVERS (RFC 6891
    /// §6.1.3; hickory names code 16 BADSIG) and BADCOOKIE (RFC 7873 §5.3:
    /// no cookie was sent).
    #[rstest]
    #[case::server_failure(ResponseCode::ServFail)]
    #[case::not_implemented(ResponseCode::NotImp)]
    #[case::refused(ResponseCode::Refused)]
    #[case::yx_domain(ResponseCode::YXDomain)]
    #[case::yx_rrset(ResponseCode::YXRRSet)]
    #[case::nx_rrset(ResponseCode::NXRRSet)]
    #[case::not_auth(ResponseCode::NotAuth)]
    #[case::not_zone(ResponseCode::NotZone)]
    #[case::unassigned(ResponseCode::Unknown(11))]
    #[case::bad_vers(ResponseCode::BADSIG)]
    #[case::bad_cookie(ResponseCode::BADCOOKIE)]
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

    /// A referral from a server that doesn't recurse (RA clear, AA clear, no
    /// answer, NS records in authority) isn't an answer for a stub
    /// resolver, which relies on recursion only from servers that offer it
    /// (RFC 1034 §4.3.1, §5.3.1).
    #[rstest]
    fn referral_fails_over(mut trace: Trace) {
        trace.query("example.com.", RecordType::A);
        let sent = trace.last();
        trace.answer(&sent, &referral(reply(&sent)));
        let sent = trace.last();
        trace.answer(&sent, &referral(reply(&sent)));

        assert_snapshot!(trace, @"
        t=0s query q0 example.com. A
          -> S1 udp q0: example.com. A
          next t=2s
        t=0s <- S1 udp q0: example.com. A: NoError, 0 answers, no RA
          -> S2 udp q0: example.com. A
          next t=2s
        t=0s <- S2 udp q0: example.com. A: NoError, 0 answers, no RA
          => q0 Failed NoRecursion
          next none
        ");
    }

    /// Any empty `NOERROR` answer with neither AA nor RA set fails over,
    /// with or without NS records and with an SOA, as glibc's `send_dg`
    /// does: the server neither recursed nor is authoritative, so it can't
    /// say the name has no data (RFC 1034 §4.3.1, §5.3.1).
    #[rstest]
    #[case::ns(|r| referral(r))]
    #[case::soa(|r| { let mut r = with_soa(referral(r)); r.authorities.retain(|a| a.record_type() == RecordType::SOA); r })]
    #[case::bare(|r| { let mut r = referral(r); r.authorities.clear(); r })]
    fn empty_answer_without_aa_or_ra_fails_over(
        mut resolver: Resolver,
        #[case] make: fn(hickory_proto::op::Message) -> hickory_proto::op::Message,
    ) {
        let now = Instant::now();
        let sent = start(&mut resolver, now);
        let response = make(reply(&sent));

        resolver.handle_datagram(udp(&sent), S1, &encode(&response), now);

        assert!(resolver.poll_event().is_none());
        assert_eq!(resolver.poll_transmit().map(|t| t.destination), Some(S2));
    }

    /// An empty answer with AA or RA set is NODATA, not a referral.
    #[rstest]
    #[case::authoritative(|r| { let mut r = referral(r); r.metadata.authoritative = true; r })]
    #[case::recursive(|r| { let mut r = referral(r); r.metadata.recursion_available = true; r })]
    #[case::recursive_with_soa(|r| { let mut r = with_soa(no_data(r)); r.metadata.recursion_available = true; r })]
    fn nodata_is_not_a_referral(
        mut resolver: Resolver,
        #[case] make: fn(hickory_proto::op::Message) -> hickory_proto::op::Message,
    ) {
        let now = Instant::now();
        let sent = start(&mut resolver, now);
        let response = make(reply(&sent));

        resolver.handle_datagram(udp(&sent), S1, &encode(&response), now);

        assert!(is_response(resolver.poll_event()));
        assert!(resolver.poll_transmit().is_none());
    }

    #[rstest]
    fn last_server_rcode_is_reported(
        #[values(ResponseCode::ServFail, ResponseCode::Refused)] code: ResponseCode,
    ) {
        let mut config = Config::new(S1, []);
        config.attempts = NonZeroUsize::MIN;
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
          next t=8s
        t=8s timeout
          -> S2 udp q0: example.com. A
          next t=12s
        t=12s timeout
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
          next t=4.5s
        t=0.5s udp q0 to S1 error NetworkUnreachable
          -> S2 udp q0: example.com. A
          next t=4.5s
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

    /// A server that answered with an error is removed from the query's
    /// list ("remove it from SLIST"): later attempts skip it, and the rounds
    /// through the remaining servers still back off.
    #[test]
    fn server_error_removes_the_server_for_the_query() {
        let mut config = config();
        config.attempts = NonZeroUsize::new(4).unwrap();
        let mut trace = Trace::new(Resolver::new(config));
        trace.query("example.com.", RecordType::A);
        let sent = trace.last();
        trace.answer(&sent, &with_code(reply(&sent), ResponseCode::Refused));

        trace.timeouts();

        assert_snapshot!(trace, @"
        t=0s query q0 example.com. A
          -> S1 udp q0: example.com. A
          next t=2s
        t=0s <- S1 udp q0: example.com. A: Refused, 0 answers
          -> S2 udp q0: example.com. A
          next t=2s
        t=2s timeout
          -> S2 udp q0: example.com. A
          next t=6s
        t=6s timeout
          -> S2 udp q0: example.com. A
          next t=14s
        t=14s timeout
          => q0 Failed Timeout
          next none
        ");
    }

    /// Once every server answered with an error, the query fails at once
    /// with the last one, without asking any of them again.
    #[rstest]
    fn query_ends_when_every_server_answered_with_an_error(mut trace: Trace) {
        trace.query("example.com.", RecordType::A);
        let sent = trace.last();
        trace.answer(&sent, &with_code(reply(&sent), ResponseCode::Refused));
        let sent = trace.last();
        trace.answer(&sent, &with_code(reply(&sent), ResponseCode::ServFail));

        assert_snapshot!(trace, @"
        t=0s query q0 example.com. A
          -> S1 udp q0: example.com. A
          next t=2s
        t=0s <- S1 udp q0: example.com. A: Refused, 0 answers
          -> S2 udp q0: example.com. A
          next t=2s
        t=0s <- S2 udp q0: example.com. A: ServFail, 0 answers
          => q0 Failed Server(ServFail)
          next none
        ");
    }

    /// With one server, an error code ends the query: there is no other
    /// server to ask, and asking the same one again at once would only
    /// repeat the error.
    #[test]
    fn one_server_error_ends_the_query() {
        let mut trace = Trace::new(Resolver::new(Config::new(S1, [])));
        trace.query("example.com.", RecordType::A);
        let sent = trace.last();

        trace.answer(&sent, &with_code(reply(&sent), ResponseCode::ServFail));

        assert_snapshot!(trace, @"
        t=0s query q0 example.com. A
          -> S1 udp q0: example.com. A
          next t=5s
        t=0s <- S1 udp q0: example.com. A: ServFail, 0 answers
          => q0 Failed Server(ServFail)
          next none
        ");
    }

    /// A server that didn't answer stays in the list: a later, longer wait
    /// may reach it.
    #[rstest]
    fn timeout_keeps_the_server(mut trace: Trace) {
        trace.query("example.com.", RecordType::A);
        trace.timeout();
        let sent = trace.last();
        trace.answer(&sent, &with_code(reply(&sent), ResponseCode::ServFail));
        let sent = trace.last();
        trace.answer(&sent, &reply(&sent));

        assert_snapshot!(trace, @"
        t=0s query q0 example.com. A
          -> S1 udp q0: example.com. A
          next t=2s
        t=2s timeout
          -> S2 udp q0: example.com. A
          next t=4s
        t=2s <- S2 udp q0: example.com. A: ServFail, 0 answers
          -> S1 udp q0: example.com. A
          next t=6s
        t=2s <- S1 udp q0: example.com. A: NoError, 1 answer
          => q0 Response example.com. A: NoError, 1 answer
          next none
        ");
    }

    /// The next search candidate is a new question: every server may be
    /// asked again.
    #[test]
    fn next_search_candidate_asks_every_server_again() {
        let mut config = config();
        config.search = vec![Name::from_ascii("corp.example.").unwrap()];
        let mut trace = Trace::new(Resolver::new(config));
        trace.query("db", RecordType::A);
        let sent = trace.last();
        trace.answer(&sent, &with_code(reply(&sent), ResponseCode::ServFail));
        let sent = trace.last();
        trace.answer(&sent, &with_code(reply(&sent), ResponseCode::NXDomain));
        let sent = trace.last();
        trace.answer(&sent, &reply(&sent));

        assert_snapshot!(trace, @"
        t=0s query q0 db A
          -> S1 udp q0: db.corp.example. A
          next t=2s
        t=0s <- S1 udp q0: db.corp.example. A: ServFail, 0 answers
          -> S2 udp q0: db.corp.example. A
          next t=2s
        t=0s <- S2 udp q0: db.corp.example. A: NXDomain, 0 answers
          -> S1 udp q0: db. A
          next t=2s
        t=0s <- S1 udp q0: db. A: NoError, 1 answer
          => q0 Response db. A: NoError, 1 answer
          next none
        ");
    }

    #[test]
    fn zero_failure_memory_always_starts_at_the_first_server() {
        let mut config = Config::new(S1, [S2]);
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

    /// A reply whose header and question match but whose records don't
    /// parse is a "bizarre response" (§7.2): the query moves on to the next
    /// server at once instead of waiting out its deadline.
    #[rstest]
    fn undecodable_reply_moves_on_at_once(mut trace: Trace) {
        trace.query("example.com.", RecordType::A);
        let sent = trace.last();
        trace.answer_bytes(&sent, &cut(&encode(&reply(&sent))), "cut short");
        let sent = trace.last();
        trace.answer(&sent, &reply(&sent));

        assert_snapshot!(trace, @"
        t=0s query q0 example.com. A
          -> S1 udp q0: example.com. A
          next t=2s
        t=0s <- S1 udp q0: cut short
          -> S2 udp q0: example.com. A
          next t=2s
        t=0s <- S2 udp q0: example.com. A: NoError, 1 answer
          => q0 Response example.com. A: NoError, 1 answer
          next none
        ");
    }

    #[rstest]
    fn undecodable_reply_on_a_stream_moves_on(mut trace: Trace) {
        trace.query("example.com.", RecordType::A);
        let sent = trace.last();
        trace.answer(&sent, &truncated(reply(&sent)));
        let tcp = trace.last();
        trace.answer_bytes(&tcp, &cut(&encode(&reply(&tcp))), "cut short");

        assert_snapshot!(trace, @"
        t=0s query q0 example.com. A
          -> S1 udp q0: example.com. A
          next t=2s
        t=0s <- S1 udp q0: example.com. A: NoError, 1 answer, TC
          -> S1 connect c0: example.com. A
          next t=2s
        t=0s <- S1 c0: cut short
          -> S2 connect c1: example.com. A
          next t=2s
        ");
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
