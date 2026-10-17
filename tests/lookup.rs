//! `addresses` (RFC 1034 §3.6.2 CNAME handling) and `IpLookup`.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::time::Instant;

use crate::common::*;
use hickory_proto::op::{Message, OpCode, Query, ResponseCode};
use hickory_proto::rr::rdata::{A, CNAME};
use hickory_proto::rr::{Name, RData, Record, RecordType};
use rstest::rstest;
use sansio_dns::{Config, Error, Event, IpLookup, IpStrategy, Progress, Resolver, addresses};

fn name(s: &str) -> Name {
    Name::from_ascii(s).unwrap()
}

fn a(owner: &str, last_octet: u8) -> Record {
    Record::from_rdata(
        name(owner),
        300,
        RData::A(A(Ipv4Addr::new(192, 0, 2, last_octet))),
    )
}

fn cname(owner: &str, target: &str) -> Record {
    Record::from_rdata(name(owner), 300, RData::CNAME(CNAME(name(target))))
}

/// A response to `www.example.com. A` with the given answer section.
fn response(answers: Vec<Record>) -> Message {
    let mut m = Message::response(0, OpCode::Query);
    m.add_query(Query::query(name("www.example.com."), RecordType::A));
    m.answers = answers;
    m
}

/// RFC 1034 §3.6.2: addresses belong to the end of the CNAME chain.
mod rfc1034_section_3_6_2 {
    use super::*;

    #[test]
    fn follows_the_chain_and_ignores_other_owners() {
        let m = response(vec![
            a("unrelated.example.", 9),
            cname("cdn.example.net.", "edge.example.org."),
            cname("www.example.com.", "cdn.example.net."),
            a("www.example.com.", 8),
            a("edge.example.org.", 1),
        ]);
        assert_eq!(addresses(&m), [IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1))]);
    }

    #[test]
    fn cname_loop_ends_without_addresses() {
        let m = response(vec![
            cname("www.example.com.", "a.example."),
            cname("a.example.", "www.example.com."),
        ]);
        assert!(addresses(&m).is_empty());
    }
}

/// Answer the lookup's A query with the first response code and its AAAA
/// query with the second. With a single attempt, SERVFAIL fails the query.
fn finish(lookup: IpLookup, resolver: &mut Resolver, codes: [ResponseCode; 2]) -> Progress {
    let now = Instant::now();
    let sent: Vec<_> = std::iter::from_fn(|| resolver.poll_transmit()).collect();
    for t in &sent {
        let [a, aaaa] = codes;
        let code = if decode(t).queries[0].query_type() == RecordType::A {
            a
        } else {
            aaaa
        };
        resolver.handle_datagram(udp(t), S1, &encode(&with_code(reply(t), code)), now);
    }
    // Feed the events in reverse, to show the result doesn't depend on order.
    let events: Vec<Event> = std::iter::from_fn(|| resolver.poll_event()).collect();
    feed(lookup, events.into_iter().rev())
}

/// Pass `events` to `lookup` in order; it must not finish before the last.
fn feed(lookup: IpLookup, events: impl IntoIterator<Item = Event>) -> Progress {
    events
        .into_iter()
        .fold(Progress::Waiting(lookup), |progress, e| match progress {
            Progress::Waiting(lookup) => lookup.handle_event(&e),
            Progress::Done(_) => panic!("done before its last event"),
        })
}

fn single_attempt_resolver(ip_strategy: IpStrategy) -> Resolver {
    let mut config = Config::new(S1, []);
    config.attempts = std::num::NonZeroUsize::MIN;
    config.ip_strategy = ip_strategy;
    Resolver::new(config)
}

mod ip_lookup {
    use super::*;

    const OK: ResponseCode = ResponseCode::NoError;
    const NX: ResponseCode = ResponseCode::NXDomain;
    const FAIL: ResponseCode = ResponseCode::ServFail;

    const V4: IpAddr = IpAddr::V4(ADDR);
    const V6: IpAddr = IpAddr::V6(ADDR6);

    /// Codes are for A, then AAAA; the default lists IPv6 first.
    #[rstest]
    #[case::both([OK, OK], Ok(vec![V6, V4]))]
    #[case::only_a([OK, FAIL], Ok(vec![V4]))]
    #[case::only_aaaa([FAIL, OK], Ok(vec![V6]))]
    #[case::no_such_name([NX, NX], Ok(vec![]))]
    #[case::no_address_and_a_failure([NX, FAIL], Err(Error::Server(FAIL)))]
    #[case::both_failed([FAIL, FAIL], Err(Error::Server(FAIL)))]
    fn merges_both_families(
        #[case] codes: [ResponseCode; 2],
        #[case] expected: Result<Vec<IpAddr>, Error>,
    ) {
        let mut resolver = single_attempt_resolver(IpStrategy::default());
        let lookup = IpLookup::start(&mut resolver, name("example.com."), Instant::now()).unwrap();

        let progress = finish(lookup, &mut resolver, codes);

        assert_eq!(progress, Progress::Done(expected));
    }

    /// The strategy picks which queries are sent, in which order, and the
    /// order of the addresses. A single family's failure is the lookup's.
    #[rstest]
    #[case::ipv4_only(IpStrategy::Ipv4Only, &[RecordType::A], [V4].as_slice())]
    #[case::ipv6_only(IpStrategy::Ipv6Only, &[RecordType::AAAA], [V6].as_slice())]
    #[case::ipv4_first(IpStrategy::Ipv4First, &[RecordType::A, RecordType::AAAA], [V4, V6].as_slice())]
    #[case::ipv6_first(IpStrategy::Ipv6First, &[RecordType::AAAA, RecordType::A], [V6, V4].as_slice())]
    fn strategy_picks_families_and_order(
        #[case] strategy: IpStrategy,
        #[case] asked: &[RecordType],
        #[case] expected: &[IpAddr],
    ) {
        let mut resolver = single_attempt_resolver(strategy);
        let lookup = IpLookup::start(&mut resolver, name("example.com."), Instant::now()).unwrap();
        assert_eq!(lookup.queries().count(), asked.len());
        let sent: Vec<_> = std::iter::from_fn(|| resolver.poll_transmit()).collect();
        let types: Vec<RecordType> = sent
            .iter()
            .map(|t| decode(t).queries[0].query_type())
            .collect();
        assert_eq!(types, asked);
        for t in &sent {
            resolver.handle_datagram(udp(t), S1, &encode(&reply(t)), Instant::now());
        }

        let progress = feed(lookup, std::iter::from_fn(|| resolver.poll_event()));

        assert_eq!(progress, Progress::Done(Ok(expected.to_vec())));
    }

    #[test]
    fn single_family_failure_fails_the_lookup() {
        let mut resolver = single_attempt_resolver(IpStrategy::Ipv4Only);
        let lookup = IpLookup::start(&mut resolver, name("example.com."), Instant::now()).unwrap();

        let progress = finish(lookup, &mut resolver, [FAIL, OK]);

        assert_eq!(progress, Progress::Done(Err(Error::Server(FAIL))));
    }

    #[rstest]
    fn ignores_events_of_other_queries(mut resolver: Resolver) {
        let lookup = IpLookup::start(&mut resolver, name("example.com."), Instant::now()).unwrap();
        let a = resolver.poll_transmit().unwrap();
        while resolver.poll_transmit().is_some() {}
        let other = start_distinct(&mut resolver, Instant::now());
        for t in [&a, &other] {
            resolver.handle_datagram(udp(t), S1, &encode(&reply(t)), Instant::now());
        }

        let progress = feed(lookup, std::iter::from_fn(|| resolver.poll_event()));

        assert!(matches!(progress, Progress::Waiting(_)), "{progress:?}");
    }

    #[rstest]
    fn localhost_resolves_without_network(mut resolver: Resolver) {
        let lookup = IpLookup::start(&mut resolver, name("localhost."), Instant::now()).unwrap();
        let progress = feed(lookup, std::iter::from_fn(|| resolver.poll_event()));

        assert!(resolver.poll_transmit().is_none());
        assert_eq!(
            progress,
            Progress::Done(Ok(vec![
                IpAddr::V6(Ipv6Addr::LOCALHOST),
                IpAddr::V4(Ipv4Addr::LOCALHOST)
            ]))
        );
    }
}
