//! `addresses` (RFC 1034 §3.6.2 CNAME handling) and `IpLookup`.

#![expect(
    clippy::disallowed_methods,
    clippy::indexing_slicing,
    clippy::unwrap_used,
    reason = "tests stand in for the driver, and helpers outside #[test] may panic"
)]

mod common;

use std::net::{IpAddr, Ipv4Addr};
use std::time::Instant;

use common::*;
use hickory_proto::op::{Message, OpCode, Query, ResponseCode};
use hickory_proto::rr::rdata::{A, CNAME};
use hickory_proto::rr::{Name, RData, Record, RecordType};
use rstest::rstest;
use sansio_dns::{Error, Event, IpLookup, Progress, Resolver, addresses};

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

/// Answer the lookup's A and AAAA queries with these response codes. With a
/// single attempt, SERVFAIL fails the query.
fn finish(lookup: IpLookup, resolver: &mut Resolver, codes: [ResponseCode; 2]) -> Progress {
    let now = Instant::now();
    let sent: Vec<_> = std::iter::from_fn(|| resolver.poll_transmit()).collect();
    for (t, code) in sent.iter().zip(codes) {
        resolver.handle_datagram(udp(t), S1, &encode(&with_code(reply(t), code)), now);
    }
    // Feed the events in reverse, to show the result doesn't depend on order.
    let events: Vec<Event> = std::iter::from_fn(|| resolver.poll_event()).collect();
    feed(lookup, events.into_iter().rev())
}

/// Pass `events` to `lookup` in order; it must not finish before the last.
#[expect(clippy::panic, reason = "a test helper fails the test")]
fn feed(lookup: IpLookup, events: impl IntoIterator<Item = Event>) -> Progress {
    events
        .into_iter()
        .fold(Progress::Waiting(lookup), |progress, e| match progress {
            Progress::Waiting(lookup) => lookup.handle_event(&e),
            Progress::Done(_) => panic!("done before its last event"),
        })
}

fn single_attempt_resolver() -> Resolver {
    let mut config = sansio_dns::Config::new(S1, []);
    config.attempts = std::num::NonZeroUsize::MIN;
    Resolver::new(config)
}

mod ip_lookup {
    use super::*;

    const OK: ResponseCode = ResponseCode::NoError;
    const NX: ResponseCode = ResponseCode::NXDomain;
    const FAIL: ResponseCode = ResponseCode::ServFail;

    #[rstest]
    #[case::both([OK, OK], Ok(vec![IpAddr::V4(ADDR), IpAddr::V6(ADDR6)]))]
    #[case::only_a([OK, FAIL], Ok(vec![IpAddr::V4(ADDR)]))]
    #[case::only_aaaa([FAIL, OK], Ok(vec![IpAddr::V6(ADDR6)]))]
    #[case::no_such_name([NX, NX], Ok(vec![]))]
    #[case::no_address_and_a_failure([NX, FAIL], Err(Error::Server(FAIL)))]
    #[case::both_failed([FAIL, FAIL], Err(Error::Server(FAIL)))]
    fn merges_both_families(
        #[case] codes: [ResponseCode; 2],
        #[case] expected: Result<Vec<IpAddr>, Error>,
    ) {
        let mut resolver = single_attempt_resolver();
        let lookup = IpLookup::start(&mut resolver, name("example.com."), Instant::now()).unwrap();

        let progress = finish(lookup, &mut resolver, codes);

        assert_eq!(progress, Progress::Done(expected));
    }

    #[rstest]
    fn ignores_events_of_other_queries(mut resolver: Resolver) {
        let lookup = IpLookup::start(&mut resolver, name("example.com."), Instant::now()).unwrap();
        let a = resolver.poll_transmit().unwrap();
        while resolver.poll_transmit().is_some() {}
        let other = start(&mut resolver, Instant::now());
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
                IpAddr::V4(Ipv4Addr::LOCALHOST),
                IpAddr::V6(std::net::Ipv6Addr::LOCALHOST)
            ]))
        );
    }
}
