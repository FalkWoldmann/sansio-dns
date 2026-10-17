//! `addresses` (RFC 1034 §3.6.2 CNAME handling) and `IpLookup`.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::time::Instant;

use crate::common::*;
use hickory_proto::op::{Message, OpCode, Query, ResponseCode};
use hickory_proto::rr::rdata::{A, CNAME};
use hickory_proto::rr::{Name, RData, Record, RecordType};
use rstest::rstest;
use sansio_dns::{
    Config, Error, Event, IpLookup, IpStrategy, Progress, Resolver, Transmit, addresses,
};

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
    let mut events = events(resolver);
    events.reverse();
    feed(lookup, resolver, events)
}

fn events(resolver: &mut Resolver) -> Vec<Event> {
    std::iter::from_fn(|| resolver.poll_event()).collect()
}

/// Pass `events` to `lookup` in order; it must not finish before the last.
fn feed(lookup: IpLookup, resolver: &mut Resolver, events: Vec<Event>) -> Progress {
    events
        .into_iter()
        .fold(Progress::Waiting(lookup), |progress, e| match progress {
            Progress::Waiting(lookup) => lookup.handle_event(resolver, &e, Instant::now()),
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

        let events = events(&mut resolver);
        let progress = feed(lookup, &mut resolver, events);

        assert_eq!(progress, Progress::Done(Ok(expected.to_vec())));
    }

    #[test]
    fn single_family_failure_fails_the_lookup() {
        let mut resolver = single_attempt_resolver(IpStrategy::Ipv4Only);
        let lookup = IpLookup::start(&mut resolver, name("example.com."), Instant::now()).unwrap();

        let progress = finish(lookup, &mut resolver, [FAIL, OK]);

        assert_eq!(progress, Progress::Done(Err(Error::Server(FAIL))));
    }

    /// RFC 1123 §6.1.4.3: the lookup tries `printer` with the search
    /// domains `corp.example` and `home.example`, then as given, asking each
    /// candidate for both families.
    mod search {
        use super::*;

        const CANDIDATES: [&str; 3] =
            ["printer.corp.example.", "printer.home.example.", "printer."];

        /// A resolver searching `corp.example` and `home.example`.
        fn searching() -> Resolver {
            let mut config = Config::new(S1, []);
            config.search = vec![name("corp.example."), name("home.example.")];
            Resolver::new(config)
        }

        /// Answer each transmit with what `answer` makes of it, by type,
        /// check they ask for `candidate`, and hand the events to `lookup`.
        fn step(
            lookup: IpLookup,
            resolver: &mut Resolver,
            candidate: &str,
            answer: impl Fn(RecordType, Message) -> Message,
        ) -> Progress {
            let sent: Vec<Transmit> = std::iter::from_fn(|| resolver.poll_transmit()).collect();
            let mut queries: Vec<_> = sent.iter().map(udp).collect();
            let mut running: Vec<_> = lookup.queries().collect();
            queries.sort();
            running.sort();
            assert_eq!(queries, running, "the lookup's queries are the ones sent");
            for t in &sent {
                let question = decode(t).queries[0].clone();
                assert_eq!(question.name(), &name(candidate));
                let response = answer(question.query_type(), reply(t));
                resolver.handle_datagram(udp(t), S1, &encode(&response), Instant::now());
            }
            let events = events(resolver);
            feed(lookup, resolver, events)
        }

        fn waiting(progress: Progress) -> IpLookup {
            match progress {
                Progress::Waiting(lookup) => lookup,
                Progress::Done(outcome) => panic!("done early: {outcome:?}"),
            }
        }

        fn start(resolver: &mut Resolver) -> IpLookup {
            IpLookup::start(resolver, name("printer"), Instant::now()).unwrap()
        }

        /// RFC 1123 §6.1.4.3 (b): an address of one family ends the search
        /// for both, so the AAAA query doesn't go on to
        /// `printer.home.example.` and pick up another host's addresses.
        #[rstest]
        #[case::nodata(|r| no_data(r))]
        #[case::nxdomain(|r| with_code(r, NX))]
        fn an_address_of_one_family_ends_the_search(#[case] other: fn(Message) -> Message) {
            let mut resolver = searching();
            let lookup = start(&mut resolver);

            let progress = step(lookup, &mut resolver, CANDIDATES[0], |t, r| {
                if t == RecordType::A { r } else { other(r) }
            });

            assert!(resolver.poll_transmit().is_none());
            assert_eq!(progress, Progress::Done(Ok(vec![V4])));
        }

        /// No address of either family, whether the name doesn't exist or
        /// has no such records (RFC 2308 §2.2), moves both queries on
        /// together.
        #[rstest]
        #[case::nodata(|_, r| no_data(r))]
        #[case::nxdomain(|_, r| with_code(r, NX))]
        #[case::mixed(|t, r| if t == RecordType::A { no_data(r) } else { with_code(r, NX) })]
        fn no_address_moves_the_search_on(#[case] none: fn(RecordType, Message) -> Message) {
            let mut resolver = searching();
            let lookup = start(&mut resolver);

            let lookup = waiting(step(lookup, &mut resolver, CANDIDATES[0], none));
            let progress = step(lookup, &mut resolver, CANDIDATES[1], |_, r| r);

            assert_eq!(progress, Progress::Done(Ok(vec![V6, V4])));
        }

        #[test]
        fn no_address_anywhere_is_an_empty_list() {
            let mut resolver = searching();
            let mut progress = Progress::Waiting(start(&mut resolver));

            for candidate in CANDIDATES {
                progress = step(waiting(progress), &mut resolver, candidate, |_, r| {
                    no_data(r)
                });
            }

            assert!(resolver.poll_transmit().is_none());
            assert_eq!(progress, Progress::Done(Ok(vec![])));
        }

        /// A failure ends the search, as in `Resolver::query`.
        #[test]
        fn failure_ends_the_search() {
            let mut resolver = searching();
            let lookup = start(&mut resolver);

            let progress = step(lookup, &mut resolver, CANDIDATES[0], |t, r| {
                if t == RecordType::A {
                    with_code(r, FAIL)
                } else {
                    no_data(r)
                }
            });

            assert!(resolver.poll_transmit().is_none());
            assert_eq!(progress, Progress::Done(Err(Error::Server(FAIL))));
        }

        /// The lookup asks for each candidate by its absolute name, so a
        /// plain query for that name joins it.
        #[test]
        fn plain_query_for_the_candidate_joins_the_lookup() {
            let mut resolver = searching();
            let _lookup = start(&mut resolver);
            while resolver.poll_transmit().is_some() {}

            resolver
                .query(name(CANDIDATES[0]), RecordType::A, Instant::now())
                .unwrap();

            assert!(resolver.poll_transmit().is_none());
        }

        /// `Config::hosts` is checked for the name as given, before any
        /// search domain, as `Resolver::query` does.
        #[test]
        fn hosts_answer_the_name_as_given() {
            let mut config = Config::new(S1, []);
            config.search = vec![name("corp.example.")];
            config.hosts = sansio_dns::Hosts::parse(b"192.0.2.9 printer\n");
            let mut resolver = Resolver::new(config);
            let lookup = start(&mut resolver);

            let events = events(&mut resolver);
            let progress = feed(lookup, &mut resolver, events);

            assert!(resolver.poll_transmit().is_none());
            assert_eq!(
                progress,
                Progress::Done(Ok(vec![IpAddr::V4(Ipv4Addr::new(192, 0, 2, 9))]))
            );
        }
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

        let events = events(&mut resolver);
        let progress = feed(lookup, &mut resolver, events);

        assert!(matches!(progress, Progress::Waiting(_)), "{progress:?}");
    }

    #[rstest]
    fn localhost_resolves_without_network(mut resolver: Resolver) {
        let lookup = IpLookup::start(&mut resolver, name("localhost."), Instant::now()).unwrap();
        let events = events(&mut resolver);
        let progress = feed(lookup, &mut resolver, events);

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
