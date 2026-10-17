//! `addresses` (RFC 1034 §3.6.2 CNAME handling) and `IpLookup`.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::time::Instant;

use crate::common::*;
use hickory_proto::op::{Message, OpCode, Query, ResponseCode};
use hickory_proto::rr::rdata::{A, AAAA, CNAME};
use hickory_proto::rr::{DNSClass, Name, RData, Record, RecordType};
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
    response_to(RecordType::A, answers)
}

/// A response to `www.example.com.` of type `record_type` with the given
/// answer section.
fn response_to(record_type: RecordType, answers: Vec<Record>) -> Message {
    let mut m = Message::response(0, OpCode::Query);
    m.add_query(Query::query(name("www.example.com."), record_type));
    m.answers = answers;
    m
}

fn aaaa(owner: &str, last: u16) -> Record {
    let address = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, last);
    Record::from_rdata(name(owner), 300, RData::AAAA(AAAA(address)))
}

fn v4(last_octet: u8) -> IpAddr {
    IpAddr::V4(Ipv4Addr::new(192, 0, 2, last_octet))
}

fn v6(last: u16) -> IpAddr {
    IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, last))
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
        assert_eq!(addresses(&m), Ok(vec![v4(1)]));
    }

    /// "CNAME loops signalled as an error" (§3.6.2, §5.2.2), even when a
    /// name on the loop also has an address.
    #[rstest]
    #[case::two_names(vec![
        cname("www.example.com.", "a.example."),
        cname("a.example.", "www.example.com."),
    ])]
    #[case::to_itself(vec![cname("www.example.com.", "WWW.example.com.")])]
    #[case::loop_with_an_address(vec![
        cname("www.example.com.", "a.example."),
        cname("a.example.", "www.example.com."),
        a("a.example.", 1),
    ])]
    #[case::loop_further_down(vec![
        cname("www.example.com.", "a.example."),
        cname("a.example.", "b.example."),
        cname("b.example.", "a.example."),
    ])]
    fn cname_loop_is_an_error(#[case] answers: Vec<Record>) {
        assert_eq!(addresses(&response(answers)), Err(Error::CnameLoop));
    }

    /// A chain that ends without address records isn't a loop.
    #[test]
    fn chain_without_addresses_is_empty() {
        let m = response(vec![
            cname("www.example.com.", "a.example."),
            cname("a.example.", "b.example."),
        ]);
        assert_eq!(addresses(&m), Ok(vec![]));
    }
}

/// RFC 3596 §2.3 and RFC 1035 §7.4: only records of the type and class
/// asked for count, at the end of the chain.
mod rfc3596_section_2_3 {
    use super::*;

    #[rstest]
    #[case::a(RecordType::A, vec![v4(1)])]
    #[case::aaaa(RecordType::AAAA, vec![v6(1)])]
    #[case::any(RecordType::ANY, vec![v4(1), v6(1)])]
    #[case::other_type(RecordType::MX, vec![])]
    fn only_the_type_asked_for(#[case] record_type: RecordType, #[case] expected: Vec<IpAddr>) {
        let m = response_to(
            record_type,
            vec![a("www.example.com.", 1), aaaa("www.example.com.", 1)],
        );
        assert_eq!(addresses(&m), Ok(expected));
    }

    #[test]
    fn records_of_another_class_are_ignored() {
        let mut chaos_alias = cname("www.example.com.", "other.example.");
        chaos_alias.dns_class = DNSClass::CH;
        let mut chaos_address = a("www.example.com.", 2);
        chaos_address.dns_class = DNSClass::CH;
        let m = response(vec![
            chaos_alias,
            chaos_address,
            a("www.example.com.", 1),
            a("other.example.", 3),
        ]);
        assert_eq!(addresses(&m), Ok(vec![v4(1)]));
    }
}

/// RFC 6761 §6.3, §6.4 and RFC 7686 §2: a chain ends at a special-use name,
/// which has no aliases; a `localhost` name has the loopback address, the
/// others no address.
mod rfc6761_chain_into_special_use {
    use super::*;

    #[rstest]
    #[case::a(RecordType::A, IpAddr::V4(Ipv4Addr::LOCALHOST))]
    #[case::aaaa(RecordType::AAAA, IpAddr::V6(Ipv6Addr::LOCALHOST))]
    fn localhost_target_gives_loopback(#[case] record_type: RecordType, #[case] loopback: IpAddr) {
        let m = response_to(
            record_type,
            vec![
                cname("www.example.com.", "app.localhost."),
                a("app.localhost.", 7),
                aaaa("app.localhost.", 7),
                cname("app.localhost.", "elsewhere.example."),
                a("elsewhere.example.", 8),
            ],
        );
        assert_eq!(addresses(&m), Ok(vec![loopback]));
    }

    #[rstest]
    #[case::invalid("x.invalid.")]
    #[case::onion("x.onion.")]
    fn nxdomain_target_gives_no_address(#[case] target: &str) {
        let m = response(vec![
            cname("www.example.com.", target),
            a(target, 7),
            cname(target, "elsewhere.example."),
            a("elsewhere.example.", 8),
        ]);
        assert_eq!(addresses(&m), Ok(vec![]));
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

    /// RFC 1034 §5.2.2: a CNAME loop is passed back as an error, merged
    /// with the other family's outcome like a failure.
    #[rstest]
    #[case::other_family_has_an_address(false, Ok(vec![V4]))]
    #[case::both_loop(true, Err(Error::CnameLoop))]
    fn cname_loop_fails_the_family(
        #[case] a_loops: bool,
        #[case] expected: Result<Vec<IpAddr>, Error>,
    ) {
        let mut resolver = single_attempt_resolver(IpStrategy::default());
        let lookup = IpLookup::start(&mut resolver, name("example.com."), Instant::now()).unwrap();
        let sent: Vec<_> = std::iter::from_fn(|| resolver.poll_transmit()).collect();
        for t in &sent {
            let mut response = reply(t);
            let is_a = decode(t).queries[0].query_type() == RecordType::A;
            if !is_a || a_loops {
                response.answers = vec![cname("example.com.", "example.com.")];
            }
            resolver.handle_datagram(udp(t), S1, &encode(&response), Instant::now());
        }

        let events = events(&mut resolver);
        let progress = feed(lookup, &mut resolver, events);

        assert_eq!(progress, Progress::Done(expected));
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

        /// A later lookup skips, for both families and without a transmit,
        /// the candidate the cache knows doesn't exist (RFC 2308 §5, RFC
        /// 1123 §6.1.4.3 (a)).
        #[test]
        fn cached_nxdomain_moves_on_without_a_transmit() {
            let mut resolver = searching();
            let lookup = start(&mut resolver);
            let lookup = waiting(step(lookup, &mut resolver, CANDIDATES[0], |_, r| {
                with_soa(with_code(r, NX))
            }));
            step(lookup, &mut resolver, CANDIDATES[1], |_, r| r);

            let lookup = start(&mut resolver);
            assert!(resolver.poll_transmit().is_none());
            let events = events(&mut resolver);
            let lookup = waiting(feed(lookup, &mut resolver, events));
            let progress = step(lookup, &mut resolver, CANDIDATES[1], |_, r| r);

            assert_eq!(progress, Progress::Done(Ok(vec![V6, V4])));
        }

        /// A cached failure ends a later lookup as the failure ended the
        /// first, without a transmit for that candidate.
        #[test]
        fn cached_failure_ends_the_search() {
            let mut resolver = searching();
            let lookup = start(&mut resolver);
            step(lookup, &mut resolver, CANDIDATES[0], |_, r| {
                with_code(r, FAIL)
            });

            let lookup = start(&mut resolver);
            assert!(resolver.poll_transmit().is_none());
            let events = events(&mut resolver);
            let progress = feed(lookup, &mut resolver, events);

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

        /// RFC 6762 §3, §22.1 item 3: a link-local name is judged per
        /// search candidate, as `Resolver::query` does.
        mod link_local {
            use super::*;

            fn searching(search: &[&str]) -> Resolver {
                let mut config = Config::new(S1, []);
                config.search = search.iter().map(|domain| name(domain)).collect();
                Resolver::new(config)
            }

            fn start(resolver: &mut Resolver, host: &str) -> IpLookup {
                IpLookup::start(resolver, name(host), Instant::now()).unwrap()
            }

            /// Kubernetes service `db` in a namespace named `local`: the
            /// lookup walks the candidates under `cluster.local.` itself,
            /// so an address of one family ends the search for both.
            #[test]
            fn walks_the_candidates_under_a_search_domain() {
                let mut resolver = searching(&["svc.cluster.local.", "cluster.local."]);
                let lookup = start(&mut resolver, "db.local");

                let progress = step(
                    lookup,
                    &mut resolver,
                    "db.local.svc.cluster.local.",
                    |t, r| {
                        if t == RecordType::A {
                            r
                        } else {
                            with_code(r, NX)
                        }
                    },
                );

                assert!(resolver.poll_transmit().is_none());
                assert_eq!(progress, Progress::Done(Ok(vec![V4])));
            }

            /// The name as given, `printer.local.`, is left out, but the
            /// searched candidate isn't link-local and is sent.
            #[test]
            fn tries_the_searched_candidates_only() {
                let mut resolver = searching(&["corp.example."]);
                let lookup = start(&mut resolver, "printer.local");

                let progress = step(
                    lookup,
                    &mut resolver,
                    "printer.local.corp.example.",
                    |_, r| with_code(r, NX),
                );

                assert!(resolver.poll_transmit().is_none());
                assert_eq!(progress, Progress::Done(Ok(vec![])));
            }

            #[rstest]
            #[case::absolute(&["cluster.local."], "printer.local.")]
            #[case::no_candidate_left(&["local."], "printer.local")]
            #[case::reverse_zone(&[], "34.12.254.169.in-addr.arpa")]
            fn is_answered_locally(#[case] search: &[&str], #[case] host: &str) {
                let mut resolver = searching(search);
                let lookup = start(&mut resolver, host);

                let events = events(&mut resolver);
                let progress = feed(lookup, &mut resolver, events);

                assert!(resolver.poll_transmit().is_none());
                assert_eq!(progress, Progress::Done(Ok(vec![])));
            }
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
