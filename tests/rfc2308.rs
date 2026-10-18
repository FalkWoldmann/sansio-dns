//! RFC 2308, Negative Caching of DNS Queries (DNS NCACHE).
//! <https://rfc-annotations.research.icann.org/rfc2308.html>

use std::time::Duration;

use crate::common::*;
use hickory_proto::op::{Message, ResponseCode};
use hickory_proto::rr::rdata::{CNAME, NS};
use hickory_proto::rr::{Name, RData, Record, RecordType};
use insta::assert_snapshot;
use rstest::rstest;
use sansio_dns::{Config, Event, Resolver};

fn name(s: &str) -> Name {
    Name::from_ascii(s).unwrap()
}

/// `S1` alone, with the fixture's two-second timeout and `config`'s
/// changes.
fn one_server(change: impl FnOnce(&mut Config)) -> Trace {
    let mut config = Config::new(S1, []);
    config.timeout = Duration::from_secs(2);
    change(&mut config);
    Trace::new(Resolver::new(config))
}

/// Query `name` for `record_type` and answer it with what `negative` makes
/// of the server's reply.
fn deny(trace: &mut Trace, name: &str, record_type: RecordType, negative: fn(Message) -> Message) {
    trace.query(name, record_type);
    let sent = trace.last();
    trace.answer(&sent, &negative(reply(&sent)));
}

fn nxdomain(response: Message) -> Message {
    with_soa(with_code(response, ResponseCode::NXDomain))
}

fn nodata(response: Message) -> Message {
    with_soa(no_data(response))
}

/// §5: "A negative answer that resulted from a name error (NXDOMAIN)
/// should be cached such that it can be retrieved and returned in response
/// to another query for the same <QNAME, QCLASS>", and one from NODATA for
/// the same <QNAME, QTYPE, QCLASS>. Its TTL is the lesser of the SOA
/// record's TTL and its MINIMUM field, and "Negative responses without SOA
/// records SHOULD NOT be cached". A resolver should limit how long it
/// caches one: one hour by default here. §8 makes caching negative answers
/// part of any resolver that caches. A truncated answer is never cached
/// (RFC 1123 §6.1.3.2).
mod section_5 {
    use super::*;

    /// A name below the one that doesn't exist is still sent: RFC 8020's
    /// cut isn't applied.
    #[test]
    fn nxdomain_is_cached_for_every_type_of_the_name() {
        let mut trace = one_server(|_| {});
        deny(&mut trace, "nx.example.com.", RecordType::A, nxdomain);
        trace.at(Duration::from_secs(1));
        trace.query("nx.example.com.", RecordType::A);
        trace.query("nx.example.com.", RecordType::MX);
        trace.query("www.nx.example.com.", RecordType::A);

        assert_snapshot!(trace, @"
        t=0s query q0 nx.example.com. A
          -> S1 udp q0: nx.example.com. A
          next t=2s
        t=0s <- S1 udp q0: nx.example.com. A: NXDomain, 0 answers, SOA 300
          => q0 Response nx.example.com. A: NXDomain, 0 answers, SOA 300
          next none
        t=1s query q1 nx.example.com. A
          => q1 Response nx.example.com. A: NXDomain, 0 answers, SOA 299, no EDNS
          next none
        t=1s query q2 nx.example.com. MX
          => q2 Response nx.example.com. MX: NXDomain, 0 answers, SOA 299, no EDNS
          next none
        t=1s query q3 www.nx.example.com. A
          -> S1 udp q3: www.nx.example.com. A
          next t=3s
        ");
    }

    #[test]
    fn nodata_is_cached_for_its_type_only() {
        let mut trace = one_server(|_| {});
        deny(&mut trace, "example.com.", RecordType::A, nodata);
        trace.at(Duration::from_secs(1));
        trace.query("example.com.", RecordType::A);
        trace.query("example.com.", RecordType::AAAA);

        assert_snapshot!(trace, @"
        t=0s query q0 example.com. A
          -> S1 udp q0: example.com. A
          next t=2s
        t=0s <- S1 udp q0: example.com. A: NoError, 0 answers, SOA 300
          => q0 Response example.com. A: NoError, 0 answers, SOA 300
          next none
        t=1s query q1 example.com. A
          => q1 Response example.com. A: NoError, 0 answers, SOA 299, no EDNS
          next none
        t=1s query q2 example.com. AAAA
          -> S1 udp q2: example.com. AAAA
          next t=3s
        ");
    }

    /// A NODATA entry for one type and a later NXDOMAIN for every type of
    /// the name are both live: the one stored last answers.
    #[test]
    fn the_latest_negative_answer_wins() {
        let mut trace = one_server(|_| {});
        deny(&mut trace, "example.com.", RecordType::A, nodata);
        trace.at(Duration::from_secs(1));
        deny(&mut trace, "example.com.", RecordType::AAAA, nxdomain);
        trace.at(Duration::from_secs(2));
        trace.query("example.com.", RecordType::A);

        assert_snapshot!(trace, @"
        t=0s query q0 example.com. A
          -> S1 udp q0: example.com. A
          next t=2s
        t=0s <- S1 udp q0: example.com. A: NoError, 0 answers, SOA 300
          => q0 Response example.com. A: NoError, 0 answers, SOA 300
          next none
        t=1s query q1 example.com. AAAA
          -> S1 udp q1: example.com. AAAA
          next t=3s
        t=1s <- S1 udp q1: example.com. AAAA: NXDomain, 0 answers, SOA 300
          => q1 Response example.com. AAAA: NXDomain, 0 answers, SOA 300
          next none
        t=2s query q2 example.com. A
          => q2 Response example.com. A: NXDomain, 0 answers, SOA 299, no EDNS
          next none
        ");
    }

    #[rstest]
    #[case::nxdomain(|r| with_code(r, ResponseCode::NXDomain))]
    #[case::nodata(|r| no_data(r))]
    fn without_soa_nothing_is_cached(#[case] negative: fn(Message) -> Message) {
        let mut trace = one_server(|_| {});
        deny(&mut trace, "example.com.", RecordType::A, negative);

        trace.query("example.com.", RecordType::A);

        assert_eq!(trace.sent().len(), 1, "not sent again:\n{trace}");
    }

    /// The answer is cached for `secs` seconds, given the SOA record's TTL
    /// and MINIMUM and `Config::max_negative_ttl`.
    #[rstest]
    #[case::ttl_lower(60, 300, None, 60)]
    #[case::minimum_lower(300, 30, None, 30)]
    #[case::capped(7200, 7200, Some(10), 10)]
    #[case::default_cap(86_400, 86_400, None, 3600)]
    fn lasts_the_lesser_of_soa_ttl_and_minimum(
        #[case] ttl: u32,
        #[case] minimum: u32,
        #[case] cap: Option<u64>,
        #[case] secs: u64,
    ) {
        let mut trace = one_server(|c| {
            if let Some(cap) = cap {
                c.max_negative_ttl = Duration::from_secs(cap);
            }
        });
        trace.query("nx.example.com.", RecordType::A);
        let sent = trace.last();
        let response = with_code(reply(&sent), ResponseCode::NXDomain);
        trace.answer(&sent, &with_soa_ttls(response, ttl, minimum));
        let end = Duration::from_secs(secs);

        trace.at(Duration::from_millis(secs * 1000 - 1));
        trace.query("nx.example.com.", RecordType::A);
        assert!(trace.sent().is_empty(), "sent while cached:\n{trace}");
        trace.at(end);
        trace.query("nx.example.com.", RecordType::A);
        assert_eq!(trace.sent().len(), 1, "not sent after {secs} s:\n{trace}");
    }

    /// No lifetime, no caching: a zero TTL or MINIMUM (RFC 1123 §6.1.2.1),
    /// a TTL with the most significant bit set, which counts as zero (RFC
    /// 2181 §8), or a zero `max_negative_ttl`, which turns negative caching
    /// off.
    #[rstest]
    #[case::zero_ttl(0, 300, None)]
    #[case::zero_minimum(300, 0, None)]
    #[case::ttl_with_msb_set(0x8000_0000, 300, None)]
    #[case::caching_off(300, 300, Some(0))]
    fn zero_lifetime_is_not_cached(
        #[case] ttl: u32,
        #[case] minimum: u32,
        #[case] cap: Option<u64>,
    ) {
        let mut trace = one_server(|c| {
            if let Some(cap) = cap {
                c.max_negative_ttl = Duration::from_secs(cap);
            }
        });
        trace.query("nx.example.com.", RecordType::A);
        let sent = trace.last();
        let response = with_code(reply(&sent), ResponseCode::NXDomain);
        trace.answer(&sent, &with_soa_ttls(response, ttl, minimum));

        trace.query("nx.example.com.", RecordType::A);

        assert_eq!(trace.sent().len(), 1, "not sent again:\n{trace}");
    }

    /// A truncated answer, used as it is over TCP, isn't cached (RFC 1123
    /// §6.1.3.2: truncated responses must not be cached and later used as
    /// if complete).
    #[test]
    fn truncated_answer_is_not_cached() {
        let mut trace = one_server(|_| {});
        trace.query("nx.example.com.", RecordType::A);
        let sent = trace.last();
        trace.answer(&sent, &truncated(reply(&sent)));
        let tcp = trace.last();
        trace.answer(&tcp, &truncated(nxdomain(reply(&tcp))));

        trace.query("nx.example.com.", RecordType::A);

        assert_snapshot!(trace, @"
        t=0s query q0 nx.example.com. A
          -> S1 udp q0: nx.example.com. A
          next t=2s
        t=0s <- S1 udp q0: nx.example.com. A: NoError, 1 answer, TC
          -> S1 connect c0: nx.example.com. A
          next t=2s
        t=0s <- S1 c0: nx.example.com. A: NXDomain, 0 answers, SOA 300, TC
          => q0 Response nx.example.com. A: NXDomain, 0 answers, SOA 300, TC
          next t=10s
        t=0s query q1 nx.example.com. A
          -> S1 write c0: nx.example.com. A
          next t=2s
        ");
    }

    /// §1, §2.1: after a CNAME chain, NXDOMAIN refers to the last name of
    /// the chain. The alias exists, so only the target is cached as
    /// nonexistent.
    #[test]
    fn nxdomain_after_a_cname_is_cached_for_its_target() {
        let mut trace = one_server(|_| {});
        trace.query("alias.example.com.", RecordType::A);
        let sent = trace.last();
        let mut response = nxdomain(reply(&sent));
        response.answers = vec![Record::from_rdata(
            name("alias.example.com."),
            300,
            RData::CNAME(CNAME(name("gone.example.com."))),
        )];
        trace.answer(&sent, &response);

        trace.query("gone.example.com.", RecordType::AAAA);
        trace.query("alias.example.com.", RecordType::A);

        assert_snapshot!(trace, @"
        t=0s query q0 alias.example.com. A
          -> S1 udp q0: alias.example.com. A
          next t=2s
        t=0s <- S1 udp q0: alias.example.com. A: NXDomain, 1 answer, SOA 300
          => q0 Response alias.example.com. A: NXDomain, 1 answer, SOA 300
          next none
        t=0s query q1 gone.example.com. AAAA
          => q1 Response gone.example.com. AAAA: NXDomain, 0 answers, SOA 300, no EDNS
          next none
        t=0s query q2 alias.example.com. A
          -> S1 udp q2: alias.example.com. A
          next t=2s
        ");
    }

    /// A chain that loops names no last name, and isn't cached.
    #[test]
    fn looping_chain_is_not_cached() {
        let mut trace = one_server(|_| {});
        trace.query("a.example.com.", RecordType::A);
        let sent = trace.last();
        let mut response = nxdomain(reply(&sent));
        response.answers = vec![
            Record::from_rdata(
                name("a.example.com."),
                300,
                RData::CNAME(CNAME(name("b.example.com."))),
            ),
            Record::from_rdata(
                name("b.example.com."),
                300,
                RData::CNAME(CNAME(name("a.example.com."))),
            ),
        ];
        trace.answer(&sent, &response);

        for name in ["a.example.com.", "b.example.com."] {
            trace.query(name, RecordType::A);
            assert_eq!(trace.sent().len(), 1, "{name} not sent:\n{trace}");
        }
    }

    /// Names are compared without regard to ASCII case (RFC 4343 §3).
    #[test]
    fn name_case_is_ignored() {
        let mut trace = one_server(|_| {});
        deny(&mut trace, "NX.Example.COM.", RecordType::A, nxdomain);

        trace.query("nx.example.com.", RecordType::A);

        assert_snapshot!(trace, @"
        t=0s query q0 NX.Example.COM. A
          -> S1 udp q0: NX.Example.COM. A
          next t=2s
        t=0s <- S1 udp q0: NX.Example.COM. A: NXDomain, 0 answers, SOA 300
          => q0 Response NX.Example.COM. A: NXDomain, 0 answers, SOA 300
          next none
        t=0s query q1 nx.example.com. A
          => q1 Response nx.example.com. A: NXDomain, 0 answers, SOA 300, no EDNS
          next none
        ");
    }
}

/// §6: "When a server, in answering a query, encounters a cached negative
/// response it MUST add the cached SOA record to the authority section of
/// the response with the TTL decremented by the amount of time it was
/// stored in the cache." The rest of the authority section comes along,
/// trimmed to the SOA's TTL, and the answer is no longer authoritative.
mod section_6 {
    use super::*;

    #[test]
    fn cached_answer_counts_its_ttls_down() {
        let mut trace = one_server(|_| {});
        trace.query("nx.example.com.", RecordType::A);
        let sent = trace.last();
        let mut response = nxdomain(reply(&sent));
        response.metadata.authoritative = true;
        let ns = NS(name("ns1.example.com."));
        response.add_authority(Record::from_rdata(
            name("example.com."),
            86_400,
            RData::NS(ns),
        ));
        trace.answer(&sent, &response);
        trace.at(Duration::from_millis(100_900));

        trace.query("NX.example.com.", RecordType::MX);

        assert_snapshot!(trace, @"
        t=0s query q0 nx.example.com. A
          -> S1 udp q0: nx.example.com. A
          next t=2s
        t=0s <- S1 udp q0: nx.example.com. A: NXDomain, 0 answers, AA, SOA 300
          => q0 Response nx.example.com. A: NXDomain, 0 answers, AA, SOA 300
          next none
        t=100.9s query q1 NX.example.com. MX
          => q1 Response NX.example.com. MX: NXDomain, 0 answers, SOA 200, no EDNS
          next none
        ");
        let Some(Event::Response { response, .. }) = trace.events().last() else {
            panic!("expected a response:\n{trace}");
        };
        assert_eq!(response.queries[0].name().to_ascii(), "NX.example.com.");
        assert_eq!(response.queries[0].query_type(), RecordType::MX);
        let ttls: Vec<_> = response
            .authorities
            .iter()
            .map(|r| (r.record_type(), r.ttl))
            .collect();
        assert_eq!(ttls, [(RecordType::SOA, 200), (RecordType::NS, 200)]);
        assert!(response.answers.is_empty() && response.additionals.is_empty());
        assert_eq!(response.metadata.id, 0, "no message was sent for it");
    }
}

/// §7.1 and §7.2 (optional) cache one server's failure or silence against
/// its address. The resolver doesn't: a server that answered a question
/// with an error is asked first again for the next query, and one that
/// didn't answer only goes after the others for `Config::failure_memory`
/// (see `rfc9520::section_3_2` for its five-minute cap).
mod section_7 {
    use super::*;

    #[rstest]
    fn server_failure_is_not_cached_per_server(mut trace: Trace) {
        trace.query("example.com.", RecordType::A);
        let sent = trace.last();
        trace.answer(&sent, &with_code(reply(&sent), ResponseCode::ServFail));
        let sent = trace.last();
        trace.answer(&sent, &reply(&sent));

        trace.query("example.com.", RecordType::A);

        assert_snapshot!(trace, @"
        t=0s query q0 example.com. A
          -> S1 udp q0: example.com. A
          next t=2s
        t=0s <- S1 udp q0: example.com. A: ServFail, 0 answers
          -> S2 udp q0: example.com. A
          next t=2s
        t=0s <- S2 udp q0: example.com. A: NoError, 1 answer
          => q0 Response example.com. A: NoError, 1 answer
          next none
        t=0s query q1 example.com. A
          -> S1 udp q1: example.com. A
          next t=2s
        ");
    }
}
