//! RFC 1123, Requirements for Internet Hosts -- Application and Support.
//! <https://rfc-annotations.research.icann.org/rfc1123.html>

use std::num::NonZeroUsize;
use std::time::{Duration, Instant};

use crate::common::*;
use hickory_proto::ProtoError;
use hickory_proto::op::ResponseCode;
use hickory_proto::rr::rdata::CNAME;
use hickory_proto::rr::{DNSClass, Name, RData, Record, RecordType};
use insta::assert_snapshot;
use rstest::rstest;
use sansio_dns::{Config, Event, Resolver};
use std::assert_matches;

/// §6.1.3.2: zone transfers must use TCP, and take more than one message;
/// a stub resolver doesn't ask for them, nor for meta types that only
/// describe a message (RFC 6895 §3.1) or that a resolver must not forward
/// (NXNAME, RFC 9824 §3.5). ANY is an ordinary query (RFC 8482).
mod section_6_1_3_2 {
    use super::*;

    #[rstest]
    #[case::axfr(RecordType::AXFR)]
    #[case::ixfr(RecordType::IXFR)]
    #[case::opt(RecordType::OPT)]
    #[case::tsig(RecordType::TSIG)]
    #[case::tkey(RecordType::from(249))]
    #[case::mailb(RecordType::from(253))]
    #[case::maila(RecordType::from(254))]
    #[case::nxname(RecordType::from(128))]
    #[case::zero(RecordType::ZERO)]
    fn transfer_and_meta_types_are_rejected(
        mut resolver: Resolver,
        #[case] record_type: RecordType,
    ) {
        let name = Name::from_ascii("example.com.").unwrap();

        let result = resolver.query(name, record_type, Instant::now());

        assert_matches!(result, Err(ProtoError::Message(_)));
        assert!(resolver.poll_transmit().is_none());
        assert!(resolver.poll_event().is_none());
    }

    #[rstest]
    #[case::any(RecordType::ANY)]
    #[case::unassigned_qtype(RecordType::from(129))]
    fn other_types_are_sent(mut resolver: Resolver, #[case] record_type: RecordType) {
        let name = Name::from_ascii("example.com.").unwrap();

        resolver.query(name, record_type, Instant::now()).unwrap();

        let sent = decode(&resolver.poll_transmit().unwrap());
        assert_eq!(sent.queries[0].query_type(), record_type);
    }
}

/// §6.1.3.3: (1) a request consumes finite resources, and (2) gives up
/// after several retransmissions. (5) Retries back off exponentially,
/// within lower and upper bounds, and without measured round trip times the
/// first wait is no less than five seconds. A limit "must exceed twice the
/// Internet maximum segment lifetime plus service delay", 240 seconds and
/// more with RFC 9293's MSL of two minutes: each wait is at most 300
/// seconds, and at least one.
mod section_6_1_3_3 {
    use super::*;

    /// `S1` alone, with `timeout` and three attempts.
    fn one_server(timeout: Duration) -> Trace {
        let mut config = Config::new(S1, []);
        config.timeout = timeout;
        config.attempts = NonZeroUsize::new(3).unwrap();
        Trace::new(Resolver::new(config))
    }

    /// `Config::new`'s defaults: five seconds on each server, then ten.
    #[test]
    fn default_waits_five_seconds_then_backs_off() {
        let mut trace = Trace::new(Resolver::new(Config::new(S1, [S2])));
        trace.query("example.com.", RecordType::A);

        trace.timeouts();

        assert_snapshot!(trace, @"
        t=0s query q0 example.com. A
          -> S1 udp q0: example.com. A
          next t=5s
        t=5s timeout
          -> S2 udp q0: example.com. A
          next t=10s
        t=10s timeout
          -> S1 udp q0: example.com. A
          next t=20s
        t=20s timeout
          -> S2 udp q0: example.com. A
          next t=30s
        t=30s timeout
          => q0 Failed Timeout
          next none
        ");
    }

    /// With one server, every attempt is a new round: each waits twice as
    /// long as the one before.
    #[test]
    fn one_server_doubles_every_attempt() {
        let mut trace = one_server(Duration::from_secs(5));
        trace.query("example.com.", RecordType::A);

        trace.timeouts();

        assert_snapshot!(trace, @"
        t=0s query q0 example.com. A
          -> S1 udp q0: example.com. A
          next t=5s
        t=5s timeout
          -> S1 udp q0: example.com. A
          next t=15s
        t=15s timeout
          -> S1 udp q0: example.com. A
          next t=35s
        t=35s timeout
          => q0 Failed Timeout
          next none
        ");
    }

    #[test]
    fn backoff_stops_at_300_seconds() {
        let mut trace = one_server(Duration::from_secs(100));
        trace.query("example.com.", RecordType::A);

        trace.timeouts();

        assert_snapshot!(trace, @"
        t=0s query q0 example.com. A
          -> S1 udp q0: example.com. A
          next t=100s
        t=100s timeout
          -> S1 udp q0: example.com. A
          next t=300s
        t=300s timeout
          -> S1 udp q0: example.com. A
          next t=600s
        t=600s timeout
          => q0 Failed Timeout
          next none
        ");
    }

    /// No timeout waits forever: even `Duration::MAX` gives up after three
    /// waits of 300 seconds.
    #[test]
    fn largest_timeout_waits_300_seconds() {
        let mut trace = one_server(Duration::MAX);
        trace.query("example.com.", RecordType::A);

        trace.timeouts();

        assert_snapshot!(trace, @"
        t=0s query q0 example.com. A
          -> S1 udp q0: example.com. A
          next t=300s
        t=300s timeout
          -> S1 udp q0: example.com. A
          next t=600s
        t=600s timeout
          -> S1 udp q0: example.com. A
          next t=900s
        t=900s timeout
          => q0 Failed Timeout
          next none
        ");
    }

    /// A zero timeout would send every attempt at once.
    #[test]
    fn timeout_below_one_second_waits_one() {
        let mut config = Config::new(S1, [S2]);
        config.timeout = Duration::ZERO;
        let mut trace = Trace::new(Resolver::new(config));
        trace.query("example.com.", RecordType::A);

        trace.timeouts();

        assert_snapshot!(trace, @"
        t=0s query q0 example.com. A
          -> S1 udp q0: example.com. A
          next t=1s
        t=1s timeout
          -> S2 udp q0: example.com. A
          next t=2s
        t=2s timeout
          -> S1 udp q0: example.com. A
          next t=4s
        t=4s timeout
          -> S2 udp q0: example.com. A
          next t=6s
        t=6s timeout
          => q0 Failed Timeout
          next none
        ");
    }
}

/// §6.1.4.3: the search list is tried "until a domain name with the desired
/// associated data is found". NODATA (RFC 2308 §2.2: `NOERROR`, but no
/// record of the type asked for at the end of the CNAME chain) isn't that,
/// so the search moves on. (glibc's moves on only when the answer section
/// is empty.) When it runs out, the first NODATA is the outcome, ahead of a
/// later NXDOMAIN. `IpLookup` moves on when neither A nor AAAA has an
/// address; see `lookup::ip_lookup::search`. To keep a search list from
/// sending "excessive queries to the root", a resolver "MUST have one of,
/// and SHOULD have both of" (a) a cache of negative answers and (b) two or
/// more interior dots before a name is sent: cached NXDOMAIN and NODATA
/// answers move the search on without a transmit, and a cached failure ends
/// it. `Config::tld_query` (glibc's `no-tld-query`, see
/// `resolv_conf::search`) is a weaker form of (b).
mod section_6_1_4_3 {
    use super::*;

    fn searching() -> Trace {
        let mut config = config();
        config.search = vec![
            Name::from_ascii("corp.example.").unwrap(),
            Name::from_ascii("lab.example.").unwrap(),
        ];
        Trace::new(Resolver::new(config))
    }

    #[test]
    fn nodata_moves_the_search_on() {
        let mut trace = searching();
        trace.query("db", RecordType::A);
        let sent = trace.last();
        trace.answer(&sent, &no_data(reply(&sent)));
        let sent = trace.last();
        trace.answer(&sent, &reply(&sent));

        assert_snapshot!(trace, @"
        t=0s query q0 db A
          -> S1 udp q0: db.corp.example. A
          next t=2s
        t=0s <- S1 udp q0: db.corp.example. A: NoError, 0 answers
          -> S1 udp q0: db.lab.example. A
          next t=2s
        t=0s <- S1 udp q0: db.lab.example. A: NoError, 1 answer
          => q0 Response db.lab.example. A: NoError, 1 answer
          next none
        ");
    }

    #[test]
    fn first_nodata_wins_over_a_later_nxdomain() {
        let mut trace = searching();
        trace.query("db", RecordType::AAAA);
        let sent = trace.last();
        trace.answer(&sent, &no_data(reply(&sent)));
        let sent = trace.last();
        trace.answer(&sent, &no_data(reply(&sent)));
        let sent = trace.last();
        trace.answer(&sent, &with_code(reply(&sent), ResponseCode::NXDomain));

        assert_snapshot!(trace, @"
        t=0s query q0 db AAAA
          -> S1 udp q0: db.corp.example. AAAA
          next t=2s
        t=0s <- S1 udp q0: db.corp.example. AAAA: NoError, 0 answers
          -> S1 udp q0: db.lab.example. AAAA
          next t=2s
        t=0s <- S1 udp q0: db.lab.example. AAAA: NoError, 0 answers
          -> S1 udp q0: db. AAAA
          next t=2s
        t=0s <- S1 udp q0: db. AAAA: NXDomain, 0 answers
          => q0 Response db.corp.example. AAAA: NoError, 0 answers
          next none
        ");
        let [Event::Response { response, .. }] = trace.events() else {
            panic!("expected one response");
        };
        assert_eq!(response.queries[0].name().to_ascii(), "db.corp.example.");
    }

    /// A CNAME whose target has no record of the type asked for is NODATA
    /// too.
    #[test]
    fn cname_without_data_at_its_end_is_nodata() {
        let mut trace = searching();
        trace.query("db", RecordType::A);
        let sent = trace.last();
        let mut response = no_data(reply(&sent));
        let alias = response.queries[0].name().clone();
        let target = Name::from_ascii("elsewhere.example.").unwrap();
        response.answers = vec![Record::from_rdata(alias, 300, RData::CNAME(CNAME(target)))];
        trace.answer(&sent, &response);

        assert_snapshot!(trace, @"
        t=0s query q0 db A
          -> S1 udp q0: db.corp.example. A
          next t=2s
        t=0s <- S1 udp q0: db.corp.example. A: NoError, 1 answer
          -> S1 udp q0: db.lab.example. A
          next t=2s
        ");
    }

    /// Records of another class than the one asked for aren't data (RFC
    /// 1035 §7.4), so an answer that holds only those is NODATA.
    #[test]
    fn records_of_another_class_are_nodata() {
        let mut trace = searching();
        trace.query("db", RecordType::A);
        let sent = trace.last();
        let mut response = reply(&sent);
        response.answers[0].dns_class = DNSClass::CH;
        trace.answer(&sent, &response);

        assert_snapshot!(trace, @"
        t=0s query q0 db A
          -> S1 udp q0: db.corp.example. A
          next t=2s
        t=0s <- S1 udp q0: db.corp.example. A: NoError, 1 answer
          -> S1 udp q0: db.lab.example. A
          next t=2s
        ");
    }

    /// Provision (a): the second search for `db` skips the candidates the
    /// cache knows don't exist, and asks only for the one left.
    #[test]
    fn cached_negative_answers_move_the_search_on_without_a_transmit() {
        let mut trace = searching();
        trace.query("db", RecordType::A);
        let sent = trace.last();
        trace.answer(
            &sent,
            &with_soa(with_code(reply(&sent), ResponseCode::NXDomain)),
        );
        let sent = trace.last();
        trace.answer(&sent, &with_soa(no_data(reply(&sent))));
        let sent = trace.last();
        trace.answer(&sent, &reply(&sent));
        trace.at(Duration::from_secs(10));
        trace.query("db", RecordType::A);
        trace.query("db", RecordType::AAAA);

        assert_snapshot!(trace, @"
        t=0s query q0 db A
          -> S1 udp q0: db.corp.example. A
          next t=2s
        t=0s <- S1 udp q0: db.corp.example. A: NXDomain, 0 answers, SOA 300
          -> S1 udp q0: db.lab.example. A
          next t=2s
        t=0s <- S1 udp q0: db.lab.example. A: NoError, 0 answers, SOA 300
          -> S1 udp q0: db. A
          next t=2s
        t=0s <- S1 udp q0: db. A: NoError, 1 answer
          => q0 Response db. A: NoError, 1 answer
          next none
        t=10s query q1 db A
          -> S1 udp q1: db. A
          next t=12s
        t=10s query q2 db AAAA
          -> S1 udp q2: db.lab.example. AAAA
          next t=12s
        ");
    }

    /// When the cache answers every candidate, the search ends at once with
    /// the first NODATA, as it would after the servers' answers.
    #[test]
    fn search_answered_from_the_cache_alone() {
        let mut trace = searching();
        trace.query("db", RecordType::A);
        let nxdomain = |sent| with_soa(with_code(reply(sent), ResponseCode::NXDomain));
        let sent = trace.last();
        trace.answer(&sent, &nxdomain(&sent));
        let sent = trace.last();
        trace.answer(&sent, &with_soa(no_data(reply(&sent))));
        let sent = trace.last();
        trace.answer(&sent, &nxdomain(&sent));
        trace.at(Duration::from_secs(1));
        trace.query("db", RecordType::A);

        assert_snapshot!(trace, @"
        t=0s query q0 db A
          -> S1 udp q0: db.corp.example. A
          next t=2s
        t=0s <- S1 udp q0: db.corp.example. A: NXDomain, 0 answers, SOA 300
          -> S1 udp q0: db.lab.example. A
          next t=2s
        t=0s <- S1 udp q0: db.lab.example. A: NoError, 0 answers, SOA 300
          -> S1 udp q0: db. A
          next t=2s
        t=0s <- S1 udp q0: db. A: NXDomain, 0 answers, SOA 300
          => q0 Response db.lab.example. A: NoError, 0 answers, SOA 300
          next none
        t=1s query q1 db A
          => q1 Response db.lab.example. A: NoError, 0 answers, SOA 299, no EDNS
          next none
        ");
    }

    /// A NODATA the cache gave an earlier candidate is still the outcome
    /// when the servers deny the later ones.
    #[test]
    fn cached_nodata_wins_over_a_later_nxdomain() {
        let mut trace = searching();
        trace.query("db", RecordType::A);
        let sent = trace.last();
        trace.answer(&sent, &with_soa(no_data(reply(&sent))));
        let sent = trace.last();
        trace.answer(&sent, &reply(&sent));
        trace.at(Duration::from_secs(1));
        trace.query("db", RecordType::A);
        for _ in 0..2 {
            let sent = trace.last();
            trace.answer(&sent, &with_code(reply(&sent), ResponseCode::NXDomain));
        }

        assert_snapshot!(trace, @"
        t=0s query q0 db A
          -> S1 udp q0: db.corp.example. A
          next t=2s
        t=0s <- S1 udp q0: db.corp.example. A: NoError, 0 answers, SOA 300
          -> S1 udp q0: db.lab.example. A
          next t=2s
        t=0s <- S1 udp q0: db.lab.example. A: NoError, 1 answer
          => q0 Response db.lab.example. A: NoError, 1 answer
          next none
        t=1s query q1 db A
          -> S1 udp q1: db.lab.example. A
          next t=3s
        t=1s <- S1 udp q1: db.lab.example. A: NXDomain, 0 answers
          -> S1 udp q1: db. A
          next t=3s
        t=1s <- S1 udp q1: db. A: NXDomain, 0 answers
          => q1 Response db.corp.example. A: NoError, 0 answers, SOA 299, no EDNS
          next none
        ");
    }

    /// A cached failure ends the search at its candidate, as the failure
    /// did when it happened.
    #[test]
    fn cached_failure_ends_the_search() {
        let mut trace = searching();
        trace.query("db", RecordType::A);
        let sent = trace.last();
        trace.answer(
            &sent,
            &with_soa(with_code(reply(&sent), ResponseCode::NXDomain)),
        );
        for _ in 0..2 {
            let sent = trace.last();
            trace.answer(&sent, &with_code(reply(&sent), ResponseCode::ServFail));
        }
        trace.query("db", RecordType::A);

        assert_snapshot!(trace, @"
        t=0s query q0 db A
          -> S1 udp q0: db.corp.example. A
          next t=2s
        t=0s <- S1 udp q0: db.corp.example. A: NXDomain, 0 answers, SOA 300
          -> S1 udp q0: db.lab.example. A
          next t=2s
        t=0s <- S1 udp q0: db.lab.example. A: ServFail, 0 answers
          -> S2 udp q0: db.lab.example. A
          next t=2s
        t=0s <- S2 udp q0: db.lab.example. A: ServFail, 0 answers
          => q0 Failed Server(ServFail)
          next none
        t=0s query q1 db A
          => q1 Failed Server(ServFail)
          next none
        ");
    }

    /// A server failure ends the search: a later candidate might name a
    /// different host than the one meant (RFC 1535).
    #[test]
    fn failure_ends_the_search() {
        let mut trace = searching();
        trace.query("db", RecordType::A);
        let sent = trace.last();
        trace.answer(&sent, &no_data(reply(&sent)));
        for _ in 0..2 {
            let sent = trace.last();
            trace.answer(&sent, &with_code(reply(&sent), ResponseCode::ServFail));
        }

        assert_snapshot!(trace, @"
        t=0s query q0 db A
          -> S1 udp q0: db.corp.example. A
          next t=2s
        t=0s <- S1 udp q0: db.corp.example. A: NoError, 0 answers
          -> S1 udp q0: db.lab.example. A
          next t=2s
        t=0s <- S1 udp q0: db.lab.example. A: ServFail, 0 answers
          -> S2 udp q0: db.lab.example. A
          next t=2s
        t=0s <- S2 udp q0: db.lab.example. A: ServFail, 0 answers
          => q0 Failed Server(ServFail)
          next none
        ");
    }
}
