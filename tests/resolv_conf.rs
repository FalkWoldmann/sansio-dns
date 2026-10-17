//! `Config::from_resolv_conf`: settings as glibc reads them from resolv.conf.

use std::net::SocketAddr;
use std::time::{Duration, Instant};

use crate::common::*;
use rstest::rstest;
use sansio_dns::{Config, IpStrategy, Resolver};
use std::assert_matches;

/// Let one query time out on every attempt; return where each attempt went
/// and how long the first one waited.
fn attempts(conf: impl AsRef<[u8]>) -> (Vec<SocketAddr>, Duration) {
    let mut resolver = Resolver::new(Config::from_resolv_conf(conf.as_ref()));
    let start_time = Instant::now();
    let first = start(&mut resolver, start_time);
    let wait = resolver.poll_timeout().unwrap() - start_time;
    let mut destinations = vec![first.destination];
    while let Some(deadline) = resolver.poll_timeout() {
        resolver.handle_timeout(deadline);
        destinations.extend(resolver.poll_transmit().map(|t| t.destination));
    }
    (destinations, wait)
}

fn addr(s: &str) -> SocketAddr {
    s.parse().unwrap()
}

#[test]
fn nameservers_in_order_two_attempts_each_by_default() {
    let (sent, wait) = attempts(
        "nameserver 192.0.2.53\n\
         nameserver 2001:db8::53\n\
         nameserver fe80::1%eth0\n\
         nameserver fe80::2%3\n",
    );
    let servers = [
        addr("192.0.2.53:53"),
        addr("[2001:db8::53]:53"),
        addr("[fe80::2%3]:53"),
    ];
    assert_eq!(sent, [servers, servers].concat(), "named scope skipped");
    assert_eq!(wait, Duration::from_secs(5));
}

/// glibc takes up to 5 attempts per server, but RFC 9520 §3.1 allows no
/// more than three sends of a query to one server over one transport. The
/// sends alone don't show the clamp, since the resolver stops at three
/// datagrams per server anyway; the attempts it leaves would go over TCP.
#[rstest]
#[case::as_given("options timeout:7 attempts:2", 7, 2)]
#[case::three("options timeout:7 attempts:3", 7, 3)]
#[case::at_most_three_attempts("options timeout:7 attempts:5", 7, 3)]
#[case::capped("options timeout:99 attempts:9", 30, 3)]
fn timeout_and_attempts(#[case] options: &str, #[case] secs: u64, #[case] tries: usize) {
    let conf = format!("nameserver 192.0.2.53\nnameserver 192.0.2.54\n{options}\n");
    assert_eq!(
        Config::from_resolv_conf(conf.as_bytes()).attempts.get(),
        2 * tries,
        "attempts per server times servers"
    );
    let (sent, wait) = attempts(conf);
    assert_eq!(sent.len(), 2 * tries);
    assert_eq!(wait, Duration::from_secs(secs));
}

/// glibc's MAXNS: a fourth server is never asked.
#[test]
fn at_most_three_nameservers() {
    let (sent, _) = attempts(
        "nameserver 192.0.2.1\n\
         nameserver 192.0.2.2\n\
         nameserver 192.0.2.3\n\
         nameserver 192.0.2.4\n",
    );
    let servers = [
        addr("192.0.2.1:53"),
        addr("192.0.2.2:53"),
        addr("192.0.2.3:53"),
    ];
    assert_eq!(sent, [servers, servers].concat());
}

/// Lines and options it can't use are skipped, as glibc skips them, and
/// the rest still applies.
#[test]
fn unusable_lines_are_skipped() {
    let (sent, wait) = attempts(
        b"nameserver not-an-address\n\
         nameserver\n\
         nameserver 192.0.2.53 extra words\n\
         unknown-directive value\n\
         options unknown-option timeout:7 ndots:x\n\
         \xff\xfe not UTF-8\n\
         nameserver 192.0.2.54\n",
    );
    assert_eq!(
        sent,
        [
            addr("192.0.2.53:53"),
            addr("192.0.2.54:53"),
            addr("192.0.2.53:53"),
            addr("192.0.2.54:53"),
        ]
    );
    assert_eq!(wait, Duration::from_secs(7));
}

#[rstest]
#[case::default("", IpStrategy::Ipv6First)]
#[case::no_aaaa("options no-aaaa\n", IpStrategy::Ipv4Only)]
fn no_aaaa_asks_only_for_ipv4(#[case] options: &str, #[case] expected: IpStrategy) {
    let config = Config::from_resolv_conf(format!("nameserver 192.0.2.53\n{options}").as_bytes());
    assert_eq!(config.ip_strategy, expected);
}

#[test]
fn no_nameserver_asks_the_local_host() {
    let (sent, _) = attempts("# empty\n");
    assert_eq!(sent, [addr("127.0.0.1:53"), addr("127.0.0.1:53")]);
}

/// `search` and `ndots`, following glibc's `res_search` order and stopping
/// as soon as a candidate has data of the type asked for.
mod search {
    use super::*;
    use hickory_proto::op::ResponseCode;
    use hickory_proto::rr::{Name, RecordType};
    use sansio_dns::Event;

    const CONF: &str = "nameserver 192.0.2.53\n\
                        search corp.example lab.example\n\
                        options ndots:2\n";

    /// Query `name`, answer every candidate with `code`, and return the
    /// names asked for, in order, plus the final event.
    fn tried(conf: &str, name: &str, code: ResponseCode) -> (Vec<String>, Option<Event>) {
        let mut resolver = Resolver::new(Config::from_resolv_conf(conf.as_bytes()));
        let now = Instant::now();
        resolver
            .query(Name::from_ascii(name).unwrap(), RecordType::A, now)
            .unwrap();
        let mut asked = Vec::new();
        while let Some(t) = resolver.poll_transmit() {
            let request = decode(&t);
            asked.push(request.queries[0].name().to_ascii());
            resolver.handle_datagram(
                udp(&t),
                t.destination,
                &encode(&with_code(reply(&t), code)),
                now,
            );
        }
        (asked, resolver.poll_event())
    }

    #[rstest]
    #[case::fewer_dots_search_first(
        "a.b",
        &["a.b.corp.example.", "a.b.lab.example.", "a.b."]
    )]
    #[case::enough_dots_as_given_first(
        "a.b.c",
        &["a.b.c.", "a.b.c.corp.example.", "a.b.c.lab.example."]
    )]
    #[case::trailing_dot_only_as_given("db.", &["db."])]
    fn candidates_in_order(#[case] name: &str, #[case] expected: &[&str]) {
        let (asked, event) = tried(CONF, name, ResponseCode::NXDomain);
        assert_eq!(asked, expected);
        let Some(Event::Response { response, .. }) = event else {
            panic!("expected the last NXDOMAIN");
        };
        assert_eq!(response.metadata.response_code, ResponseCode::NXDomain);
    }

    /// resolv-conf's default `ndots` is 1, as glibc's.
    #[rstest]
    #[case::no_dots("db", &["db.a.example.", "db.b.example.", "db."])]
    #[case::one_dot("db.x", &["db.x.", "db.x.a.example.", "db.x.b.example."])]
    fn default_ndots_is_one(#[case] name: &str, #[case] expected: &[&str]) {
        let conf = "nameserver 192.0.2.53\nsearch a.example b.example\n";
        assert_eq!(Config::from_resolv_conf(conf.as_bytes()).ndots, 1);

        let (asked, _) = tried(conf, name, ResponseCode::NXDomain);

        assert_eq!(asked, expected);
    }

    /// `options no-tld-query`, as in glibc: with search domains, a name of
    /// one label isn't tried as given, which would ask for a top-level
    /// domain (a weaker form of RFC 1123 §6.1.4.3 (b)). Names with a dot
    /// still are, and without search domains every name is.
    #[rstest]
    #[case::one_label("search a.example b.example\n", "db", &["db.a.example.", "db.b.example."])]
    #[case::one_dot("search a.example\n", "db.x", &["db.x.", "db.x.a.example."])]
    #[case::absolute("search a.example\n", "db.", &["db."])]
    #[case::no_search_domains("", "db", &["db."])]
    fn no_tld_query_keeps_single_labels_from_the_name_servers(
        #[case] search: &str,
        #[case] name: &str,
        #[case] expected: &[&str],
    ) {
        let conf = format!("nameserver 192.0.2.53\n{search}options no-tld-query\n");
        assert!(!Config::from_resolv_conf(conf.as_bytes()).tld_query);

        let (asked, _) = tried(&conf, name, ResponseCode::NXDomain);

        assert_eq!(asked, expected);
    }

    /// Unless every candidate is left out: then the name gets NXDOMAIN at
    /// once.
    #[test]
    fn no_tld_query_without_a_candidate_left() {
        let conf = "nameserver 192.0.2.53\nsearch local\noptions no-tld-query\n";
        let (asked, event) = tried(conf, "printer", ResponseCode::NoError);
        assert!(asked.is_empty());
        let Some(Event::Response { response, .. }) = event else {
            panic!("expected a local answer");
        };
        assert_eq!(response.metadata.response_code, ResponseCode::NXDomain);
    }

    #[test]
    fn tld_query_is_on_by_default() {
        let conf = "nameserver 192.0.2.53\nsearch a.example\n";
        assert!(Config::from_resolv_conf(conf.as_bytes()).tld_query);
        assert!(Config::new(addr("192.0.2.53:53"), []).tld_query);
    }

    /// A record of the type asked for ends the search. NODATA doesn't; see
    /// `rfc1123::section_6_1_4_3`.
    #[test]
    fn existing_name_ends_the_search() {
        let (asked, event) = tried(CONF, "db", ResponseCode::NoError);
        assert_eq!(asked, ["db.corp.example."]);
        assert_matches!(event, Some(Event::Response { .. }));
    }

    #[test]
    fn special_use_search_domain_is_skipped() {
        let conf = "nameserver 192.0.2.53\nsearch invalid corp.example\n";
        let (asked, _) = tried(conf, "printer", ResponseCode::NXDomain);
        assert_eq!(asked, ["printer.corp.example.", "printer."]);
    }

    /// A Kubernetes pod's resolv.conf: short service names resolve through
    /// the `cluster.local` search domains.
    #[test]
    fn kubernetes_service_name_is_found() {
        let conf = "nameserver 10.96.0.10\n\
                    search ns.svc.cluster.local svc.cluster.local cluster.local\n\
                    options ndots:5\n";
        let (asked, event) = tried(conf, "myservice", ResponseCode::NoError);
        assert_eq!(asked, ["myservice.ns.svc.cluster.local."]);
        assert_matches!(event, Some(Event::Response { .. }));
    }

    /// Service `db` in a namespace named `local`: every candidate under
    /// `cluster.local` is tried, and only `db.local.` itself, link-local
    /// (RFC 6762 §22.1), is left out.
    #[test]
    fn kubernetes_namespace_named_local_is_searched() {
        let conf = "nameserver 10.96.0.10\n\
                    search ns.svc.cluster.local svc.cluster.local cluster.local\n\
                    options ndots:5\n";
        let (asked, event) = tried(conf, "db.local", ResponseCode::NXDomain);
        assert_eq!(
            asked,
            [
                "db.local.ns.svc.cluster.local.",
                "db.local.svc.cluster.local.",
                "db.local.cluster.local.",
            ]
        );
        assert_matches!(event, Some(Event::Response { .. }));
    }

    #[test]
    fn localhost_is_not_searched() {
        let (asked, event) = tried(CONF, "localhost", ResponseCode::NXDomain);
        assert!(asked.is_empty());
        assert_matches!(event, Some(Event::Response { .. }));
    }
}
