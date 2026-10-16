//! `Config::from_resolv_conf`: settings as glibc reads them from resolv.conf.

#![expect(
    clippy::disallowed_methods,
    clippy::indexing_slicing,
    clippy::unwrap_used,
    reason = "tests stand in for the driver, and helpers outside #[test] may panic"
)]

mod common;

use std::net::SocketAddr;
use std::time::{Duration, Instant};

use common::*;
use rstest::rstest;
use sansio_dns::{Config, Resolver};

/// Let one query time out on every attempt; return where each attempt went
/// and how long the first one waited.
fn attempts(conf: &str) -> (Vec<SocketAddr>, Duration) {
    let mut resolver = Resolver::new(Config::from_resolv_conf(conf.as_bytes()).unwrap());
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

#[rstest]
#[case::as_given("options timeout:7 attempts:3", 7, 3)]
#[case::capped_like_glibc("options timeout:99 attempts:9", 30, 5)]
fn timeout_and_attempts(#[case] options: &str, #[case] secs: u64, #[case] tries: usize) {
    let (sent, wait) = attempts(&format!("nameserver 192.0.2.53\n{options}\n"));
    assert_eq!(sent.len(), tries);
    assert_eq!(wait, Duration::from_secs(secs));
}

#[test]
fn no_nameserver_asks_the_local_host() {
    let (sent, _) = attempts("# empty\n");
    assert_eq!(sent, [addr("127.0.0.1:53"), addr("127.0.0.1:53")]);
}

/// `search` and `ndots`, following glibc's `res_search` order and stopping,
/// like musl, as soon as the name exists.
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
        let mut resolver = Resolver::new(Config::from_resolv_conf(conf.as_bytes()).unwrap());
        let now = Instant::now();
        resolver
            .query(Name::from_ascii(name).unwrap(), RecordType::A, now)
            .unwrap();
        let mut asked = Vec::new();
        while let Some(t) = resolver.poll_transmit() {
            let request = decode(&t);
            asked.push(request.queries[0].name().to_ascii());
            resolver.handle_datagram(t.destination, &encode(&with_code(reply(&t), code)), now);
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

    /// NOERROR, with or without records, means the name exists: stop.
    #[test]
    fn existing_name_ends_the_search() {
        let (asked, event) = tried(CONF, "db", ResponseCode::NoError);
        assert_eq!(asked, ["db.corp.example."]);
        assert!(matches!(event, Some(Event::Response { .. })));
    }

    #[test]
    fn special_use_search_domain_is_skipped() {
        let conf = "nameserver 192.0.2.53\nsearch local corp.example\n";
        let (asked, _) = tried(conf, "printer", ResponseCode::NXDomain);
        assert_eq!(asked, ["printer.corp.example.", "printer."]);
    }

    #[test]
    fn localhost_is_not_searched() {
        let (asked, event) = tried(CONF, "localhost", ResponseCode::NXDomain);
        assert!(asked.is_empty());
        assert!(matches!(event, Some(Event::Response { .. })));
    }
}
