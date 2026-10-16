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
