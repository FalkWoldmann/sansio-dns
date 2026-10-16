//! `Hosts`: static entries answered before DNS, as hosts(5) describes.

#![expect(
    clippy::disallowed_methods,
    clippy::indexing_slicing,
    clippy::unwrap_used,
    reason = "tests stand in for the driver, and helpers outside #[test] may panic"
)]

mod common;

use std::net::IpAddr;
use std::time::Instant;

use common::*;
use hickory_proto::op::ResponseCode;
use hickory_proto::rr::{Name, RecordType};
use rstest::rstest;
use sansio_dns::{Config, Event, Hosts, Resolver, addresses};

const FILE: &str = "\u{feff}192.0.2.1 first.example
# comment line
127.0.0.1   localhost
192.0.2.10  dev.example  dev   # alias, then a comment
2001:db8::10 dev.example
not-an-address broken.example
fe80::1%eth0 zoned.example
";

fn name(s: &str) -> Name {
    Name::from_ascii(s).unwrap()
}

fn ip(s: &str) -> IpAddr {
    s.parse().unwrap()
}

#[rstest]
#[case::all_addresses_in_order("dev.example", Some(vec![ip("192.0.2.10"), ip("2001:db8::10")]))]
#[case::alias_and_case("DEV", Some(vec![ip("192.0.2.10")]))]
#[case::unparsable_line_skipped("broken.example", None)]
#[case::zoned_address_skipped("zoned.example", None)]
#[case::not_listed("other.example", None)]
#[case::comment_is_not_a_name("comment", None)]
#[case::byte_order_mark_ignored("first.example", Some(vec![ip("192.0.2.1")]))]
fn parse_and_lookup(#[case] host: &str, #[case] expected: Option<Vec<IpAddr>>) {
    assert_eq!(Hosts::parse(FILE.as_bytes()).lookup(&name(host)), expected);
}

fn resolver() -> Resolver {
    let mut config = Config::new(S1, []);
    config.hosts = Hosts::parse(FILE.as_bytes());
    Resolver::new(config)
}

/// A and AAAA queries for a listed name are answered locally, with that
/// family's addresses only, even when there are none.
#[rstest]
#[case::a("dev.example", RecordType::A, vec![ip("192.0.2.10")])]
#[case::aaaa("dev.example", RecordType::AAAA, vec![ip("2001:db8::10")])]
#[case::no_address_of_that_family("dev", RecordType::AAAA, vec![])]
fn listed_names_are_answered_locally(
    #[case] host: &str,
    #[case] record_type: RecordType,
    #[case] expected: Vec<IpAddr>,
) {
    let mut r = resolver();
    r.query(name(host), record_type, Instant::now()).unwrap();

    assert!(r.poll_transmit().is_none(), "listed name was sent to DNS");
    let Some(Event::Response { response, .. }) = r.poll_event() else {
        panic!("expected a local answer");
    };
    assert_eq!(response.metadata.response_code, ResponseCode::NoError);
    assert_eq!(addresses(&response), expected);
}

/// Hosts files only hold addresses: other record types, and names the file
/// doesn't list, go to DNS.
#[rstest]
#[case::other_type("dev.example", RecordType::MX)]
#[case::unlisted_name("other.example", RecordType::A)]
fn everything_else_goes_to_dns(#[case] host: &str, #[case] record_type: RecordType) {
    let mut r = resolver();
    r.query(name(host), record_type, Instant::now()).unwrap();
    assert!(r.poll_transmit().is_some());
}
