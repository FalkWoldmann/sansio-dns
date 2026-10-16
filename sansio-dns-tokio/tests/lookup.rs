//! `Resolver::lookup_ip` against a name server on localhost.

#![expect(
    clippy::indexing_slicing,
    clippy::unwrap_used,
    reason = "helpers outside #[test] may panic"
)]

mod common;

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use common::{V4, V6, name_server};
use rstest::rstest;
use sansio_dns::Config;
use sansio_dns_tokio::{Error, Resolver};

#[rstest]
#[case::over_udp(false)]
#[case::truncated_then_over_tcp(true)]
#[tokio::test]
async fn finds_both_families(#[case] truncate_udp: bool) {
    let server = name_server("app.example.", truncate_udp).await;
    let resolver = Resolver::new(Config::new(server, []));

    let addresses = resolver.lookup_ip("app.example").await.unwrap();

    assert_eq!(addresses, [IpAddr::V4(V4), IpAddr::V6(V6)]);
}

#[tokio::test]
async fn unknown_name_is_not_found() {
    let server = name_server("app.example.", false).await;
    let resolver = Resolver::new(Config::new(server, []));

    let result = resolver.lookup_ip("other.example").await;

    assert!(matches!(result, Err(Error::NotFound)), "{result:?}");
}

/// An address needs no lookup; the server here doesn't exist.
#[rstest]
#[case::v4(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 7)))]
#[case::v6(IpAddr::V6(Ipv6Addr::LOCALHOST))]
#[tokio::test]
async fn addresses_are_returned_as_they_are(#[case] ip: IpAddr) {
    let nowhere = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 9);
    let resolver = Resolver::new(Config::new(nowhere, []));

    let addresses = resolver.lookup_ip(&ip.to_string()).await.unwrap();

    assert_eq!(addresses, [ip]);
}
