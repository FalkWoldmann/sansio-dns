//! RFC 6761, Special-Use Domain Names, plus the special-use registrations in
//! RFC 6762 §3 (`local.`) and RFC 7686 §2 (`onion.`).
//! <https://rfc-annotations.research.icann.org/rfc6761.html>

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::time::Instant;

use crate::common::*;
use hickory_proto::op::ResponseCode;
use hickory_proto::rr::{Name, RecordType};
use rstest::rstest;
use sansio_dns::{Event, Resolver, addresses};

/// Query `name` and return the response, asserting nothing was sent.
fn answered_locally(
    resolver: &mut Resolver,
    name: &str,
    record_type: RecordType,
) -> hickory_proto::op::Message {
    let name = Name::from_ascii(name).unwrap();
    resolver.query(name, record_type, Instant::now()).unwrap();
    assert!(
        resolver.poll_transmit().is_none(),
        "special-use name was sent"
    );
    let Some(Event::Response { response, .. }) = resolver.poll_event() else {
        panic!("expected an immediate response");
    };
    response
}

/// §6.3: `localhost` names resolve to loopback, without a query.
mod section_6_3 {
    use super::*;

    #[rstest]
    #[case::a("localhost.", RecordType::A, IpAddr::V4(Ipv4Addr::LOCALHOST))]
    #[case::aaaa("localhost", RecordType::AAAA, IpAddr::V6(Ipv6Addr::LOCALHOST))]
    #[case::subdomain_any_case("App.LocalHost.", RecordType::A, IpAddr::V4(Ipv4Addr::LOCALHOST))]
    fn address_queries_get_loopback(
        mut resolver: Resolver,
        #[case] name: &str,
        #[case] record_type: RecordType,
        #[case] expected: IpAddr,
    ) {
        let response = answered_locally(&mut resolver, name, record_type);
        assert_eq!(addresses(&response), [expected]);
    }

    #[rstest]
    fn other_types_get_a_negative_answer(mut resolver: Resolver) {
        let response = answered_locally(&mut resolver, "localhost.", RecordType::MX);
        assert_eq!(response.metadata.response_code, ResponseCode::NoError);
        assert!(response.answers.is_empty());
    }
}

/// §6.4 `invalid.`, RFC 6762 §3 `local.` and RFC 7686 §2 `onion.` get an
/// immediate NXDOMAIN and never reach the unicast resolver.
mod section_6_4 {
    use super::*;

    #[rstest]
    #[case::invalid("host.invalid.")]
    #[case::invalid_itself("invalid.")]
    #[case::mdns_local("printer.local.")]
    #[case::onion("duckduckgogg42xjoc72x3sjasowoarfbgcmvfimaftt6twagswzczad.onion.")]
    fn names_get_nxdomain(mut resolver: Resolver, #[case] name: &str) {
        let response = answered_locally(&mut resolver, name, RecordType::A);
        assert_eq!(response.metadata.response_code, ResponseCode::NXDomain);
    }

    /// Only names *under* a special-use zone are special.
    #[rstest]
    #[case::suffix_label("localhost.example.com.")]
    #[case::shared_suffix("notlocal.")]
    #[case::shared_prefix("invalidated.")]
    fn lookalike_names_are_sent(mut resolver: Resolver, #[case] name: &str) {
        start_name(&mut resolver, name, Instant::now());
        assert!(resolver.poll_event().is_none());
    }
}
