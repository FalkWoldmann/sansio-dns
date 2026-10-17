//! RFC 6761, Special-Use Domain Names, plus RFC 7686 §2 (`onion.`), RFC
//! 6762 §22.1 (`local.` and the link-local reverse zones), RFC 8375 §4
//! (`home.arpa.`) and RFC 9476 §3.2 (`alt.`).
//! <https://rfc-annotations.research.icann.org/rfc6761.html>

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::time::Instant;

use crate::common::*;
use hickory_proto::op::ResponseCode;
use hickory_proto::rr::{Name, RecordType};
use rstest::rstest;
use sansio_dns::{Event, Hosts, Resolver, addresses};

fn name(s: &str) -> Name {
    Name::from_ascii(s).unwrap()
}

/// Query `name` and return the response, asserting nothing was sent.
fn answered_locally(
    resolver: &mut Resolver,
    name: &str,
    record_type: RecordType,
) -> hickory_proto::op::Message {
    resolver
        .query(self::name(name), record_type, Instant::now())
        .unwrap();
    assert!(
        resolver.poll_transmit().is_none(),
        "special-use name was sent"
    );
    let Some(Event::Response { response, .. }) = resolver.poll_event() else {
        panic!("expected an immediate response");
    };
    response
}

/// Query `name` and return the names of the questions sent for it.
fn asked(resolver: &mut Resolver, name: &str, record_type: RecordType) -> Vec<String> {
    resolver
        .query(self::name(name), record_type, Instant::now())
        .unwrap();
    std::iter::from_fn(|| resolver.poll_transmit())
        .map(|t| decode(&t).queries[0].name().to_ascii())
        .collect()
}

/// A resolver with `config`'s servers and the given search domains.
fn searching(search: &[&str]) -> Resolver {
    let mut config = config();
    config.search = search.iter().map(|domain| name(domain)).collect();
    Resolver::new(config)
}

/// §6.1, §6.2, §6.5, RFC 8375 §4 and RFC 9476 §3.2: these special-use
/// names are not special to a stub resolver, and are sent like any other.
mod not_special_to_resolvers {
    use super::*;

    #[rstest]
    #[case::private_reverse_6_1("1.0.0.10.in-addr.arpa.", RecordType::PTR)]
    #[case::test_6_2("foo.test.", RecordType::A)]
    #[case::example_6_5("www.example.com.", RecordType::A)]
    #[case::example_tld_6_5("example.", RecordType::A)]
    #[case::home_arpa("router.home.arpa.", RecordType::A)]
    #[case::alt("foo.alt.", RecordType::A)]
    fn names_are_sent(mut resolver: Resolver, #[case] name: &str, #[case] record_type: RecordType) {
        assert_eq!(asked(&mut resolver, name, record_type), [name]);
    }
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
        assert_eq!(addresses(&response), Ok(vec![expected]));
    }

    #[rstest]
    fn other_types_get_a_negative_answer(mut resolver: Resolver) {
        let response = answered_locally(&mut resolver, "localhost.", RecordType::MX);
        assert_eq!(response.metadata.response_code, ResponseCode::NoError);
        assert!(response.answers.is_empty());
    }

    /// Item 3: "SHOULD always return the IP loopback address", whatever the
    /// hosts file says.
    #[test]
    fn hosts_entry_does_not_override() {
        let mut config = config();
        config.hosts = Hosts::parse(b"192.0.2.9 localhost app.localhost\n");
        let mut resolver = Resolver::new(config);

        for name in ["localhost", "app.localhost."] {
            let response = answered_locally(&mut resolver, name, RecordType::A);
            let loopback = IpAddr::V4(Ipv4Addr::LOCALHOST);
            assert_eq!(addresses(&response), Ok(vec![loopback]), "{name}");
        }
    }

    #[test]
    fn relative_name_is_not_searched() {
        let mut resolver = searching(&["corp.example."]);
        let response = answered_locally(&mut resolver, "app.localhost", RecordType::A);
        let loopback = IpAddr::V4(Ipv4Addr::LOCALHOST);
        assert_eq!(addresses(&response), Ok(vec![loopback]));
    }
}

/// §6.4 `invalid.` and RFC 7686 §2 `onion.` get an immediate NXDOMAIN and
/// never reach the unicast resolver.
mod section_6_4 {
    use super::*;

    #[rstest]
    #[case::invalid("host.invalid.")]
    #[case::invalid_itself("invalid.")]
    #[case::onion("duckduckgogg42xjoc72x3sjasowoarfbgcmvfimaftt6twagswzczad.onion.")]
    #[case::onion_itself("onion.")]
    #[case::onion_subdomain("a.b.onion.")]
    fn names_get_nxdomain(mut resolver: Resolver, #[case] name: &str) {
        let response = answered_locally(&mut resolver, name, RecordType::A);
        assert_eq!(response.metadata.response_code, ResponseCode::NXDomain);
    }

    /// Relative names aren't searched, so they can't leak to the servers
    /// through a search domain.
    #[rstest]
    #[case::invalid("invalid")]
    #[case::onion("x.onion")]
    fn relative_names_are_not_searched(#[case] name: &str) {
        let mut resolver = searching(&["corp.example."]);
        let response = answered_locally(&mut resolver, name, RecordType::A);
        assert_eq!(response.metadata.response_code, ResponseCode::NXDomain);
    }

    /// RFC 7686 §2 item 3: `onion.` names must get NXDOMAIN, whatever the
    /// hosts file says.
    #[test]
    fn hosts_entry_does_not_override() {
        let mut config = config();
        config.hosts = Hosts::parse(b"192.0.2.9 x.onion\n");
        let mut resolver = Resolver::new(config);

        let response = answered_locally(&mut resolver, "x.onion", RecordType::A);

        assert_eq!(response.metadata.response_code, ResponseCode::NXDomain);
    }

    /// Only names *under* a special-use zone are special.
    #[rstest]
    #[case::suffix_label("localhost.example.com.")]
    #[case::shared_suffix("notlocal.")]
    #[case::shared_prefix("invalidated.")]
    #[case::local_as_a_lower_label("local.example.")]
    fn lookalike_names_are_sent(mut resolver: Resolver, #[case] name: &str) {
        start_name(&mut resolver, name, Instant::now());
        assert!(resolver.poll_event().is_none());
    }
}

/// RFC 6762 §22.1: `local.` and the link-local reverse zones belong to
/// multicast DNS, and libraries "SHOULD NOT send queries for these names to
/// their configured (unicast) caching DNS server(s)" (item 3). They get the
/// NXDOMAIN that item 4 asks caching servers to answer, unless the servers
/// are configured to serve the zone.
mod rfc6762_section_22_1 {
    use super::*;

    #[rstest]
    #[case::local("printer.local.", RecordType::A)]
    #[case::local_any_case("Printer.LOCAL.", RecordType::AAAA)]
    #[case::local_itself("local.", RecordType::SOA)]
    #[case::service("Ink-Jet._pdl-datastream._tcp.local.", RecordType::SRV)]
    #[case::ipv4_link_local("34.12.254.169.in-addr.arpa.", RecordType::PTR)]
    #[case::fe8(
        "1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.e.f.ip6.arpa.",
        RecordType::PTR
    )]
    #[case::fe9("9.e.f.ip6.arpa.", RecordType::PTR)]
    #[case::fea("0.a.e.f.ip6.arpa.", RecordType::PTR)]
    #[case::feb("f.b.e.f.ip6.arpa.", RecordType::PTR)]
    fn names_get_nxdomain(
        mut resolver: Resolver,
        #[case] name: &str,
        #[case] record_type: RecordType,
    ) {
        let response = answered_locally(&mut resolver, name, record_type);
        assert_eq!(response.metadata.response_code, ResponseCode::NXDomain);
    }

    #[rstest]
    #[case::ipv4_outside("1.0.253.169.in-addr.arpa.")]
    #[case::fec("c.e.f.ip6.arpa.")]
    fn neighbouring_reverse_zones_are_sent(mut resolver: Resolver, #[case] name: &str) {
        assert_eq!(asked(&mut resolver, name, RecordType::PTR), [name]);
    }

    /// RFC 6762 §3: what counts is the name queried, typed or built from
    /// the search list. So a relative name is judged by its candidates:
    /// `printer.local.` is left out, `printer.local.corp.example.` isn't
    /// link-local and is sent.
    #[test]
    fn relative_name_is_searched_without_the_name_as_given() {
        let mut resolver = searching(&["corp.example."]);
        let sent = asked(&mut resolver, "printer.local", RecordType::A);
        assert_eq!(sent, ["printer.local.corp.example."]);
    }

    #[rstest]
    #[case::no_search_domain(&[])]
    #[case::no_candidate_left(&["local."])]
    fn relative_name_without_a_candidate_gets_nxdomain(#[case] search: &[&str]) {
        let mut resolver = searching(search);
        let response = answered_locally(&mut resolver, "printer.local", RecordType::A);
        assert_eq!(response.metadata.response_code, ResponseCode::NXDomain);
    }

    /// A search domain under `local.`, such as Kubernetes' `cluster.local`
    /// or an Active Directory `corp.local`, shows the servers serve it.
    #[rstest]
    #[case::kubernetes("myservice.ns.svc.cluster.local.")]
    #[case::search_domain_itself("cluster.local.")]
    #[case::relative("myservice.ns.svc.cluster.local")]
    fn names_under_a_search_domain_are_sent(#[case] name: &str) {
        let mut resolver = searching(&["cluster.local."]);
        let sent = asked(&mut resolver, name, RecordType::A);
        assert_eq!(sent, [name.trim_end_matches('.').to_owned() + "."]);
    }

    /// Service `db` in a Kubernetes namespace named `local`: the name as
    /// given is link-local, but its candidates under `cluster.local.` are
    /// sent.
    #[test]
    fn relative_name_is_sent_under_a_search_domain() {
        let mut resolver = searching(&["cluster.local."]);
        let sent = asked(&mut resolver, "db.local", RecordType::A);
        assert_eq!(sent, ["db.local.cluster.local."]);
    }

    #[test]
    fn other_names_under_local_are_not_sent_with_such_a_search_domain() {
        let mut resolver = searching(&["cluster.local."]);
        let response = answered_locally(&mut resolver, "printer.local.", RecordType::A);
        assert_eq!(response.metadata.response_code, ResponseCode::NXDomain);
    }

    /// RFC 6762 §3: a name ending in `.local.` is link-local whether the
    /// user typed it or the search list added it, so `local` as a search
    /// domain isn't a zone the servers serve: its candidates are left out.
    #[test]
    fn local_itself_as_a_search_domain_does_not_count() {
        let mut resolver = searching(&["local.", "corp.example."]);
        let sent = asked(&mut resolver, "printer", RecordType::A);
        assert_eq!(sent, ["printer.corp.example."]);
    }

    #[rstest]
    #[case::listed_zone(&["corp.local."], "dc.corp.local.")]
    #[case::listed_reverse_zone(&["254.169.in-addr.arpa."], "34.12.254.169.in-addr.arpa.")]
    #[case::all_of_local(&["local."], "printer.local.")]
    fn names_under_unicast_local_zones_are_sent(#[case] zones: &[&str], #[case] name: &str) {
        let mut config = config();
        config.unicast_local_zones = zones.iter().map(|zone| self::name(zone)).collect();
        let mut resolver = Resolver::new(config);

        assert_eq!(asked(&mut resolver, name, RecordType::A), [name]);
    }

    /// Unlike `localhost`, a hosts entry answers a `local.` name: the hosts
    /// file isn't a unicast server.
    #[test]
    fn hosts_entry_answers() {
        let mut config = config();
        config.hosts = Hosts::parse(b"192.0.2.9 printer.local\n");
        let mut resolver = Resolver::new(config);

        let response = answered_locally(&mut resolver, "printer.local", RecordType::A);

        let address = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 9));
        assert_eq!(addresses(&response), Ok(vec![address]));
    }
}
