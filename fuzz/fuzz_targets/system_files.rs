//! `Hosts::parse` and `Config::from_resolv_conf` on generated files, mostly
//! well-formed lines with names from a small set and now and then raw
//! bytes, then lookups of listed names, short names and special-use names.
//! Hosts and special-use names must be answered locally with the right
//! addresses; other names walk the search candidates in glibc's order,
//! each answered NXDOMAIN until the one chosen to exist.

#![no_main]

use std::io::Write;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;
use sansio_dns::hickory_proto::op::{Message, ResponseCode};
use sansio_dns::hickory_proto::rr::domain::usage::{INVALID, LOCALHOST, ONION};
use sansio_dns::hickory_proto::rr::{Name, RecordType};
use sansio_dns::{Config, Event, Hosts, Transport, addresses};
use sansio_dns_fuzz::{Harness, S1, reply};

/// Labels for every generated name, so lookups often hit listed names and
/// search domains.
const LABELS: [&str; 8] = [
    "a",
    "b",
    "example",
    "corp",
    "local",
    "localhost",
    "invalid",
    "onion",
];

const SPECIAL: [&str; 6] = [
    "localhost.",
    "db.localhost",
    "LocalHost.",
    "foo.invalid.",
    "invalid",
    "x.onion.",
];

#[derive(Arbitrary, Debug)]
struct Label(u8);

/// A name of one to four labels from [`LABELS`].
#[derive(Arbitrary, Debug)]
struct Labels(Label, Vec<Label>);

impl Labels {
    fn render(&self) -> String {
        std::iter::once(&self.0)
            .chain(self.1.iter().take(3))
            .map(|Label(i)| LABELS[usize::from(*i) % LABELS.len()])
            .collect::<Vec<_>>()
            .join(".")
    }
}

#[derive(Arbitrary, Debug)]
enum ConfLine<'a> {
    Nameserver(IpAddr),
    Search(Vec<Labels>),
    Domain(Labels),
    Ndots(u8),
    Timeout(u8),
    Attempts(u8),
    Raw(&'a [u8]),
}

#[derive(Arbitrary, Debug)]
enum HostsLine<'a> {
    Entry(IpAddr, Labels, Vec<Labels>),
    /// An entry commented out.
    Comment(IpAddr, Labels),
    Raw(&'a [u8]),
}

#[derive(Arbitrary, Debug)]
enum Lookup<'a> {
    /// A name some hosts entry lists.
    Listed(u8),
    /// Labels from [`LABELS`], absolute or relative.
    Labels(Labels, bool),
    Special(u8),
    Text(&'a str),
}

#[derive(Arbitrary, Debug)]
struct Step<'a> {
    lookup: Lookup<'a>,
    aaaa: bool,
    /// The search candidate that exists; the others are NXDOMAIN.
    found: Option<u8>,
}

#[derive(Arbitrary, Debug)]
struct Input<'a> {
    hosts: Vec<HostsLine<'a>>,
    resolv_conf: Vec<ConfLine<'a>>,
    steps: Vec<Step<'a>>,
}

/// The hosts file, and the names its entries list with their addresses.
fn render_hosts(lines: &[HostsLine<'_>]) -> (Vec<u8>, Vec<(String, IpAddr)>) {
    let mut text = Vec::new();
    let mut listed = Vec::new();
    for line in lines.iter().take(16) {
        let _ = match line {
            HostsLine::Entry(address, first, more) => {
                let names: Vec<String> = std::iter::once(first)
                    .chain(more.iter().take(3))
                    .map(Labels::render)
                    .collect();
                let written = writeln!(text, "{address}\t{}", names.join(" "));
                listed.extend(names.into_iter().map(|name| (name, *address)));
                written
            }
            HostsLine::Comment(address, name) => writeln!(text, "# {address} {}", name.render()),
            HostsLine::Raw(bytes) => text.write_all(bytes).and_then(|()| writeln!(text)),
        };
    }
    (text, listed)
}

fn render_resolv_conf(lines: &[ConfLine<'_>]) -> Vec<u8> {
    let mut text = Vec::new();
    for line in lines.iter().take(16) {
        let _ = match line {
            ConfLine::Nameserver(address) => writeln!(text, "nameserver {address}"),
            ConfLine::Search(domains) => {
                let domains: Vec<String> = domains.iter().take(6).map(Labels::render).collect();
                writeln!(text, "search {}", domains.join(" "))
            }
            ConfLine::Domain(domain) => writeln!(text, "domain {}", domain.render()),
            ConfLine::Ndots(n) => writeln!(text, "options ndots:{n}"),
            ConfLine::Timeout(n) => writeln!(text, "options timeout:{n}"),
            ConfLine::Attempts(n) => writeln!(text, "options attempts:{n}"),
            ConfLine::Raw(bytes) => text.write_all(bytes).and_then(|()| writeln!(text)),
        };
    }
    text
}

fn is_special_use(name: &Name) -> bool {
    [&LOCALHOST, &INVALID, &ONION]
        .iter()
        .any(|zone| zone.name().zone_of(name))
}

/// The names glibc's `res_search` tries for `name`, in order, leaving out
/// those under special-use zones.
fn candidates(name: &Name, search: &[Name], ndots: u8) -> Vec<Name> {
    let mut absolute = name.clone();
    absolute.set_fqdn(true);
    if name.is_fqdn() || search.is_empty() {
        return vec![absolute];
    }
    let searched = search
        .iter()
        .filter_map(|domain| name.clone().append_domain(domain).ok())
        .filter(|candidate| !is_special_use(candidate));
    let dots = usize::from(name.num_labels()).saturating_sub(1);
    if dots >= usize::from(ndots) {
        std::iter::once(absolute).chain(searched).collect()
    } else {
        searched.chain(std::iter::once(absolute)).collect()
    }
}

/// The local answer for `name`, if any: its response code and addresses.
fn local_answer(
    name: &Name,
    record_type: RecordType,
    hosts: &Hosts,
) -> Option<(ResponseCode, Vec<IpAddr>)> {
    let v4 = record_type == RecordType::A;
    if is_special_use(name) {
        let loopback = if v4 {
            IpAddr::V4(Ipv4Addr::LOCALHOST)
        } else {
            IpAddr::V6(Ipv6Addr::LOCALHOST)
        };
        return Some(if LOCALHOST.name().zone_of(name) {
            (ResponseCode::NoError, vec![loopback])
        } else {
            (ResponseCode::NXDomain, Vec::new())
        });
    }
    let listed = hosts.lookup(name)?;
    let family = listed.into_iter().filter(|a| a.is_ipv4() == v4).collect();
    Some((ResponseCode::NoError, family))
}

fuzz_target!(|input: Input<'_>| {
    let (text, listed) = render_hosts(&input.hosts);
    let hosts = Hosts::parse(&text);
    for (text, address) in &listed {
        let found = Name::from_ascii(text).ok().and_then(|n| hosts.lookup(&n));
        assert!(
            found.is_some_and(|found| found.contains(address)),
            "{text} {address} missing from the hosts entries"
        );
    }
    let mut config = Config::from_resolv_conf(&render_resolv_conf(&input.resolv_conf))
        .unwrap_or_else(|_| Config::new(S1, []));
    config.hosts = hosts.clone();
    let (search, ndots) = (config.search.clone(), config.ndots);
    let mut harness = Harness::new(config, Vec::new(), None);

    for step in input.steps.iter().take(6) {
        let text = match &step.lookup {
            Lookup::Listed(i) => listed
                .get(usize::from(*i) % listed.len().max(1))
                .map_or("a", |(name, _)| name.as_str())
                .to_owned(),
            Lookup::Labels(labels, absolute) => labels.render() + if *absolute { "." } else { "" },
            Lookup::Special(i) => SPECIAL[usize::from(*i) % SPECIAL.len()].to_owned(),
            Lookup::Text(text) => (*text).to_owned(),
        };
        let Ok(name) = Name::from_ascii(&text) else {
            continue;
        };
        let record_type = if step.aaaa {
            RecordType::AAAA
        } else {
            RecordType::A
        };
        let mut absolute = name.clone();
        absolute.set_fqdn(true);
        let local = local_answer(&absolute, record_type, &hosts);
        let expected = candidates(&name, &search, ndots);
        let found = step.found.map(usize::from);
        let Some(query) = harness.query(name, record_type) else {
            continue;
        };

        let mut asked = Vec::new();
        for _ in 0..2 * expected.len() + 8 {
            let transmits = harness.check();
            if !harness.live().contains(&query) {
                break;
            }
            assert!(local.is_none(), "a local name went to the network");
            if transmits.is_empty() {
                harness.next_deadline();
            }
            for t in transmits {
                let Transport::Udp(q) = t.transport else {
                    continue;
                };
                let request = Message::from_vec(&t.payload).expect("the resolver sent garbage");
                let name = request.queries.first().map(|q| q.name().clone());
                assert_eq!(
                    name.as_ref(),
                    expected.get(asked.len()),
                    "asked {asked:?} then {name:?}, expected {expected:?}"
                );
                let code = if found == Some(asked.len()) {
                    ResponseCode::NoError
                } else {
                    ResponseCode::NXDomain
                };
                asked.extend(name);
                if let Ok(bytes) = reply(&request, code).to_vec() {
                    let now = harness.now;
                    harness
                        .resolver
                        .handle_datagram(q, t.destination, &bytes, now);
                }
            }
        }
        assert!(!harness.live().contains(&query), "lookup never finished");

        let events = harness.take_events();
        let response = events.iter().find_map(|event| match event {
            Event::Response { query: q, response } if *q == query => Some(response),
            _ => None,
        });
        let response = response.expect("a lookup answered every time failed");
        let code = response.metadata.response_code;
        match &local {
            Some((local_code, local_addresses)) => {
                assert_eq!(code, *local_code, "wrong local response code");
                assert_eq!(&addresses(response), local_addresses, "wrong local answer");
            }
            None => {
                let last = found.filter(|f| *f < expected.len());
                assert_eq!(asked.len(), last.map_or(expected.len(), |f| f + 1));
                let want = match last {
                    Some(_) => ResponseCode::NoError,
                    None => ResponseCode::NXDomain,
                };
                assert_eq!(code, want, "search walk ended with the wrong code");
            }
        }
    }
});
