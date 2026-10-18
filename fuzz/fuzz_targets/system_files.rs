//! `Hosts::parse` and `Config::from_resolv_conf` on generated files, mostly
//! well-formed lines with names from a small set and now and then raw
//! bytes, then lookups of listed names, short names and special-use names.
//! Hosts and special-use names, and link-local names none of whose search
//! candidates is sent, must be answered locally with the right addresses;
//! other names walk the search candidates in glibc's order, link-local ones
//! left out, and a name of one label as given too with `options
//! no-tld-query`, each answered NXDOMAIN, or NODATA for one of them, until
//! the one chosen to have data. When none has, the walk ends on the NODATA
//! answer if there was one. The environment glibc reads besides the file
//! is generated too: `LOCALDOMAIN` must replace the search domains,
//! `RES_OPTIONS` must win over the file's options, and the host name's
//! domain must be the search domain when nothing else sets one.

#![no_main]

use std::io::Write;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;
use sansio_dns::hickory_proto::op::{Message, ResponseCode};
use sansio_dns::hickory_proto::rr::domain::usage::{INVALID, LOCALHOST, ONION};
use sansio_dns::hickory_proto::rr::{Name, RecordType};
use sansio_dns::{Config, Event, Hosts, ResolvEnv, Transport, addresses};
use sansio_dns_fuzz::{Harness, reply};

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

const SPECIAL: [&str; 11] = [
    "localhost.",
    "db.localhost",
    "LocalHost.",
    "foo.invalid.",
    "invalid",
    "x.onion.",
    "printer.local.",
    "a.corp.local",
    "db.local",
    "34.12.254.169.in-addr.arpa.",
    "1.0.a.e.f.ip6.arpa.",
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
    NoTldQuery,
    Raw(&'a [u8]),
}

/// An option in `RES_OPTIONS`.
#[derive(Arbitrary, Debug)]
enum EnvOption<'a> {
    Ndots(u8),
    /// `no-tld-query`, or with `true` `no_tld_query`.
    NoTldQuery(bool),
    /// `-no-tld-query`, which turns it off again.
    TldQuery,
    Raw(&'a [u8]),
}

/// What glibc reads besides `resolv.conf`.
#[derive(Arbitrary, Debug)]
struct Env<'a> {
    localdomain: Option<Vec<Labels>>,
    res_options: Option<Vec<EnvOption<'a>>>,
    hostname: Option<Labels>,
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
    /// The search candidate that has data.
    found: Option<u8>,
    /// A search candidate that exists without data (NODATA); the others
    /// are NXDOMAIN.
    nodata: Option<u8>,
}

#[derive(Arbitrary, Debug)]
struct Input<'a> {
    hosts: Vec<HostsLine<'a>>,
    resolv_conf: Vec<ConfLine<'a>>,
    env: Env<'a>,
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
            ConfLine::NoTldQuery => writeln!(text, "options no-tld-query"),
            ConfLine::Raw(bytes) => text.write_all(bytes).and_then(|()| writeln!(text)),
        };
    }
    text
}

/// `RES_OPTIONS` and the settings it must leave: `ndots` and `tld_query`,
/// if it sets them and has no raw bytes that might too.
fn render_res_options(options: &[EnvOption<'_>]) -> (Vec<u8>, Option<u8>, Option<bool>) {
    let mut text = Vec::new();
    let (mut ndots, mut tld_query, mut raw) = (None, None, false);
    for option in options.iter().take(8) {
        let _ = match option {
            EnvOption::Ndots(n) => {
                ndots = Some((*n).min(15));
                write!(text, " ndots:{n}")
            }
            EnvOption::NoTldQuery(underscores) => {
                tld_query = Some(false);
                let option = if *underscores {
                    "no_tld_query"
                } else {
                    "no-tld-query"
                };
                write!(text, "\t{option}")
            }
            EnvOption::TldQuery => {
                tld_query = Some(true);
                write!(text, " -no-tld-query")
            }
            EnvOption::Raw(bytes) => {
                raw = true;
                text.write_all(b" ").and_then(|()| text.write_all(bytes))
            }
        };
    }
    if raw {
        (text, None, None)
    } else {
        (text, ndots, tld_query)
    }
}

/// `labels` as an absolute name.
fn absolute(labels: &str) -> Name {
    let mut name = Name::from_ascii(labels).expect("labels from LABELS");
    name.set_fqdn(true);
    name
}

/// The search domains the environment must leave, if it settles them:
/// `LOCALDOMAIN`'s, or else the host name's domain when the file sets
/// none (and has no raw lines that might).
fn expected_search(env: &Env<'_>, lines: &[ConfLine<'_>]) -> Option<Vec<Name>> {
    if let Some(domains) = &env.localdomain {
        return Some(
            domains
                .iter()
                .take(6)
                .map(|d| absolute(&d.render()))
                .collect(),
        );
    }
    let file_may_set = lines.iter().take(16).any(|line| match line {
        ConfLine::Search(domains) => !domains.is_empty(),
        ConfLine::Domain(_) | ConfLine::Raw(_) => true,
        _ => false,
    });
    if file_may_set {
        return None;
    }
    let hostname = env.hostname.as_ref().map(Labels::render);
    let domain = hostname
        .as_deref()
        .and_then(|h| h.split_once('.'))
        .map(|(_, d)| absolute(d));
    Some(domain.into_iter().collect())
}

fn is_special_use(name: &Name) -> bool {
    [&LOCALHOST, &INVALID, &ONION]
        .iter()
        .any(|zone| zone.name().zone_of(name))
}

/// The zones RFC 6762 reserves for multicast DNS.
fn link_local_zones() -> Vec<Name> {
    [
        "local.",
        "254.169.in-addr.arpa.",
        "8.e.f.ip6.arpa.",
        "9.e.f.ip6.arpa.",
        "a.e.f.ip6.arpa.",
        "b.e.f.ip6.arpa.",
    ]
    .iter()
    .map(|zone| Name::from_ascii(zone).expect("a valid fixed name"))
    .collect()
}

/// Whether `name` doesn't go to the servers: special-use, or link-local
/// and not under a search domain strictly under a link-local zone (no
/// `unicast_local_zones` here).
fn never_sent(name: &Name, search: &[Name]) -> bool {
    let zones = link_local_zones();
    let link_local = zones.iter().any(|zone| zone.zone_of(name));
    let served = search.iter().any(|domain| {
        let under = zones
            .iter()
            .any(|zone| zone.zone_of(domain) && zone.num_labels() < domain.num_labels());
        under && domain.zone_of(name)
    });
    is_special_use(name) || (link_local && !served)
}

/// The names glibc's `res_search` tries for `name`, in order, leaving out
/// those that are never sent, the name as given among them, and a name of
/// one label as given without `tld_query` (`options no-tld-query`). A name
/// tried only as given is kept: the local answer covers it.
fn candidates(name: &Name, search: &[Name], ndots: u8, tld_query: bool) -> Vec<Name> {
    let mut absolute = name.clone();
    absolute.set_fqdn(true);
    if name.is_fqdn() || search.is_empty() {
        return vec![absolute];
    }
    let searched = search
        .iter()
        .filter_map(|domain| name.clone().append_domain(domain).ok());
    let dots = usize::from(name.num_labels()).saturating_sub(1);
    let as_given = (tld_query || dots > 0).then_some(absolute);
    let all: Vec<Name> = if dots >= usize::from(ndots) {
        as_given.into_iter().chain(searched).collect()
    } else {
        searched.chain(as_given).collect()
    };
    all.into_iter()
        .filter(|candidate| !never_sent(candidate, search))
        .collect()
}

/// The local answer for `name`, as given, if any: its response code and
/// addresses. Special-use names and the hosts file are checked as given;
/// a link-local name gets NXDOMAIN when it is never sent and tried only as
/// given, or when none of its `candidates` is left.
fn local_answer(
    name: &Name,
    record_type: RecordType,
    hosts: &Hosts,
    search: &[Name],
    candidates: &[Name],
) -> Option<(ResponseCode, Vec<IpAddr>)> {
    let v4 = record_type == RecordType::A;
    let mut absolute = name.clone();
    absolute.set_fqdn(true);
    let as_given = name.is_fqdn() || search.is_empty();
    let name = &absolute;
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
    if let Some(listed) = hosts.lookup(name) {
        let family = listed.into_iter().filter(|a| a.is_ipv4() == v4).collect();
        return Some((ResponseCode::NoError, family));
    }
    let unsent = if as_given {
        never_sent(name, search)
    } else {
        candidates.is_empty()
    };
    unsent.then(|| (ResponseCode::NXDomain, Vec::new()))
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
    let mut env = ResolvEnv::default();
    env.localdomain = input.env.localdomain.as_ref().map(|domains| {
        let domains: Vec<String> = domains.iter().take(6).map(Labels::render).collect();
        domains.join(" ").into_bytes()
    });
    let (res_options, ndots, tld_query) = match &input.env.res_options {
        Some(options) => {
            let (text, ndots, tld_query) = render_res_options(options);
            (Some(text), ndots, tld_query)
        }
        None => (None, None, None),
    };
    env.res_options = res_options;
    env.hostname = input.env.hostname.as_ref().map(|h| h.render().into_bytes());
    let mut config =
        Config::from_resolv_conf_with_env(&render_resolv_conf(&input.resolv_conf), &env);
    if let Some(search) = expected_search(&input.env, &input.resolv_conf) {
        assert_eq!(config.search, search, "the environment's search domains");
    }
    if let Some(ndots) = ndots {
        assert_eq!(config.ndots, ndots, "RES_OPTIONS's ndots");
    }
    if let Some(tld_query) = tld_query {
        assert_eq!(config.tld_query, tld_query, "RES_OPTIONS's no-tld-query");
    }
    config.hosts = hosts.clone();
    let (search, ndots, tld_query) = (config.search.clone(), config.ndots, config.tld_query);
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
        let expected = candidates(&name, &search, ndots, tld_query);
        let local = local_answer(&name, record_type, &hosts, &search, &expected);
        let found = step.found.map(usize::from);
        let nodata = step.nodata.map(usize::from).filter(|n| found != Some(*n));
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
                let code = if found == Some(asked.len()) || nodata == Some(asked.len()) {
                    ResponseCode::NoError
                } else {
                    ResponseCode::NXDomain
                };
                let mut response = reply(&request, code);
                if nodata == Some(asked.len()) {
                    response.answers.clear();
                }
                asked.extend(name);
                if let Ok(bytes) = response.to_vec() {
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
                assert_eq!(
                    addresses(response).as_ref(),
                    Ok(local_addresses),
                    "wrong local answer"
                );
            }
            None => {
                let last = found.filter(|f| *f < expected.len());
                assert_eq!(asked.len(), last.map_or(expected.len(), |f| f + 1));
                let empty = nodata.filter(|n| *n < asked.len());
                let (want, question) = match (last, empty) {
                    (Some(f), _) => (ResponseCode::NoError, expected.get(f)),
                    (None, Some(n)) => (ResponseCode::NoError, expected.get(n)),
                    (None, None) => (ResponseCode::NXDomain, expected.last()),
                };
                assert_eq!(code, want, "search walk ended with the wrong code");
                assert_eq!(
                    response.queries.first().map(|q| q.name()),
                    question,
                    "search walk ended on the wrong candidate"
                );
                assert_eq!(
                    addresses(response).is_ok_and(|found| found.is_empty()),
                    last.is_none(),
                    "addresses only from the candidate with data"
                );
            }
        }
    }
});
