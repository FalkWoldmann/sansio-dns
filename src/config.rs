//! Resolver settings, and reading them from a `resolv.conf`.

use std::collections::VecDeque;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV6};
use std::num::NonZeroUsize;
#[cfg(feature = "tls")]
use std::sync::Arc;
use std::time::Duration;

use hickory_proto::rr::{Name, RecordType};

use crate::Hosts;
#[cfg(feature = "tls")]
use crate::tls::{self, TlsConfigError};
use crate::wire::{is_link_local, is_special_use, is_under_link_local};

/// Which address families an [`IpLookup`](crate::IpLookup) asks for, and the
/// order of its addresses.
///
/// With both families, the addresses of the first come first. Clients that
/// race connections (RFC 8305), such as hyper's, try that family first and
/// the other one shortly after.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub enum IpStrategy {
    /// Only A queries.
    Ipv4Only,
    /// Only AAAA queries.
    Ipv6Only,
    /// Both; the IPv4 addresses first.
    Ipv4First,
    /// Both; the IPv6 addresses first. RFC 6724's default policy table
    /// orders them so only for global unicast IPv6 destinations, on a host
    /// with a global IPv6 source address: it puts IPv4 before ULA, 6to4
    /// and Teredo destinations (§2.1), and its rules also weigh scope and
    /// prefix length (§6), which this order ignores.
    #[default]
    Ipv6First,
}

impl IpStrategy {
    /// The record types to ask for, in the order their addresses are listed.
    pub(crate) fn record_types(self) -> (RecordType, Option<RecordType>) {
        match self {
            Self::Ipv4Only => (RecordType::A, None),
            Self::Ipv6Only => (RecordType::AAAA, None),
            Self::Ipv4First => (RecordType::A, Some(RecordType::AAAA)),
            Self::Ipv6First => (RecordType::AAAA, Some(RecordType::A)),
        }
    }
}

/// The shortest wait for an answer, whatever [`Config::timeout`] says
/// (RFC 1123 §6.1.3.3 (5)).
const MIN_WAIT: Duration = Duration::from_secs(1);

/// The longest wait for an answer, after backoff (RFC 1123 §6.1.3.3 (5)).
/// Above twice the maximum segment lifetime of two minutes (RFC 9293), as
/// that section requires of a limit.
const MAX_WAIT: Duration = Duration::from_secs(300);

/// The longest a server stays failed (RFC 2308 §7.2, RFC 9520 §3.2).
const MAX_FAILURE_MEMORY: Duration = Duration::from_secs(300);

/// The shortest time a resolution failure is cached (RFC 9520 §3.2: "at
/// least 1 second").
const MIN_FAILURE_CACHE: Duration = Duration::from_secs(1);

/// The longest time a resolution failure is cached (RFC 9520 §3.2: "MUST
/// NOT be cached for longer than 5 minutes").
const MAX_FAILURE_CACHE: Duration = Duration::from_secs(300);

/// How often a search candidate may be sent to one server over one
/// transport (RFC 9520 §3.1).
pub(crate) const MAX_SENDS_PER_SERVER: u8 = 3;

/// Resolver settings.
#[derive(Clone, Debug)]
pub struct Config {
    /// Name servers, tried in order and rotated on each retry. Never empty.
    servers: Vec<SocketAddr>,
    /// How long to wait for a response before retrying, on each server's
    /// first attempt. Each later round through the servers waits twice as
    /// long as the one before (RFC 1123 §6.1.3.3 (5)). That section also
    /// asks for a lower and an upper bound: a value below one second counts
    /// as one second, and no wait is longer than 300 seconds, above the
    /// 240 that the section's limit must exceed (twice the maximum segment
    /// lifetime of RFC 9293, plus service delay). So `Duration::MAX` waits
    /// 300 seconds on every attempt.
    pub timeout: Duration,
    /// Total number of attempts per query, across all servers: the first
    /// goes to the first server that hasn't failed recently (see
    /// `failure_memory`), and each next one to the server after, wrapping
    /// around and skipping servers that answered the current search
    /// candidate with an error. A query whose servers all did fails before
    /// using up its attempts.
    /// Switching to TCP, dropping EDNS and resending after a lost
    /// connection don't count as one; see the crate docs on how a query
    /// moves on.
    ///
    /// RFC 9520 §3.1 allows at most three sends of a query to a server over
    /// one transport, free ones included, so a search candidate gets at
    /// most three attempts per server over UDP, and three more over a
    /// stream, after a truncated answer or on an open connection. Attempts
    /// beyond that go unused: a query whose servers have all had their
    /// three fails early.
    pub attempts: NonZeroUsize,
    /// Domains to try appending to names without a trailing dot, in order.
    /// Empty means every name is used as given. A candidate that wouldn't
    /// be sent, under `localhost.`, `invalid.` or `onion.`, or a
    /// link-local name not served over unicast (see
    /// `unicast_local_zones`), is left out, the name as given among them.
    ///
    /// A search domain under `local.`, such as Kubernetes' `cluster.local.`
    /// or an Active Directory domain `corp.local.`, shows that the name
    /// servers serve it, so names under it are sent to them.
    pub search: Vec<Name>,
    /// Zones under `local.`, or under the link-local reverse zones, that the
    /// name servers serve, in addition to those under a search domain. Empty
    /// by default, and [`Config::from_resolv_conf`] leaves it empty.
    ///
    /// RFC 6762 reserves `local.`, `254.169.in-addr.arpa.` and
    /// `8.e.f.ip6.arpa.` to `b.e.f.ip6.arpa.` for multicast DNS (§3, §4),
    /// and asks libraries not to send their names to unicast servers
    /// (§22.1 item 3). So a name in them, as given or as a search
    /// candidate, is sent only when it is under one of these zones or
    /// under a search domain that is itself under one of the six (not
    /// `local.` itself); any other gets NXDOMAIN without a transmit, the
    /// answer §22.1 item 4 asks of caching servers. Multicast DNS itself is
    /// up to the caller. Listing `local.` here sends every `local.` name to
    /// the servers.
    pub unicast_local_zones: Vec<Name>,
    /// A name with at least this many dots is tried as given before the
    /// search domains; one with fewer, after them. `db` has no dots and
    /// `db.x` has one.
    pub ndots: u8,
    /// How long a stream connection may go without any query on it before
    /// the resolver asks for it to be closed (RFC 7766 §6.2.3), counted
    /// from the last query written to it or complete response read from it
    /// (partial messages don't count), or from the deadline of any query
    /// that left it before its answer came: cancelled, or moved on after a
    /// timeout.
    pub idle_timeout: Duration,
    /// How long a server that failed to answer, by timing out or with a
    /// network error, stays failed: until then, new queries start at the
    /// next server in the list instead, and their attempts rotate on from
    /// there. An answer from the server, even an error code, ends it early.
    /// Zero turns it off. At most five minutes: longer values count as five
    /// minutes, the longest RFC 2308 §7.2 and RFC 9520 §3.2 let a server be
    /// deemed dead. The failure is kept per server address, for every
    /// query, as RFC 9520 §3.2 allows for unresponsive servers, and
    /// [`Resolver::flush_cache`](crate::Resolver::flush_cache) forgets it.
    pub failure_memory: Duration,
    /// Static entries answered before DNS, like `/etc/hosts`. Empty by
    /// default; fill it with [`Hosts::parse`].
    pub hosts: Hosts,
    /// Which addresses an [`IpLookup`](crate::IpLookup) asks for, and which
    /// come first. [`IpStrategy::Ipv6First`] by default.
    pub ip_strategy: IpStrategy,
    /// Whether a name of one label, such as `db`, is also tried as given
    /// when there are search domains, which asks the name servers for a
    /// top-level domain. True by default, as in glibc; `options
    /// no-tld-query` in a `resolv.conf` turns it off. Without search
    /// domains, such a name is always tried as given.
    ///
    /// RFC 1123 §6.1.4.3 asks a search list to keep from sending excessive
    /// queries to the root, by caching negative answers (provision (a)),
    /// which the resolver does (see the crate docs), and preferably also
    /// by sending only names with two or more interior dots to non-local
    /// servers (provision (b)). Turning this off keeps single-label names
    /// from being sent as given, a weaker form of (b): a name with one dot,
    /// such as `db.corp`, is still sent as given.
    pub tld_query: bool,
    /// How many failures and negative answers the cache holds, 1024 by
    /// default. When it is full, a new entry first drops the expired ones,
    /// and then the oldest, which bounds the memory it takes, as RFC 9520
    /// §3.2 asks of a failure cache.
    pub cache_entries: NonZeroUsize,
    /// How long a resolution failure is cached the first time: while it
    /// is, nothing is sent for the question and queries for it fail at once
    /// with the cached error (RFC 9520 §3.2). One second by default, the
    /// least §3.2 allows: shorter values count as one second, and longer
    /// ones than five minutes as five minutes.
    pub failure_cache_min: Duration,
    /// How long a resolution failure is cached at most. Each time a
    /// question fails again, and was first sent less than this long after
    /// its cached failure expired, it is cached twice as long as before
    /// (the backoff RFC 9520 §3.2 asks for), however long its retries
    /// took, up to this. A useful answer (data, NXDOMAIN or NODATA) for the
    /// question starts it over. 30 seconds by default;
    /// at least `failure_cache_min`, and at most five minutes, the longest
    /// §3.2 allows.
    pub failure_cache_max: Duration,
    /// How long a negative answer (NXDOMAIN or NODATA) is cached at most,
    /// whatever its SOA record says. One hour by default, the low end of
    /// the one to three hours RFC 2308 §5 recommends; it found more than a
    /// day problematic. Zero turns negative caching off.
    pub max_negative_ttl: Duration,
    /// DNS over TLS settings; see `Config::with_tls`.
    #[cfg(feature = "tls")]
    pub(crate) tls: Option<tls::Settings>,
}

impl Config {
    /// `first` and then `more`, two attempts per server, waiting five
    /// seconds on the first round and ten on the second: without measured
    /// round trip times, RFC 1123 §6.1.3.3 asks for no less than five. A
    /// server that fails to answer is tried after the others for a minute.
    /// A question that fails is cached for a second, backing off to 30
    /// seconds, and a negative answer for at most an hour, in a cache of
    /// 1024 entries.
    pub fn new(first: SocketAddr, more: impl IntoIterator<Item = SocketAddr>) -> Self {
        let servers: Vec<SocketAddr> = std::iter::once(first).chain(more).collect();
        let attempts = NonZeroUsize::new(servers.len() * 2).unwrap_or(NonZeroUsize::MIN);
        Self {
            servers,
            timeout: Duration::from_secs(5),
            attempts,
            search: Vec::new(),
            unicast_local_zones: Vec::new(),
            ndots: 1,
            idle_timeout: Duration::from_secs(10),
            failure_memory: Duration::from_secs(60),
            hosts: Hosts::default(),
            ip_strategy: IpStrategy::default(),
            tld_query: true,
            cache_entries: NonZeroUsize::new(1024).unwrap_or(NonZeroUsize::MIN),
            failure_cache_min: MIN_FAILURE_CACHE,
            failure_cache_max: Duration::from_secs(30),
            max_negative_ttl: Duration::from_secs(3600),
            #[cfg(feature = "tls")]
            tls: None,
        }
    }

    /// Send every query over DNS over TLS (RFC 7858), authenticating every
    /// server as `server_name` with `client` (RFC 8310 strict profile).
    /// [`Config::with_tls_names`] gives each server a name of its own.
    ///
    /// Give the servers' TLS addresses: port 853, or another port agreed
    /// with the server's operator, but never 53 (RFC 7858 §3.1). Queries
    /// are padded to a multiple of 128 octets (RFC 8467 §4.1) and carry an
    /// EDNS Client Subnet option with SOURCE PREFIX-LENGTH 0, which asks
    /// the server not to pass any part of the client's address on to
    /// other servers (RFC 8310 §11.1, RFC 7871 §7.1.2).
    ///
    /// `client` brings its own crypto provider and root certificates, and
    /// decides how strict the authentication is. For RFC 8310's strict
    /// profile, keep rustls' default WebPKI certificate verifier, or one
    /// that checks the certificate path and the name just as well (§8.1):
    /// a custom verifier that accepts more gives the profile up. Keep TLS
    /// 1.3 enabled (RFC 9325 §3.1.1), session resumption on, as it is by
    /// default (RFC 7858 §3.4, RFC 8310 §9), and SNI on, which servers that
    /// host several names need (RFC 9325 §3.7). Setting
    /// `client.alpn_protocols` to `[b"dot"]`, the identifier IANA
    /// registered for DNS over TLS, guards against cross-protocol attacks
    /// (RFC 9325 §3.8). rustls only speaks TLS 1.2 and 1.3 and never
    /// compresses (RFC 8310 §9), and this crate never sends early data
    /// (RFC 9325 §3.10).
    ///
    /// A `ServerName::IpAddress` makes rustls match the certificate's IP
    /// address entries and send no SNI. That is not one of RFC 8310's
    /// authentication mechanisms, which name the server by a domain name
    /// (§8.1) or pin its key (RFC 7858 §4.2).
    ///
    /// # Errors
    ///
    /// If a server uses port 53, or rustls can't start a session with
    /// `client` and `server_name`.
    #[cfg(feature = "tls")]
    pub fn with_tls(
        self,
        client: Arc<rustls::ClientConfig>,
        server_name: rustls::pki_types::ServerName<'static>,
    ) -> Result<Self, TlsConfigError> {
        let names: Vec<_> = self
            .servers
            .iter()
            .copied()
            .zip(std::iter::repeat_n(server_name, self.servers.len()))
            .collect();
        self.with_tls_names(client, names)
    }

    /// [`Config::with_tls`], with an authentication name for each server
    /// (RFC 8310 §7.1), so servers of different operators can be mixed:
    /// `names` pairs each server's address with the name its certificate
    /// must match. If an address appears more than once, its last name
    /// counts.
    ///
    /// # Errors
    ///
    /// If a server uses port 53, a server has no name, a name is given for
    /// an address that isn't one of the servers, or rustls can't start a
    /// session with `client` and one of the names.
    #[cfg(feature = "tls")]
    pub fn with_tls_names(
        mut self,
        client: Arc<rustls::ClientConfig>,
        names: impl IntoIterator<Item = (SocketAddr, rustls::pki_types::ServerName<'static>)>,
    ) -> Result<Self, TlsConfigError> {
        self.tls = Some(tls::Settings::new(client, &self.servers, names)?);
        Ok(self)
    }

    /// Whether queries go over TLS, and so over a stream from the start.
    pub(crate) fn uses_tls(&self) -> bool {
        #[cfg(feature = "tls")]
        return self.tls.is_some();
        #[cfg(not(feature = "tls"))]
        false
    }

    /// Settings from the text of a `resolv.conf` file, read the way glibc
    /// reads it: the first three usable `nameserver` lines (port 53),
    /// `search` or `domain`, `options ndots:` (default 1, at most 15),
    /// `options timeout:` in seconds (default 5, at most 30),
    /// `options attempts:` per server (default 2),
    /// `options no-aaaa` ([`IpStrategy::Ipv4Only`]) and
    /// `options no-tld-query` (`tld_query` off). Without usable
    /// `nameserver` lines, the local host is asked (127.0.0.1). Unlike glibc,
    /// later rounds through the servers wait longer; see `timeout`. And
    /// where glibc takes up to 5 attempts per server, this takes at most 3,
    /// since RFC 9520 §3.1 allows no more than three sends of a query to a
    /// server over one transport.
    ///
    /// Like glibc, it never fails: lines and options it can't use are
    /// skipped, and so is a link-local server with a named scope
    /// (`fe80::1%eth0`), since mapping an interface name to its index needs
    /// a system call; numeric scopes (`fe80::1%2`) work. Other options, such
    /// as `rotate`, `use-vc` and `edns0` (EDNS is always on), are ignored.
    pub fn from_resolv_conf(text: &[u8]) -> Self {
        let (parsed, _skipped) = resolv_conf::Config::parse_with_errors(text);
        // glibc's MAXNS: later servers are ignored.
        let mut servers = parsed
            .nameservers
            .iter()
            .filter_map(|ip| match ip {
                resolv_conf::ScopedIp::V4(v4) => Some(SocketAddr::from((*v4, 53))),
                resolv_conf::ScopedIp::V6(v6, None) => Some(SocketAddr::from((*v6, 53))),
                resolv_conf::ScopedIp::V6(v6, Some(scope)) => scope
                    .parse()
                    .ok()
                    .map(|id| SocketAddr::V6(SocketAddrV6::new(*v6, 53, 0, id))),
            })
            .take(3);
        let first = servers
            .next()
            .unwrap_or_else(|| SocketAddr::from((Ipv4Addr::LOCALHOST, 53)));
        let mut config = Self::new(first, servers);
        config.timeout = Duration::from_secs(u64::from(parsed.timeout.clamp(1, 30)));
        let per_server =
            usize::try_from(parsed.attempts.clamp(1, MAX_SENDS_PER_SERVER.into())).unwrap_or(1);
        config.attempts =
            NonZeroUsize::new(per_server * config.servers.len()).unwrap_or(NonZeroUsize::MIN);
        config.search = parsed
            .get_last_search_or_domain()
            .filter_map(|domain| Name::from_ascii(domain).ok())
            .map(|mut domain| {
                domain.set_fqdn(true);
                domain
            })
            .collect();
        config.ndots = u8::try_from(parsed.ndots.min(15)).unwrap_or(15);
        if parsed.no_aaaa {
            config.ip_strategy = IpStrategy::Ipv4Only;
        }
        config.tld_query = !parsed.no_tld_query;
        config
    }

    /// The names to try for `name`, in order, as glibc's `res_search` does.
    /// Candidates that wouldn't be sent ([`Config::never_sent`]), the name
    /// as given among them, are left out, and so is a name of one label as
    /// given without `tld_query`. Empty when the name is only tried as
    /// given, which needs no list, or when no candidate is left.
    pub(crate) fn candidates(&self, name: &Name) -> VecDeque<Name> {
        if name.is_fqdn() || self.search.is_empty() {
            return VecDeque::new();
        }
        let mut absolute = name.clone();
        absolute.set_fqdn(true);
        let searched = self
            .search
            .iter()
            .filter_map(|domain| name.clone().append_domain(domain).ok());
        // `num_labels` doesn't count the root label.
        let dots = usize::from(name.num_labels()).saturating_sub(1);
        let as_given = (self.tld_query || dots > 0).then_some(absolute);
        let all: VecDeque<Name> = if dots >= usize::from(self.ndots) {
            as_given.into_iter().chain(searched).collect()
        } else {
            searched.chain(as_given).collect()
        };
        all.into_iter()
            .filter(|candidate| !self.never_sent(candidate))
            .collect()
    }

    /// Whether `name`, as given, gets NXDOMAIN without a transmit: an
    /// absolute name, or one tried only as given, that is never sent, or a
    /// relative name none of whose search candidates is sent. RFC 6762 §3
    /// makes no difference between a `.local.` suffix typed and one
    /// appended from the search list, so a relative name is judged by the
    /// names actually queried.
    pub(crate) fn never_sent_as_given(&self, name: &Name) -> bool {
        if name.is_fqdn() || self.search.is_empty() {
            let mut absolute = name.clone();
            absolute.set_fqdn(true);
            self.never_sent(&absolute)
        } else {
            self.candidates(name).is_empty()
        }
    }

    /// Whether `name` must not reach the name servers: it is under
    /// `localhost.`, `invalid.` or `onion.` (RFC 6761 §6.3, §6.4, RFC 7686
    /// §2), or a link-local name (RFC 6762 §3, §4) that isn't under
    /// `unicast_local_zones` or a search domain under a link-local zone
    /// (§22.1 item 3).
    pub(crate) fn never_sent(&self, name: &Name) -> bool {
        is_special_use(name) || (is_link_local(name) && !self.served_over_unicast(name))
    }

    /// Whether the link-local name `name` is under a zone the name servers
    /// serve: one in `unicast_local_zones`, or a search domain strictly
    /// under a link-local zone.
    fn served_over_unicast(&self, name: &Name) -> bool {
        let listed = self.unicast_local_zones.iter();
        let searched = self
            .search
            .iter()
            .filter(|domain| is_under_link_local(domain));
        listed.chain(searched).any(|zone| zone.zone_of(name))
    }

    /// How long an attempt in `round` waits for an answer: `timeout`,
    /// doubled for each round through the servers before it, between
    /// [`MIN_WAIT`] and [`MAX_WAIT`].
    pub(crate) fn wait(&self, round: usize) -> Duration {
        let factor = u32::try_from(round)
            .ok()
            .and_then(|round| 1u32.checked_shl(round))
            .unwrap_or(u32::MAX);
        self.timeout
            .max(MIN_WAIT)
            .saturating_mul(factor)
            .min(MAX_WAIT)
    }

    /// How long a server that failed to answer stays failed.
    pub(crate) fn failed_for(&self) -> Duration {
        self.failure_memory.min(MAX_FAILURE_MEMORY)
    }

    /// The shortest and the longest time a resolution failure is cached:
    /// `failure_cache_min` and `failure_cache_max` within the bounds of RFC
    /// 9520 §3.2, the longest no shorter than the shortest.
    pub(crate) fn failure_cache(&self) -> (Duration, Duration) {
        let shortest = self
            .failure_cache_min
            .clamp(MIN_FAILURE_CACHE, MAX_FAILURE_CACHE);
        let longest = self.failure_cache_max.clamp(shortest, MAX_FAILURE_CACHE);
        (shortest, longest)
    }

    pub(crate) fn servers(&self) -> &[SocketAddr] {
        &self.servers
    }

    /// The server at `position` in the rotation: the list repeated
    /// without end.
    #[expect(clippy::indexing_slicing, reason = "servers is never empty")]
    pub(crate) fn server(&self, position: usize) -> SocketAddr {
        self.servers[position % self.servers.len()]
    }
}
