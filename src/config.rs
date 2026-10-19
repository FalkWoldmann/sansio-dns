//! Resolver settings, and reading them from a `resolv.conf`.

use std::collections::VecDeque;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV6};
use std::num::NonZeroUsize;
#[cfg(feature = "tls")]
use std::sync::Arc;
use std::time::{Duration, Instant};

use hickory_proto::rr::{Name, RecordType};

use crate::Hosts;
#[cfg(feature = "tls")]
use crate::tls::{self, TlsConfigError};
use crate::wire::{is_link_local, is_special_use, is_under_link_local};

/// Which address families [`Resolver::lookup_ip`] asks for, and the order
/// of its addresses.
///
/// With both families, the addresses of the first come first. Clients that
/// race connections (RFC 8305), such as hyper's, try that family first and
/// the other one shortly after.
///
/// [`Resolver::lookup_ip`]: crate::Resolver::lookup_ip
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
    ///
    /// It is the default even on a host without a global IPv6 address,
    /// such as a container with only a ULA, where `getaddrinfo`'s RFC 6724
    /// sorting puts IPv4 first (§6 rule 5): a client there that tries the
    /// addresses one at a time waits on each IPv6 one. Race the
    /// connections (Happy Eyeballs, RFC 8305), or use
    /// [`IpStrategy::Ipv4First`] on such hosts.
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
    /// Which addresses [`Resolver::lookup_ip`](crate::Resolver::lookup_ip)
    /// asks for, and which come first. [`IpStrategy::Ipv6First`] by
    /// default.
    pub ip_strategy: IpStrategy,
    /// Whether a name of one label, such as `db`, is also tried as given
    /// when there are search domains, which asks the name servers for a
    /// top-level domain. True by default, as in glibc; `options
    /// no-tld-query` (or `no_tld_query`) in a `resolv.conf` turns it off.
    /// Without search domains, such a name is always tried as given.
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
    ///
    /// A server at the unspecified address, `0.0.0.0` or `::`, is the local
    /// host, as for glibc: Linux sends its queries for `nameserver 0.0.0.0`
    /// to the loopback address. No datagram may be sent to the unspecified
    /// address (RFC 1122 §3.2.1.3, RFC 4291 §2.5.2), and the replies would
    /// come from the loopback address and fail the source check (RFC 5452
    /// §9.1), so it is replaced by `127.0.0.1` or `::1`, keeping the port.
    pub fn new(first: SocketAddr, more: impl IntoIterator<Item = SocketAddr>) -> Self {
        let servers: Vec<SocketAddr> = std::iter::once(first)
            .chain(more)
            .map(loopback_if_unspecified)
            .collect();
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
    /// counts. An unspecified address stands for the loopback address, as
    /// in [`Config::new`].
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
        let names = names
            .into_iter()
            .map(|(server, name)| (loopback_if_unspecified(server), name));
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

    /// Settings from the text of a `resolv.conf` file, read the way glibc's
    /// `res_init` reads it. [`Config::from_resolv_conf_with_env`] also
    /// takes what glibc reads from the environment and the host name.
    ///
    /// A line counts only if it starts with its keyword, followed by a
    /// space or a tab: an indented line is ignored, and so is a line that
    /// starts with `#` or `;`. As in glibc, a NUL byte ends its line. It
    /// reads these lines:
    ///
    /// - `nameserver`: the first three usable ones, on port 53. An IPv4
    ///   address may take any form `inet_aton` reads, such as `127.1`,
    ///   `0x7f.0.0.1` or `2130706433`; an IPv6 address may have a decimal
    ///   scope (`fe80::1%2`). Without a usable one, the local host is asked
    ///   (127.0.0.1), and `0.0.0.0` or `::` asks it too (see
    ///   [`Config::new`]).
    /// - `search` and `domain`: the last of them with a word sets the search
    ///   domains, `domain` its first word only. Words that aren't valid
    ///   names are left out after that, so a last line of only such words
    ///   leaves no search domains.
    /// - `options`: `ndots:` (default 1, at most 15), `timeout:` in seconds
    ///   (default 5, 1 to 30), `attempts:` per server (default 2),
    ///   `no-aaaa` ([`IpStrategy::Ipv4Only`]), and `no-tld-query` or
    ///   `no_tld_query` (`tld_query` off). As in glibc, an option is known
    ///   by how it starts, so `no-aaaa-x` is `no-aaaa`, a `-` in front of a
    ///   flag turns it off again (`-no-aaaa`), and a number is read the way
    ///   `strtol` reads it: `ndots:2x` and `ndots: 2` are 2, and `ndots:x`
    ///   is 0. On a 64-bit system glibc then keeps only the low 32 bits of
    ///   the number, so `ndots:4294967298` is 2 there; here it is 15.
    ///
    /// Unlike glibc, later rounds through the servers wait longer; see
    /// `timeout`. Where glibc takes up to 5 attempts per server, this takes
    /// at most 3, since RFC 9520 §3.1 allows no more than three sends of a
    /// query to a server over one transport, and at least 1, where glibc
    /// would send nothing. A negative `ndots` counts as 0, where glibc keeps
    /// its low four bits (-2 is 14). And unlike glibc, which reads `#` and
    /// `;` as a comment only at the start of a line and a carriage return
    /// as part of the last word, it reads the rest of a line from a `#` or
    /// `;` on as a comment, and takes lines that end in CRLF.
    ///
    /// Like glibc, it never fails: lines and options it can't use are
    /// skipped. So is a server whose scope isn't a decimal number that fits
    /// in 32 bits: an empty, signed or too large one, or an interface name
    /// (`fe80::1%eth0`), which would take a system call to map to its
    /// index. glibc keeps such a server: for an address of interface-local
    /// or link-local scope it maps an interface name to its index, and a
    /// scope it can't read becomes 0. Other options, such as `rotate`,
    /// `use-vc` and `edns0` (EDNS is always on), are ignored, and so are
    /// `sortlist` lines.
    pub fn from_resolv_conf(text: &[u8]) -> Self {
        Self::from_resolv_conf_with_env(text, &ResolvEnv::default())
    }

    /// [`Config::from_resolv_conf`], with what glibc's `res_init` also reads
    /// from the process and the host, in [`ResolvEnv`]:
    ///
    /// - `LOCALDOMAIN` replaces the file's `search` and `domain` lines, even
    ///   when it is empty: its words, separated by spaces or tabs up to the
    ///   first newline, are the search domains, leaving out any that aren't
    ///   valid names.
    /// - Without it and without a `search` or `domain` line with a word, the
    ///   search domain is the host name's domain, the part after its first
    ///   dot, if that is a valid name. A host name without a dot, or whose
    ///   first dot ends it, gives none.
    /// - `RES_OPTIONS` holds options as an `options` line does, applied
    ///   after the file's, so they win.
    pub fn from_resolv_conf_with_env(text: &[u8], env: &ResolvEnv) -> Self {
        let parsed = ResolvConf::parse(text, env);
        // glibc's MAXNS: later servers are ignored.
        let mut servers = parsed.servers.into_iter().take(3);
        let first = servers
            .next()
            .unwrap_or_else(|| SocketAddr::from((Ipv4Addr::LOCALHOST, 53)));
        let mut config = Self::new(first, servers);
        let options = parsed.options;
        // 30 is glibc's RES_MAXRETRANS.
        config.timeout = Duration::from_secs(options.timeout.clamp(1, 30).unsigned_abs());
        // At most MAX_SENDS_PER_SERVER, not glibc's RES_MAXRETRY (5).
        let per_server =
            usize::try_from(options.attempts.clamp(1, MAX_SENDS_PER_SERVER.into())).unwrap_or(1);
        config.attempts =
            NonZeroUsize::new(per_server * config.servers.len()).unwrap_or(NonZeroUsize::MIN);
        config.search = parsed.search.into_iter().filter_map(domain).collect();
        // 15 is glibc's RES_MAXNDOTS.
        config.ndots = u8::try_from(options.ndots.clamp(0, 15)).unwrap_or(15);
        if options.no_aaaa {
            config.ip_strategy = IpStrategy::Ipv4Only;
        }
        config.tld_query = !options.no_tld_query;
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

    /// When an attempt in `round` started at `now` times out: [`Config::wait`]
    /// for `round` after `now`, or `now` itself if that overflows.
    pub(crate) fn deadline(&self, round: usize, now: Instant) -> Instant {
        // Only an `Instant` within minutes of the end of its range
        // overflows; the attempt then times out at once.
        now.checked_add(self.wait(round)).unwrap_or(now)
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

/// `server`, with the unspecified address replaced by the loopback address
/// of its family, keeping the port; see [`Config::new`].
fn loopback_if_unspecified(mut server: SocketAddr) -> SocketAddr {
    if server.ip().is_unspecified() {
        server.set_ip(match server {
            SocketAddr::V4(_) => IpAddr::V4(Ipv4Addr::LOCALHOST),
            SocketAddr::V6(_) => IpAddr::V6(Ipv6Addr::LOCALHOST),
        });
    }
    server
}

/// What glibc's `res_init` reads besides `resolv.conf`, for
/// [`Config::from_resolv_conf_with_env`]: two environment variables and
/// the host name, each `None` when unset. Each ends at its first NUL byte,
/// as the C string glibc reads does. The resolver reads none of them
/// itself; a driver fills this in.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct ResolvEnv {
    /// The `LOCALDOMAIN` environment variable: search domains, separated by
    /// spaces or tabs, that replace the file's `search` and `domain` lines.
    /// Only the text before the first newline counts.
    pub localdomain: Option<Vec<u8>>,
    /// The `RES_OPTIONS` environment variable: options as on an `options`
    /// line, applied after the file's.
    pub res_options: Option<Vec<u8>>,
    /// The host name, as `gethostname` returns it. Its domain, the part
    /// after the first dot, is the search domain when there is neither
    /// `LOCALDOMAIN` nor a `search` or `domain` line with a word.
    pub hostname: Option<Vec<u8>>,
}

/// What glibc's `res_init` takes from a `resolv.conf` and a [`ResolvEnv`],
/// before it becomes a [`Config`].
struct ResolvConf<'a> {
    /// Every usable `nameserver` line, in order.
    servers: Vec<SocketAddr>,
    /// The search domains, as words not yet checked to be names.
    search: Vec<&'a [u8]>,
    options: Options,
}

impl<'a> ResolvConf<'a> {
    /// Read `text` and `env` in the stages of glibc's `res_vinit_1`:
    ///
    /// 1. `LOCALDOMAIN`, which sets the search domains even without a word
    ///    ([`search_list`]).
    /// 2. The file, a line at a time ([`lines`]): `domain` and `search`
    ///    lines ([`line_domains`]), `nameserver` lines ([`nameserver`]) and
    ///    `options` lines (`res_setoptions`, [`Options::apply`]). glibc
    ///    then adds the local host if no server was read; here
    ///    [`Config::from_resolv_conf_with_env`] does that.
    /// 3. Unless `LOCALDOMAIN` or a line set the search domains, the host
    ///    name's domain (`domain_from_hostname`, [`host_domain`]).
    /// 4. `RES_OPTIONS` (`res_setoptions`).
    ///
    /// Besides the differences its helpers' docs note (comments and line ends
    /// in [`lines`], scopes in [`nameserver`], numbers outside an `int` in
    /// [`Options`]), it leaves out an empty search domain glibc keeps:
    ///
    /// - One in front of `LOCALDOMAIN`'s words, when its text up to the
    ///   first newline is empty or starts with a space or a tab.
    /// - The domain of a host name whose first dot ends it (`host.`).
    fn parse(text: &'a [u8], env: &'a ResolvEnv) -> Self {
        // LOCALDOMAIN replaces the file's `domain` and `search` lines. glibc
        // skips them when `LOCALDOMAIN` is set (`haveenv`); here they are
        // read and lose to it below, with the same result.
        let localdomain = env.localdomain.as_deref().map(search_list);
        let mut servers = Vec::new();
        let mut search = None;
        let mut options = Options::default();
        // The keywords in glibc's order. `sortlist`, which glibc also reads,
        // is ignored, and so is every other line.
        for line in lines(text) {
            if let Some(rest) = keyword(line, b"domain") {
                search = line_domains(words(rest).take(1)).or(search);
            } else if let Some(rest) = keyword(line, b"search") {
                search = line_domains(words(rest)).or(search);
            } else if let Some(rest) = keyword(line, b"nameserver") {
                servers.extend(words(rest).next().and_then(nameserver));
            } else if let Some(rest) = keyword(line, b"options") {
                options.apply(rest);
            }
        }
        let search = localdomain.or(search).unwrap_or_else(|| {
            let hostname = env.hostname.as_deref();
            hostname.and_then(host_domain).into_iter().collect()
        });
        if let Some(text) = env.res_options.as_deref() {
            options.apply(c_str(text));
        }
        Self {
            servers,
            search,
            options,
        }
    }
}

/// The options glibc's `res_setoptions` reads, with its defaults. glibc
/// caps each number from above as it stores it; here the numbers stay as
/// [`strtol`] read them, and [`Config::from_resolv_conf_with_env`] limits
/// them once, to the bounds [`Config::from_resolv_conf`] lists (the lower
/// bounds and the cap of 3 on `attempts` are this crate's own). Limiting
/// once at the end gives what limiting each would, since only the last
/// number of each kind counts.
/// The number as read differs from glibc's only outside the range of an
/// `int`: glibc stores `strtol`'s `long` in an `int`, which on a 64-bit
/// system keeps only its low 32 bits (4294967298 is 2 there).
#[derive(Clone, Copy, Debug)]
struct Options {
    ndots: i64,
    timeout: i64,
    attempts: i64,
    no_aaaa: bool,
    no_tld_query: bool,
}

impl Default for Options {
    fn default() -> Self {
        Self {
            ndots: 1,
            timeout: 5,
            attempts: 2,
            no_aaaa: false,
            no_tld_query: false,
        }
    }
}

impl Options {
    /// Apply the options in `text`, the rest of an `options` line or
    /// `RES_OPTIONS`, as `res_setoptions` does: an option starts after a
    /// run of spaces or tabs and is known by how it starts, its number is
    /// read by `strtol` from there on (which may read past the option's
    /// end), and a `-` in front of a flag turns it off.
    fn apply(&mut self, mut text: &[u8]) {
        loop {
            text = text
                .get(text.iter().take_while(|&&byte| is_blank(byte)).count()..)
                .unwrap_or_default();
            if text.is_empty() {
                return;
            }
            if let Some(number) = text.strip_prefix(b"ndots:") {
                self.ndots = strtol(number);
            } else if let Some(number) = text.strip_prefix(b"timeout:") {
                self.timeout = strtol(number);
            } else if let Some(number) = text.strip_prefix(b"attempts:") {
                self.attempts = strtol(number);
            } else {
                let (on, flag) = text
                    .strip_prefix(b"-")
                    .map_or((true, text), |flag| (false, flag));
                if flag.starts_with(b"no-aaaa") {
                    self.no_aaaa = on;
                } else if flag.starts_with(b"no-tld-query") || flag.starts_with(b"no_tld_query") {
                    self.no_tld_query = on;
                }
            }
            let end = text.iter().take_while(|&&byte| !is_blank(byte)).count();
            text = text.get(end..).unwrap_or_default();
        }
    }
}

/// The lines of `text`, as the keywords see them. As glibc does, it splits
/// `text` at each newline (`getline`) and ends a line at its first NUL
/// byte, where the C string glibc reads ends. Unlike glibc, it then strips
/// one carriage return from the end, so lines may end in CRLF, and cuts the
/// line at its first `#` or `;`, so a comment may follow a word; glibc
/// skips only a line that starts with one.
fn lines(text: &[u8]) -> impl Iterator<Item = &[u8]> {
    text.split(|&byte| byte == b'\n').map(|line| {
        let line = c_str(line);
        let line = line.strip_suffix(b"\r").unwrap_or(line);
        line.split(|&byte| byte == b'#' || byte == b';')
            .next()
            .unwrap_or_default()
    })
}

/// Whether `byte` separates words on a `resolv.conf` line, as for glibc.
fn is_blank(byte: u8) -> bool {
    byte == b' ' || byte == b'\t'
}

/// The words of `text`, separated by runs of spaces and tabs.
fn words(text: &[u8]) -> impl Iterator<Item = &[u8]> {
    text.split(|&byte| is_blank(byte))
        .filter(|word| !word.is_empty())
}

/// The rest of `line` after `keyword`, if the line starts with it and a
/// space or a tab follows, as glibc's `MATCH` asks.
fn keyword<'a>(line: &'a [u8], keyword: &[u8]) -> Option<&'a [u8]> {
    let rest = line.strip_prefix(keyword)?;
    rest.first()
        .is_some_and(|&byte| is_blank(byte))
        .then_some(rest)
}

/// `bytes` up to its first NUL byte, where a C string ends.
fn c_str(bytes: &[u8]) -> &[u8] {
    bytes.split(|&byte| byte == 0).next().unwrap_or_default()
}

/// The search domains in `LOCALDOMAIN`: its words, up to the first newline
/// of its C string. Empty when it has none.
fn search_list(localdomain: &[u8]) -> Vec<&[u8]> {
    let text = c_str(localdomain)
        .split(|&byte| byte == b'\n')
        .next()
        .unwrap_or_default();
    words(text).collect()
}

/// The search domains that a `domain` or `search` line with `line_words`
/// sets, or `None` for a line without a word, which glibc skips: it keeps
/// the search domains set before it.
fn line_domains<'a>(line_words: impl Iterator<Item = &'a [u8]>) -> Option<Vec<&'a [u8]>> {
    let domains: Vec<&[u8]> = line_words.collect();
    (!domains.is_empty()).then_some(domains)
}

/// The domain of `hostname`: the part after its first dot, unless empty.
fn host_domain(hostname: &[u8]) -> Option<&[u8]> {
    let hostname = c_str(hostname);
    let dot = hostname.iter().position(|&byte| byte == b'.')?;
    hostname.get(dot + 1..).filter(|domain| !domain.is_empty())
}

/// `word` as an absolute search domain, if it is a valid name.
fn domain(word: &[u8]) -> Option<Name> {
    let mut domain = Name::from_ascii(std::str::from_utf8(word).ok()?).ok()?;
    domain.set_fqdn(true);
    Some(domain)
}

/// The server on a `nameserver` line whose address is `word`, on port 53,
/// as glibc reads it: an IPv4 address in any form `inet_aton` takes, or
/// else an IPv6 address with an optional scope after `%`. Unlike glibc,
/// it skips a server whose scope isn't a decimal number that fits in 32
/// bits: an empty, signed or too large one, or an interface name
/// (`fe80::1%eth0`), which would take a system call to map to its index.
/// glibc keeps such a server (`__inet6_scopeid_pton`): for an address of
/// interface-local or link-local scope it maps an interface name to its
/// index, and a scope it can't read becomes 0.
fn nameserver(word: &[u8]) -> Option<SocketAddr> {
    if let Some(address) = inet_aton(word) {
        return Some(SocketAddr::from((address, 53)));
    }
    let mut parts = word.splitn(2, |&byte| byte == b'%');
    let address: Ipv6Addr = std::str::from_utf8(parts.next()?).ok()?.parse().ok()?;
    let scope = match parts.next() {
        None => 0,
        Some(scope) if !scope.is_empty() && scope.iter().all(u8::is_ascii_digit) => {
            std::str::from_utf8(scope).ok()?.parse().ok()?
        }
        Some(_) => return None,
    };
    Some(SocketAddr::V6(SocketAddrV6::new(address, 53, 0, scope)))
}

/// `text` as an IPv4 address in any form glibc's `inet_aton` reads, with
/// nothing after it (`__inet_aton_exact`): one to four numbers separated
/// by dots, each as [`c_number`] reads it, the last one filling the bytes
/// the others leave. So `127.1` is 127.0.0.1, `1.2.3` is 1.2.0.3, and
/// `16843009` is 1.1.1.1.
fn inet_aton(text: &[u8]) -> Option<Ipv4Addr> {
    let mut leading = [0u32; 3];
    let mut count = 0;
    let mut rest = text;
    let last = loop {
        let (number, after) = c_number(rest)?;
        match after.split_first() {
            None => break number,
            Some((b'.', next)) if number <= 0xff => {
                *leading.get_mut(count)? = number;
                count += 1;
                rest = next;
            }
            Some(_) => return None,
        }
    };
    if last > u32::MAX >> (8 * count) {
        return None;
    }
    let address = leading
        .iter()
        .take(count)
        .enumerate()
        .fold(last, |address, (i, byte)| address | byte << (24 - 8 * i));
    Some(Ipv4Addr::from(address))
}

/// The number that `text` starts with, as `strtoul` reads it in base 0,
/// and the rest of `text`: hexadecimal after `0x` or `0X`, octal after a
/// leading `0`, decimal otherwise. `None` unless `text` starts with a
/// digit and the number fits in 32 bits.
fn c_number(text: &[u8]) -> Option<(u32, &[u8])> {
    let (radix, digits) = match text {
        [b'0', b'x' | b'X', rest @ ..] if rest.first().is_some_and(u8::is_ascii_hexdigit) => {
            (16, rest)
        }
        [b'0', ..] => (8, text),
        [first, ..] if first.is_ascii_digit() => (10, text),
        _ => return None,
    };
    let len = digits
        .iter()
        .take_while(|&&byte| char::from(byte).is_digit(radix))
        .count();
    let (number, rest) = digits.split_at_checked(len)?;
    let value = number.iter().try_fold(0u32, |value, &byte| {
        let digit = char::from(byte).to_digit(radix)?;
        value.checked_mul(radix)?.checked_add(digit)
    })?;
    Some((value, rest))
}

/// The number that `text` starts with, as C's `strtol` reads it in base
/// 10: after any white space, an optional sign and the digits; 0 without
/// digits. It saturates at `i64::MAX`, and at `-i64::MAX` for a negative
/// number, one above C's `LONG_MIN`, which the limits on the options hide.
fn strtol(text: &[u8]) -> i64 {
    let space = |byte: &&u8| matches!(byte, b' ' | b'\t' | b'\n' | b'\x0b' | b'\x0c' | b'\r');
    let text = text
        .get(text.iter().take_while(space).count()..)
        .unwrap_or_default();
    let (negative, digits) = match text.split_first() {
        Some((b'-', rest)) => (true, rest),
        Some((b'+', rest)) => (false, rest),
        _ => (false, text),
    };
    let value =
        digits
            .iter()
            .take_while(|byte| byte.is_ascii_digit())
            .fold(0i64, |value, &digit| {
                value
                    .saturating_mul(10)
                    .saturating_add(i64::from(digit - b'0'))
            });
    if negative {
        value.saturating_neg()
    } else {
        value
    }
}
