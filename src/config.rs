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
use crate::tls;
use crate::wire::is_special_use;

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
    /// Both; the IPv6 addresses first, as RFC 6724's default policy orders
    /// them on a host with global IPv6.
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

/// Resolver settings.
#[derive(Clone, Debug)]
pub struct Config {
    /// Name servers, tried in order and rotated on each retry. Never empty.
    servers: Vec<SocketAddr>,
    /// How long to wait for a response before retrying. A value too large
    /// to add to an `Instant`, such as `Duration::MAX`, means wait forever.
    pub timeout: Duration,
    /// Total number of attempts per query, across all servers: attempt `n`
    /// goes to server `n` modulo their number. Switching to TCP, dropping
    /// EDNS and resending after a lost connection don't count as one; see
    /// the crate docs on how a query moves on.
    pub attempts: NonZeroUsize,
    /// Domains to try appending to names without a trailing dot, in order.
    /// Empty means every name is used as given.
    pub search: Vec<Name>,
    /// A name with at least this many dots is tried as given before the
    /// search domains; one with fewer, after them. `db` has no dots and
    /// `db.x` has one.
    pub ndots: u8,
    /// How long a stream connection may go without any query on it before
    /// the resolver asks for it to be closed (RFC 7766 §6.2.3), counted
    /// from the last write or read on it.
    pub idle_timeout: Duration,
    /// Static entries answered before DNS, like `/etc/hosts`. Empty by
    /// default; fill it with [`Hosts::parse`].
    pub hosts: Hosts,
    /// Which addresses an [`IpLookup`](crate::IpLookup) asks for, and which
    /// come first. [`IpStrategy::Ipv6First`] by default.
    pub ip_strategy: IpStrategy,
    /// DNS over TLS settings; see `Config::with_tls`.
    #[cfg(feature = "tls")]
    pub(crate) tls: Option<tls::Settings>,
}

impl Config {
    /// `first` and then `more`, two attempts per server, two seconds each.
    pub fn new(first: SocketAddr, more: impl IntoIterator<Item = SocketAddr>) -> Self {
        let servers: Vec<SocketAddr> = std::iter::once(first).chain(more).collect();
        let attempts = NonZeroUsize::new(servers.len() * 2).unwrap_or(NonZeroUsize::MIN);
        Self {
            servers,
            timeout: Duration::from_secs(2),
            attempts,
            search: Vec::new(),
            ndots: 1,
            idle_timeout: Duration::from_secs(10),
            hosts: Hosts::default(),
            ip_strategy: IpStrategy::default(),
            #[cfg(feature = "tls")]
            tls: None,
        }
    }

    /// Send every query over DNS over TLS (RFC 7858), authenticating the
    /// servers as `server_name` with `client` (RFC 8310 strict profile).
    /// Give the servers' TLS addresses, usually port 853. Queries are padded
    /// to a multiple of 128 octets (RFC 8467 §4.1).
    ///
    /// `client` brings its own crypto provider and root certificates. Fails
    /// if rustls can't start a session with it.
    #[cfg(feature = "tls")]
    pub fn with_tls(
        mut self,
        client: Arc<rustls::ClientConfig>,
        server_name: rustls::pki_types::ServerName<'static>,
    ) -> Result<Self, rustls::Error> {
        rustls::ClientConnection::new(Arc::clone(&client), server_name.clone())?;
        self.tls = Some(tls::Settings {
            client,
            server_name,
        });
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
    /// `options attempts:` per server (default 2, at most 5) and
    /// `options no-aaaa` ([`IpStrategy::Ipv4Only`]). Without usable
    /// `nameserver` lines, the local host is asked (127.0.0.1).
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
        let per_server = usize::try_from(parsed.attempts.clamp(1, 5)).unwrap_or(1);
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
        config
    }

    /// The names to try for `name`, in order, as glibc's `res_search` does.
    /// Candidates under special-use zones are left out. Empty when the name
    /// is only tried as given, which needs no list.
    pub(crate) fn candidates(&self, name: &Name) -> VecDeque<Name> {
        if name.is_fqdn() || self.search.is_empty() {
            return VecDeque::new();
        }
        let mut absolute = name.clone();
        absolute.set_fqdn(true);
        let searched = self
            .search
            .iter()
            .filter_map(|domain| name.clone().append_domain(domain).ok())
            .filter(|candidate| !is_special_use(candidate));
        // `num_labels` doesn't count the root label.
        let dots = usize::from(name.num_labels()).saturating_sub(1);
        if dots >= usize::from(self.ndots) {
            std::iter::once(absolute).chain(searched).collect()
        } else {
            searched.chain(std::iter::once(absolute)).collect()
        }
    }

    /// The server for the given attempt, rotating through the list.
    #[expect(clippy::indexing_slicing, reason = "servers is never empty")]
    pub(crate) fn server(&self, attempt: usize) -> SocketAddr {
        self.servers[attempt % self.servers.len()]
    }
}
