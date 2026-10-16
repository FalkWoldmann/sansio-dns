//! A sans-IO DNS stub resolver built on [`hickory_proto`].
//!
//! [`Resolver`] owns no sockets, timers or tasks. The caller drives it:
//!
//! 1. Start a lookup with [`Resolver::query`].
//! 2. Send everything returned by [`Resolver::poll_transmit`], over the
//!    [`Transport`] it names.
//! 3. Feed received datagrams to [`Resolver::handle_datagram`], and bytes
//!    read from TCP connections to [`Resolver::handle_stream_data`].
//! 4. Call [`Resolver::handle_timeout`] once the instant from
//!    [`Resolver::poll_timeout`] has passed.
//! 5. Collect results from [`Resolver::poll_event`].
//!
//! Queries go over UDP. A truncated response switches that query to TCP,
//! as RFC 7766 §5 requires. Special-use names never reach the network; see
//! [`Resolver::query`].
//!
//! For hostnames, [`IpLookup`] runs the A and AAAA queries and collects the
//! addresses, following CNAMEs.
//!
//! With the `tls` feature, `Config::with_tls` sends every query over DNS
//! over TLS (RFC 7858) instead.
//!
//! # Driver obligations
//!
//! Stream connections (TCP, and TLS on top of it) are named by a
//! [`ConnectionId`]. For [`Transport::TcpConnect`], open a TCP connection to
//! the destination under that id and write the payload; for
//! [`Transport::TcpWrite`], write the payload to that connection; for
//! [`Transport::TcpClose`], close it. Pass everything read from a connection
//! to [`Resolver::handle_stream_data`], and call
//! [`Resolver::handle_stream_closed`] when it ends or fails on its own.
//! Payloads are already length-prefixed (RFC 7766 §8) or TLS-encrypted.
//!
//! The resolver keeps one connection per server open and sends further
//! queries over it, several at a time (RFC 7766 §6.2.1, RFC 7858 §3.4). It
//! asks for the connection to be closed once it has been idle for
//! [`Config::idle_timeout`], or when a query on it times out.
//!
//! For UDP, [RFC 5452 §9.2] requires an unpredictable source port, and a
//! different one for each outstanding query. The resolver can't choose
//! ports, so the driver must bind a fresh ephemeral socket per query
//! ([`Transport::Udp`] names it) and pass that query along with every
//! datagram the socket receives to [`Resolver::handle_datagram`]. The
//! resolver checks everything else §9.1 asks for: source address and port,
//! message ID and question.
//!
//! [RFC 5452 §9.2]: https://rfc-annotations.research.icann.org/rfc5452.html

use std::collections::{BTreeMap, VecDeque};
use std::fmt;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV6};
use std::num::NonZeroUsize;
use std::time::{Duration, Instant};

pub use hickory_proto;
use hickory_proto::ProtoError;
use hickory_proto::op::{Edns, Message, MessageType, OpCode, Query, ResponseCode};
use hickory_proto::rr::domain::usage::{INVALID, LOCAL, LOCALHOST, ONION};
#[cfg(feature = "tls")]
use hickory_proto::rr::rdata::opt::EdnsOption;
use hickory_proto::rr::rdata::{A, AAAA};
use hickory_proto::rr::{Name, RData, Record, RecordType};

mod hosts;
mod lookup;
pub use hosts::Hosts;
pub use lookup::{IpLookup, Progress, addresses};
#[cfg(feature = "tls")]
mod tls;
#[cfg(feature = "tls")]
pub use rustls;
#[cfg(feature = "tls")]
use std::sync::Arc;

/// EDNS UDP payload size recommended by DNS Flag Day 2020.
const EDNS_PAYLOAD: u16 = 1232;

/// Resolver settings.
#[derive(Clone, Debug)]
pub struct Config {
    /// Name servers, tried in order and rotated on each retry. Never empty.
    servers: Vec<SocketAddr>,
    /// How long to wait for a response before retrying. A value too large
    /// to add to an `Instant`, such as `Duration::MAX`, means wait forever.
    pub timeout: Duration,
    /// Total number of attempts per query, across all servers. Switching to
    /// TCP or dropping EDNS doesn't count as one.
    pub attempts: NonZeroUsize,
    /// Domains to try appending to names without a trailing dot, in order.
    /// Empty means every name is used as given.
    pub search: Vec<Name>,
    /// A name with at least this many dots is tried as given before the
    /// search domains; one with fewer, after them.
    pub ndots: u8,
    /// How long a stream connection may sit without queries before the
    /// resolver asks for it to be closed (RFC 7766 §6.2.3).
    pub idle_timeout: Duration,
    /// Static entries answered before DNS, like `/etc/hosts`. Empty by
    /// default; fill it with [`Hosts::parse`].
    pub hosts: Hosts,
    /// DNS over TLS settings; see `Config::with_tls`.
    #[cfg(feature = "tls")]
    tls: Option<tls::Settings>,
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
    fn uses_tls(&self) -> bool {
        #[cfg(feature = "tls")]
        return self.tls.is_some();
        #[cfg(not(feature = "tls"))]
        false
    }

    /// Settings from the text of a `resolv.conf` file, read the way glibc
    /// reads it: `nameserver` lines (port 53), `search` or `domain`,
    /// `options ndots:` (at most 15), `options timeout:` in seconds (at most
    /// 30) and `options attempts:` per server (at most 5). Without
    /// usable `nameserver` lines, the local host is asked (127.0.0.1).
    ///
    /// A link-local server with a named scope (`fe80::1%eth0`) is skipped,
    /// since mapping an interface name to its index needs a system call;
    /// numeric scopes (`fe80::1%2`) work. Other options, such as `rotate`,
    /// `use-vc` and `edns0` (EDNS is always on), are ignored.
    pub fn from_resolv_conf(text: &[u8]) -> Result<Self, resolv_conf::ParseError> {
        let parsed = resolv_conf::Config::parse(text)?;
        let mut servers = parsed.nameservers.iter().filter_map(|ip| match ip {
            resolv_conf::ScopedIp::V4(v4) => Some(SocketAddr::from((*v4, 53))),
            resolv_conf::ScopedIp::V6(v6, None) => Some(SocketAddr::from((*v6, 53))),
            resolv_conf::ScopedIp::V6(v6, Some(scope)) => scope
                .parse()
                .ok()
                .map(|id| SocketAddr::V6(SocketAddrV6::new(*v6, 53, 0, id))),
        });
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
        Ok(config)
    }

    /// The names to try for `name`, in order, as glibc's `res_search` does.
    /// Candidates under special-use zones are left out.
    fn candidates(&self, name: &Name) -> VecDeque<Name> {
        let mut absolute = name.clone();
        absolute.set_fqdn(true);
        if name.is_fqdn() || self.search.is_empty() {
            return VecDeque::from([absolute]);
        }
        let searched = self
            .search
            .iter()
            .filter_map(|domain| name.clone().append_domain(domain).ok())
            .filter(|candidate| !is_special_use(candidate));
        let dots = usize::from(name.num_labels()).saturating_sub(1);
        if dots >= usize::from(self.ndots) {
            std::iter::once(absolute).chain(searched).collect()
        } else {
            searched.chain(std::iter::once(absolute)).collect()
        }
    }

    /// The server for the given attempt, rotating through the list.
    #[expect(clippy::indexing_slicing, reason = "servers is never empty")]
    fn server(&self, attempt: usize) -> SocketAddr {
        self.servers[attempt % self.servers.len()]
    }
}

/// Handle for an in-flight query.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct QueryId(u64);

/// Handle for a stream connection; see the crate docs.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ConnectionId(u64);

/// How a [`Transmit`] must be sent.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Transport {
    /// As one UDP datagram, from the socket bound for this query.
    Udp(QueryId),
    /// Open a new TCP connection to the destination, named by this id, and
    /// write the payload.
    TcpConnect(ConnectionId),
    /// Write the payload to this open connection.
    TcpWrite(ConnectionId),
    /// Close this connection. The payload is empty.
    TcpClose(ConnectionId),
}

/// Something the caller must do on the network.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Transmit {
    /// How to send it, and which socket or connection it belongs to.
    pub transport: Transport,
    /// The name server to send it to.
    pub destination: SocketAddr,
    /// The bytes to send: a DNS message, length-prefixed or TLS-encrypted
    /// on streams.
    pub payload: Vec<u8>,
}

/// Outcome of a query.
#[derive(Debug)]
pub enum Event {
    /// A server answered. `NXDOMAIN` and empty answers arrive here too;
    /// inspect `response.metadata.response_code`.
    Response {
        /// The query that completed.
        query: QueryId,
        /// The server's answer.
        response: Message,
    },
    /// The query gave up.
    Failed {
        /// The query that failed.
        query: QueryId,
        /// Why it failed.
        error: Error,
    },
}

/// Why a query failed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    /// No server answered within the configured attempts.
    Timeout,
    /// The last TCP connection closed before a complete response arrived.
    ConnectionClosed,
    /// The last TLS session failed, for example on an invalid certificate.
    /// Only with the `tls` feature.
    Tls(String),
    /// The last server answered with this error code (e.g. `SERVFAIL`).
    Server(ResponseCode),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Timeout => f.write_str("no response from any name server"),
            Self::ConnectionClosed => f.write_str("connection closed before a response"),
            Self::Tls(error) => write!(f, "TLS failed: {error}"),
            Self::Server(code) => write!(f, "name server returned {code}"),
        }
    }
}

impl std::error::Error for Error {}

#[derive(Debug)]
struct Pending {
    request: Message,
    payload: Vec<u8>,
    attempt: usize,
    server: SocketAddr,
    /// `None` if `now + timeout` overflows: the query then waits forever.
    deadline: Option<Instant>,
    route: Route,
    /// Search candidates still to try if this name doesn't exist.
    rest: VecDeque<Name>,
}

/// How a query's current attempt travels.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Route {
    /// As a datagram, from the query's own socket.
    Udp,
    /// Over a stream: after a truncated UDP answer, or always with DNS over
    /// TLS. Names the connection once the attempt has been written to one.
    Stream(Option<ConnectionId>),
}

/// A stream connection to one server, shared by its queries.
#[derive(Debug)]
struct Connection {
    server: SocketAddr,
    /// Decrypted bytes not yet split into messages.
    received: Vec<u8>,
    /// When it last carried data; the idle timeout counts from here once
    /// no query uses it.
    last_active: Instant,
    /// The TLS session, when using DNS over TLS.
    #[cfg(feature = "tls")]
    tls: Option<Box<rustls::ClientConnection>>,
}

/// Prefix `message` with its two-byte length (RFC 7766 §8).
fn frame(message: &[u8]) -> Vec<u8> {
    // A single-question query stays below 500 octets, far from the limit.
    let len = u16::try_from(message.len()).unwrap_or(u16::MAX);
    [&len.to_be_bytes()[..], message].concat()
}

/// Pad `request` with an EDNS padding option so it encodes to a multiple of
/// 128 octets (RFC 8467 §4.1, RFC 7830). The option adds 4 octets of header.
#[cfg(feature = "tls")]
fn pad(request: &mut Message) -> Result<(), ProtoError> {
    let unpadded = request.to_vec()?.len();
    let fill = (128 - (unpadded + 4) % 128) % 128;
    if let Some(edns) = &mut request.edns {
        edns.options_mut()
            .insert(EdnsOption::Unknown(12, vec![0; fill]));
    }
    Ok(())
}

/// Remove and return the first complete length-prefixed message in `buf`.
fn next_frame(buf: &mut Vec<u8>) -> Option<Vec<u8>> {
    let (len, rest) = buf.split_first_chunk::<2>()?;
    let message = rest.get(..usize::from(u16::from_be_bytes(*len)))?.to_vec();
    buf.drain(..2 + message.len());
    Some(message)
}

/// Whether `name` is under a zone that must not reach a unicast server.
fn is_special_use(name: &Name) -> bool {
    [&LOCALHOST, &INVALID, &LOCAL, &ONION]
        .iter()
        .any(|z| z.name().zone_of(name))
}

/// The local answer for a special-use name, or `None` for any other name.
fn special_use(name: &Name, record_type: RecordType) -> Option<Message> {
    if !is_special_use(name) {
        return None;
    }
    let localhost = LOCALHOST.name().zone_of(name);
    let mut response = Message::response(0, OpCode::Query);
    response.add_query(Query::query(name.clone(), record_type));
    response.metadata.response_code = if localhost {
        ResponseCode::NoError
    } else {
        ResponseCode::NXDomain
    };
    let loopback = match record_type {
        RecordType::A if localhost => Some(RData::A(A(Ipv4Addr::LOCALHOST))),
        RecordType::AAAA if localhost => Some(RData::AAAA(AAAA(Ipv6Addr::LOCALHOST))),
        _ => None,
    };
    response
        .answers
        .extend(loopback.map(|data| Record::from_rdata(name.clone(), 0, data)));
    Some(response)
}

/// Whether `response` answers `request` (RFC 5452 §9.1, RFC 1035 §7.3).
fn is_reply(request: &Message, response: &Message) -> bool {
    response.metadata.message_type == MessageType::Response
        && request.metadata.id == response.metadata.id
        && request.metadata.op_code == response.metadata.op_code
        && request.queries == response.queries
}

/// The resolver state machine. See the crate docs for how to drive it.
#[derive(Debug)]
pub struct Resolver {
    config: Config,
    next_query: u64,
    pending: BTreeMap<QueryId, Pending>,
    next_connection: u64,
    connections: BTreeMap<ConnectionId, Connection>,
    transmits: VecDeque<Transmit>,
    events: VecDeque<Event>,
}

impl Resolver {
    /// A resolver with no queries in flight.
    pub fn new(config: Config) -> Self {
        Self {
            config,
            next_query: 0,
            pending: BTreeMap::new(),
            next_connection: 0,
            connections: BTreeMap::new(),
            transmits: VecDeque::new(),
            events: VecDeque::new(),
        }
    }

    /// Start a recursive lookup of `name`/`record_type`.
    ///
    /// A name ending in a dot is used as given. Other names are tried with
    /// the [`Config::search`] domains, ordered by [`Config::ndots`]; the next
    /// candidate is tried while the answer is NXDOMAIN, and the event carries
    /// the last answer. Without search domains, `example.com` and
    /// `example.com.` are the same query.
    ///
    /// Special-use names are answered at once, without a transmit:
    /// `localhost` gets the loopback address (RFC 6761 §6.3), and names
    /// under `invalid.`, `local.` and `onion.` get NXDOMAIN (RFC 6761 §6.4,
    /// RFC 6762 §3, RFC 7686 §2). Resolve `.local` names with mDNS instead.
    ///
    /// Names listed in [`Config::hosts`] are answered from there for A and
    /// AAAA queries, with the addresses of that family (possibly none), as
    /// glibc's `hosts: files dns` does. The name is matched as given, before
    /// any search domain.
    pub fn query(
        &mut self,
        name: Name,
        record_type: RecordType,
        now: Instant,
    ) -> Result<QueryId, ProtoError> {
        let mut candidates = self.config.candidates(&name);
        let mut absolute = name;
        absolute.set_fqdn(true);
        let id = QueryId(self.next_query);
        self.next_query += 1;
        let local = special_use(&absolute, record_type)
            .or_else(|| self.config.hosts.answer(&absolute, record_type));
        if let Some(response) = local {
            self.events.push_back(Event::Response {
                query: id,
                response,
            });
            return Ok(id);
        }
        let first = candidates.pop_front().unwrap_or(absolute);
        let pending = self.new_pending(first, record_type, candidates, now)?;
        self.pending.insert(id, pending);
        self.emit(id, now);
        Ok(id)
    }

    /// A fresh first attempt for `name`, with its own message ID.
    fn new_pending(
        &self,
        name: Name,
        record_type: RecordType,
        rest: VecDeque<Name>,
        now: Instant,
    ) -> Result<Pending, ProtoError> {
        let mut request = self.new_message();
        request.metadata.recursion_desired = true;
        request.add_query(Query::query(name, record_type));
        let mut edns = Edns::new();
        edns.set_max_payload(EDNS_PAYLOAD);
        request.set_edns(edns);
        #[cfg(feature = "tls")]
        if self.config.uses_tls() {
            pad(&mut request)?;
        }
        let payload = request.to_vec()?;
        Ok(Pending {
            request,
            payload,
            attempt: 0,
            server: self.config.server(0),
            deadline: now.checked_add(self.config.timeout),
            route: if self.config.uses_tls() {
                Route::Stream(None)
            } else {
                Route::Udp
            },
            rest,
        })
    }

    /// Replace `id`'s attempt with one for its next search candidate.
    /// Returns `false` if there is none, so the current answer stands.
    fn next_candidate(&mut self, id: QueryId, now: Instant) -> bool {
        let Some((name, rest, record_type)) = self.pending.get_mut(&id).and_then(|p| {
            let record_type = p.request.queries.first()?.query_type();
            let name = p.rest.pop_front()?;
            Some((name, std::mem::take(&mut p.rest), record_type))
        }) else {
            return false;
        };
        let Ok(next) = self.new_pending(name, record_type, rest, now) else {
            return false;
        };
        self.pending.insert(id, next);
        self.emit(id, now);
        true
    }

    /// Process a datagram received from `from` on the socket of `query`,
    /// the one its [`Transport::Udp`] transmits were sent from.
    ///
    /// Datagrams that aren't a response to that query (wrong source address,
    /// message ID, opcode or question, RFC 5452 §9.1 and RFC 1035 §7.3) are
    /// ignored, so spoofed or late responses can't complete it. Naming the
    /// socket keeps each query's source port its own (§9.2). Once the query
    /// has switched to TCP, UDP replies to it are ignored too.
    pub fn handle_datagram(&mut self, query: QueryId, from: SocketAddr, data: &[u8], now: Instant) {
        let Ok(response) = Message::from_vec(data) else {
            return;
        };
        let Some(pending) = self.pending.get(&query) else {
            return;
        };
        if pending.route != Route::Udp
            || pending.server != from
            || !is_reply(&pending.request, &response)
        {
            return;
        }
        self.handle_response(query, response, now);
    }

    /// Process bytes read from `connection`.
    ///
    /// Bytes may arrive in any chunking, and answers in any order: each
    /// complete message goes to the query on this connection it answers,
    /// and is ignored if there is none (RFC 7766 §6.2.1.1). Over TLS, the
    /// bytes go through the session first, which may queue a
    /// [`Transport::TcpWrite`]; a TLS error closes the connection and moves
    /// its queries on to their next attempt.
    pub fn handle_stream_data(&mut self, connection: ConnectionId, data: &[u8], now: Instant) {
        let Some(conn) = self.connections.get_mut(&connection) else {
            return;
        };
        conn.last_active = now;
        #[cfg(feature = "tls")]
        let decrypted;
        #[cfg(feature = "tls")]
        let data = match &mut conn.tls {
            None => data,
            Some(session) => match tls::receive(session, data) {
                Ok((reply, plaintext)) => {
                    if !reply.is_empty() {
                        self.transmits.push_back(Transmit {
                            transport: Transport::TcpWrite(connection),
                            destination: conn.server,
                            payload: reply,
                        });
                    }
                    decrypted = plaintext;
                    &decrypted[..]
                }
                Err(error) => {
                    self.close(connection, now, &Error::Tls(error));
                    return;
                }
            },
        };
        conn.received.extend_from_slice(data);
        let mut messages = Vec::new();
        while let Some(message) = next_frame(&mut conn.received) {
            messages.push(message);
        }
        for message in messages {
            let Ok(response) = Message::from_vec(&message) else {
                continue;
            };
            let id = self
                .pending
                .iter()
                .find(|(_, p)| {
                    p.route == Route::Stream(Some(connection)) && is_reply(&p.request, &response)
                })
                .map(|(id, _)| *id);
            if let Some(id) = id {
                self.handle_response(id, response, now);
            }
        }
    }

    /// `connection` ended or failed on its own. Its queries move on to their
    /// next attempt, still over a stream.
    pub fn handle_stream_closed(&mut self, connection: ConnectionId, now: Instant) {
        if self.connections.remove(&connection).is_some() {
            self.retry_all_on(connection, now, &Error::ConnectionClosed);
        }
    }

    /// Act on a response already matched to `id`.
    fn handle_response(&mut self, id: QueryId, response: Message, now: Instant) {
        if response.metadata.truncation && self.switch_to_tcp(id, now) {
            return;
        }
        match response.metadata.response_code {
            // RFC 6891 §7: a server without EDNS answers FORMERR and no OPT;
            // §6.2.2 lets us ask the same server again without EDNS.
            ResponseCode::FormErr if response.edns.is_none() => self.drop_edns(id, now),
            ResponseCode::NXDomain if self.next_candidate(id, now) => {}
            code @ (ResponseCode::ServFail
            | ResponseCode::Refused
            | ResponseCode::NotImp
            | ResponseCode::FormErr) => self.retry(id, now, Error::Server(code)),
            _ => {
                self.pending.remove(&id);
                self.events.push_back(Event::Response {
                    query: id,
                    response,
                });
            }
        }
    }

    /// Retry or fail every query whose deadline is at or before `now`, and
    /// close connections that have been idle for too long.
    ///
    /// A query that times out on a stream suggests the connection is dead,
    /// so the connection is closed and all its queries move on.
    pub fn handle_timeout(&mut self, now: Instant) {
        let expired: Vec<QueryId> = self
            .pending
            .iter()
            .filter(|(_, p)| p.deadline.is_some_and(|d| d <= now))
            .map(|(id, _)| *id)
            .collect();
        for id in expired {
            // An earlier close may already have moved this query on.
            let Some(pending) = self.pending.get(&id) else {
                continue;
            };
            if !pending.deadline.is_some_and(|d| d <= now) {
                continue;
            }
            match pending.route {
                Route::Stream(Some(connection)) if self.connections.contains_key(&connection) => {
                    self.close(connection, now, &Error::Timeout);
                }
                _ => self.retry(id, now, Error::Timeout),
            }
        }
        let idle: Vec<ConnectionId> = self
            .connections
            .keys()
            .filter(|c| self.idle_deadline(**c).is_some_and(|d| d <= now))
            .copied()
            .collect();
        for connection in idle {
            if let Some(conn) = self.connections.remove(&connection) {
                self.transmits.push_back(Transmit {
                    transport: Transport::TcpClose(connection),
                    destination: conn.server,
                    payload: Vec::new(),
                });
            }
        }
    }

    /// Next datagram to send, if any.
    pub fn poll_transmit(&mut self) -> Option<Transmit> {
        self.transmits.pop_front()
    }

    /// Earliest instant at which [`Resolver::handle_timeout`] must be called.
    pub fn poll_timeout(&self) -> Option<Instant> {
        let queries = self.pending.values().filter_map(|p| p.deadline);
        let idle = self
            .connections
            .keys()
            .filter_map(|c| self.idle_deadline(*c));
        queries.chain(idle).min()
    }

    /// When `connection` should close for being idle: `None` while a query
    /// uses it.
    fn idle_deadline(&self, connection: ConnectionId) -> Option<Instant> {
        let conn = self.connections.get(&connection)?;
        if self
            .pending
            .values()
            .any(|p| p.route == Route::Stream(Some(connection)))
        {
            return None;
        }
        conn.last_active.checked_add(self.config.idle_timeout)
    }

    /// Next completed query, if any.
    pub fn poll_event(&mut self) -> Option<Event> {
        self.events.pop_front()
    }

    /// Stop tracking a query. No event is emitted for it.
    pub fn cancel(&mut self, id: QueryId) {
        self.pending.remove(&id);
    }

    /// Send `id` to the next server, or fail it with `error` if it is out of attempts.
    fn retry(&mut self, id: QueryId, now: Instant, error: Error) {
        let Some(pending) = self.pending.get_mut(&id) else {
            return;
        };
        pending.attempt += 1;
        if pending.attempt >= self.config.attempts.get() {
            self.fail(id, error);
            return;
        }
        pending.server = self.config.server(pending.attempt);
        pending.deadline = now.checked_add(self.config.timeout);
        self.emit(id, now);
    }

    /// Move every query on `connection` on to its next attempt.
    fn retry_all_on(&mut self, connection: ConnectionId, now: Instant, error: &Error) {
        let affected: Vec<QueryId> = self
            .pending
            .iter()
            .filter(|(_, p)| p.route == Route::Stream(Some(connection)))
            .map(|(id, _)| *id)
            .collect();
        for id in affected {
            self.retry(id, now, error.clone());
        }
    }

    /// Ask the driver to close `connection`, and move its queries on.
    fn close(&mut self, connection: ConnectionId, now: Instant, error: &Error) {
        let Some(conn) = self.connections.remove(&connection) else {
            return;
        };
        self.transmits.push_back(Transmit {
            transport: Transport::TcpClose(connection),
            destination: conn.server,
            payload: Vec::new(),
        });
        self.retry_all_on(connection, now, error);
    }

    /// Re-send `id` to the same server over TCP (RFC 7766 §5). Doesn't
    /// consume an attempt. Returns `false` if it already uses TCP, in which
    /// case the response is used as it is.
    fn switch_to_tcp(&mut self, id: QueryId, now: Instant) -> bool {
        let Some(pending) = self.pending.get_mut(&id) else {
            return false;
        };
        if pending.route != Route::Udp {
            return false;
        }
        pending.route = Route::Stream(None);
        pending.deadline = now.checked_add(self.config.timeout);
        self.emit(id, now);
        true
    }

    /// Re-send `id` to the same server without an OPT record. Doesn't consume
    /// an attempt. If EDNS was already dropped, FORMERR is a plain server error.
    fn drop_edns(&mut self, id: QueryId, now: Instant) {
        let Some(pending) = self.pending.get_mut(&id) else {
            return;
        };
        if pending.request.edns.take().is_none() {
            self.retry(id, now, Error::Server(ResponseCode::FormErr));
            return;
        }
        let Ok(payload) = pending.request.to_vec() else {
            self.fail(id, Error::Server(ResponseCode::FormErr));
            return;
        };
        pending.payload = payload;
        pending.deadline = now.checked_add(self.config.timeout);
        self.emit(id, now);
    }

    /// Send `id`'s current attempt: as a datagram, or on the open
    /// connection to its server, opening one if there is none. Fails the
    /// query if the bytes can't be produced.
    fn emit(&mut self, id: QueryId, now: Instant) {
        let Some(pending) = self.pending.get(&id) else {
            return;
        };
        let server = pending.server;
        if pending.route == Route::Udp {
            self.transmits.push_back(Transmit {
                transport: Transport::Udp(id),
                destination: server,
                payload: pending.payload.clone(),
            });
            return;
        }
        let message = frame(&pending.payload);
        let open = self
            .connections
            .iter()
            .find(|(_, c)| c.server == server)
            .map(|(c, _)| *c);
        let sent = match open {
            Some(connection) => self.write(connection, &message, now).map(|()| connection),
            None => self.connect(server, &message, now),
        };
        match (sent, self.pending.get_mut(&id)) {
            (Ok(connection), Some(pending)) => pending.route = Route::Stream(Some(connection)),
            (Err(error), _) => self.fail(id, error),
            (Ok(_), None) => {}
        }
    }

    /// Open a connection to `server` with `message` as its first query.
    #[cfg_attr(
        not(feature = "tls"),
        expect(
            clippy::unnecessary_wraps,
            reason = "only TLS settings can make connecting fail"
        )
    )]
    fn connect(
        &mut self,
        server: SocketAddr,
        message: &[u8],
        now: Instant,
    ) -> Result<ConnectionId, Error> {
        let connection = ConnectionId(self.next_connection);
        self.next_connection += 1;
        #[cfg(feature = "tls")]
        let (tls, payload) = match &self.config.tls {
            Some(settings) => {
                let (session, hello) = settings.connect(message).map_err(Error::Tls)?;
                (Some(Box::new(session)), hello)
            }
            None => (None, message.to_vec()),
        };
        #[cfg(not(feature = "tls"))]
        let payload = message.to_vec();
        let conn = Connection {
            server,
            received: Vec::new(),
            last_active: now,
            #[cfg(feature = "tls")]
            tls,
        };
        self.connections.insert(connection, conn);
        self.transmits.push_back(Transmit {
            transport: Transport::TcpConnect(connection),
            destination: server,
            payload,
        });
        Ok(connection)
    }

    /// Write `message` to an open connection. Over TLS it may wait inside
    /// the session until the handshake is done.
    #[cfg_attr(
        not(feature = "tls"),
        expect(
            clippy::unnecessary_wraps,
            reason = "only a TLS session can refuse a write"
        )
    )]
    fn write(
        &mut self,
        connection: ConnectionId,
        message: &[u8],
        now: Instant,
    ) -> Result<(), Error> {
        let Some(conn) = self.connections.get_mut(&connection) else {
            return Ok(());
        };
        conn.last_active = now;
        #[cfg(feature = "tls")]
        let payload = match &mut conn.tls {
            Some(session) => tls::send(session, message).map_err(Error::Tls)?,
            None => message.to_vec(),
        };
        #[cfg(not(feature = "tls"))]
        let payload = message.to_vec();
        if !payload.is_empty() {
            self.transmits.push_back(Transmit {
                transport: Transport::TcpWrite(connection),
                destination: conn.server,
                payload,
            });
        }
        Ok(())
    }

    fn fail(&mut self, id: QueryId, error: Error) {
        self.pending.remove(&id);
        self.events.push_back(Event::Failed { query: id, error });
    }

    /// A query message whose ID no in-flight query is using.
    ///
    /// The ID comes from hickory-proto's `rand::random`, a CSPRNG, covering
    /// the full 16-bit range as RFC 5452 §9.2 requires.
    fn new_message(&self) -> Message {
        loop {
            let message = Message::query();
            if self
                .pending
                .values()
                .all(|p| p.request.metadata.id != message.metadata.id)
            {
                return message;
            }
        }
    }
}
