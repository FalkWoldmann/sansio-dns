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
//! # Driver obligations
//!
//! For a [`Transport::Tcp`] transmit, open a new TCP connection to its
//! destination, replacing any earlier connection for the same query, and
//! write the payload; it is already length-prefixed (RFC 7766 §8). Pass
//! everything read from that connection to [`Resolver::handle_stream_data`]
//! and call [`Resolver::handle_stream_closed`] on end of stream or error.
//! The connection can be dropped once the query's [`Event`] arrives.
//!
//! For UDP, [RFC 5452 §9.2] requires an unpredictable source port, and a different
//! one for each outstanding query. The resolver can't choose ports, so the
//! driver must: bind a fresh ephemeral socket per [`Transmit::query`], and
//! only feed a datagram to [`Resolver::handle_datagram`] if it arrived on
//! the socket that query was sent from. The resolver checks everything else
//! §9.1 asks for: source address and port, message ID and question.
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
use hickory_proto::rr::rdata::{A, AAAA};
use hickory_proto::rr::{Name, RData, Record, RecordType};

mod lookup;
pub use lookup::{IpLookup, addresses};

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
        }
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

/// How a [`Transmit`] must be sent.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Transport {
    /// As one UDP datagram.
    Udp,
    /// Over a new TCP connection; see the crate docs.
    Tcp,
}

/// Bytes the caller must send.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Transmit {
    /// The query these bytes belong to; see the crate docs on source ports.
    pub query: QueryId,
    /// Whether to send them as a UDP datagram or over a new TCP connection.
    pub transport: Transport,
    /// The name server to send them to.
    pub destination: SocketAddr,
    /// The DNS message, length-prefixed for TCP.
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
    /// The last server answered with this error code (e.g. `SERVFAIL`).
    Server(ResponseCode),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Timeout => f.write_str("no response from any name server"),
            Self::ConnectionClosed => f.write_str("connection closed before a response"),
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
    /// Bytes received so far on the TCP connection, once the query has
    /// switched to TCP; `None` while it still uses UDP.
    tcp: Option<Vec<u8>>,
    /// Search candidates still to try if this name doesn't exist.
    rest: VecDeque<Name>,
}

impl Pending {
    /// The bytes to send for the current attempt. Starts a fresh TCP buffer,
    /// since every TCP transmit means a new connection.
    fn transmit(&mut self, query: QueryId) -> Transmit {
        let (transport, payload) = match &mut self.tcp {
            None => (Transport::Udp, self.payload.clone()),
            Some(received) => {
                received.clear();
                (Transport::Tcp, frame(&self.payload))
            }
        };
        Transmit {
            query,
            transport,
            destination: self.server,
            payload,
        }
    }
}

/// Prefix `message` with its two-byte length (RFC 7766 §8).
fn frame(message: &[u8]) -> Vec<u8> {
    // A single-question query is far below 64 KiB.
    let len = u16::try_from(message.len()).unwrap_or(u16::MAX);
    len.to_be_bytes().iter().chain(message).copied().collect()
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
        if let Some(response) = special_use(&absolute, record_type) {
            self.events.push_back(Event::Response {
                query: id,
                response,
            });
            return Ok(id);
        }
        let first = candidates.pop_front().unwrap_or(absolute);
        let mut pending = self.new_pending(first, record_type, candidates, now)?;
        self.transmits.push_back(pending.transmit(id));
        self.pending.insert(id, pending);
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
        let payload = request.to_vec()?;
        Ok(Pending {
            request,
            payload,
            attempt: 0,
            server: self.config.server(0),
            deadline: now.checked_add(self.config.timeout),
            tcp: None,
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
        let Ok(mut next) = self.new_pending(name, record_type, rest, now) else {
            return false;
        };
        self.transmits.push_back(next.transmit(id));
        self.pending.insert(id, next);
        true
    }

    /// Process a datagram received from `from`.
    ///
    /// Datagrams that aren't a response to an in-flight UDP query (wrong
    /// source address, message ID, opcode or question, RFC 5452 §9.1 and
    /// RFC 1035 §7.3) are ignored, so spoofed or late responses can't
    /// complete a query. Once a query has switched to TCP, UDP replies to it
    /// are ignored too.
    pub fn handle_datagram(&mut self, from: SocketAddr, data: &[u8], now: Instant) {
        let Ok(response) = Message::from_vec(data) else {
            return;
        };
        let Some(id) = self
            .pending
            .iter()
            .find(|(_, p)| p.tcp.is_none() && p.server == from && is_reply(&p.request, &response))
            .map(|(id, _)| *id)
        else {
            return;
        };
        self.handle_response(id, response, now);
    }

    /// Process bytes read from the TCP connection opened for `query`.
    ///
    /// Bytes may arrive in any chunking. The first complete message that
    /// answers the query is used; others are ignored.
    pub fn handle_stream_data(&mut self, query: QueryId, data: &[u8], now: Instant) {
        let Some(pending) = self.pending.get_mut(&query) else {
            return;
        };
        let Some(received) = &mut pending.tcp else {
            return;
        };
        received.extend_from_slice(data);
        while let Some(message) = next_frame(received) {
            if let Ok(response) = Message::from_vec(&message)
                && is_reply(&pending.request, &response)
            {
                self.handle_response(query, response, now);
                return;
            }
        }
    }

    /// The TCP connection for `query` ended or failed. Retries the query on
    /// the next server, still over TCP.
    pub fn handle_stream_closed(&mut self, query: QueryId, now: Instant) {
        if self.pending.get(&query).is_some_and(|p| p.tcp.is_some()) {
            self.retry(query, now, Error::ConnectionClosed);
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

    /// Retry or fail every query whose deadline is at or before `now`.
    pub fn handle_timeout(&mut self, now: Instant) {
        let expired: Vec<QueryId> = self
            .pending
            .iter()
            .filter(|(_, p)| p.deadline.is_some_and(|d| d <= now))
            .map(|(id, _)| *id)
            .collect();
        for id in expired {
            self.retry(id, now, Error::Timeout);
        }
    }

    /// Next datagram to send, if any.
    pub fn poll_transmit(&mut self) -> Option<Transmit> {
        self.transmits.pop_front()
    }

    /// Earliest instant at which [`Resolver::handle_timeout`] must be called.
    pub fn poll_timeout(&self) -> Option<Instant> {
        self.pending.values().filter_map(|p| p.deadline).min()
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
        self.transmits.push_back(pending.transmit(id));
    }

    /// Re-send `id` to the same server over TCP (RFC 7766 §5). Doesn't
    /// consume an attempt. Returns `false` if it already uses TCP, in which
    /// case the response is used as it is.
    fn switch_to_tcp(&mut self, id: QueryId, now: Instant) -> bool {
        let Some(pending) = self.pending.get_mut(&id) else {
            return false;
        };
        if pending.tcp.is_some() {
            return false;
        }
        pending.tcp = Some(Vec::new());
        pending.deadline = now.checked_add(self.config.timeout);
        self.transmits.push_back(pending.transmit(id));
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
        self.transmits.push_back(pending.transmit(id));
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
