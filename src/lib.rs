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
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
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

/// The local answer for a special-use name, or `None` for any other name.
fn special_use(name: &Name, record_type: RecordType) -> Option<Message> {
    let localhost = LOCALHOST.name().zone_of(name);
    if !localhost
        && ![&INVALID, &LOCAL, &ONION]
            .iter()
            .any(|z| z.name().zone_of(name))
    {
        return None;
    }
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
    /// `name` is treated as absolute: there is no search list, so
    /// `example.com` and `example.com.` are the same query.
    ///
    /// Special-use names are answered at once, without a transmit:
    /// `localhost` gets the loopback address (RFC 6761 §6.3), and names
    /// under `invalid.`, `local.` and `onion.` get NXDOMAIN (RFC 6761 §6.4,
    /// RFC 6762 §3, RFC 7686 §2). Resolve `.local` names with mDNS instead.
    pub fn query(
        &mut self,
        mut name: Name,
        record_type: RecordType,
        now: Instant,
    ) -> Result<QueryId, ProtoError> {
        name.set_fqdn(true);
        if let Some(response) = special_use(&name, record_type) {
            let id = QueryId(self.next_query);
            self.next_query += 1;
            self.events.push_back(Event::Response {
                query: id,
                response,
            });
            return Ok(id);
        }
        let mut request = self.new_message();
        request.metadata.recursion_desired = true;
        request.add_query(Query::query(name, record_type));
        let mut edns = Edns::new();
        edns.set_max_payload(EDNS_PAYLOAD);
        request.set_edns(edns);
        let payload = request.to_vec()?;

        let id = QueryId(self.next_query);
        self.next_query += 1;
        let mut pending = Pending {
            request,
            payload,
            attempt: 0,
            server: self.config.server(0),
            deadline: now.checked_add(self.config.timeout),
            tcp: None,
        };
        self.transmits.push_back(pending.transmit(id));
        self.pending.insert(id, pending);
        Ok(id)
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
