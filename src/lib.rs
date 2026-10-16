//! A sans-IO DNS stub resolver built on [`hickory_proto`].
//!
//! [`Resolver`] owns no sockets, timers or tasks. The caller drives it:
//!
//! 1. Start a lookup with [`Resolver::query`].
//! 2. Send every datagram returned by [`Resolver::poll_transmit`].
//! 3. Feed received datagrams to [`Resolver::handle_datagram`].
//! 4. Call [`Resolver::handle_timeout`] once the instant from
//!    [`Resolver::poll_timeout`] has passed.
//! 5. Collect results from [`Resolver::poll_event`].
//!
//! Only UDP is implemented. A truncated response is reported as
//! [`Error::Truncated`] so the caller can retry over TCP.
//!
//! # Driver obligations
//!
//! [RFC 5452 §9.2] requires an unpredictable source port, and a different
//! one for each outstanding query. The resolver can't choose ports, so the
//! driver must: bind a fresh ephemeral socket per [`Transmit::query`], and
//! only feed a datagram to [`Resolver::handle_datagram`] if it arrived on
//! the socket that query was sent from. The resolver checks everything else
//! §9.1 asks for: source address and port, message ID and question.
//!
//! [RFC 5452 §9.2]: https://rfc-annotations.research.icann.org/rfc5452.html

use std::collections::{BTreeMap, VecDeque};
use std::fmt;
use std::net::SocketAddr;
use std::time::{Duration, Instant};

pub use hickory_proto;
use hickory_proto::ProtoError;
use hickory_proto::op::{Edns, Message, MessageType, Query, ResponseCode};
use hickory_proto::rr::{Name, RecordType};

/// EDNS UDP payload size recommended by DNS Flag Day 2020.
const EDNS_PAYLOAD: u16 = 1232;

/// Resolver settings.
#[derive(Clone, Debug)]
pub struct Config {
    /// Name servers, tried in order and rotated on each retry.
    pub servers: Vec<SocketAddr>,
    /// How long to wait for a response before retrying.
    pub timeout: Duration,
    /// Total number of datagrams sent per query, across all servers.
    pub attempts: usize,
}

impl Config {
    /// Two attempts per server, two seconds each.
    pub fn new(servers: Vec<SocketAddr>) -> Self {
        let attempts = servers.len() * 2;
        Self {
            servers,
            timeout: Duration::from_secs(2),
            attempts,
        }
    }
}

/// Handle for an in-flight query.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct QueryId(u64);

/// A datagram the caller must send.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Transmit {
    /// The query this datagram belongs to; see the crate docs on source ports.
    pub query: QueryId,
    pub destination: SocketAddr,
    pub payload: Vec<u8>,
}

/// Outcome of a query.
#[derive(Debug)]
pub enum Event {
    /// A server answered. `NXDOMAIN` and empty answers arrive here too;
    /// inspect `response.metadata.response_code`.
    Response { query: QueryId, response: Message },
    /// The query gave up.
    Failed { query: QueryId, error: Error },
}

/// Why a query failed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    /// No server answered within the configured attempts.
    Timeout,
    /// The response did not fit in a UDP datagram; retry over TCP.
    Truncated,
    /// The last server answered with this error code (e.g. `SERVFAIL`).
    Server(ResponseCode),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Timeout => f.write_str("no response from any name server"),
            Self::Truncated => f.write_str("response truncated"),
            Self::Server(code) => write!(f, "name server returned {code}"),
        }
    }
}

impl std::error::Error for Error {}

struct Pending {
    request: Message,
    payload: Vec<u8>,
    attempt: usize,
    server: SocketAddr,
    deadline: Instant,
}

/// The resolver state machine. See the crate docs for how to drive it.
pub struct Resolver {
    config: Config,
    next_query: u64,
    pending: BTreeMap<QueryId, Pending>,
    transmits: VecDeque<Transmit>,
    events: VecDeque<Event>,
}

impl Resolver {
    /// # Panics
    ///
    /// If `config.servers` is empty or `config.attempts` is zero.
    pub fn new(config: Config) -> Self {
        assert!(!config.servers.is_empty(), "no name servers configured");
        assert!(config.attempts > 0, "attempts must be at least 1");
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
    pub fn query(
        &mut self,
        mut name: Name,
        record_type: RecordType,
        now: Instant,
    ) -> Result<QueryId, ProtoError> {
        name.set_fqdn(true);
        let mut request = self.new_message();
        request.metadata.recursion_desired = true;
        request.add_query(Query::query(name, record_type));
        let mut edns = Edns::new();
        edns.set_max_payload(EDNS_PAYLOAD);
        request.set_edns(edns);
        let payload = request.to_vec()?;

        let id = QueryId(self.next_query);
        self.next_query += 1;
        let server = self.config.servers[0];
        self.pending.insert(
            id,
            Pending {
                request,
                payload: payload.clone(),
                attempt: 0,
                server,
                deadline: now + self.config.timeout,
            },
        );
        self.transmits.push_back(Transmit {
            query: id,
            destination: server,
            payload,
        });
        Ok(id)
    }

    /// Process a datagram received from `from`.
    ///
    /// Datagrams that aren't a response to an in-flight query (wrong source
    /// address, message ID, opcode or question, RFC 5452 §9.1 and
    /// RFC 1035 §7.3) are ignored, so spoofed or late responses can't
    /// complete a query.
    pub fn handle_datagram(&mut self, from: SocketAddr, data: &[u8], now: Instant) {
        let Ok(response) = Message::from_vec(data) else {
            return;
        };
        if response.metadata.message_type != MessageType::Response {
            return;
        }
        let Some(id) = self
            .pending
            .iter()
            .find(|(_, p)| {
                p.server == from
                    && p.request.metadata.id == response.metadata.id
                    && p.request.metadata.op_code == response.metadata.op_code
                    && p.request.queries == response.queries
            })
            .map(|(id, _)| *id)
        else {
            return;
        };

        if response.metadata.truncation {
            self.fail(id, Error::Truncated);
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
            .filter(|(_, p)| p.deadline <= now)
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
        self.pending.values().map(|p| p.deadline).min()
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
        if pending.attempt >= self.config.attempts {
            self.fail(id, error);
            return;
        }
        pending.server = self.config.servers[pending.attempt % self.config.servers.len()];
        pending.deadline = now + self.config.timeout;
        self.transmits.push_back(Transmit {
            query: id,
            destination: pending.server,
            payload: pending.payload.clone(),
        });
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
        pending.deadline = now + self.config.timeout;
        self.transmits.push_back(Transmit {
            query: id,
            destination: pending.server,
            payload: pending.payload.clone(),
        });
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
        std::iter::repeat_with(Message::query)
            .find(|m| {
                self.pending
                    .values()
                    .all(|p| p.request.metadata.id != m.metadata.id)
            })
            .expect("repeat_with is infinite")
    }
}
