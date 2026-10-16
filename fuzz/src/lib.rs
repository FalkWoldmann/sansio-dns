//! A driver shared by the fuzz targets. It records what the resolver sends
//! and reports, and panics as soon as that breaks one of these invariants:
//!
//! - each query gets at most one event, and none after it was cancelled;
//! - datagrams and stream writes belong to live queries, stream writes and
//!   closes to open connections, and connection ids are never reused;
//! - a query causes a bounded number of sends;
//! - there is a timer exactly while queries are pending or connections open,
//!   and `handle_timeout(now)` leaves no deadline at or before `now`.

use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::io::ErrorKind;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::time::{Duration, Instant};

use arbitrary::Arbitrary;
use sansio_dns::hickory_proto::op::{Message, ResponseCode};
use sansio_dns::hickory_proto::rr::rdata::{A, AAAA};
use sansio_dns::hickory_proto::rr::{Name, RData, Record, RecordType};
use sansio_dns::{Config, ConnectionId, Event, QueryId, Resolver, Transmit, Transport};

pub const S1: SocketAddr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), 53);
pub const S2: SocketAddr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)), 53);
pub const S3: SocketAddr = SocketAddr::new(
    IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 3)),
    53,
);

/// Transmits kept for replies, so late answers to old ones happen too.
const RECENT: usize = 16;

/// A query the resolver sent, decoded.
#[derive(Debug)]
pub struct Sent {
    pub transport: Transport,
    pub destination: SocketAddr,
    pub request: Message,
}

/// A resolver plus everything observed from it so far.
#[derive(Debug)]
pub struct Harness {
    pub resolver: Resolver,
    pub now: Instant,
    /// The configured servers; empty when unknown, so not checked.
    servers: Vec<SocketAddr>,
    /// Whether stream payloads are TLS records, which can't be decoded here.
    tls: bool,
    max_sends: Option<usize>,
    live: BTreeSet<QueryId>,
    finished: BTreeSet<QueryId>,
    open: BTreeSet<ConnectionId>,
    opened: BTreeSet<ConnectionId>,
    /// Live queries for the same name and type, which the resolver
    /// coalesces: the first one sends, the others join it.
    groups: BTreeMap<Group, Vec<QueryId>>,
    group_of: BTreeMap<QueryId, Group>,
    /// The member a group's datagrams last came from. Another member may
    /// only send after that one was cancelled in the same step (it takes
    /// the query over) or failed in it (it starts over on its own).
    sender: BTreeMap<Group, QueryId>,
    /// Groups whose sender was cancelled in the current step.
    handed_over: BTreeSet<Group>,
    sends: BTreeMap<Group, usize>,
    by_message_id: BTreeMap<u16, Group>,
    pub recent: VecDeque<Sent>,
    events: Vec<Event>,
}

impl Harness {
    /// `servers` are the ones `config` uses, or empty if unknown. With
    /// `max_sends`, no query may cause more datagrams and stream writes.
    #[expect(clippy::disallowed_methods, reason = "the driver owns the clock")]
    pub fn new(config: Config, servers: Vec<SocketAddr>, max_sends: Option<usize>) -> Self {
        Self {
            resolver: Resolver::new(config),
            now: Instant::now(),
            servers,
            tls: false,
            max_sends,
            live: BTreeSet::new(),
            finished: BTreeSet::new(),
            open: BTreeSet::new(),
            opened: BTreeSet::new(),
            sends: BTreeMap::new(),
            groups: BTreeMap::new(),
            group_of: BTreeMap::new(),
            sender: BTreeMap::new(),
            handed_over: BTreeSet::new(),
            by_message_id: BTreeMap::new(),
            recent: VecDeque::new(),
            events: Vec::new(),
        }
    }

    /// For a resolver using DNS over TLS.
    pub fn tls(mut self) -> Self {
        self.tls = true;
        self
    }

    pub fn query(&mut self, name: Name, record_type: RecordType) -> Option<QueryId> {
        let group = (name.to_ascii().to_ascii_lowercase(), u16::from(record_type));
        let id = self.resolver.query(name, record_type, self.now).ok()?;
        self.live.insert(id);
        self.groups.entry(group.clone()).or_default().push(id);
        self.group_of.insert(id, group);
        Some(id)
    }

    /// `id` is over: it leaves its group, and an empty group is forgotten.
    fn leave(&mut self, id: QueryId) {
        let Some(group) = self.group_of.remove(&id) else {
            return;
        };
        let Some(members) = self.groups.get_mut(&group) else {
            return;
        };
        members.retain(|&member| member != id);
        if members.is_empty() {
            self.groups.remove(&group);
            self.sender.remove(&group);
            self.handed_over.remove(&group);
            self.sends.remove(&group);
            self.by_message_id.retain(|_, g| *g != group);
        }
    }

    pub fn live(&self) -> &BTreeSet<QueryId> {
        &self.live
    }

    /// The events checked so far and not yet taken.
    pub fn take_events(&mut self) -> Vec<Event> {
        std::mem::take(&mut self.events)
    }

    pub fn cancel(&mut self, which: u8) {
        if let Some(id) = pick(&self.live, which) {
            self.resolver.cancel(id, self.now);
            self.live.remove(&id);
            self.finished.insert(id);
            let group = self.group_of.get(&id).cloned();
            let was_sender = group
                .as_ref()
                .is_some_and(|g| self.sender.get(g) == Some(&id));
            self.leave(id);
            if let Some(group) = group.filter(|g| was_sender && self.groups.contains_key(g)) {
                self.handed_over.insert(group);
            }
        }
    }

    /// An open connection, if there is one.
    pub fn open(&self, which: u8) -> Option<ConnectionId> {
        pick(&self.open, which)
    }

    /// The server closes `connection`, or it fails.
    pub fn lose(&mut self, connection: ConnectionId, failed: bool) {
        if !self.open.remove(&connection) {
            return;
        }
        if failed {
            self.resolver
                .handle_stream_error(connection, ErrorKind::ConnectionReset, self.now);
        } else {
            self.resolver.handle_stream_closed(connection, self.now);
        }
    }

    pub fn elapse(&mut self, millis: u16) {
        self.now += Duration::from_millis(u64::from(millis));
        self.timeout();
    }

    /// Jump to the next deadline, if any, and handle it.
    pub fn next_deadline(&mut self) {
        if let Some(deadline) = self.resolver.poll_timeout() {
            self.now = self.now.max(deadline);
            self.timeout();
        }
    }

    fn timeout(&mut self) {
        self.resolver.handle_timeout(self.now);
        let next = self.resolver.poll_timeout();
        assert!(
            next.is_none_or(|t| t > self.now),
            "handle_timeout left a deadline that has passed"
        );
    }

    /// A recent transmit matching `keep`, chosen by `which`.
    pub fn recent(&self, which: u8, keep: impl Fn(&Sent) -> bool) -> Option<&Sent> {
        let matching: Vec<&Sent> = self.recent.iter().filter(|s| keep(s)).collect();
        matching
            .get(usize::from(which) % matching.len().max(1))
            .copied()
    }

    /// Drain transmits and events, checking every invariant, and return the
    /// transmits.
    pub fn check(&mut self) -> Vec<Transmit> {
        let mut out = Vec::new();
        let mut started_over = Vec::new();
        while let Some(t) = self.resolver.poll_transmit() {
            assert!(
                self.servers.is_empty() || self.servers.contains(&t.destination),
                "transmit to an unknown server: {t:?}"
            );
            match t.transport {
                Transport::Udp(q) => {
                    assert!(
                        self.live.contains(&q),
                        "datagram for {q:?}, which isn't live"
                    );
                    let group = self.group_of[&q].clone();
                    match self.sender.insert(group.clone(), q) {
                        Some(previous) if previous != q => {
                            if !self.handed_over.remove(&group) {
                                // A late joiner starting over with a budget
                                // of its own: `previous` must fail now.
                                started_over.push(previous);
                                self.sends.remove(&group);
                                self.count(&group);
                            }
                        }
                        _ => self.count(&group),
                    }
                    let request = Message::from_vec(&t.payload).expect("the resolver sent garbage");
                    self.by_message_id.insert(request.metadata.id, group);
                    self.remember(&t, request);
                }
                Transport::TcpConnect(c) | Transport::TcpWrite(c) => {
                    if matches!(t.transport, Transport::TcpConnect(_)) {
                        assert!(self.opened.insert(c), "connection id {c:?} reused");
                        self.open.insert(c);
                    }
                    assert!(self.open.contains(&c), "write on closed {c:?}");
                    assert!(!self.live.is_empty(), "stream write with no query pending");
                    if !self.tls {
                        self.stream_write(&t);
                    }
                }
                Transport::TcpClose(c) => {
                    assert!(self.open.remove(&c), "closing {c:?}, which isn't open");
                    assert!(t.payload.is_empty(), "close with a payload");
                }
            }
            out.push(t);
        }

        while let Some(event) = self.resolver.poll_event() {
            let id = match event {
                Event::Response { query, .. } | Event::Failed { query, .. } => query,
            };
            assert!(
                self.finished.insert(id),
                "second event for {id:?}, or one after cancel"
            );
            assert!(self.live.remove(&id), "event for unknown {id:?}");
            self.leave(id);
            self.events.push(event);
        }
        for previous in started_over {
            assert!(
                !self.live.contains(&previous),
                "another query of {previous:?}'s group sent while it is live"
            );
        }
        self.handed_over.clear();

        assert_eq!(
            self.resolver.poll_timeout().is_some(),
            !self.live.is_empty() || !self.open.is_empty(),
            "a timer exactly while queries are pending or connections open"
        );
        out
    }

    /// A length-prefixed query on a plain TCP connection. Its message ID
    /// was first sent over UDP, which names the query.
    fn stream_write(&mut self, t: &Transmit) {
        let (len, message) = t
            .payload
            .split_first_chunk::<2>()
            .expect("no length prefix");
        assert_eq!(
            usize::from(u16::from_be_bytes(*len)),
            message.len(),
            "wrong length prefix"
        );
        let request = Message::from_vec(message).expect("the resolver sent garbage");
        let group = self
            .by_message_id
            .get(&request.metadata.id)
            .expect("stream query with an ID never sent over UDP")
            .clone();
        assert!(
            self.groups.contains_key(&group),
            "stream query for {group:?}, which has no live query"
        );
        self.count(&group);
        self.remember(t, request);
    }

    fn count(&mut self, group: &Group) {
        let sends = self.sends.entry(group.clone()).or_default();
        *sends += 1;
        if let Some(max) = self.max_sends {
            assert!(*sends <= max, "{group:?} sent more than {max} times");
        }
    }

    fn remember(&mut self, t: &Transmit, request: Message) {
        if self.recent.len() == RECENT {
            self.recent.pop_front();
        }
        self.recent.push_back(Sent {
            transport: t.transport,
            destination: t.destination,
            request,
        });
    }
}

/// The name, as given and lowercased, and record type of a query.
type Group = (String, u16);

fn pick<T: Copy>(set: &BTreeSet<T>, which: u8) -> Option<T> {
    set.iter()
        .nth(usize::from(which) % set.len().max(1))
        .copied()
}

/// A response code, mostly one the resolver acts on. Drawn from a full
/// `u16`, nearly every code would be one it doesn't know.
#[derive(Arbitrary, Clone, Copy, Debug)]
pub enum Code {
    NoError,
    FormErr,
    ServFail,
    NXDomain,
    NotImp,
    Refused,
    Other(u16),
}

impl From<Code> for ResponseCode {
    fn from(code: Code) -> Self {
        match code {
            Code::NoError => Self::NoError,
            Code::FormErr => Self::FormErr,
            Code::ServFail => Self::ServFail,
            Code::NXDomain => Self::NXDomain,
            Code::NotImp => Self::NotImp,
            Code::Refused => Self::Refused,
            Code::Other(code) => code.into(),
        }
    }
}

/// The answer a well-behaved server would give to `request`, with `code`.
/// Only `NOERROR` carries an address.
pub fn reply(request: &Message, code: ResponseCode) -> Message {
    let mut response = Message::response(request.metadata.id, request.metadata.op_code);
    response.add_queries(request.queries.clone());
    response.metadata.response_code = code;
    if let Some(question) = request.queries.first()
        && code == ResponseCode::NoError
    {
        let data = match question.query_type() {
            RecordType::AAAA => RData::AAAA(AAAA(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 7))),
            _ => RData::A(A(Ipv4Addr::new(192, 0, 2, 7))),
        };
        response.add_answer(Record::from_rdata(question.name().clone(), 300, data));
    }
    if let Some(edns) = &request.edns {
        response.set_edns(edns.clone());
    }
    response
}

/// `message` with the two-byte TCP length prefix.
pub fn frame(message: &[u8]) -> Vec<u8> {
    let len = u16::try_from(message.len()).unwrap_or(u16::MAX);
    [&len.to_be_bytes()[..], message].concat()
}

/// XOR each `(offset, mask)` into `bytes`, offsets wrapping around.
pub fn flip(bytes: &mut [u8], flips: &[(u16, u8)]) {
    let len = bytes.len();
    for (offset, mask) in flips {
        if let Some(byte) = bytes.get_mut(usize::from(*offset) % len.max(1)) {
            *byte ^= mask;
        }
    }
}

/// Overwrite the message ID at the start of `bytes` with `id`.
pub fn set_id(bytes: &mut [u8], id: u16) {
    if let Some(head) = bytes.first_chunk_mut::<2>() {
        *head = id.to_be_bytes();
    }
}

pub fn name(text: &str) -> Name {
    Name::from_ascii(text).expect("a valid fixed name")
}
