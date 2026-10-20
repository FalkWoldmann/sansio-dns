//! A driver shared by the fuzz targets. It records what the resolver sends
//! and reports, and panics as soon as that breaks one of these invariants:
//!
//! - each query gets at most one event, and none after it was cancelled;
//! - datagrams and stream writes belong to live queries, stream writes and
//!   closes to open connections, and connection ids are never reused; with
//!   TLS, a write with no query live is the session's last before the
//!   connection closes (RFC 8446 §6.1);
//! - no datagram goes to a server with an open connection (RFC 7766 §5),
//!   and no server has two connections open (RFC 7766 §6.2.2);
//! - a query causes a bounded number of sends, not counting the resends
//!   after a lost connection or a cancel hand-over, and at most three to
//!   one server over one transport, those included (RFC 9520 §3.1);
//! - queries for an absolute name never start over: their messages keep
//!   one message ID, and only the first of them, or its heir after a
//!   cancel, sends;
//! - nothing is sent for a question within `Config::failure_cache_min` of
//!   the failure that ended its queries (RFC 9520 §3.2), unless they failed
//!   when a cancel handed them over with no server left. The targets never
//!   have two groups of queries ask the same question at once, so a group
//!   that fails sent its question itself;
//! - there is a timer exactly while queries are pending or connections open,
//!   and `handle_timeout(now)` leaves no deadline at or before `now`.

use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::io::ErrorKind;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::time::{Duration, Instant};

use arbitrary::Arbitrary;
use sansio_dns::hickory_proto::op::{Message, ResponseCode};
use sansio_dns::hickory_proto::rr::rdata::{A, AAAA, NS, SOA};
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
    /// Open connections and their servers.
    open: BTreeMap<ConnectionId, SocketAddr>,
    opened: BTreeSet<ConnectionId>,
    /// The server of a connection lost in the current step: the sends to
    /// it are resends, outside `max_sends`.
    lost: Option<SocketAddr>,
    /// Live queries for the same name and type, which the resolver
    /// coalesces: the first one sends, the others join it.
    groups: BTreeMap<Group, Vec<QueryId>>,
    group_of: BTreeMap<QueryId, Group>,
    /// The member a group's datagrams last came from, or that took the
    /// query over when that one was cancelled. No other member sends.
    sender: BTreeMap<Group, QueryId>,
    /// Groups whose sender was cancelled in the current step.
    handed_over: BTreeSet<Group>,
    sends: BTreeMap<Group, usize>,
    /// Sends of each group to each server, over UDP (`true`) or a stream.
    per_server: BTreeMap<(Group, SocketAddr, bool), usize>,
    by_message_id: BTreeMap<u16, Group>,
    /// The message ID of each group's last message. A new one starts a new
    /// budget: a new search candidate, which only a relative name has.
    message_id: BTreeMap<Group, u16>,
    /// The question of each group's last message.
    question: BTreeMap<Group, Question>,
    /// When the queries of a group whose last message asked this question
    /// failed: the failure is cached for at least `failure_cache`.
    failed: BTreeMap<Question, Instant>,
    /// The shortest time the resolver caches a failure.
    failure_cache: Duration,
    pub recent: VecDeque<Sent>,
    events: Vec<Event>,
}

impl Harness {
    /// `servers` are the ones `config` uses, or empty if unknown. With
    /// `max_sends`, no query may cause more datagrams and stream writes,
    /// nor more than three to one server over one transport. Both are
    /// counted per query, not per search candidate, so they hold only for
    /// absolute names.
    #[expect(clippy::disallowed_methods, reason = "the driver owns the clock")]
    pub fn new(config: Config, servers: Vec<SocketAddr>, max_sends: Option<usize>) -> Self {
        let failure_cache = config.failure_cache.shortest();
        Self {
            resolver: Resolver::new(config),
            now: Instant::now(),
            servers,
            tls: false,
            max_sends,
            live: BTreeSet::new(),
            finished: BTreeSet::new(),
            open: BTreeMap::new(),
            opened: BTreeSet::new(),
            lost: None,
            sends: BTreeMap::new(),
            per_server: BTreeMap::new(),
            groups: BTreeMap::new(),
            group_of: BTreeMap::new(),
            sender: BTreeMap::new(),
            handed_over: BTreeSet::new(),
            by_message_id: BTreeMap::new(),
            message_id: BTreeMap::new(),
            question: BTreeMap::new(),
            failed: BTreeMap::new(),
            failure_cache,
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
            self.per_server.retain(|(g, _, _), _| *g != group);
            self.by_message_id.retain(|_, g| *g != group);
            self.message_id.remove(&group);
            self.question.remove(&group);
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
            let heir = group
                .filter(|_| was_sender)
                .and_then(|g| Some((self.groups.get(&g)?.first().copied()?, g)));
            if let Some((heir, group)) = heir {
                // The first member in flight takes the query over, and may
                // send its attempt again in this step.
                self.sender.insert(group.clone(), heir);
                self.handed_over.insert(group);
            }
        }
    }

    /// Empty the resolver's cache, as after a network change.
    pub fn flush(&mut self) {
        self.resolver.flush_cache();
        self.failed.clear();
    }

    /// The driver stops: every query is over without an event.
    pub fn shutdown(&mut self) {
        self.resolver.shutdown();
        for id in std::mem::take(&mut self.live) {
            self.finished.insert(id);
            self.leave(id);
        }
    }

    /// An open connection, if there is one.
    pub fn open(&self, which: u8) -> Option<ConnectionId> {
        self.open
            .keys()
            .nth(usize::from(which) % self.open.len().max(1))
            .copied()
    }

    /// The server closes `connection`, or it fails.
    pub fn lose(&mut self, connection: ConnectionId, failed: bool) {
        let Some(server) = self.open.remove(&connection) else {
            return;
        };
        self.lost = Some(server);
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
        let transmits: Vec<Transmit> =
            std::iter::from_fn(|| self.resolver.poll_transmit()).collect();
        let following: Vec<Option<Transport>> = transmits
            .iter()
            .skip(1)
            .map(|t| Some(t.transport))
            .chain([None])
            .collect();
        for (t, followed_by) in transmits.into_iter().zip(following) {
            assert!(
                self.servers.is_empty() || self.servers.contains(&t.destination),
                "transmit to an unknown server: {t:?}"
            );
            let free = self.lost == Some(t.destination);
            match t.transport {
                Transport::Udp(q) => {
                    assert!(
                        self.live.contains(&q),
                        "datagram for {q:?}, which isn't live"
                    );
                    assert!(
                        !self.open.values().any(|&server| server == t.destination),
                        "datagram to {}, which has an open connection",
                        t.destination
                    );
                    let group = self.group_of[&q].clone();
                    let request = Message::from_vec(&t.payload).expect("the resolver sent garbage");
                    let id = request.metadata.id;
                    self.asks(&group, &request);
                    let previous_id = self.message_id.insert(group.clone(), id);
                    let fresh = previous_id.is_some_and(|previous| previous != id);
                    let handed_over = self.handed_over.remove(&group);
                    let previous = self.sender.insert(group.clone(), q);
                    assert!(
                        previous.is_none_or(|previous| previous == q) || handed_over,
                        "{q:?} sent for {group:?}, whose sender is {previous:?}"
                    );
                    if fresh {
                        // A new search candidate.
                        self.restart(&group);
                        self.count(&group, t.destination, true, false);
                    } else if handed_over {
                        // The heir sends the attempt again, or its next one:
                        // outside `max_sends`, but not outside the
                        // per-server limit.
                        self.count_per_server(&group, t.destination, true);
                    } else {
                        self.count(&group, t.destination, true, free);
                    }
                    self.by_message_id.insert(id, group);
                    self.remember(&t, request);
                }
                Transport::TcpConnect(c) | Transport::TcpWrite(c) => {
                    if matches!(t.transport, Transport::TcpConnect(_)) {
                        assert!(self.opened.insert(c), "connection id {c:?} reused");
                        assert!(
                            !self.open.values().any(|&server| server == t.destination),
                            "a second connection to {}",
                            t.destination
                        );
                        self.open.insert(c, t.destination);
                    }
                    assert!(self.open.contains_key(&c), "write on closed {c:?}");
                    assert!(
                        !self.live.is_empty()
                            || (self.tls && followed_by == Some(Transport::TcpClose(c))),
                        "stream write with no query pending"
                    );
                    if !self.tls {
                        self.stream_write(&t, free);
                    }
                }
                Transport::TcpClose(c) => {
                    assert!(
                        self.open.remove(&c).is_some(),
                        "closing {c:?}, which isn't open"
                    );
                    assert!(t.payload.is_empty(), "close with a payload");
                }
            }
            out.push(t);
        }

        let mut failed = Vec::new();
        while let Some(event) = self.resolver.poll_event() {
            let id = match event {
                Event::Response { query, .. } | Event::Failed { query, .. } => query,
            };
            assert!(
                self.finished.insert(id),
                "second event for {id:?}, or one after cancel"
            );
            assert!(self.live.remove(&id), "event for unknown {id:?}");
            // Not when a cancel handed the group over with no server left
            // to send to, which isn't a resolution failure.
            if matches!(event, Event::Failed { .. })
                && let Some(group) = self.group_of.get(&id)
                && !self.handed_over.contains(group)
                && let Some(question) = self.question.get(group)
            {
                failed.push((group.clone(), question.clone()));
            }
            self.leave(id);
            self.events.push(event);
        }
        for (group, question) in failed {
            // The whole group failed, after sending its question: unless
            // the failure was cached already, it is now.
            let cached = self
                .failed
                .get(&question)
                .is_some_and(|at| self.now < *at + self.failure_cache);
            if !self.groups.contains_key(&group) && !cached {
                self.failed.insert(question, self.now);
            }
        }
        self.handed_over.clear();
        self.lost = None;

        assert_eq!(
            self.resolver.poll_timeout().is_some(),
            !self.live.is_empty() || !self.open.is_empty(),
            "a timer exactly while queries are pending or connections open"
        );
        out
    }

    /// A length-prefixed query on a plain TCP connection. Its message ID
    /// names the query if it went over UDP before; otherwise the query
    /// went straight to an open connection, and its question names its
    /// group, as long as the name was asked for as an absolute name. A
    /// new message ID for the group means a new budget, as for datagrams.
    fn stream_write(&mut self, t: &Transmit, free: bool) {
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
        let id = request.metadata.id;
        let asked = request.queries.first().map(|q| {
            (
                q.name().to_ascii().to_ascii_lowercase(),
                u16::from(q.query_type()),
            )
        });
        let group = self
            .by_message_id
            .get(&id)
            .cloned()
            .or(asked)
            .expect("stream query without a question");
        assert!(
            self.groups.contains_key(&group),
            "stream query for {group:?}, which has no live query"
        );
        self.asks(&group, &request);
        let previous = self.message_id.insert(group.clone(), id);
        let leader = self.groups.get(&group).and_then(|m| m.first()).copied();
        if let (None, Some(leader)) = (previous, leader) {
            // The group's first send, from its leader: its earliest query.
            self.sender.entry(group.clone()).or_insert(leader);
        }
        if previous.is_some_and(|previous| previous != id) {
            // A new search candidate, on an open connection.
            self.restart(&group);
            self.count(&group, t.destination, false, false);
        } else if self.handed_over.remove(&group) {
            // The heir of a sender cancelled in this step sends the attempt
            // again on the connection opened since: outside `max_sends`,
            // but not outside the per-server limit.
            self.count_per_server(&group, t.destination, false);
        } else {
            self.count(&group, t.destination, false, free);
        }
        self.by_message_id.insert(id, group);
        self.remember(t, request);
    }

    /// `group` sent a message with a new message ID: a new budget, for a
    /// new search candidate. Queries for absolute names (`max_sends`) have
    /// only one, and never start over.
    fn restart(&mut self, group: &Group) {
        assert!(
            self.max_sends.is_none(),
            "{group:?} started over with a new message ID"
        );
        self.sends.remove(group);
        self.per_server.retain(|(g, _, _), _| g != group);
    }

    /// `group` sends `request`: nothing may be sent for its question while
    /// a failure is cached for it.
    fn asks(&mut self, group: &Group, request: &Message) {
        let Some(question) = request.queries.first() else {
            return;
        };
        let question = (
            question.name().to_ascii().to_ascii_lowercase(),
            u16::from(question.query_type()),
        );
        if let Some(at) = self.failed.get(&question) {
            assert!(
                self.now >= *at + self.failure_cache,
                "{question:?} sent {:?} after it failed",
                self.now - *at
            );
        }
        self.question.insert(group.clone(), question);
    }

    /// Count a send, towards `max_sends` too unless it is `free`.
    fn count(&mut self, group: &Group, to: SocketAddr, datagram: bool, free: bool) {
        if !free {
            let sends = self.sends.entry(group.clone()).or_default();
            *sends += 1;
            if let Some(max) = self.max_sends {
                assert!(*sends <= max, "{group:?} sent more than {max} times");
            }
        }
        self.count_per_server(group, to, datagram);
    }

    fn count_per_server(&mut self, group: &Group, to: SocketAddr, datagram: bool) {
        let sends = self
            .per_server
            .entry((group.clone(), to, datagram))
            .or_default();
        *sends += 1;
        if self.max_sends.is_some() {
            assert!(
                *sends <= 3,
                "{group:?} sent a fourth time to {to} over one transport"
            );
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

/// The name, as sent and lowercased, and record type of a message.
type Question = (String, u16);

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

/// The answer a well-behaved recursive server would give to `request`, with
/// `code`. Only `NOERROR` carries an address.
pub fn reply(request: &Message, code: ResponseCode) -> Message {
    let mut response = Message::response(request.metadata.id, request.metadata.op_code);
    response.metadata.recursion_available = true;
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

/// Add an SOA record with `ttl` as its TTL and MINIMUM to `response`'s
/// authority section, as in a negative answer the resolver caches (RFC
/// 2308 §5).
pub fn add_soa(response: &mut Message, ttl: u32) {
    let zone = Name::root();
    let mname = Name::from_ascii("a.root-servers.net.").unwrap_or_else(|_| Name::root());
    let rname = Name::from_ascii("nstld.verisign-grs.com.").unwrap_or_else(|_| Name::root());
    let soa = SOA::new(mname, rname, 1, 1800, 900, 604_800, ttl);
    response.add_authority(Record::from_rdata(zone, ttl, RData::SOA(soa)));
}

/// Add an NS record to `response`'s authority section, as in a referral
/// (RFC 1034 §4.3.1).
pub fn add_ns(response: &mut Message) {
    let zone = Name::root();
    let server = Name::from_ascii("a.root-servers.net.").unwrap_or_else(|_| Name::root());
    response.add_authority(Record::from_rdata(zone, 300, RData::NS(NS(server))));
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

/// Drop the last `n % 16` bytes of `bytes`, so its last records may no
/// longer decode while its header and question still do.
pub fn cut(bytes: &mut Vec<u8>, n: u8) {
    bytes.truncate(bytes.len().saturating_sub(usize::from(n % 16)));
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
