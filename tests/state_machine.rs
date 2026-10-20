//! Random sequences of driver calls, checking invariants after every step.
//!
//! The resolver only ever sees `query`, `handle_datagram`,
//! `handle_udp_error`, `handle_stream_data`, `handle_stream_closed`,
//! `handle_stream_error`, `handle_timeout`, `cancel` and `shutdown`, so any
//! sequence of those is a valid input. Replies and send errors go to recent transmits
//! over their transport, replies often tampered with or cut short and, over
//! TCP, split into two chunks; there is raw garbage too.
//!
//! [`Model`] generates the calls from what a driver knows without asking the
//! resolver: how many queries it started, and whether it sent a reply that
//! can move a query to TCP. Which queries are still in flight and which
//! connections are open depend on how the resolver took the replies, so the
//! model only bounds them from above, and a call is generated, or kept while
//! shrinking, unless it surely does nothing. [`Harness`] checks that the
//! bound holds. Cancels and garbage pick their query in the harness, among
//! the ones in flight when the call is made, so that dropping an earlier
//! call while shrinking doesn't change which query a later one hits.
//!
//! Queries for the same name join each other (see "How a query moves on" in
//! the crate docs), so the names come from a small pool and the harness
//! tracks the queries in flight for each name as one group, as the fuzz
//! harness does.
//!
//! The harness also models the cache (see "Cache" in the crate docs) from
//! the outcomes it sees: a name whose queries failed has a failure cached
//! for one to four seconds, depending on the backoff, unless they failed
//! when a cancel handed them over with no server left, and one whose answer was
//! NXDOMAIN or NODATA with an SOA record, which some replies carry, has it
//! cached for that record's three seconds. Nothing may be sent for a name
//! while either is cached (RFC 9520 §3.2), a query for it is answered from
//! the cache at once, with the SOA's TTL counted down (RFC 2308 §6), and a
//! query for a name with nothing cached is sent.

use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::io::ErrorKind;
use std::net::SocketAddr;
use std::num::NonZeroUsize;
use std::time::{Duration, Instant};

use crate::common::*;
use hickory_proto::op::ResponseCode;
use hickory_proto::rr::{Name, RecordType};
use proptest::prelude::*;
use proptest::sample::Index;
use proptest::strategy::Union;
use proptest_state_machine::{ReferenceStateMachine, StateMachineTest, prop_state_machine};
use sansio_dns::{ConnectionId, Event, FailureCache, QueryId, Resolver, Transmit, Transport};

/// Names to query. Few, so that queries often join one in flight.
const NAMES: usize = 3;

/// Attempts per query: four per server, more than RFC 9520 §3.1 lets a
/// query send over UDP, so that limit is reached.
const ATTEMPTS: usize = 8;

/// Sends of one search candidate to one server over one transport, a
/// hand-over's resend included (RFC 9520 §3.1).
const MAX_SENDS_PER_SERVER: usize = 3;

/// Datagrams one query may cause: three to each of the two servers. One per
/// attempt plus one EDNS downgrade would allow more.
const MAX_DATAGRAMS: usize = 2 * MAX_SENDS_PER_SERVER;

/// Datagrams and stream writes one search candidate may cause: one per
/// attempt, plus switching to TCP, dropping EDNS and one free resend. A
/// cancel hand-over's resend and the resends after a lost connection don't
/// count (see `Group`): a connection that answered since a query was
/// written gives it a free resend each time it is lost, bounded only by
/// `MAX_SENDS_PER_SERVER`.
const MAX_SENDS: usize = ATTEMPTS + 3;

/// The TTL and MINIMUM of the SOA record in the replies that carry one, so
/// the negative answer is cached for that many seconds (RFC 2308 §5).
const NEGATIVE_TTL: u32 = 3;

/// How long a failure is cached at least and at most: `FailureCache`'s
/// default shortest time, and a longest short enough for the backoff to
/// reach it.
const FAILURE_CACHED: (Duration, Duration) = (Duration::from_secs(1), Duration::from_secs(4));

/// Transmits kept for replies, so late replies to old ones still happen.
const RECENT: usize = 16;

#[derive(Clone, Debug)]
enum Reply {
    Answer,
    Code(ResponseCode),
    FormErrWithoutOpt,
    /// `NOERROR` without an answer.
    NoData,
    /// NXDOMAIN or NODATA with an SOA record, which the resolver caches.
    Negative {
        nxdomain: bool,
    },
    /// `NOERROR` without an answer, AA or RA, with NS records in authority.
    Referral,
    Truncated,
    /// An answer whose last record is cut short, with or without TC.
    Cut {
        truncated: bool,
    },
    WrongId,
    WrongSource,
    /// An answer without a question section, which only a stream matches
    /// (RFC 7766 §7).
    NoQuestion,
    BitFlip {
        byte: usize,
        bit: u8,
    },
}

#[derive(Clone, Debug)]
enum Op {
    Query {
        name: usize,
    },
    Reply {
        to: usize,
        reply: Reply,
        split: usize,
    },
    /// Sending a recent datagram failed; nothing for a stream transmit.
    UdpError {
        to: usize,
    },
    Elapse {
        millis: u16,
    },
    Timeout,
    /// Cancel a query picked by [`Harness::pick`].
    Cancel {
        query: Index,
    },
    /// Empty the cache, as after a network change.
    Flush,
    StreamClosed {
        which: usize,
        failed: bool,
    },
    /// Garbage on the socket of a query picked by [`Harness::pick`].
    Garbage {
        query: Index,
        bytes: Vec<u8>,
    },
    Shutdown,
}

fn reply_strategy() -> impl Strategy<Value = Reply> {
    prop_oneof![
        3 => Just(Reply::Answer),
        1 => prop::sample::select(vec![
            ResponseCode::NXDomain,
            ResponseCode::ServFail,
            ResponseCode::Refused,
            ResponseCode::NotImp,
            ResponseCode::FormErr,
            ResponseCode::NotAuth,
            ResponseCode::Unknown(11),
            ResponseCode::BADCOOKIE,
        ])
        .prop_map(Reply::Code),
        1 => Just(Reply::FormErrWithoutOpt),
        1 => prop_oneof![Just(Reply::NoData), Just(Reply::Referral)],
        1 => any::<bool>().prop_map(|nxdomain| Reply::Negative { nxdomain }),
        1 => Just(Reply::Truncated),
        1 => any::<bool>().prop_map(|truncated| Reply::Cut { truncated }),
        1 => Just(Reply::WrongId),
        1 => Just(Reply::WrongSource),
        1 => Just(Reply::NoQuestion),
        1 => (any::<usize>(), 0u8..8).prop_map(|(byte, bit)| Reply::BitFlip { byte, bit }),
    ]
}

/// The bytes and source address a server would reply with.
fn datagram(sent: &Transmit, kind: &Reply) -> (SocketAddr, Vec<u8>) {
    let answer = reply(sent);
    let bytes = match kind {
        Reply::Answer | Reply::WrongSource | Reply::BitFlip { .. } => encode(&answer),
        Reply::Code(code) => encode(&with_code(answer, *code)),
        Reply::FormErrWithoutOpt => {
            let mut m = with_code(answer, ResponseCode::FormErr);
            m.edns = None;
            encode(&m)
        }
        Reply::NoData => encode(&no_data(answer)),
        Reply::Negative { nxdomain } => {
            let negative = if *nxdomain {
                with_code(answer, ResponseCode::NXDomain)
            } else {
                no_data(answer)
            };
            encode(&with_soa_ttls(negative, NEGATIVE_TTL, NEGATIVE_TTL))
        }
        Reply::Referral => encode(&referral(answer)),
        Reply::Cut { truncated } => {
            let mut m = answer;
            m.metadata.truncation = *truncated;
            cut(&encode(&m))
        }
        Reply::Truncated => {
            let mut m = answer;
            m.metadata.truncation = true;
            encode(&m)
        }
        Reply::WrongId => {
            let mut m = answer;
            m.metadata.id = m.metadata.id.wrapping_add(1);
            encode(&m)
        }
        Reply::NoQuestion => {
            let mut m = answer;
            m.queries.clear();
            encode(&m)
        }
    };
    let bytes = match kind {
        Reply::BitFlip { byte, bit } => {
            let mut b = bytes;
            let i = byte % b.len();
            b[i] ^= 1 << bit;
            b
        }
        _ => bytes,
    };
    let from = match kind {
        Reply::WrongSource => SocketAddr::new(sent.destination.ip(), 5353),
        _ => sent.destination,
    };
    (from, bytes)
}

/// What the driver knows without asking the resolver.
#[derive(Clone, Debug, Default)]
struct Model {
    /// How many queries were started.
    queries: usize,
    /// Whether a reply was sent that can switch a query to TCP, so that a
    /// connection may be open: one with TC set, decodable or not. A flipped
    /// bit can set the TC flag too.
    streams: bool,
}

impl ReferenceStateMachine for Model {
    type State = Self;
    type Transition = Op;

    fn init_state() -> BoxedStrategy<Self> {
        Just(Self::default()).boxed()
    }

    fn transitions(model: &Self) -> BoxedStrategy<Op> {
        let mut ops = vec![
            (2, (0..NAMES).prop_map(|name| Op::Query { name }).boxed()),
            (
                1,
                any::<u16>()
                    .prop_map(|millis| Op::Elapse { millis })
                    .boxed(),
            ),
            (1, Just(Op::Timeout).boxed()),
            (1, Just(Op::Shutdown).boxed()),
            (1, Just(Op::Flush).boxed()),
        ];
        if model.queries > 0 {
            ops.push((
                4,
                (any::<usize>(), reply_strategy(), any::<usize>())
                    .prop_map(|(to, reply, split)| Op::Reply { to, reply, split })
                    .boxed(),
            ));
            ops.push((1, any::<usize>().prop_map(|to| Op::UdpError { to }).boxed()));
            ops.push((
                1,
                any::<Index>()
                    .prop_map(|query| Op::Cancel { query })
                    .boxed(),
            ));
            ops.push((
                1,
                (any::<Index>(), prop::collection::vec(any::<u8>(), 0..64))
                    .prop_map(|(query, bytes)| Op::Garbage { query, bytes })
                    .boxed(),
            ));
        }
        if model.streams {
            ops.push((
                1,
                (any::<usize>(), any::<bool>())
                    .prop_map(|(which, failed)| Op::StreamClosed { which, failed })
                    .boxed(),
            ));
        }
        Union::new_weighted(ops).boxed()
    }

    fn preconditions(model: &Self, op: &Op) -> bool {
        match op {
            Op::Query { name } => *name < NAMES,
            Op::Elapse { .. } | Op::Timeout | Op::Shutdown | Op::Flush => true,
            Op::Reply { .. } | Op::UdpError { .. } | Op::Cancel { .. } | Op::Garbage { .. } => {
                model.queries > 0
            }
            Op::StreamClosed { .. } => model.streams,
        }
    }

    fn apply(mut model: Self, op: &Op) -> Self {
        match op {
            Op::Query { .. } => model.queries += 1,
            Op::Reply {
                reply: Reply::Truncated | Reply::Cut { truncated: true } | Reply::BitFlip { .. },
                ..
            } => model.streams = true,
            Op::Reply { .. }
            | Op::UdpError { .. }
            | Op::Elapse { .. }
            | Op::Timeout
            | Op::Cancel { .. }
            | Op::StreamClosed { .. }
            | Op::Garbage { .. }
            | Op::Shutdown
            | Op::Flush => {}
        }
        model
    }
}

/// What one name's queries in flight have sent since the first of them
/// started. They never start over: when the first one fails, they all do.
#[derive(Debug, Default)]
struct Group {
    /// The query whose socket the group's datagrams come from: the first
    /// one, or its heir once it was cancelled.
    sender: Option<QueryId>,
    /// Whether the sender was cancelled in this step, so that its heir may
    /// send the attempt again for free.
    handed_over: bool,
    /// The message ID of every message the group sends.
    message_id: Option<u16>,
    datagrams: usize,
    sends: usize,
    /// Sends to each server, over UDP (`true`) or TCP.
    per_server: BTreeMap<(SocketAddr, bool), usize>,
}

impl Group {
    /// Count a send to `to`, towards `MAX_SENDS` too unless it is `free`.
    fn count(&mut self, to: SocketAddr, datagram: bool, free: bool) {
        if !free {
            self.sends += 1;
            assert!(self.sends <= MAX_SENDS, "too many sends for one name");
        }
        if datagram {
            self.datagrams += 1;
            assert!(
                self.datagrams <= MAX_DATAGRAMS,
                "too many datagrams for one name"
            );
        }
        self.count_per_server(to, datagram);
    }

    fn count_per_server(&mut self, to: SocketAddr, datagram: bool) {
        let sends = self.per_server.entry((to, datagram)).or_default();
        *sends += 1;
        assert!(
            *sends <= MAX_SENDS_PER_SERVER,
            "a fourth send to one server over one transport"
        );
    }
}

/// What the cache holds for a name, as the outcomes seen so far imply.
#[derive(Clone, Copy, Debug)]
enum Cached {
    /// Its queries failed at this instant.
    Failed(Instant),
    /// Its answer was a negative one with an SOA record, stored at this
    /// instant.
    Negative(Instant),
}

/// Driver state plus everything observed so far.
struct Harness {
    resolver: Resolver,
    now: Instant,
    /// The id of each query, in the order the model started them.
    started: Vec<QueryId>,
    name_of: BTreeMap<QueryId, usize>,
    live: BTreeSet<QueryId>,
    done: BTreeSet<QueryId>,
    datagrams: BTreeMap<QueryId, usize>,
    /// Open connections and their servers.
    open: BTreeMap<ConnectionId, SocketAddr>,
    ever_opened: BTreeSet<ConnectionId>,
    recent: VecDeque<Transmit>,
    /// By name, for names with queries in flight.
    groups: BTreeMap<usize, Group>,
    /// The message ID of a datagram just answered with TC set: a stream
    /// write of that ID in the same step means the query switched to TCP,
    /// to the same server or, when that one had no room left (RFC 9520
    /// §3.1), to the next.
    truncated: Option<u16>,
    /// Message IDs that switched to TCP since their name's query last
    /// started, and that name: such a query never goes back to UDP (RFC
    /// 1123 §6.1.3.2), while one that went over a stream only because a
    /// connection was open may.
    switched: BTreeMap<u16, usize>,
    /// The server of a connection lost in this step: the sends to it are
    /// resends, which `MAX_SENDS` leaves out.
    lost: Option<SocketAddr>,
    /// By name, what the cache holds.
    cached: BTreeMap<usize, Cached>,
    /// The query started in this step, its name, and whether it found the
    /// name's queries in flight and joined them.
    asked: Option<(QueryId, usize, bool)>,
    /// The name of a query this step cancelled and handed over: its heir
    /// fails in this step only with no server left to send to, which isn't
    /// cached.
    handed_over: Option<usize>,
}

impl Harness {
    fn new() -> Self {
        Self {
            resolver: {
                let mut config = config();
                config.attempts = NonZeroUsize::new(ATTEMPTS).unwrap();
                config.failure_cache = FailureCache::new(FAILURE_CACHED.0, FAILURE_CACHED.1);
                Resolver::new(config)
            },
            now: Instant::now(),
            started: Vec::new(),
            name_of: BTreeMap::new(),
            live: BTreeSet::new(),
            done: BTreeSet::new(),
            datagrams: BTreeMap::new(),
            open: BTreeMap::new(),
            ever_opened: BTreeSet::new(),
            recent: VecDeque::new(),
            groups: BTreeMap::new(),
            truncated: None,
            switched: BTreeMap::new(),
            lost: None,
            cached: BTreeMap::new(),
            asked: None,
            handed_over: None,
        }
    }

    fn call(&mut self, op: Op) {
        match op {
            Op::Query { name } => {
                let text = format!("q{name}.example.");
                let joined = self.has_live(name);
                let id = self
                    .resolver
                    .query(Name::from_ascii(text).unwrap(), RecordType::A, self.now)
                    .unwrap();
                self.asked = Some((id, name, joined));
                self.started.push(id);
                self.name_of.insert(id, name);
                self.live.insert(id);
            }
            Op::Reply { to, reply, split } => {
                let sent = &self.recent[to % self.recent.len()];
                let (from, bytes) = datagram(sent, &reply);
                match sent.transport {
                    Transport::Udp(q) => {
                        if matches!(reply, Reply::Truncated | Reply::Cut { truncated: true }) {
                            self.truncated = Some(decode(sent).metadata.id);
                        }
                        self.resolver.handle_datagram(q, from, &bytes, self.now);
                    }
                    Transport::TcpConnect(c) | Transport::TcpWrite(c) => {
                        let framed = frame(&bytes);
                        let (a, b) = framed.split_at(split % (framed.len() + 1));
                        self.resolver.handle_stream_data(c, a, self.now);
                        self.resolver.handle_stream_data(c, b, self.now);
                    }
                    Transport::TcpClose(_) => {}
                }
            }
            Op::UdpError { to } => {
                let sent = &self.recent[to % self.recent.len()];
                if let Transport::Udp(q) = sent.transport {
                    self.resolver.handle_udp_error(
                        q,
                        sent.destination,
                        ErrorKind::NetworkUnreachable,
                        self.now,
                    );
                }
            }
            Op::Elapse { millis } => {
                self.now += Duration::from_millis(u64::from(millis));
                self.resolver.handle_timeout(self.now);
            }
            Op::Timeout => {
                if let Some(deadline) = self.resolver.poll_timeout() {
                    self.now = self.now.max(deadline);
                    self.resolver.handle_timeout(self.now);
                }
            }
            Op::Cancel { query } => self.cancel(self.pick(query)),
            Op::Flush => {
                self.resolver.flush_cache();
                self.cached.clear();
            }
            Op::StreamClosed { which, failed } => {
                if let Some(&c) = self.open.keys().nth(which % self.open.len().max(1)) {
                    self.lost = self.open.remove(&c);
                    if failed {
                        self.resolver
                            .handle_stream_error(c, ErrorKind::ConnectionReset, self.now);
                    } else {
                        self.resolver.handle_stream_closed(c, self.now);
                    }
                }
            }
            Op::Garbage { query, bytes } => {
                let id = self.pick(query);
                self.resolver.handle_datagram(id, S1, &bytes, self.now);
            }
            // Every query is over without an event, and every connection
            // closes. The cache stays.
            Op::Shutdown => {
                self.resolver.shutdown();
                self.done.append(&mut self.live);
                self.groups.clear();
                self.switched.clear();
            }
        }
    }

    /// Cancel `id`, as the driver does when its lookup is dropped.
    fn cancel(&mut self, id: QueryId) {
        self.resolver.cancel(id, self.now);
        self.done.insert(id);
        if self.live.remove(&id) {
            let name = self.name_of[&id];
            let heir = self.first_live(name);
            if let Some(group) = self.groups.get_mut(&name)
                && group.sender == Some(id)
            {
                group.sender = heir;
                group.handed_over = true;
                if heir.is_some() {
                    self.handed_over = Some(name);
                }
            }
            self.leave(name);
        }
    }

    /// The query `index` picks among those in flight, or among all started
    /// ones if none is.
    fn pick(&self, index: Index) -> QueryId {
        let live: Vec<QueryId> = self
            .started
            .iter()
            .copied()
            .filter(|q| self.live.contains(q))
            .collect();
        let pool = if live.is_empty() {
            &self.started
        } else {
            &live
        };
        pool[index.index(pool.len())]
    }

    fn has_live(&self, name: usize) -> bool {
        self.live.iter().any(|q| self.name_of[q] == name)
    }

    /// The earliest started of `name`'s queries in flight. Followers are
    /// kept in join order, so this is the one a cancelled leader hands over
    /// to.
    fn first_live(&self, name: usize) -> Option<QueryId> {
        self.started
            .iter()
            .copied()
            .find(|q| self.live.contains(q) && self.name_of[q] == name)
    }

    /// Forget `name`'s group once none of its queries is in flight.
    fn leave(&mut self, name: usize) {
        if !self.has_live(name) {
            self.groups.remove(&name);
            self.switched.retain(|_, n| *n != name);
        }
    }

    /// Drain the resolver's transmits and events, checking each.
    fn observe(&mut self) {
        // Names something was sent for in this step.
        let mut sent = BTreeSet::new();
        while let Some(t) = self.resolver.poll_transmit() {
            assert!(t.destination == S1 || t.destination == S2, "unknown server");
            let free = self.lost == Some(t.destination);
            match t.transport {
                Transport::Udp(q) => {
                    assert!(self.live.contains(&q), "datagram for a finished query");
                    assert!(
                        !self.open.values().any(|&server| server == t.destination),
                        "a datagram to a server with an open connection"
                    );
                    let id = decode(&t).metadata.id;
                    let name = self.name_of[&q];
                    sent.insert(name);
                    let group = self.groups.entry(name).or_default();
                    let previous = group.sender.replace(q);
                    assert!(
                        previous.is_none_or(|p| p == q) || group.handed_over,
                        "another query sent for a name in flight"
                    );
                    assert!(
                        group.message_id.is_none_or(|m| m == id),
                        "a query for a name in flight started over"
                    );
                    if group.handed_over {
                        // The heir of a sender cancelled in this step sends
                        // the attempt again for free, or its next one.
                        group.handed_over = false;
                        group.count_per_server(t.destination, true);
                    } else {
                        group.count(t.destination, true, free);
                    }
                    group.message_id = Some(id);
                    let count = self.datagrams.entry(q).or_default();
                    *count += 1;
                    assert!(*count <= MAX_DATAGRAMS, "too many datagrams for one query");
                    assert!(
                        !self.switched.contains_key(&id),
                        "a query back on UDP after a truncated answer"
                    );
                }
                Transport::TcpConnect(c) | Transport::TcpWrite(c) => {
                    if matches!(t.transport, Transport::TcpConnect(_)) {
                        assert!(self.ever_opened.insert(c), "connection id reused");
                        assert!(
                            !self.open.values().any(|&server| server == t.destination),
                            "a second connection to one server"
                        );
                        self.open.insert(c, t.destination);
                    }
                    assert!(self.open.contains_key(&c), "write on a closed connection");
                    assert!(!self.live.is_empty(), "query written with none pending");
                    let len = usize::from(u16::from_be_bytes([t.payload[0], t.payload[1]]));
                    assert_eq!(len + 2, t.payload.len(), "wrong TCP length prefix");
                    let request = decode(&t);
                    let id = request.metadata.id;
                    let name = name_of(&request);
                    sent.insert(name);
                    assert!(self.has_live(name), "stream write for no query in flight");
                    if self.truncated == Some(id) {
                        self.switched.insert(id, name);
                    }
                    let leader = self.first_live(name);
                    let group = self.groups.entry(name).or_default();
                    if group.message_id.is_none() {
                        // The group's first send: from its leader, the
                        // earliest of its queries in flight.
                        group.sender = group.sender.or(leader);
                    }
                    assert!(
                        group.message_id.is_none_or(|m| m == id),
                        "a query for a name in flight started over"
                    );
                    if group.handed_over {
                        // The heir of a sender cancelled in this step sends
                        // the attempt again on a connection opened since.
                        group.handed_over = false;
                        group.count_per_server(t.destination, false);
                    } else {
                        group.count(t.destination, false, free);
                    }
                    group.message_id = Some(id);
                }
                Transport::TcpClose(c) => {
                    assert!(
                        self.open.remove(&c).is_some(),
                        "closing a connection that isn't open"
                    );
                    assert!(t.payload.is_empty(), "close with a payload");
                    continue;
                }
            }
            if self.recent.len() == RECENT {
                self.recent.pop_front();
            }
            self.recent.push_back(t);
        }
        self.truncated = None;
        self.lost = None;

        for name in &sent {
            assert!(
                self.cached_at(*name).is_none(),
                "sent for a name while the cache holds it"
            );
        }

        let asked = self.asked.take();
        let mut finished = BTreeMap::new();
        let mut answered = None;
        while let Some(event) = self.resolver.poll_event() {
            let id = match &event {
                Event::Response { query, .. } | Event::Failed { query, .. } => *query,
            };
            assert!(self.done.insert(id), "second event, or event after cancel");
            assert!(self.live.remove(&id), "event for unknown query");
            let name = self.name_of[&id];
            if asked.is_some_and(|(q, _, joined)| q == id && !joined) {
                answered = Some(event);
            } else {
                finished.insert(name, event);
            }
            self.leave(name);
        }
        if let Some((id, name, false)) = asked {
            self.check_cache(id, name, answered.as_ref(), sent.contains(&name));
        }
        let handed_over = self.handed_over.take();
        for (name, event) in finished {
            assert!(
                !self.has_live(name),
                "an event for some queries of a name, but not the others"
            );
            if handed_over != Some(name) {
                self.remember(name, &event);
            }
        }
        for group in self.groups.values_mut() {
            group.handed_over = false;
        }
    }

    /// What the cache surely holds for `name` now: a failure for at least
    /// a second, a negative answer for `NEGATIVE_TTL` seconds.
    fn cached_at(&self, name: usize) -> Option<Cached> {
        self.cached
            .get(&name)
            .copied()
            .filter(|cached| match cached {
                Cached::Failed(at) => self.now < *at + FAILURE_CACHED.0,
                Cached::Negative(at) => self.now < *at + Duration::from_secs(NEGATIVE_TTL.into()),
            })
    }

    /// The query `id` for `name`, which joined no query in flight, got
    /// `event` in its own step, or none, and something was sent for the
    /// name or not: as the cache says.
    fn check_cache(&self, id: QueryId, name: usize, event: Option<&Event>, sent: bool) {
        match (self.cached_at(name), event) {
            (Some(Cached::Failed(_)), Some(Event::Failed { .. })) => {}
            (Some(Cached::Negative(at)), Some(Event::Response { response, .. })) => {
                let soa = response
                    .authorities
                    .iter()
                    .find(|r| r.record_type() == RecordType::SOA)
                    .map(|r| r.ttl);
                let elapsed = u32::try_from(self.now.duration_since(at).as_secs()).unwrap();
                assert_eq!(
                    soa,
                    Some(NEGATIVE_TTL - elapsed),
                    "SOA TTL not counted down"
                );
            }
            (Some(_), _) => panic!("a cached name not answered from the cache: {event:?}"),
            (None, Some(Event::Failed { .. })) => {
                // A failure cached longer than the minimum, by the backoff.
                let Some(Cached::Failed(at)) = self.cached.get(&name) else {
                    panic!("a failure from no cached one");
                };
                assert!(
                    self.now < *at + FAILURE_CACHED.1,
                    "a failure cached for longer than the maximum"
                );
            }
            (None, Some(Event::Response { .. })) => panic!("a response from no cached one"),
            (None, None) => assert!(
                sent && self.live.contains(&id),
                "a query for a name with nothing cached wasn't sent"
            ),
        }
        assert!(
            event.is_none() || !sent,
            "sent for a query answered from the cache"
        );
    }

    /// The queries for `name` ended with `event`, from the network: the
    /// cache holds it if it is a failure or a negative answer with an SOA
    /// record, and any other answer ends what it held.
    fn remember(&mut self, name: usize, event: &Event) {
        let cached = match event {
            Event::Failed { .. } => Some(Cached::Failed(self.now)),
            Event::Response { response, .. } => {
                let negative = response.answers.is_empty()
                    && !response.metadata.truncation
                    && response
                        .authorities
                        .iter()
                        .any(|r| r.record_type() == RecordType::SOA);
                negative.then_some(Cached::Negative(self.now))
            }
        };
        match cached {
            Some(cached) => self.cached.insert(name, cached),
            None => self.cached.remove(&name),
        };
    }
}

/// Which of the `NAMES` a query asks for: `q{n}.example.`.
fn name_of(request: &hickory_proto::op::Message) -> usize {
    let name = request.queries[0].name().to_ascii();
    name.trim_start_matches('q')
        .trim_end_matches(".example.")
        .parse()
        .unwrap()
}

impl StateMachineTest for Harness {
    type SystemUnderTest = Self;
    type Reference = Model;

    fn init_test(_: &Model) -> Self {
        Self::new()
    }

    fn apply(mut harness: Self, _: &Model, op: Op) -> Self {
        harness.call(op);
        harness.observe();
        harness
    }

    fn check_invariants(harness: &Self, model: &Model) {
        let timeout = harness.resolver.poll_timeout();
        assert_eq!(
            timeout.is_some(),
            !harness.live.is_empty() || !harness.open.is_empty(),
            "timer iff queries pending or connections open"
        );
        assert!(
            timeout.is_none_or(|t| t > harness.now),
            "deadline already passed"
        );
        assert_eq!(
            harness.recent.is_empty(),
            model.queries == 0,
            "transmits to reply to iff a query was started"
        );
        assert!(
            harness.open.is_empty() || model.streams,
            "a connection opened without a reply that can switch to TCP"
        );
    }
}

prop_state_machine! {
    #[test]
    fn invariants_hold_for_any_call_sequence(sequential 1..64 => Harness);
}
