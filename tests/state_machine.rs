//! Random sequences of driver calls, checking invariants after every step.
//!
//! The resolver only ever sees `query`, `handle_datagram`,
//! `handle_stream_data`, `handle_stream_closed`, `handle_stream_error`,
//! `handle_timeout` and `cancel`, so any sequence of those is a valid input.
//! Replies go to recent transmits over their transport, often tampered with
//! and, over TCP, split into two chunks; there is raw garbage too.
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

use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::io::ErrorKind;
use std::net::SocketAddr;
use std::time::{Duration, Instant};

use crate::common::*;
use hickory_proto::op::ResponseCode;
use hickory_proto::rr::{Name, RecordType};
use proptest::prelude::*;
use proptest::sample::Index;
use proptest::strategy::Union;
use proptest_state_machine::{ReferenceStateMachine, StateMachineTest, prop_state_machine};
use sansio_dns::{ConnectionId, Event, QueryId, Resolver, Transmit, Transport};

/// Names to query. Few, so that queries often join one in flight.
const NAMES: usize = 3;

/// Datagrams one query may cause: one per attempt, plus one EDNS downgrade.
const MAX_DATAGRAMS: usize = 2 * 2 + 1;

/// Datagrams and stream writes one search candidate may cause: one per
/// attempt, plus switching to TCP, dropping EDNS and one free resend. A
/// cancel hand-over's resend and a late joiner's fresh start don't count
/// (see `Group`).
const MAX_SENDS: usize = 2 * 2 + 3;

/// Transmits kept for replies, so late replies to old ones still happen.
const RECENT: usize = 16;

#[derive(Clone, Debug)]
enum Reply {
    Answer,
    Code(ResponseCode),
    FormErrWithoutOpt,
    Truncated,
    WrongId,
    WrongSource,
    BitFlip { byte: usize, bit: u8 },
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
    Elapse {
        millis: u16,
    },
    Timeout,
    /// Cancel a query picked by [`Harness::pick`].
    Cancel {
        query: Index,
    },
    StreamClosed {
        which: usize,
        failed: bool,
    },
    /// Garbage on the socket of a query picked by [`Harness::pick`].
    Garbage {
        query: Index,
        bytes: Vec<u8>,
    },
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
        ])
        .prop_map(Reply::Code),
        1 => Just(Reply::FormErrWithoutOpt),
        1 => Just(Reply::Truncated),
        1 => Just(Reply::WrongId),
        1 => Just(Reply::WrongSource),
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
    /// connection may be open. A flipped bit can set the TC flag too.
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
        ];
        if model.queries > 0 {
            ops.push((
                4,
                (any::<usize>(), reply_strategy(), any::<usize>())
                    .prop_map(|(to, reply, split)| Op::Reply { to, reply, split })
                    .boxed(),
            ));
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
            Op::Elapse { .. } | Op::Timeout => true,
            Op::Reply { .. } | Op::Cancel { .. } | Op::Garbage { .. } => model.queries > 0,
            Op::StreamClosed { .. } => model.streams,
        }
    }

    fn apply(mut model: Self, op: &Op) -> Self {
        match op {
            Op::Query { .. } => model.queries += 1,
            Op::Reply {
                reply: Reply::Truncated | Reply::BitFlip { .. },
                ..
            } => model.streams = true,
            Op::Reply { .. }
            | Op::Elapse { .. }
            | Op::Timeout
            | Op::Cancel { .. }
            | Op::StreamClosed { .. }
            | Op::Garbage { .. } => {}
        }
        model
    }
}

/// What one name's queries in flight have sent since the first of them
/// started, or since they started over.
#[derive(Debug, Default)]
struct Group {
    /// The query whose socket the group's datagrams come from: the one that
    /// last sent, or its heir once it was cancelled. Another one may only
    /// take over after the sender failed in the same step (a query that
    /// joined later then starts over).
    sender: Option<QueryId>,
    /// Whether the sender was cancelled in this step, so that its heir may
    /// send the attempt again for free.
    handed_over: bool,
    datagrams: usize,
    sends: usize,
}

impl Group {
    fn count(&mut self, datagram: bool) {
        self.sends += 1;
        assert!(self.sends <= MAX_SENDS, "too many sends for one name");
        if datagram {
            self.datagrams += 1;
            assert!(
                self.datagrams <= MAX_DATAGRAMS,
                "too many datagrams for one name"
            );
        }
    }
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
    open: BTreeSet<ConnectionId>,
    ever_opened: BTreeSet<ConnectionId>,
    recent: VecDeque<Transmit>,
    /// By name, for names with queries in flight.
    groups: BTreeMap<usize, Group>,
    /// The name each message ID was sent for over UDP, which tells the
    /// group of a stream write.
    by_message_id: BTreeMap<u16, usize>,
    /// Message IDs sent over a stream since their name's query last
    /// started, and that name: such a query never goes back to UDP, since a
    /// retry keeps the route.
    streamed: BTreeMap<u16, usize>,
}

impl Harness {
    fn new() -> Self {
        Self {
            resolver: resolver(),
            now: Instant::now(),
            started: Vec::new(),
            name_of: BTreeMap::new(),
            live: BTreeSet::new(),
            done: BTreeSet::new(),
            datagrams: BTreeMap::new(),
            open: BTreeSet::new(),
            ever_opened: BTreeSet::new(),
            recent: VecDeque::new(),
            groups: BTreeMap::new(),
            by_message_id: BTreeMap::new(),
            streamed: BTreeMap::new(),
        }
    }

    fn call(&mut self, op: Op) {
        match op {
            Op::Query { name } => {
                let text = format!("q{name}.example.");
                let id = self
                    .resolver
                    .query(Name::from_ascii(text).unwrap(), RecordType::A, self.now)
                    .unwrap();
                self.started.push(id);
                self.name_of.insert(id, name);
                self.live.insert(id);
            }
            Op::Reply { to, reply, split } => {
                let sent = &self.recent[to % self.recent.len()];
                let (from, bytes) = datagram(sent, &reply);
                match sent.transport {
                    Transport::Udp(q) => {
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
            Op::Cancel { query } => {
                let id = self.pick(query);
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
                    }
                    self.leave(name);
                }
            }
            Op::StreamClosed { which, failed } => {
                if let Some(&c) = self.open.iter().nth(which % self.open.len().max(1)) {
                    self.open.remove(&c);
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
            self.by_message_id.retain(|_, n| *n != name);
            self.streamed.retain(|_, n| *n != name);
        }
    }

    /// Drain the resolver's transmits and events, checking each.
    fn observe(&mut self) {
        // Names whose queries started over, and the sender before that.
        let mut started_over = Vec::new();
        while let Some(t) = self.resolver.poll_transmit() {
            assert!(t.destination == S1 || t.destination == S2, "unknown server");
            match t.transport {
                Transport::Udp(q) => {
                    assert!(self.live.contains(&q), "datagram for a finished query");
                    let count = self.datagrams.entry(q).or_default();
                    *count += 1;
                    assert!(*count <= MAX_DATAGRAMS, "too many datagrams for one query");
                    let name = self.name_of[&q];
                    let group = self.groups.entry(name).or_default();
                    match group.sender.replace(q) {
                        // The heir of a sender cancelled in this step sends
                        // the attempt again for free.
                        Some(heir) if heir == q && group.handed_over => {
                            group.handed_over = false;
                        }
                        Some(previous) if previous != q => {
                            started_over.push((name, previous));
                            // A new query with a new message ID; the old one's
                            // IDs may come up again for any query.
                            self.streamed.retain(|_, n| *n != name);
                            *group = Group {
                                sender: Some(q),
                                ..Group::default()
                            };
                            group.count(true);
                        }
                        _ => group.count(true),
                    }
                    let id = decode(&t).metadata.id;
                    assert!(
                        !self.streamed.contains_key(&id),
                        "a query back on UDP after a stream"
                    );
                    self.by_message_id.insert(id, name);
                }
                Transport::TcpConnect(c) | Transport::TcpWrite(c) => {
                    if matches!(t.transport, Transport::TcpConnect(_)) {
                        assert!(self.ever_opened.insert(c), "connection id reused");
                        self.open.insert(c);
                    }
                    assert!(self.open.contains(&c), "write on a closed connection");
                    assert!(!self.live.is_empty(), "query written with none pending");
                    let len = usize::from(u16::from_be_bytes([t.payload[0], t.payload[1]]));
                    assert_eq!(len + 2, t.payload.len(), "wrong TCP length prefix");
                    let id = decode(&t).metadata.id;
                    let name = self.by_message_id.get(&id);
                    if let Some(&name) = name {
                        self.streamed.insert(id, name);
                    }
                    let Some(group) = name.and_then(|name| self.groups.get_mut(name)) else {
                        panic!("stream write for no query in flight");
                    };
                    group.count(false);
                }
                Transport::TcpClose(c) => {
                    assert!(self.open.remove(&c), "closing a connection that isn't open");
                    assert!(t.payload.is_empty(), "close with a payload");
                    continue;
                }
            }
            if self.recent.len() == RECENT {
                self.recent.pop_front();
            }
            self.recent.push_back(t);
        }

        let mut finished = BTreeSet::new();
        while let Some(event) = self.resolver.poll_event() {
            let id = match event {
                Event::Response { query, .. } | Event::Failed { query, .. } => query,
            };
            assert!(self.done.insert(id), "second event, or event after cancel");
            assert!(self.live.remove(&id), "event for unknown query");
            let name = self.name_of[&id];
            finished.insert(name);
            self.leave(name);
        }
        for (_, previous) in &started_over {
            assert!(
                !self.live.contains(previous),
                "a query sent for a name while another one for it is in flight"
            );
        }
        for name in finished {
            assert!(
                !self.has_live(name) || started_over.iter().any(|(n, _)| *n == name),
                "an event for some queries of a name, but the others neither \
                 got one nor started over"
            );
        }
        for group in self.groups.values_mut() {
            group.handed_over = false;
        }
    }
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
