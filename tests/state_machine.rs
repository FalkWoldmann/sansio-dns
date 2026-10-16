//! Random sequences of driver calls, checking invariants after every step.
//!
//! The resolver only ever sees `query`, `handle_datagram`, `handle_timeout`
//! and `cancel`, so any sequence of those is a valid input. Datagrams are
//! replies to recent transmits, often tampered with, plus raw garbage.

#![expect(
    clippy::disallowed_methods,
    clippy::indexing_slicing,
    clippy::unwrap_used,
    reason = "tests stand in for the driver, and helpers outside #[test] may panic"
)]

mod common;

use std::collections::{HashMap, HashSet};
use std::net::SocketAddr;
use std::time::{Duration, Instant};

use common::*;
use hickory_proto::op::ResponseCode;
use proptest::prelude::*;
use sansio_dns::{Event, QueryId, Resolver, Transmit};

/// Datagrams one query may cause: one per attempt, plus one EDNS downgrade.
const MAX_TRANSMITS: usize = 2 * 2 + 1;

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
    Query,
    Reply { to: usize, reply: Reply },
    Elapse { millis: u16 },
    Timeout,
    Cancel { which: usize },
    Garbage(Vec<u8>),
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

fn op_strategy() -> impl Strategy<Value = Op> {
    prop_oneof![
        2 => Just(Op::Query),
        4 => (any::<usize>(), reply_strategy()).prop_map(|(to, reply)| Op::Reply { to, reply }),
        1 => any::<u16>().prop_map(|millis| Op::Elapse { millis }),
        1 => Just(Op::Timeout),
        1 => any::<usize>().prop_map(|which| Op::Cancel { which }),
        1 => prop::collection::vec(any::<u8>(), 0..64).prop_map(Op::Garbage),
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

/// Driver state plus everything observed so far.
struct Harness {
    resolver: Resolver,
    now: Instant,
    sent: Vec<Transmit>,
    live: Vec<QueryId>,
    done: HashSet<QueryId>,
    transmits: HashMap<QueryId, usize>,
}

impl Harness {
    fn new() -> Self {
        Self {
            resolver: resolver(),
            now: Instant::now(),
            sent: Vec::new(),
            live: Vec::new(),
            done: HashSet::new(),
            transmits: HashMap::new(),
        }
    }

    fn apply(&mut self, op: &Op) {
        match op {
            Op::Query => {
                let name = hickory_proto::rr::Name::from_ascii("example.com.").unwrap();
                let id = self
                    .resolver
                    .query(name, hickory_proto::rr::RecordType::A, self.now)
                    .unwrap();
                self.live.push(id);
            }
            Op::Reply { to, reply } => {
                if let Some(sent) = self.sent.get(to % self.sent.len().max(1)) {
                    let (from, bytes) = datagram(sent, reply);
                    self.resolver.handle_datagram(from, &bytes, self.now);
                }
            }
            Op::Elapse { millis } => {
                self.now += Duration::from_millis(u64::from(*millis));
                self.resolver.handle_timeout(self.now);
            }
            Op::Timeout => {
                if let Some(deadline) = self.resolver.poll_timeout() {
                    self.now = self.now.max(deadline);
                    self.resolver.handle_timeout(self.now);
                }
            }
            Op::Cancel { which } => {
                if !self.live.is_empty() {
                    let id = self.live.swap_remove(which % self.live.len());
                    self.resolver.cancel(id);
                    self.done.insert(id);
                }
            }
            Op::Garbage(bytes) => self.resolver.handle_datagram(S1, bytes, self.now),
        }
    }

    /// Drain the resolver's outputs and check every invariant.
    fn check(&mut self) -> Result<(), TestCaseError> {
        while let Some(t) = self.resolver.poll_transmit() {
            prop_assert!(t.destination == S1 || t.destination == S2, "unknown server");
            prop_assert!(
                self.live.contains(&t.query),
                "transmit for a finished query"
            );
            let count = self.transmits.entry(t.query).or_default();
            *count += 1;
            prop_assert!(*count <= MAX_TRANSMITS, "too many transmits for one query");
            self.sent.push(t);
        }
        // Keep recent transmits only, so late replies to old ones still happen.
        let excess = self.sent.len().saturating_sub(16);
        self.sent.drain(..excess);

        while let Some(event) = self.resolver.poll_event() {
            let id = match event {
                Event::Response { query, .. } | Event::Failed { query, .. } => query,
            };
            prop_assert!(self.done.insert(id), "second event, or event after cancel");
            let position = self.live.iter().position(|q| *q == id);
            prop_assert!(position.is_some(), "event for unknown query");
            if let Some(i) = position {
                self.live.swap_remove(i);
            }
        }

        let timeout = self.resolver.poll_timeout();
        prop_assert_eq!(
            timeout.is_some(),
            !self.live.is_empty(),
            "timer iff pending"
        );
        prop_assert!(
            timeout.is_none_or(|t| t > self.now),
            "deadline already passed"
        );
        Ok(())
    }
}

proptest! {
    #[test]
    fn invariants_hold_for_any_call_sequence(ops in prop::collection::vec(op_strategy(), 1..64)) {
        let mut harness = Harness::new();
        for op in &ops {
            harness.apply(op);
            harness.check()?;
        }
    }
}
