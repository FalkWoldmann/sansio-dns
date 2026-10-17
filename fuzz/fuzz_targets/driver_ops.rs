//! Sequences of driver calls, like the state machine proptest but coverage
//! guided and with the timeouts, attempts and servers chosen too. Replies
//! go to recent transmits over their transport, well-formed or tampered
//! with, and send errors to recent datagrams; raw bytes go to datagram
//! sockets and connections.

#![no_main]

use std::io::ErrorKind;
use std::net::SocketAddr;
use std::num::NonZeroUsize;
use std::time::Duration;

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;
use sansio_dns::hickory_proto::op::ResponseCode;
use sansio_dns::hickory_proto::rr::RecordType;
use sansio_dns::{Config, Transport};
use sansio_dns_fuzz::{
    Code, Harness, S1, S2, S3, Sent, add_ns, add_soa, cut, flip, frame, name, reply,
};

const NAMES: [&str; 5] = [
    "example.com.",
    "EXAMPLE.com.",
    "a.example.net.",
    "localhost.",
    "foo.invalid.",
];
const TYPES: [RecordType; 4] = [
    RecordType::A,
    RecordType::AAAA,
    RecordType::MX,
    RecordType::TXT,
];

#[derive(Arbitrary, Debug)]
enum Reply {
    Answer,
    Code(Code),
    FormErrWithoutOpt,
    /// `NOERROR` without an answer.
    NoData,
    /// NXDOMAIN or NODATA with an SOA record, which the resolver caches for
    /// the record's TTL in seconds.
    Negative {
        nxdomain: bool,
        ttl: u8,
    },
    /// `NOERROR` without an answer, AA or RA, with an NS record in authority.
    Referral,
    Truncated,
    /// Cut short by up to 15 bytes, with or without TC.
    Cut {
        bytes: u8,
        truncated: bool,
    },
    WrongId,
    WrongQuestion,
    WrongSource,
    BitFlip {
        byte: u16,
        bit: u8,
    },
}

#[derive(Arbitrary, Debug)]
enum Op {
    Query { name: u8, record_type: u8 },
    Reply { to: u8, reply: Reply, split: u16 },
    Elapse(u16),
    NextDeadline,
    Cancel(u8),
    StreamClosed { connection: u8, failed: bool },
    StreamBytes { connection: u8, bytes: Vec<u8> },
    Garbage { to: u8, bytes: Vec<u8> },
    UdpError(u8),
    Shutdown,
    Flush,
}

#[derive(Arbitrary, Debug)]
struct Setup {
    servers: u8,
    attempts: u8,
    timeout_millis: u16,
    idle_millis: u16,
}

#[derive(Arbitrary, Debug)]
struct Input {
    setup: Setup,
    ops: Vec<Op>,
}

/// The bytes and source a server would reply to `sent` with.
fn answer(sent: &Sent, kind: &Reply) -> Option<(SocketAddr, Vec<u8>)> {
    let code = match kind {
        Reply::Code(code) => (*code).into(),
        Reply::FormErrWithoutOpt => ResponseCode::FormErr,
        Reply::Negative { nxdomain: true, .. } => ResponseCode::NXDomain,
        _ => ResponseCode::NoError,
    };
    let mut response = reply(&sent.request, code);
    match kind {
        Reply::FormErrWithoutOpt => response.edns = None,
        Reply::NoData => response.answers.clear(),
        Reply::Negative { ttl, .. } => {
            response.answers.clear();
            add_soa(&mut response, u32::from(*ttl % 8));
        }
        Reply::Referral => {
            response.answers.clear();
            response.metadata.recursion_available = false;
            add_ns(&mut response);
        }
        Reply::Truncated
        | Reply::Cut {
            truncated: true, ..
        } => {
            response.metadata.truncation = true;
        }
        Reply::WrongId => response.metadata.id = response.metadata.id.wrapping_add(1),
        Reply::WrongQuestion => {
            if let Some(question) = response.queries.first_mut() {
                question.set_query_type(RecordType::NS);
            }
        }
        _ => {}
    }
    let mut bytes = response.to_vec().ok()?;
    match kind {
        Reply::BitFlip { byte, bit } => flip(&mut bytes, &[(*byte, 1 << (bit % 8))]),
        Reply::Cut { bytes: n, .. } => cut(&mut bytes, *n),
        _ => {}
    }
    let from = match kind {
        Reply::WrongSource => SocketAddr::new(sent.destination.ip(), 5353),
        _ => sent.destination,
    };
    Some((from, bytes))
}

fuzz_target!(|input: Input| {
    let Setup {
        servers,
        attempts,
        timeout_millis,
        idle_millis,
    } = input.setup;
    let servers: Vec<SocketAddr> = [S1, S2, S3]
        .into_iter()
        .take(1 + usize::from(servers % 3))
        .collect();
    let mut config = Config::new(S1, servers.iter().skip(1).copied());
    let attempts = 1 + usize::from(attempts % 6);
    config.attempts = NonZeroUsize::new(attempts).unwrap_or(NonZeroUsize::MIN);
    config.timeout = Duration::from_millis(1 + u64::from(timeout_millis));
    config.idle_timeout = Duration::from_millis(1 + u64::from(idle_millis));
    // One send per attempt, plus a switch to TCP, an EDNS downgrade and a
    // free resend, each at most once; the harness leaves out the resends
    // after a lost connection, which can come more often. Up to six
    // attempts on one server reach RFC 9520 §3.1's limit of three sends per
    // server and transport, which the harness checks for every send.
    let mut harness = Harness::new(config, servers, Some(attempts + 3));

    for op in input.ops.iter().take(256) {
        let now = harness.now;
        match op {
            Op::Query {
                name: n,
                record_type,
            } => {
                let text = NAMES[usize::from(*n) % NAMES.len()];
                let record_type = TYPES[usize::from(*record_type) % TYPES.len()];
                harness.query(name(text), record_type);
            }
            Op::Reply { to, reply, split } => {
                let Some(sent) = harness.recent(*to, |_| true) else {
                    continue;
                };
                let transport = sent.transport;
                let Some((from, bytes)) = answer(sent, reply) else {
                    continue;
                };
                match transport {
                    Transport::Udp(q) => harness.resolver.handle_datagram(q, from, &bytes, now),
                    Transport::TcpConnect(c) | Transport::TcpWrite(c) => {
                        let framed = frame(&bytes);
                        let (a, b) = framed.split_at(usize::from(*split) % (framed.len() + 1));
                        harness.resolver.handle_stream_data(c, a, now);
                        harness.resolver.handle_stream_data(c, b, now);
                    }
                    Transport::TcpClose(_) => {}
                }
            }
            Op::Elapse(millis) => harness.elapse(*millis),
            Op::NextDeadline => harness.next_deadline(),
            Op::Cancel(which) => harness.cancel(*which),
            Op::StreamClosed { connection, failed } => {
                if let Some(c) = harness.open(*connection) {
                    harness.lose(c, *failed);
                }
            }
            Op::StreamBytes { connection, bytes } => {
                if let Some(c) = harness.open(*connection) {
                    harness.resolver.handle_stream_data(c, bytes, now);
                }
            }
            Op::Garbage { to, bytes } => {
                let target = harness
                    .recent(*to, |s| matches!(s.transport, Transport::Udp(_)))
                    .map(|s| (s.transport, s.destination));
                if let Some((Transport::Udp(q), from)) = target {
                    harness.resolver.handle_datagram(q, from, bytes, now);
                }
            }
            Op::UdpError(to) => {
                let target = harness
                    .recent(*to, |s| matches!(s.transport, Transport::Udp(_)))
                    .map(|s| (s.transport, s.destination));
                if let Some((Transport::Udp(q), to)) = target {
                    let unreachable = ErrorKind::NetworkUnreachable;
                    harness.resolver.handle_udp_error(q, to, unreachable, now);
                }
            }
            Op::Shutdown => harness.shutdown(),
            Op::Flush => harness.flush(),
        }
        harness.check();
    }
});
