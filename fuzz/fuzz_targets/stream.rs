//! Bytes of any content and chunking on TCP connections, with queries
//! pipelined on them, connections closing or failing, and timeouts.

#![no_main]

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;
use sansio_dns::hickory_proto::op::ResponseCode;
use sansio_dns::hickory_proto::rr::RecordType;
use sansio_dns::{Config, Transport};
use sansio_dns_fuzz::{Code, Harness, S1, S2, flip, frame, name, reply, set_id};

#[derive(Arbitrary, Debug)]
enum Step {
    /// Raw bytes on an open connection.
    Bytes {
        connection: u8,
        bytes: Vec<u8>,
    },
    /// A length-prefixed message carrying the ID of a query on a
    /// connection, in two chunks.
    Message {
        to: u8,
        body: Vec<u8>,
        split: u16,
    },
    /// A well-formed reply to a query on a connection, tampered with, in
    /// two chunks.
    Reply {
        to: u8,
        code: Code,
        truncated: bool,
        flips: Vec<(u16, u8)>,
        split: u16,
    },
    Closed {
        connection: u8,
    },
    Failed {
        connection: u8,
    },
    /// Another query, moved to TCP like the first.
    Query,
    Elapse(u16),
}

/// Start a query and answer it with TC set, so it moves to TCP.
fn query_over_tcp(harness: &mut Harness) {
    harness.query(name("example.com."), RecordType::A);
    for t in harness.check() {
        let Transport::Udp(query) = t.transport else {
            continue;
        };
        let Ok(request) = sansio_dns::hickory_proto::op::Message::from_vec(&t.payload) else {
            continue;
        };
        let mut truncated = reply(&request, ResponseCode::NoError);
        truncated.metadata.truncation = true;
        if let Ok(bytes) = truncated.to_vec() {
            let now = harness.now;
            harness
                .resolver
                .handle_datagram(query, t.destination, &bytes, now);
        }
    }
    harness.check();
}

fn is_stream(transport: Transport) -> bool {
    matches!(transport, Transport::TcpConnect(_) | Transport::TcpWrite(_))
}

fuzz_target!(|steps: Vec<Step>| {
    let mut harness = Harness::new(Config::new(S1, [S2]), vec![S1, S2], Some(2 * 2 + 3));
    query_over_tcp(&mut harness);
    for step in steps.iter().take(256) {
        let now = harness.now;
        match step {
            Step::Bytes { connection, bytes } => {
                if let Some(c) = harness.open(*connection) {
                    harness.resolver.handle_stream_data(c, bytes, now);
                }
            }
            Step::Message { to, body, split } => {
                let Some(sent) = harness.recent(*to, |s| is_stream(s.transport)) else {
                    continue;
                };
                let (Transport::TcpConnect(c) | Transport::TcpWrite(c)) = sent.transport else {
                    continue;
                };
                let mut body = body.clone();
                set_id(&mut body, sent.request.metadata.id);
                let bytes = frame(&body);
                let (a, b) = bytes.split_at(usize::from(*split) % (bytes.len() + 1));
                harness.resolver.handle_stream_data(c, a, now);
                harness.resolver.handle_stream_data(c, b, now);
            }
            Step::Reply {
                to,
                code,
                truncated,
                flips,
                split,
            } => {
                let Some(sent) = harness.recent(*to, |s| is_stream(s.transport)) else {
                    continue;
                };
                let (Transport::TcpConnect(c) | Transport::TcpWrite(c)) = sent.transport else {
                    continue;
                };
                let mut response = reply(&sent.request, (*code).into());
                response.metadata.truncation = *truncated;
                let Ok(mut message) = response.to_vec() else {
                    continue;
                };
                flip(&mut message, flips);
                let bytes = frame(&message);
                let (a, b) = bytes.split_at(usize::from(*split) % (bytes.len() + 1));
                harness.resolver.handle_stream_data(c, a, now);
                harness.resolver.handle_stream_data(c, b, now);
            }
            Step::Closed { connection } => {
                if let Some(c) = harness.open(*connection) {
                    harness.lose(c, false);
                }
            }
            Step::Failed { connection } => {
                if let Some(c) = harness.open(*connection) {
                    harness.lose(c, true);
                }
            }
            Step::Query => query_over_tcp(&mut harness),
            Step::Elapse(millis) => harness.elapse(*millis),
        }
        harness.check();
    }
});
