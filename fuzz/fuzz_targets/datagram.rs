//! Datagrams of any content, mostly from the right server and for the right
//! query so they reach the parser and the reply checks, interleaved with
//! timeouts.

#![no_main]

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;
use sansio_dns::hickory_proto::rr::RecordType;
use sansio_dns::{Config, Transport};
use sansio_dns_fuzz::{Code, Harness, S1, S2, add_ns, cut, flip, name, reply, set_id};

#[derive(Arbitrary, Debug)]
enum Body {
    /// Raw bytes, with the query's message ID written over the first two.
    Raw { bytes: Vec<u8>, keep_id: bool },
    /// A well-formed reply, then tampered with: without its answer or RA,
    /// with an NS record in authority, cut short, and with bits flipped.
    Reply {
        code: Code,
        truncated: bool,
        edns: bool,
        empty: bool,
        recursion_available: bool,
        ns: bool,
        cut: u8,
        flips: Vec<(u16, u8)>,
    },
}

#[derive(Arbitrary, Debug)]
enum Step {
    Datagram { to: u8, source: u8, body: Body },
    Elapse(u16),
    NextDeadline,
}

#[derive(Arbitrary, Debug)]
struct Input {
    queries: u8,
    steps: Vec<Step>,
}

fuzz_target!(|input: Input| {
    let mut harness = Harness::new(Config::new(S1, [S2]), vec![S1, S2], Some(2 * 2 + 3));
    for i in 0..=input.queries % 4 {
        let (text, record_type) = if i % 2 == 0 {
            ("example.com.", RecordType::A)
        } else {
            ("example.net.", RecordType::AAAA)
        };
        harness.query(name(text), record_type);
    }
    harness.check();
    for step in input.steps.iter().take(256) {
        match step {
            Step::Datagram { to, source, body } => {
                let Some(sent) = harness.recent(*to, |s| matches!(s.transport, Transport::Udp(_)))
                else {
                    continue;
                };
                let Transport::Udp(query) = sent.transport else {
                    continue;
                };
                let id = sent.request.metadata.id;
                let from = match source % 8 {
                    0 => std::net::SocketAddr::new(sent.destination.ip(), 5353),
                    1 if sent.destination == S1 => S2,
                    1 => S1,
                    _ => sent.destination,
                };
                let bytes = match body {
                    Body::Raw { bytes, keep_id } => {
                        let mut bytes = bytes.clone();
                        if !keep_id {
                            set_id(&mut bytes, id);
                        }
                        bytes
                    }
                    Body::Reply {
                        code,
                        truncated,
                        edns,
                        empty,
                        recursion_available,
                        ns,
                        cut: n,
                        flips,
                    } => {
                        let mut response = reply(&sent.request, (*code).into());
                        response.metadata.truncation = *truncated;
                        response.metadata.recursion_available = *recursion_available;
                        if !edns {
                            response.edns = None;
                        }
                        if *empty {
                            response.answers.clear();
                        }
                        if *ns {
                            add_ns(&mut response);
                        }
                        let Ok(mut bytes) = response.to_vec() else {
                            continue;
                        };
                        cut(&mut bytes, *n);
                        flip(&mut bytes, flips);
                        bytes
                    }
                };
                let now = harness.now;
                harness.resolver.handle_datagram(query, from, &bytes, now);
            }
            Step::Elapse(millis) => harness.elapse(*millis),
            Step::NextDeadline => harness.next_deadline(),
        }
        harness.check();
    }
});
