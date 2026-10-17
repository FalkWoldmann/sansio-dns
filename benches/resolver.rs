//! Core resolver paths, with no network: `cargo bench --bench resolver`

#![expect(
    clippy::disallowed_methods,
    clippy::indexing_slicing,
    clippy::unreachable,
    clippy::unwrap_used,
    reason = "a benchmark drives the resolver with fixed, valid inputs"
)]

use std::hint::black_box;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::Instant;

use criterion::{BatchSize, BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};
use hickory_proto::op::{Message, OpCode, Query};
use hickory_proto::rr::rdata::{A, CNAME};
use hickory_proto::rr::{Name, RData, Record, RecordType};
use sansio_dns::{Config, ConnectionId, Resolver, Transport, addresses};

const SERVER: SocketAddr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 53)), 53);
const STRANGER: SocketAddr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 54)), 53);

fn name(s: &str) -> Name {
    Name::from_ascii(s).unwrap()
}

/// An encoded answer to `qname A`, with message ID 0: patch in the ID of
/// the query it answers.
fn answer(qname: &str, truncated: bool) -> Vec<u8> {
    let mut m = Message::response(0, OpCode::Query);
    m.add_query(Query::query(name(qname), RecordType::A));
    if !truncated {
        let a = RData::A(A(Ipv4Addr::new(192, 0, 2, 7)));
        m.add_answer(Record::from_rdata(name(qname), 300, a));
    }
    m.metadata.truncation = truncated;
    m.to_vec().unwrap()
}

/// `answer` with the message ID of the query in `payload`.
fn answering(template: &[u8], payload: &[u8]) -> Vec<u8> {
    [&payload[..2], &template[2..]].concat()
}

/// Gives `message` the ID of the query in `payload`, in place.
fn set_id(message: &mut [u8], payload: &[u8]) {
    message[..2].copy_from_slice(&payload[..2]);
}

/// `message` with the two-byte TCP length prefix.
fn framed(message: &[u8]) -> Vec<u8> {
    [
        &u16::try_from(message.len()).unwrap().to_be_bytes()[..],
        message,
    ]
    .concat()
}

/// `resolver` with `in_flight` more unanswered queries, each for a name of
/// its own so none joins another.
fn busy_resolver(mut resolver: Resolver, in_flight: usize, now: Instant) -> Resolver {
    for i in 0..in_flight {
        resolver
            .query(name(&format!("busy{i}.example.")), RecordType::A, now)
            .unwrap();
    }
    while resolver.poll_transmit().is_some() {}
    resolver
}

/// A resolver whose query a truncated answer moved to a new connection,
/// and the framed answer the connection will deliver for it.
fn connecting_resolver(now: Instant) -> (Resolver, ConnectionId, Vec<u8>) {
    let mut resolver = Resolver::new(Config::new(SERVER, []));
    resolver
        .query(name("example.com."), RecordType::A, now)
        .unwrap();
    let udp = resolver.poll_transmit().unwrap();
    let Transport::Udp(query) = udp.transport else {
        unreachable!("queries start over UDP");
    };
    let truncated = answer("example.com.", true);
    resolver.handle_datagram(query, SERVER, &answering(&truncated, &udp.payload), now);
    let tcp = resolver.poll_transmit().unwrap();
    let Transport::TcpConnect(connection) = tcp.transport else {
        unreachable!("a truncated answer switches to TCP");
    };
    let template = answer("example.com.", false);
    let reply = framed(&answering(&template, &tcp.payload[2..]));
    (resolver, connection, reply)
}

/// A resolver with an open connection that has answered a query and has
/// none in flight.
fn connected_resolver(now: Instant) -> (Resolver, ConnectionId) {
    let (mut resolver, connection, reply) = connecting_resolver(now);
    resolver.handle_stream_data(connection, &reply, now);
    resolver.poll_event().unwrap();
    (resolver, connection)
}

/// `connected_resolver` with `in_flight` unanswered queries for other names
/// on its connection, moved there by truncated answers.
fn busy_stream_resolver(in_flight: usize, now: Instant) -> (Resolver, ConnectionId) {
    let (mut resolver, connection) = connected_resolver(now);
    for i in 0..in_flight {
        let busy = format!("busy{i}.example.");
        let truncated = answer(&busy, true);
        let query = resolver.query(name(&busy), RecordType::A, now).unwrap();
        let udp = resolver.poll_transmit().unwrap();
        resolver.handle_datagram(query, SERVER, &answering(&truncated, &udp.payload), now);
        let tcp = resolver.poll_transmit().unwrap();
        assert_eq!(tcp.transport, Transport::TcpWrite(connection));
    }
    (resolver, connection)
}

/// A query, its datagram and the answer, with other queries in flight.
/// Matching an answer looks up the query it was received for, but picking
/// a message ID that no other query uses checks all of them.
fn udp(c: &mut Criterion) {
    let now = Instant::now();
    let template = answer("example.com.", false);
    let mut reply = template.clone();
    let spoofed = answer("spoofed.example.", false);
    let mut group = c.benchmark_group("udp");
    for in_flight in [0, 16, 256] {
        let mut resolver = busy_resolver(Resolver::new(Config::new(SERVER, [])), in_flight, now);
        group.bench_with_input(
            BenchmarkId::new("round_trip", in_flight),
            &in_flight,
            |b, _| {
                b.iter(|| {
                    resolver
                        .query(name("example.com."), RecordType::A, now)
                        .unwrap();
                    let sent = resolver.poll_transmit().unwrap();
                    let Transport::Udp(query) = sent.transport else {
                        unreachable!("queries start over UDP");
                    };
                    set_id(&mut reply, &sent.payload);
                    resolver.handle_datagram(query, SERVER, &reply, now);
                    black_box(resolver.poll_event().unwrap());
                });
            },
        );
        let target = resolver
            .query(name("example.com."), RecordType::A, now)
            .unwrap();
        let genuine = answering(&template, &resolver.poll_transmit().unwrap().payload);
        group.bench_with_input(
            BenchmarkId::new("reject_spoofed", in_flight),
            &in_flight,
            |b, _| b.iter(|| resolver.handle_datagram(target, SERVER, black_box(&spoofed), now)),
        );
        // The right answer, from an address the query wasn't sent to: turned
        // away before parsing.
        group.bench_with_input(
            BenchmarkId::new("reject_wrong_source", in_flight),
            &in_flight,
            |b, _| b.iter(|| resolver.handle_datagram(target, STRANGER, black_box(&genuine), now)),
        );
    }
    group.finish();
}

/// A query moved to TCP by a truncated answer and answered on the shared
/// connection, with other queries in flight on it. An answer is matched by
/// searching the queries, and this one, the newest, is checked last.
fn tcp(c: &mut Criterion) {
    let now = Instant::now();
    let mut truncated = answer("example.com.", true);
    let mut reply = framed(&answer("example.com.", false));
    let mut group = c.benchmark_group("tcp");
    for in_flight in [0, 16, 256] {
        let (mut resolver, connection) = busy_stream_resolver(in_flight, now);
        group.bench_with_input(
            BenchmarkId::new("round_trip", in_flight),
            &in_flight,
            |b, _| {
                b.iter(|| {
                    let query = resolver
                        .query(name("example.com."), RecordType::A, now)
                        .unwrap();
                    let udp = resolver.poll_transmit().unwrap();
                    set_id(&mut truncated, &udp.payload);
                    resolver.handle_datagram(query, SERVER, &truncated, now);
                    let tcp = resolver.poll_transmit().unwrap();
                    assert_eq!(tcp.transport, Transport::TcpWrite(connection));
                    set_id(&mut reply[2..], &tcp.payload[2..]);
                    resolver.handle_stream_data(connection, &reply, now);
                    black_box(resolver.poll_event().unwrap());
                });
            },
        );
    }
    group.finish();
}

/// Finding the next deadline with many queries pending: over UDP, over one
/// stream, and over UDP with an idle stream, whose idle deadline needs a
/// search of all of them.
fn poll_timeout(c: &mut Criterion) {
    let now = Instant::now();
    let mut group = c.benchmark_group("poll_timeout");
    for pending in [16, 256] {
        let resolver = busy_resolver(Resolver::new(Config::new(SERVER, [])), pending, now);
        group.bench_with_input(BenchmarkId::new("udp", pending), &pending, |b, _| {
            b.iter(|| black_box(resolver.poll_timeout()));
        });
        let (resolver, _) = busy_stream_resolver(pending, now);
        group.bench_with_input(BenchmarkId::new("stream", pending), &pending, |b, _| {
            b.iter(|| black_box(resolver.poll_timeout()));
        });
        let resolver = busy_resolver(connected_resolver(now).0, pending, now);
        group.bench_with_input(
            BenchmarkId::new("udp_idle_stream", pending),
            &pending,
            |b, _| b.iter(|| black_box(resolver.poll_timeout())),
        );
    }
    group.finish();
}

/// Reassembling a TCP answer delivered in chunks of different sizes.
fn tcp_reassembly(c: &mut Criterion) {
    let now = Instant::now();
    let mut group = c.benchmark_group("tcp_reassembly");
    group.throughput(Throughput::Elements(1));
    for chunk in [1, 16, usize::MAX] {
        let label = if chunk == usize::MAX {
            "whole".to_owned()
        } else {
            chunk.to_string()
        };
        group.bench_function(BenchmarkId::new("chunk", label), |b| {
            b.iter_batched(
                || connecting_resolver(now),
                |(mut resolver, connection, reply): (Resolver, ConnectionId, Vec<u8>)| {
                    reply
                        .chunks(chunk.min(reply.len()))
                        .for_each(|part| resolver.handle_stream_data(connection, part, now));
                    black_box(resolver.poll_event().unwrap())
                },
                BatchSize::SmallInput,
            );
        });
    }
    group.finish();
}

/// Following a CNAME chain of different lengths to the addresses.
fn cname_chain(c: &mut Criterion) {
    let mut group = c.benchmark_group("addresses");
    for length in [0, 4, 16] {
        let mut m = Message::response(0, OpCode::Query);
        m.add_query(Query::query(name("www.example.com."), RecordType::A));
        let hops: Vec<Name> = std::iter::once(name("www.example.com."))
            .chain((0..length).map(|i| name(&format!("hop{i}.example."))))
            .collect();
        // Answers in reverse order, so each step searches the whole section.
        hops.windows(2).rev().for_each(|pair| {
            let target = RData::CNAME(CNAME(pair[1].clone()));
            m.add_answer(Record::from_rdata(pair[0].clone(), 300, target));
        });
        let last = hops.last().unwrap().clone();
        m.add_answer(Record::from_rdata(
            last,
            300,
            RData::A(A(Ipv4Addr::LOCALHOST)),
        ));
        group.bench_with_input(BenchmarkId::new("cname_hops", length), &m, |b, m| {
            b.iter(|| black_box(addresses(m)));
        });
    }
    group.finish();
}

fn resolv_conf(c: &mut Criterion) {
    let text = b"# generated\n\
                 nameserver 192.0.2.53\n\
                 nameserver 2001:db8::53\n\
                 search corp.example lab.example\n\
                 options ndots:2 timeout:3 attempts:2\n";
    c.bench_function("config/from_resolv_conf", |b| {
        b.iter(|| black_box(Config::from_resolv_conf(black_box(text))));
    });
}

criterion_group!(
    benches,
    udp,
    tcp,
    tcp_reassembly,
    poll_timeout,
    cname_chain,
    resolv_conf
);
criterion_main!(benches);
