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

/// A resolver with `in_flight` unanswered queries for other names.
fn busy_resolver(in_flight: usize, now: Instant) -> Resolver {
    let mut resolver = Resolver::new(Config::new(SERVER, []));
    for _ in 0..in_flight {
        resolver
            .query(name("busy.example."), RecordType::A, now)
            .unwrap();
    }
    while resolver.poll_transmit().is_some() {}
    resolver
}

/// A query, its datagram and the answer, with other queries in flight.
/// Matching an answer looks up the query it was received for, so this
/// should not depend on how many are in flight.
fn udp(c: &mut Criterion) {
    let now = Instant::now();
    let template = answer("example.com.", false);
    let spoofed = answer("spoofed.example.", false);
    let mut group = c.benchmark_group("udp");
    for in_flight in [0, 16, 256] {
        let mut resolver = busy_resolver(in_flight, now);
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
                    resolver.handle_datagram(
                        query,
                        SERVER,
                        &answering(&template, &sent.payload),
                        now,
                    );
                    black_box(resolver.poll_event().unwrap());
                });
            },
        );
        let target = resolver
            .query(name("example.com."), RecordType::A, now)
            .unwrap();
        while resolver.poll_transmit().is_some() {}
        group.bench_with_input(
            BenchmarkId::new("reject_spoofed", in_flight),
            &in_flight,
            |b, _| b.iter(|| resolver.handle_datagram(target, SERVER, black_box(&spoofed), now)),
        );
    }
    group.finish();
}

/// Reassembling a TCP answer delivered in chunks of different sizes.
fn tcp_reassembly(c: &mut Criterion) {
    let now = Instant::now();
    let truncated = answer("example.com.", true);
    let template = answer("example.com.", false);
    let setup = || {
        let mut resolver = Resolver::new(Config::new(SERVER, []));
        resolver
            .query(name("example.com."), RecordType::A, now)
            .unwrap();
        let udp = resolver.poll_transmit().unwrap();
        let Transport::Udp(query) = udp.transport else {
            unreachable!("queries start over UDP");
        };
        resolver.handle_datagram(query, SERVER, &answering(&truncated, &udp.payload), now);
        let tcp = resolver.poll_transmit().unwrap();
        let Transport::TcpConnect(connection) = tcp.transport else {
            unreachable!("a truncated answer switches to TCP");
        };
        let message = answering(&template, &tcp.payload[2..]);
        let framed = [
            &u16::try_from(message.len()).unwrap().to_be_bytes()[..],
            &message,
        ]
        .concat();
        (resolver, connection, framed)
    };
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
                setup,
                |(mut resolver, connection, framed): (Resolver, ConnectionId, Vec<u8>)| {
                    framed
                        .chunks(chunk.min(framed.len()))
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
        b.iter(|| black_box(Config::from_resolv_conf(black_box(text)).unwrap()));
    });
}

criterion_group!(benches, udp, tcp_reassembly, cname_chain, resolv_conf);
criterion_main!(benches);
