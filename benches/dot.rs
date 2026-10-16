//! DNS over TLS cost against an in-process rustls server:
//! `cargo bench --bench dot --features tls`
//!
//! Counts TCP connections and TLS handshakes per query, and the time for a
//! batch of queries. Every new connection costs one round trip for TCP and
//! one for the TLS handshake before the query's own round trip.

#![expect(
    clippy::disallowed_methods,
    clippy::indexing_slicing,
    clippy::print_stdout,
    clippy::unreachable,
    clippy::unwrap_used,
    reason = "a benchmark drives the resolver, reads the clock and prints results"
)]

use std::collections::HashMap;
use std::io::{ErrorKind, Read, Write};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant};

use hickory_proto::op::Message;
use hickory_proto::rr::rdata::A;
use hickory_proto::rr::{Name, RData, Record, RecordType};
use rustls::pki_types::{PrivatePkcs8KeyDer, ServerName};
use rustls::server::ServerConnection;
use rustls::{ClientConfig, HandshakeKind, RootCertStore, ServerConfig};
use sansio_dns::{Config, ConnectionId, IpLookup, Resolver, Transport};

const SERVER: SocketAddr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 53)), 853);

fn configs() -> (Arc<ClientConfig>, Arc<ServerConfig>) {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let cert = rcgen::generate_simple_self_signed(vec!["dns.example".to_owned()]).unwrap();
    let mut roots = RootCertStore::empty();
    roots.add(cert.cert.der().clone()).unwrap();
    let client = ClientConfig::builder_with_provider(Arc::clone(&provider))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_root_certificates(roots)
        .with_no_client_auth();
    let key = PrivatePkcs8KeyDer::from(cert.signing_key.serialize_der());
    let server = ServerConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(vec![cert.cert.der().clone()], key.into())
        .unwrap();
    (Arc::new(client), Arc::new(server))
}

/// A DoT server answering every query on a connection, in order.
#[derive(Default)]
struct Stats {
    connections: usize,
    full_handshakes: usize,
    resumed_handshakes: usize,
}

struct Connection {
    session: ServerConnection,
    plaintext: Vec<u8>,
    counted: bool,
}

struct Server {
    config: Arc<ServerConfig>,
    connections: HashMap<ConnectionId, Connection>,
    stats: Stats,
}

impl Server {
    fn receive(&mut self, transport: Transport, payload: &[u8]) -> Vec<u8> {
        let key = match transport {
            Transport::TcpConnect(c) | Transport::TcpWrite(c) => c,
            Transport::TcpClose(c) => {
                self.connections.remove(&c);
                return Vec::new();
            }
            Transport::Udp(_) => unreachable!("DNS over TLS never uses UDP"),
        };
        if matches!(transport, Transport::TcpConnect(_)) {
            self.stats.connections += 1;
            let session = ServerConnection::new(Arc::clone(&self.config)).unwrap();
            self.connections.insert(
                key,
                Connection {
                    session,
                    plaintext: Vec::new(),
                    counted: false,
                },
            );
        }
        let conn = self.connections.get_mut(&key).unwrap();
        let mut data = payload;
        while !data.is_empty() {
            conn.session.read_tls(&mut data).unwrap();
            conn.session.process_new_packets().unwrap();
        }
        if !conn.counted && !conn.session.is_handshaking() {
            conn.counted = true;
            match conn.session.handshake_kind() {
                Some(HandshakeKind::Resumed) => self.stats.resumed_handshakes += 1,
                _ => self.stats.full_handshakes += 1,
            }
        }
        match conn.session.reader().read_to_end(&mut conn.plaintext) {
            Ok(_) => {}
            Err(e) => assert_eq!(e.kind(), ErrorKind::WouldBlock),
        }
        while conn.plaintext.len() >= 2 {
            let len = usize::from(u16::from_be_bytes([conn.plaintext[0], conn.plaintext[1]]));
            if conn.plaintext.len() < 2 + len {
                break;
            }
            let query: Vec<u8> = conn.plaintext.drain(..2 + len).skip(2).collect();
            let answer = answer(&query);
            let framed = [
                &u16::try_from(answer.len()).unwrap().to_be_bytes()[..],
                &answer,
            ]
            .concat();
            conn.session.writer().write_all(&framed).unwrap();
        }
        let mut out = Vec::new();
        while conn.session.wants_write() {
            conn.session.write_tls(&mut out).unwrap();
        }
        out
    }
}

fn answer(query: &[u8]) -> Vec<u8> {
    let request = Message::from_vec(query).unwrap();
    let mut response = Message::response(request.metadata.id, request.metadata.op_code);
    response.add_queries(request.queries.clone());
    let name = request.queries[0].name().clone();
    response.add_answer(Record::from_rdata(
        name,
        300,
        RData::A(A(Ipv4Addr::new(192, 0, 2, 7))),
    ));
    response.to_vec().unwrap()
}

/// Pass bytes back and forth until nothing is left to send.
fn pump(resolver: &mut Resolver, server: &mut Server, now: Instant) {
    while let Some(t) = resolver.poll_transmit() {
        let back = server.receive(t.transport, &t.payload);
        if let Transport::TcpConnect(c) | Transport::TcpWrite(c) = t.transport
            && !back.is_empty()
        {
            resolver.handle_stream_data(c, &back, now);
        }
    }
}

fn report(name: &str, queries: usize, elapsed: Duration, stats: &Stats) {
    println!(
        "{name:<28} {queries:>5} queries  {:>8.1} µs/query  {:>5} connections  {:>5} full + {:>5} resumed handshakes",
        elapsed.as_secs_f64() * 1e6 / queries as f64,
        stats.connections,
        stats.full_handshakes,
        stats.resumed_handshakes,
    );
}

fn main() {
    let (client, server_config) = configs();
    let name = ServerName::try_from("dns.example").unwrap();
    let config = Config::new(SERVER, []).with_tls(client, name).unwrap();
    let qname = Name::from_ascii("example.com.").unwrap();
    let rounds = 300;

    // One query at a time, each waiting for its answer.
    let mut resolver = Resolver::new(config.clone());
    let mut server = Server {
        config: Arc::clone(&server_config),
        connections: HashMap::new(),
        stats: Stats::default(),
    };
    let start = Instant::now();
    for _ in 0..rounds {
        resolver.query(qname.clone(), RecordType::A, start).unwrap();
        pump(&mut resolver, &mut server, start);
        assert!(resolver.poll_event().is_some());
    }
    report("sequential queries", rounds, start.elapsed(), &server.stats);

    // A and AAAA together, as IpLookup sends them.
    let mut resolver = Resolver::new(config);
    let mut server = Server {
        config: server_config,
        connections: HashMap::new(),
        stats: Stats::default(),
    };
    let start = Instant::now();
    for _ in 0..rounds / 2 {
        let mut lookup = IpLookup::start(&mut resolver, qname.clone(), start).unwrap();
        pump(&mut resolver, &mut server, start);
        std::iter::from_fn(|| resolver.poll_event()).for_each(|e| {
            lookup.handle_event(&e);
        });
        assert!(lookup.result().is_some());
    }
    report(
        "IpLookup (A + AAAA)",
        rounds,
        start.elapsed(),
        &server.stats,
    );
}
