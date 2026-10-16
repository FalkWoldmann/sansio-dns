//! DNS over TLS against an in-process rustls server (ring):
//! `cargo bench --bench tls --features tls`
//!
//! Times include the server's side of each exchange, since both run in this
//! process. On a network, every new connection also costs a round trip for
//! TCP and one for the TLS handshake before the query's own.

#![expect(
    clippy::disallowed_methods,
    clippy::indexing_slicing,
    clippy::unreachable,
    clippy::unwrap_used,
    reason = "a benchmark drives the resolver and a test server with fixed, valid inputs"
)]

use std::collections::HashMap;
use std::hint::black_box;
use std::io::{ErrorKind, Read, Write};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Instant;

use criterion::{BatchSize, Criterion, criterion_group, criterion_main};
use hickory_proto::op::Message;
use hickory_proto::rr::rdata::A;
use hickory_proto::rr::{Name, RData, Record, RecordType};
use rustls::client::Resumption;
use rustls::pki_types::{PrivatePkcs8KeyDer, ServerName};
use rustls::server::ServerConnection;
use rustls::{ClientConfig, HandshakeKind, RootCertStore, ServerConfig};
use sansio_dns::{Config, ConnectionId, Resolver, Transport};

const SERVER: SocketAddr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 53)), 853);

/// A client trusting a fresh self-signed `dns.example` certificate, with or
/// without session resumption, and the server presenting it.
fn configs(resumption: bool) -> (Arc<ClientConfig>, Arc<ServerConfig>) {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let cert = rcgen::generate_simple_self_signed(vec!["dns.example".to_owned()]).unwrap();
    let mut roots = RootCertStore::empty();
    roots.add(cert.cert.der().clone()).unwrap();
    let mut client = ClientConfig::builder_with_provider(Arc::clone(&provider))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_root_certificates(roots)
        .with_no_client_auth();
    if !resumption {
        client.resumption = Resumption::disabled();
    }
    let key = PrivatePkcs8KeyDer::from(cert.signing_key.serialize_der());
    let server = ServerConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(vec![cert.cert.der().clone()], key.into())
        .unwrap();
    (Arc::new(client), Arc::new(server))
}

/// A DoT server answering every query on every connection.
struct Server {
    config: Arc<ServerConfig>,
    connections: HashMap<ConnectionId, (ServerConnection, Vec<u8>)>,
    last_handshake: Option<HandshakeKind>,
}

impl Server {
    fn new(config: Arc<ServerConfig>) -> Self {
        Self {
            config,
            connections: HashMap::new(),
            last_handshake: None,
        }
    }

    fn receive(&mut self, transport: Transport, payload: &[u8]) -> Vec<u8> {
        let key = match transport {
            Transport::TcpConnect(c) => {
                let session = ServerConnection::new(Arc::clone(&self.config)).unwrap();
                self.connections.insert(c, (session, Vec::new()));
                c
            }
            Transport::TcpWrite(c) => c,
            Transport::TcpClose(c) => {
                self.connections.remove(&c);
                return Vec::new();
            }
            Transport::Udp(_) => unreachable!("DNS over TLS never uses UDP"),
        };
        let (session, plaintext) = self.connections.get_mut(&key).unwrap();
        let mut data = payload;
        while !data.is_empty() {
            session.read_tls(&mut data).unwrap();
            session.process_new_packets().unwrap();
        }
        self.last_handshake = session.handshake_kind();
        match session.reader().read_to_end(plaintext) {
            Ok(_) => {}
            Err(e) => assert_eq!(e.kind(), ErrorKind::WouldBlock),
        }
        while plaintext.len() >= 2 {
            let len = usize::from(u16::from_be_bytes([plaintext[0], plaintext[1]]));
            if plaintext.len() < 2 + len {
                break;
            }
            let query: Vec<u8> = plaintext.drain(..2 + len).skip(2).collect();
            let answer = answer(&query);
            let len = u16::try_from(answer.len()).unwrap().to_be_bytes();
            session
                .writer()
                .write_all(&[&len[..], &answer].concat())
                .unwrap();
        }
        let mut out = Vec::new();
        while session.wants_write() {
            session.write_tls(&mut out).unwrap();
        }
        out
    }
}

fn answer(query: &[u8]) -> Vec<u8> {
    let request = Message::from_vec(query).unwrap();
    let mut response = Message::response(request.metadata.id, request.metadata.op_code);
    response.add_queries(request.queries.clone());
    let name = request.queries[0].name().clone();
    let a = RData::A(A(Ipv4Addr::new(192, 0, 2, 7)));
    response.add_answer(Record::from_rdata(name, 300, a));
    response.to_vec().unwrap()
}

fn resolver(client: &Arc<ClientConfig>) -> Resolver {
    let tls_name = ServerName::try_from("dns.example").unwrap();
    Resolver::new(
        Config::new(SERVER, [])
            .with_tls(Arc::clone(client), tls_name)
            .unwrap(),
    )
}

/// One query from start to answer, shuttling bytes until there are none.
fn resolve(resolver: &mut Resolver, server: &mut Server, now: Instant) {
    let qname = Name::from_ascii("example.com.").unwrap();
    resolver.query(qname, RecordType::A, now).unwrap();
    while let Some(t) = resolver.poll_transmit() {
        let back = server.receive(t.transport, &t.payload);
        if let Transport::TcpConnect(c) | Transport::TcpWrite(c) = t.transport
            && !back.is_empty()
        {
            resolver.handle_stream_data(c, &back, now);
        }
    }
    black_box(resolver.poll_event().unwrap());
}

fn dot(c: &mut Criterion) {
    let now = Instant::now();
    let mut group = c.benchmark_group("dot");

    // The usual case: the connection is already open.
    let (client, server_config) = configs(true);
    let mut open = resolver(&client);
    let mut server = Server::new(Arc::clone(&server_config));
    resolve(&mut open, &mut server, now);
    group.bench_function("query_on_open_connection", |b| {
        b.iter(|| resolve(&mut open, &mut server, now));
    });

    // A new connection that resumes an earlier session.
    let mut fresh = Server::new(Arc::clone(&server_config));
    resolve(&mut resolver(&client), &mut fresh, now);
    resolve(&mut resolver(&client), &mut fresh, now);
    assert_eq!(fresh.last_handshake, Some(HandshakeKind::Resumed));
    group.bench_function("new_connection/resumed_handshake", |b| {
        b.iter_batched(
            || resolver(&client),
            |mut r| resolve(&mut r, &mut fresh, now),
            BatchSize::SmallInput,
        );
    });

    // A new connection with a full handshake every time.
    let (client, server_config) = configs(false);
    let mut fresh = Server::new(server_config);
    resolve(&mut resolver(&client), &mut fresh, now);
    assert_eq!(fresh.last_handshake, Some(HandshakeKind::Full));
    group.bench_function("new_connection/full_handshake", |b| {
        b.iter_batched(
            || resolver(&client),
            |mut r| resolve(&mut r, &mut fresh, now),
            BatchSize::SmallInput,
        );
    });
    group.finish();
}

criterion_group!(benches, dot);
criterion_main!(benches);
