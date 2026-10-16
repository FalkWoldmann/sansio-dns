//! RFC 7858, DNS over TLS, with RFC 8310's strict profile and RFC 8467
//! padding. Runs against an in-process rustls server.
//! <https://rfc-annotations.research.icann.org/rfc7858.html>

#![cfg(feature = "tls")]
#![expect(
    clippy::disallowed_methods,
    clippy::indexing_slicing,
    clippy::unwrap_used,
    reason = "tests stand in for the driver, and helpers outside #[test] may panic"
)]

mod common;

use std::io::{ErrorKind, Read, Write};
use std::sync::Arc;
use std::time::Instant;

use common::*;
use hickory_proto::op::Message;
use hickory_proto::rr::{Name, RecordType};
use rustls::pki_types::{PrivatePkcs8KeyDer, ServerName};
use rustls::{ClientConfig, RootCertStore, ServerConfig, ServerConnection};
use sansio_dns::{Config, Error, Event, Resolver, Transmit, Transport};
use std::assert_matches;

/// A client that trusts a self-signed `dns.example` certificate, and a
/// server presenting a certificate for `presented`.
fn configs(presented: &str) -> (Arc<ClientConfig>, Arc<ServerConfig>) {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let trusted = rcgen::generate_simple_self_signed(vec!["dns.example".to_owned()]).unwrap();
    let impostor = (presented != "dns.example")
        .then(|| rcgen::generate_simple_self_signed(vec![presented.to_owned()]).unwrap());
    let served = impostor.as_ref().unwrap_or(&trusted);
    let mut roots = RootCertStore::empty();
    roots.add(trusted.cert.der().clone()).unwrap();
    let client = ClientConfig::builder_with_provider(Arc::clone(&provider))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_root_certificates(roots)
        .with_no_client_auth();
    let key = PrivatePkcs8KeyDer::from(served.signing_key.serialize_der());
    let server = ServerConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(vec![served.cert.der().clone()], key.into())
        .unwrap();
    (Arc::new(client), Arc::new(server))
}

/// A resolver using DNS over TLS, with an `example.com. A` query started.
fn tls_resolver(client: Arc<ClientConfig>, now: Instant) -> Resolver {
    let name = ServerName::try_from("dns.example").unwrap();
    let mut resolver = Resolver::new(Config::new(S1, [S2]).with_tls(client, name).unwrap());
    let query = Name::from_ascii("example.com.").unwrap();
    resolver.query(query, RecordType::A, now).unwrap();
    resolver
}

/// A name server behind TLS. Records the queries it decrypts and answers
/// each one like `reply` does.
struct Server {
    config: Arc<ServerConfig>,
    session: Option<ServerConnection>,
    plaintext: Vec<u8>,
    queries: Vec<Vec<u8>>,
    sni: Option<String>,
}

impl Server {
    fn new(config: Arc<ServerConfig>) -> Self {
        Self {
            config,
            session: None,
            plaintext: Vec::new(),
            queries: Vec::new(),
            sni: None,
        }
    }

    /// Take bytes the resolver sent; return the bytes to send back.
    fn receive(&mut self, transmit: &Transmit) -> Vec<u8> {
        if transmit.transport == Transport::Tcp {
            self.session = Some(ServerConnection::new(Arc::clone(&self.config)).unwrap());
            self.plaintext.clear();
        }
        let session = self.session.as_mut().unwrap();
        let mut data = &transmit.payload[..];
        while !data.is_empty() {
            session.read_tls(&mut data).unwrap();
            if session.process_new_packets().is_err() {
                // Flush the alert, as a real server would, then give up.
                let mut out = Vec::new();
                while session.wants_write() {
                    session.write_tls(&mut out).unwrap();
                }
                return out;
            }
        }
        self.sni = session.server_name().map(str::to_owned);
        match session.reader().read_to_end(&mut self.plaintext) {
            Ok(_) => {}
            Err(e) => assert_eq!(e.kind(), ErrorKind::WouldBlock),
        }
        if self.plaintext.len() >= 2 {
            let len = usize::from(u16::from_be_bytes([self.plaintext[0], self.plaintext[1]]));
            if self.plaintext.len() >= 2 + len {
                let query: Vec<u8> = self.plaintext.drain(..2 + len).skip(2).collect();
                let fake = Transmit {
                    query: transmit.query,
                    transport: Transport::Udp,
                    destination: transmit.destination,
                    payload: query.clone(),
                };
                session
                    .writer()
                    .write_all(&frame(&encode(&reply(&fake))))
                    .unwrap();
                self.queries.push(query);
            }
        }
        let mut out = Vec::new();
        while session.wants_write() {
            session.write_tls(&mut out).unwrap();
        }
        out
    }
}

/// Shuttle bytes between resolver and server until neither has more.
fn run(resolver: &mut Resolver, server: &mut Server, now: Instant) -> Vec<Transmit> {
    let mut sent = Vec::new();
    while let Some(t) = resolver.poll_transmit() {
        let back = server.receive(&t);
        if !back.is_empty() {
            resolver.handle_stream_data(t.query, &back, now);
        }
        sent.push(t);
    }
    sent
}

/// §3.1, §3.3: the query goes over TLS on a stream, never over UDP, and
/// the name server's answer comes back through the session.
#[test]
fn query_is_answered_over_tls() {
    let (client, server_config) = configs("dns.example");
    let now = Instant::now();
    let mut resolver = tls_resolver(client, now);
    let mut server = Server::new(server_config);

    let sent = run(&mut resolver, &mut server, now);

    let (first, rest) = sent.split_first().unwrap();
    assert_eq!(first.transport, Transport::Tcp);
    assert_eq!(first.destination, S1);
    assert_eq!(first.payload[0], 0x16, "TLS handshake record");
    assert!(rest.iter().all(|t| t.transport == Transport::TcpContinue));
    assert_eq!(server.sni.as_deref(), Some("dns.example"));
    assert!(is_response(resolver.poll_event()));
}

/// RFC 8467 §4.1: queries are padded to a multiple of 128 octets.
#[test]
fn query_is_padded_to_a_multiple_of_128() {
    let (client, server_config) = configs("dns.example");
    let now = Instant::now();
    let mut resolver = tls_resolver(client, now);
    let mut server = Server::new(server_config);

    run(&mut resolver, &mut server, now);

    let query = &server.queries[0];
    assert_eq!(query.len() % 128, 0, "length {}", query.len());
    assert!(Message::from_vec(query).unwrap().edns.is_some());
}

/// RFC 8310 §5: a certificate that doesn't match the name fails the
/// attempt; the next server is tried, and the error is reported last.
#[test]
fn wrong_certificate_moves_on_then_fails() {
    let (client, server_config) = configs("impostor.example");
    let now = Instant::now();
    let mut resolver = tls_resolver(client, now);
    let mut server = Server::new(server_config);

    let sent = run(&mut resolver, &mut server, now);

    let new_connections: Vec<_> = sent
        .iter()
        .filter(|t| t.transport == Transport::Tcp)
        .map(|t| t.destination)
        .collect();
    assert_eq!(new_connections, [S1, S2, S1, S2]);
    assert!(server.queries.is_empty(), "no query sent to the impostor");
    assert_matches!(
        resolver.poll_event(),
        Some(Event::Failed {
            error: Error::Tls(_),
            ..
        })
    );
}
