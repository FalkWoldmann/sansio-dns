//! RFC 7858, DNS over TLS, with RFC 8310's strict profile, RFC 8467 and
//! RFC 7830 padding, RFC 7871's privacy election and RFC 8446's closure
//! alerts. Runs against an in-process rustls server.
//! <https://rfc-annotations.research.icann.org/rfc7858.html>

use std::collections::HashMap;
use std::io::{ErrorKind, Read, Write};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use std::time::Instant;

use crate::common::*;
use hickory_proto::op::{Message, ResponseCode};
use hickory_proto::rr::rdata::A;
use hickory_proto::rr::rdata::opt::{EdnsCode, EdnsOption};
use hickory_proto::rr::{Name, RData, Record, RecordType};
use rcgen::{CertifiedKey, KeyPair};
use rustls::pki_types::{PrivatePkcs8KeyDer, ServerName};
use rustls::{
    AlertDescription, ClientConfig, HandshakeKind, RootCertStore, ServerConfig, ServerConnection,
};
use sansio_dns::{
    Config, ConnectionId, Error, Event, Resolver, TlsConfigError, Transmit, Transport,
};
use std::assert_matches;

/// Name servers on the DNS over TLS port.
const T1: SocketAddr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), 853);
const T2: SocketAddr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)), 853);
const T6: SocketAddr = SocketAddr::new(
    IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 3)),
    853,
);

/// A self-signed certificate for `name`.
fn cert(name: &str) -> CertifiedKey<KeyPair> {
    rcgen::generate_simple_self_signed(vec![name.to_owned()]).unwrap()
}

fn provider() -> Arc<rustls::crypto::CryptoProvider> {
    Arc::new(rustls::crypto::ring::default_provider())
}

/// A client that trusts the certificates `trusted`, with rustls' defaults
/// otherwise: the WebPKI verifier, SNI and session resumption.
fn client(trusted: &[&CertifiedKey<KeyPair>]) -> Arc<ClientConfig> {
    let mut roots = RootCertStore::empty();
    for cert in trusted {
        roots.add(cert.cert.der().clone()).unwrap();
    }
    let client = ClientConfig::builder_with_provider(provider())
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_root_certificates(roots)
        .with_no_client_auth();
    Arc::new(client)
}

/// A server presenting `presented`.
fn server_config(presented: &CertifiedKey<KeyPair>) -> Arc<ServerConfig> {
    let key = PrivatePkcs8KeyDer::from(presented.signing_key.serialize_der());
    let server = ServerConfig::builder_with_provider(provider())
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(vec![presented.cert.der().clone()], key.into())
        .unwrap();
    Arc::new(server)
}

/// A client that trusts a self-signed `dns.example` certificate, and a
/// server presenting it.
fn configs() -> (Arc<ClientConfig>, Arc<ServerConfig>) {
    let trusted = cert("dns.example");
    (client(&[&trusted]), server_config(&trusted))
}

fn dns_example() -> ServerName<'static> {
    ServerName::try_from("dns.example").unwrap()
}

/// A resolver using DNS over TLS to `T1` and `T2`, with an
/// `example.com. A` query started.
fn tls_resolver(client: Arc<ClientConfig>, now: Instant) -> Resolver {
    let config = Config::new(T1, [T2])
        .with_tls(client, dns_example())
        .unwrap();
    let mut resolver = Resolver::new(config);
    query(&mut resolver, "example.com.", now);
    resolver
}

fn query(resolver: &mut Resolver, name: &str, now: Instant) {
    let name = Name::from_ascii(name).unwrap();
    resolver.query(name, RecordType::A, now).unwrap();
}

/// The server's end of one connection.
struct Peer {
    to: SocketAddr,
    session: ServerConnection,
    /// Decrypted bytes not yet split into queries.
    plaintext: Vec<u8>,
    /// Whether the session ended: the client sent close_notify or an
    /// alert, or the server's session failed.
    ended: bool,
    /// Whether its handshake was recorded in `Server::handshakes`.
    handshake: bool,
}

/// A name server behind TLS. Records the queries it decrypts and answers
/// each one like `reply` does, on every connection the resolver opens.
struct Server {
    /// What it presents, and per destination address, if not that.
    config: Arc<ServerConfig>,
    configs: HashMap<SocketAddr, Arc<ServerConfig>>,
    peers: HashMap<ConnectionId, Peer>,
    /// The queries it decrypted, and the address they were sent to.
    queries: Vec<(SocketAddr, Vec<u8>)>,
    /// The SNI of each connection, in order.
    sni: Vec<Option<String>>,
    /// How each handshake went, in order.
    handshakes: Vec<HandshakeKind>,
    /// How many sessions the client ended with close_notify.
    close_notifies: usize,
    /// The alerts the client sent.
    alerts: Vec<AlertDescription>,
    /// Answer every query with FORMERR and no OPT, like a server without EDNS.
    formerr: bool,
    /// Answer the queries sent to this address with REFUSED.
    refuse: Option<SocketAddr>,
    /// Read queries but don't answer them.
    silent: bool,
    /// How many A records an answer has.
    records: u32,
}

impl Server {
    fn new(config: Arc<ServerConfig>) -> Self {
        Self {
            config,
            configs: HashMap::new(),
            peers: HashMap::new(),
            queries: Vec::new(),
            sni: Vec::new(),
            handshakes: Vec::new(),
            close_notifies: 0,
            alerts: Vec::new(),
            formerr: false,
            refuse: None,
            silent: false,
            records: 1,
        }
    }

    /// Take bytes the resolver sent; return the bytes to send back.
    fn receive(&mut self, transmit: &Transmit) -> Vec<u8> {
        let connection = conn(transmit);
        match transmit.transport {
            Transport::TcpConnect(_) => {
                let to = transmit.destination;
                let config = self.configs.get(&to).unwrap_or(&self.config);
                let peer = Peer {
                    to,
                    session: ServerConnection::new(Arc::clone(config)).unwrap(),
                    plaintext: Vec::new(),
                    ended: false,
                    handshake: false,
                };
                self.peers.insert(connection, peer);
            }
            Transport::TcpClose(_) => {
                self.peers.remove(&connection);
                return Vec::new();
            }
            _ => {}
        }
        let Some(peer) = self.peers.get_mut(&connection) else {
            return Vec::new();
        };
        let mut out = Vec::new();
        let mut data = &transmit.payload[..];
        while !data.is_empty() && !peer.ended {
            peer.session.read_tls(&mut data).unwrap();
            match peer.session.process_new_packets() {
                Ok(state) => {
                    if state.peer_has_closed() {
                        self.close_notifies += 1;
                        peer.ended = true;
                    }
                }
                Err(rustls::Error::AlertReceived(alert)) => {
                    self.alerts.push(alert);
                    peer.ended = true;
                }
                Err(_) => {
                    // Flush the alert, as a real server would, then give up.
                    peer.ended = true;
                    flush(&mut peer.session, &mut out);
                    return out;
                }
            }
            // At most 16 KiB of plaintext wait in rustls.
            match peer.session.reader().read_to_end(&mut peer.plaintext) {
                Ok(_) => {}
                Err(e) => assert_eq!(e.kind(), ErrorKind::WouldBlock),
            }
        }
        if !peer.handshake && !peer.session.is_handshaking() {
            peer.handshake = true;
            self.handshakes.push(peer.session.handshake_kind().unwrap());
            self.sni.push(peer.session.server_name().map(str::to_owned));
        }
        while peer.plaintext.len() >= 2 {
            let len = usize::from(u16::from_be_bytes([peer.plaintext[0], peer.plaintext[1]]));
            if peer.plaintext.len() < 2 + len {
                break;
            }
            let query: Vec<u8> = peer.plaintext.drain(..2 + len).skip(2).collect();
            let request = Message::from_vec(&query).unwrap();
            self.queries.push((peer.to, query));
            if self.silent {
                continue;
            }
            let mut answer = reply_to(&request);
            for i in 1..self.records {
                let name = request.queries[0].name().clone();
                let address = Ipv4Addr::from(u32::from(ADDR) + i);
                answer.add_answer(Record::from_rdata(name, 300, RData::A(A(address))));
            }
            if self.formerr {
                answer = with_code(answer, ResponseCode::FormErr);
                answer.edns = None;
            }
            if self.refuse == Some(peer.to) {
                answer = no_data(with_code(answer, ResponseCode::Refused));
            }
            // Flushed after each answer: rustls holds at most 64 KiB.
            peer.session
                .writer()
                .write_all(&frame(&encode(&answer)))
                .unwrap();
            flush(&mut peer.session, &mut out);
        }
        flush(&mut peer.session, &mut out);
        out
    }

    /// The bytes of the server's close_notify on `connection`.
    fn close_notify(&mut self, connection: ConnectionId) -> Vec<u8> {
        let peer = self.peers.get_mut(&connection).unwrap();
        peer.session.send_close_notify();
        let mut out = Vec::new();
        flush(&mut peer.session, &mut out);
        out
    }

    /// The bytes of `answer` and then the server's close_notify on
    /// `connection`, as one chunk.
    fn answer_and_close(&mut self, connection: ConnectionId, answer: &Message) -> Vec<u8> {
        let peer = self.peers.get_mut(&connection).unwrap();
        peer.session
            .writer()
            .write_all(&frame(&encode(answer)))
            .unwrap();
        peer.session.send_close_notify();
        let mut out = Vec::new();
        flush(&mut peer.session, &mut out);
        out
    }

    /// The decrypted queries, decoded.
    fn requests(&self) -> Vec<Message> {
        self.queries
            .iter()
            .map(|(_, query)| Message::from_vec(query).unwrap())
            .collect()
    }
}

fn flush(session: &mut ServerConnection, out: &mut Vec<u8>) {
    while session.wants_write() {
        session.write_tls(out).unwrap();
    }
}

/// Shuttle bytes between resolver and server until neither has more.
fn run(resolver: &mut Resolver, server: &mut Server, now: Instant) -> Vec<Transmit> {
    let mut sent = Vec::new();
    while let Some(t) = resolver.poll_transmit() {
        let back = server.receive(&t);
        if !back.is_empty() {
            resolver.handle_stream_data(conn(&t), &back, now);
        }
        sent.push(t);
    }
    sent
}

fn connects(sent: &[Transmit]) -> Vec<SocketAddr> {
    sent.iter()
        .filter(|t| is_connect(t))
        .map(|t| t.destination)
        .collect()
}

/// The EDNS options of `request`, in order.
fn options(request: &Message) -> Vec<(EdnsCode, EdnsOption)> {
    request
        .edns
        .as_ref()
        .map(|edns| edns.options().as_ref().to_vec())
        .unwrap_or_default()
}

/// §3.1, §3.3: the query goes over TLS on a stream, never over UDP, and
/// the name server's answer comes back through the session.
#[test]
fn query_is_answered_over_tls() {
    let (client, server_config) = configs();
    let now = Instant::now();
    let mut resolver = tls_resolver(client, now);
    let mut server = Server::new(server_config);

    let sent = run(&mut resolver, &mut server, now);

    let (first, rest) = sent.split_first().unwrap();
    assert!(is_connect(first));
    assert_eq!(first.destination, T1);
    assert_eq!(first.payload[0], 0x16, "TLS handshake record");
    assert!(
        rest.iter()
            .all(|t| matches!(t.transport, Transport::TcpWrite(_)))
    );
    assert_eq!(server.sni, [Some("dns.example".to_owned())]);
    assert!(is_response(resolver.poll_event()));
}

/// §3.1: DNS over TLS must not use port 53, so a configuration with a
/// server on it, such as one read from `resolv.conf`, is refused.
#[test]
fn port_53_is_refused() {
    let (client, _) = configs();

    let mixed = Config::new(T1, [S2]).with_tls(Arc::clone(&client), dns_example());
    let resolv_conf =
        Config::from_resolv_conf(b"nameserver 10.0.0.1\n").with_tls(client, dns_example());

    assert_eq!(mixed.unwrap_err(), TlsConfigError::Port53(S2));
    assert_eq!(resolv_conf.unwrap_err(), TlsConfigError::Port53(S1));
}

/// RFC 8467 §4.1: queries are padded to a multiple of 128 octets, with the
/// padding as the last option (§3) and only once (RFC 7830 §3).
#[test]
fn query_is_padded_to_a_multiple_of_128() {
    let (client, server_config) = configs();
    let now = Instant::now();
    let mut resolver = tls_resolver(client, now);
    let mut server = Server::new(server_config);

    run(&mut resolver, &mut server, now);

    let (_, query) = &server.queries[0];
    assert_eq!(query.len() % 128, 0, "length {}", query.len());
    let options = options(&Message::from_vec(query).unwrap());
    let codes: Vec<EdnsCode> = options.iter().map(|(code, _)| *code).collect();
    assert_eq!(codes, [EdnsCode::Subnet, EdnsCode::Padding]);
}

/// RFC 8310 §11.1, RFC 7871 §7.1.2: every query over TLS asks the server
/// not to pass the client's address on: an EDNS Client Subnet option with
/// SOURCE and SCOPE PREFIX-LENGTH 0, no address octets, and the FAMILY of
/// the transport. A query that moves to a server of the other family
/// changes FAMILY and is padded again, still once.
#[test]
fn query_carries_the_client_subnet_privacy_election() {
    let (client, server_config) = configs();
    let now = Instant::now();
    let config = Config::new(T1, [T6])
        .with_tls(client, dns_example())
        .unwrap();
    let mut resolver = Resolver::new(config);
    query(&mut resolver, "example.com.", now);
    let mut server = Server::new(server_config);
    server.refuse = Some(T1);

    run(&mut resolver, &mut server, now);

    let to: Vec<SocketAddr> = server.queries.iter().map(|(to, _)| *to).collect();
    assert_eq!(to, [T1, T6]);
    for ((_, query), family) in server.queries.iter().zip([1u8, 2]) {
        // OPTION-CODE 8, OPTION-LENGTH 4, FAMILY, SOURCE and SCOPE
        // PREFIX-LENGTH 0.
        let ecs = [0, 8, 0, 4, 0, family, 0, 0];
        assert!(query.windows(8).any(|w| w == ecs), "family {family}");
        assert_eq!(query.len() % 128, 0);
        let options = options(&Message::from_vec(query).unwrap());
        assert_matches!(
            options.as_slice(),
            [
                (EdnsCode::Subnet, EdnsOption::Subnet(subnet)),
                (EdnsCode::Padding, _),
            ] if subnet.source_prefix() == 0 && subnet.scope_prefix() == 0
        );
    }
    assert!(is_response(resolver.poll_event()));
}

/// RFC 7830 §6: queries in cleartext, over UDP and over TCP after a
/// truncated answer, carry no padding, and no Client Subnet option either.
#[test]
fn cleartext_queries_are_not_padded() {
    let now = Instant::now();
    let mut resolver = resolver();

    let datagram = start(&mut resolver, now);
    resolver.handle_datagram(
        udp(&datagram),
        S1,
        &encode(&truncated(reply(&datagram))),
        now,
    );
    let stream = resolver.poll_transmit().unwrap();

    assert!(is_connect(&stream));
    let over_tcp = Message::from_vec(&stream.payload[2..]).unwrap();
    for request in [decode(&datagram), over_tcp] {
        assert!(request.edns.is_some());
        assert!(options(&request).is_empty());
    }
}

/// RFC 8310 §5, §8.1: a certificate that no trusted authority issued fails
/// the attempt; the next server is tried, and the error is reported last.
/// Each time the client tells the server with an alert (RFC 8446 §6.2).
#[test]
fn untrusted_certificate_moves_on_then_fails() {
    let trusted = cert("dns.example");
    let impostor = cert("dns.example");
    let now = Instant::now();
    let mut resolver = tls_resolver(client(&[&trusted]), now);
    let mut server = Server::new(server_config(&impostor));

    let sent = run(&mut resolver, &mut server, now);

    assert_eq!(connects(&sent), [T1, T2, T1, T2]);
    assert!(server.queries.is_empty(), "no query sent to the impostor");
    assert_eq!(server.alerts.len(), 4);
    assert_matches!(
        resolver.poll_event(),
        Some(Event::Failed {
            error: Error::Tls(_),
            ..
        })
    );
}

/// RFC 8310 §8.1: a certificate from a trusted issuer for another name is
/// rejected, with a `bad_certificate` alert to the server (RFC 8446 §6.2).
#[test]
fn certificate_for_another_name_is_rejected() {
    let ours = cert("dns.example");
    let theirs = cert("impostor.example");
    let now = Instant::now();
    let mut resolver = tls_resolver(client(&[&ours, &theirs]), now);
    let mut server = Server::new(server_config(&theirs));

    let sent = run(&mut resolver, &mut server, now);

    assert_eq!(connects(&sent), [T1, T2, T1, T2]);
    assert!(server.queries.is_empty());
    assert_eq!(server.alerts, [AlertDescription::BadCertificate; 4]);
    let Some(Event::Failed {
        error: Error::Tls(message),
        ..
    }) = resolver.poll_event()
    else {
        panic!("expected a TLS failure");
    };
    assert!(message.contains("not valid for name"), "{message}");
}

/// RFC 8310 §7.1: each server can have its own authentication name, so
/// servers of different operators can be mixed. With one name for both,
/// the second server's certificate is rejected.
#[test]
fn each_server_has_its_own_name() {
    let first = cert("dns.example");
    let second = cert("other.example");
    let client = client(&[&first, &second]);
    let now = Instant::now();
    let other = ServerName::try_from("other.example").unwrap();
    let names = [(T1, dns_example()), (T2, other)];
    let config = Config::new(T1, [T2]).with_tls_names(Arc::clone(&client), names);
    let mut resolver = Resolver::new(config.unwrap());
    query(&mut resolver, "example.com.", now);
    let mut server = Server::new(server_config(&first));
    server.configs.insert(T2, server_config(&second));
    server.refuse = Some(T1);

    run(&mut resolver, &mut server, now);
    let mut single = tls_resolver(client, now);
    run(&mut single, &mut server, now);

    assert_eq!(
        server.sni[..2],
        [
            Some("dns.example".to_owned()),
            Some("other.example".to_owned())
        ]
    );
    assert!(is_response(resolver.poll_event()));
    assert_matches!(
        single.poll_event(),
        Some(Event::Failed {
            error: Error::Tls(_),
            ..
        })
    );
}

#[test]
fn every_server_needs_a_name_and_every_name_a_server() {
    let (client, _) = configs();

    let missing = Config::new(T1, [T2]).with_tls_names(Arc::clone(&client), [(T1, dns_example())]);
    let names = [
        (T1, dns_example()),
        (T2, dns_example()),
        (T6, dns_example()),
    ];
    let unknown = Config::new(T1, [T2]).with_tls_names(client, names);

    assert_eq!(missing.unwrap_err(), TlsConfigError::NoName(T2));
    assert_eq!(unknown.unwrap_err(), TlsConfigError::UnknownServer(T6));
}

/// A FORMERR without OPT doesn't make the query drop EDNS over TLS, since
/// EDNS carries the padding: it moves on like any other server error, and
/// the server isn't asked again (RFC 1035 §7.2).
#[test]
fn formerr_without_opt_over_tls_keeps_edns_and_moves_on() {
    let (client, server_config) = configs();
    let now = Instant::now();
    let mut resolver = tls_resolver(client, now);
    let mut server = Server::new(server_config);
    server.formerr = true;

    let sent = run(&mut resolver, &mut server, now);

    assert_eq!(connects(&sent), [T1, T2]);
    assert_eq!(server.queries.len(), 2, "one query per server");
    assert!(server.queries.iter().all(|(_, q)| q.len() % 128 == 0));
    assert!(server.requests().iter().all(|r| r.edns.is_some()));
    assert_matches!(
        resolver.poll_event(),
        Some(Event::Failed {
            error: Error::Server(ResponseCode::FormErr),
            ..
        })
    );
}

/// §3.4: later queries reuse the established session, without a new
/// connection or handshake.
#[test]
fn later_query_reuses_the_session() {
    let (client, server_config) = configs();
    let now = Instant::now();
    let mut resolver = tls_resolver(client, now);
    let mut server = Server::new(server_config);
    run(&mut resolver, &mut server, now);
    assert!(is_response(resolver.poll_event()));

    query(&mut resolver, "example.org.", now);
    let sent = run(&mut resolver, &mut server, now);

    assert!(
        sent.iter()
            .all(|t| matches!(t.transport, Transport::TcpWrite(_)))
    );
    assert_eq!(server.queries.len(), 2);
    assert_eq!(server.handshakes.len(), 1);
    assert!(is_response(resolver.poll_event()));
}

/// RFC 8446 §6.1: the resolver sends close_notify before it closes an idle
/// connection. §3.4, RFC 8310 §9: the next connection resumes the session.
#[test]
fn idle_close_sends_close_notify_and_the_next_connection_resumes() {
    let (client, server_config) = configs();
    let now = Instant::now();
    let mut resolver = tls_resolver(client, now);
    let mut server = Server::new(server_config);
    run(&mut resolver, &mut server, now);
    assert!(is_response(resolver.poll_event()));

    let later = resolver.poll_timeout().unwrap();
    resolver.handle_timeout(later);
    let closing = run(&mut resolver, &mut server, later);
    query(&mut resolver, "example.org.", later);
    let sent = run(&mut resolver, &mut server, later);

    assert_matches!(
        closing.as_slice(),
        [
            Transmit {
                transport: Transport::TcpWrite(a),
                ..
            },
            Transmit {
                transport: Transport::TcpClose(b),
                payload,
                ..
            },
        ] if a == b && payload.is_empty()
    );
    assert_eq!(server.close_notifies, 1);
    assert_eq!(connects(&sent), [T1]);
    assert_eq!(
        server.handshakes,
        [HandshakeKind::Full, HandshakeKind::Resumed]
    );
    assert!(is_response(resolver.poll_event()));
}

/// RFC 8446 §6.1: a connection closed because a query on it timed out
/// gets close_notify too.
#[test]
fn timeout_close_sends_close_notify() {
    let (client, server_config) = configs();
    let now = Instant::now();
    let mut resolver = tls_resolver(client, now);
    let mut server = Server::new(server_config);
    server.silent = true;
    run(&mut resolver, &mut server, now);

    let deadline = resolver.poll_timeout().unwrap();
    resolver.handle_timeout(deadline);
    let sent = run(&mut resolver, &mut server, deadline);

    assert!(matches!(sent[0].transport, Transport::TcpWrite(_)));
    assert!(matches!(sent[1].transport, Transport::TcpClose(_)));
    assert_eq!(server.close_notifies, 1);
    assert_eq!(connects(&sent), [T2]);
}

/// RFC 8446 §6.1: `shutdown`, for a driver that stops, closes every
/// connection after its close_notify and forgets the queries in flight.
#[test]
fn shutdown_sends_close_notify() {
    let (client, server_config) = configs();
    let now = Instant::now();
    let mut resolver = tls_resolver(client, now);
    let mut server = Server::new(server_config);
    server.silent = true;
    run(&mut resolver, &mut server, now);

    resolver.shutdown();
    let sent = run(&mut resolver, &mut server, now);

    assert_matches!(
        sent.as_slice(),
        [
            Transmit {
                transport: Transport::TcpWrite(a),
                ..
            },
            Transmit {
                transport: Transport::TcpClose(b),
                ..
            },
        ] if a == b
    );
    assert_eq!(server.close_notifies, 1);
    assert!(resolver.poll_event().is_none());
    assert_eq!(resolver.poll_timeout(), None);
}

/// §3.4, RFC 8446 §6.1: the server's close_notify retires the connection.
/// What follows it is ignored, the resolver answers with its own and
/// closes, and the query still on the connection is sent again on a new
/// one, as after the server closed it. The driver's later report of the
/// close changes nothing.
#[test]
fn server_close_notify_closes_the_connection() {
    let (client, server_config) = configs();
    let now = Instant::now();
    let mut resolver = tls_resolver(client, now);
    let mut server = Server::new(server_config);
    let connection = conn(&run(&mut resolver, &mut server, now)[0]);
    assert!(is_response(resolver.poll_event()));
    server.silent = true;
    query(&mut resolver, "example.org.", now);
    run(&mut resolver, &mut server, now);

    let mut bytes = server.close_notify(connection);
    // An application data record after it.
    bytes.extend([0x17, 3, 3, 0, 2, 0, 0]);
    resolver.handle_stream_data(connection, &bytes, now);
    let closing: Vec<Transmit> = std::iter::from_fn(|| resolver.poll_transmit()).collect();
    resolver.handle_stream_closed(connection, now);
    resolver.handle_stream_error(connection, ErrorKind::ConnectionReset, now);

    assert_matches!(
        closing.as_slice(),
        [
            Transmit {
                transport: Transport::TcpWrite(a),
                ..
            },
            Transmit {
                transport: Transport::TcpClose(b),
                ..
            },
            Transmit {
                transport: Transport::TcpConnect(_),
                destination,
                ..
            },
        ] if *a == connection && *b == connection && *destination == T1
    );
    assert!(resolver.poll_transmit().is_none());
    assert!(resolver.poll_event().is_none());
    server.silent = false;
    for t in &closing {
        let back = server.receive(t);
        if !back.is_empty() {
            resolver.handle_stream_data(conn(t), &back, now);
        }
    }
    run(&mut resolver, &mut server, now);
    assert_eq!(server.close_notifies, 1);
    assert!(is_response(resolver.poll_event()));
}

/// §3.4, RFC 8446 §6.1: an answer that arrives with the server's
/// close_notify can move its query on to the same server, here to the next
/// search candidate. That goes to a new connection, not the one being
/// closed, and is its first send there (RFC 9520 §3.1).
#[test]
fn answer_with_close_notify_moves_on_over_a_new_connection() {
    let (client, server_config) = configs();
    let now = Instant::now();
    let mut config = Config::new(T1, [T2])
        .with_tls(client, dns_example())
        .unwrap();
    config.search = vec![Name::from_ascii("example.com.").unwrap()];
    let mut resolver = Resolver::new(config);
    let mut server = Server::new(server_config);
    server.silent = true;
    let name = Name::from_ascii("host").unwrap();
    resolver.query(name, RecordType::A, now).unwrap();
    let connection = conn(&run(&mut resolver, &mut server, now)[0]);

    let request = server.requests().pop().unwrap();
    assert_eq!(request.queries[0].name().to_ascii(), "host.example.com.");
    let nxdomain = with_code(reply_to(&request), ResponseCode::NXDomain);
    let bytes = server.answer_and_close(connection, &nxdomain);
    resolver.handle_stream_data(connection, &bytes, now);
    let sent: Vec<Transmit> = std::iter::from_fn(|| resolver.poll_transmit()).collect();

    assert_matches!(
        sent.as_slice(),
        [
            Transmit {
                transport: Transport::TcpConnect(new),
                destination,
                ..
            },
            Transmit {
                transport: Transport::TcpWrite(a),
                ..
            },
            Transmit {
                transport: Transport::TcpClose(b),
                ..
            },
        ] if *new != connection && *destination == T1 && *a == connection && *b == connection
    );
    server.silent = false;
    for t in &sent {
        let back = server.receive(t);
        if !back.is_empty() {
            resolver.handle_stream_data(conn(t), &back, now);
        }
    }
    run(&mut resolver, &mut server, now);
    let names: Vec<String> = server
        .requests()
        .iter()
        .map(|r| r.queries[0].name().to_ascii())
        .collect();
    assert_eq!(names, ["host.example.com.", "host."]);
    assert!(is_response(resolver.poll_event()));
}

/// §3.4: clients must handle abrupt closes and reestablish connections. A
/// query on a connection the server closed after answering is sent again
/// on a new one, with a new (resumed) handshake.
#[test]
fn lost_connection_is_reestablished() {
    let (client, server_config) = configs();
    let now = Instant::now();
    let mut resolver = tls_resolver(client, now);
    let mut server = Server::new(server_config);
    let connection = conn(&run(&mut resolver, &mut server, now)[0]);
    assert!(is_response(resolver.poll_event()));
    server.silent = true;
    query(&mut resolver, "example.org.", now);
    run(&mut resolver, &mut server, now);
    server.silent = false;

    resolver.handle_stream_closed(connection, now);
    let sent = run(&mut resolver, &mut server, now);

    assert_eq!(connects(&sent), [T1]);
    assert_eq!(
        server.handshakes,
        [HandshakeKind::Full, HandshakeKind::Resumed]
    );
    assert_eq!(server.queries.len(), 3);
    assert!(is_response(resolver.poll_event()));
}

/// A query started during the handshake waits for it on the same
/// connection, as with the A and AAAA queries of an `IpLookup`.
#[test]
fn query_during_handshake_waits_for_it() {
    let (client, server_config) = configs();
    let now = Instant::now();
    let mut resolver = tls_resolver(client, now);
    let mut server = Server::new(server_config);
    let name = Name::from_ascii("example.org.").unwrap();
    resolver.query(name, RecordType::AAAA, now).unwrap();

    let sent = run(&mut resolver, &mut server, now);

    assert_eq!(connects(&sent), [T1]);
    assert_eq!(server.queries.len(), 2);
    assert!(is_response(resolver.poll_event()));
    assert!(is_response(resolver.poll_event()));
}

/// §3.3: any number of queries can wait for the handshake, beyond the 64
/// KiB rustls would buffer, and each goes out whole with its length. Their
/// answers arrive in one read of more than 16 KiB.
#[test]
fn many_queries_wait_for_the_handshake() {
    let (client, server_config) = configs();
    let now = Instant::now();
    let mut resolver = tls_resolver(client, now);
    let mut server = Server::new(server_config);
    for i in 1..700 {
        query(&mut resolver, &format!("q{i}.example.com."), now);
    }

    let sent = run(&mut resolver, &mut server, now);

    assert_eq!(connects(&sent), [T1]);
    assert_eq!(server.queries.len(), 700);
    let events: Vec<Event> = std::iter::from_fn(|| resolver.poll_event()).collect();
    assert_eq!(events.len(), 700);
    assert!(events.into_iter().all(|e| is_response(Some(e))));
}

/// §3.3, RFC 7766 §8: an answer of more than 16 KiB, read in one chunk,
/// comes through the session whole.
#[test]
fn large_answer_in_one_read() {
    let (client, server_config) = configs();
    let now = Instant::now();
    let mut resolver = tls_resolver(client, now);
    let mut server = Server::new(server_config);
    server.records = 1500;

    let sent = run(&mut resolver, &mut server, now);

    assert_eq!(connects(&sent), [T1]);
    let Some(Event::Response { response, .. }) = resolver.poll_event() else {
        panic!("expected a response");
    };
    assert_eq!(response.answers.len(), 1500);
    assert!(response.to_vec().unwrap().len() > 16 * 1024);
}
