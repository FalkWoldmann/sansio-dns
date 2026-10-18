//! DNS over TLS connections fed arbitrary bytes, or the records of an
//! in-process rustls server that the input steers and tampers with: what
//! it says inside the session, when it sends close_notify, and what
//! follows. The server checks each query it decrypts: it keeps its OPT
//! record, carries a Client Subnet option with SOURCE PREFIX-LENGTH 0 for
//! the server's address family (RFC 8310 §11.1, RFC 7871 §7.1.2), then one
//! padding option, last, to a multiple of 128 octets (RFC 8467 §3, §4.1),
//! and is sent at most `attempts + 3` times, and at most three times to one
//! server (RFC 9520 §3.1). Every connection the resolver closes ends its
//! session first, with close_notify or an alert (RFC 8446 §6), unless an
//! alert from the server that rustls reports as the error ended it: the
//! server's own fatal alert, or one that raw or tampered bytes may hold
//! while the client still takes a plaintext alert, before it has decrypted
//! anything. Once the server's own fatal alert reaches an untampered
//! connection, the resolver writes nothing more to it (§6.2). Run with
//! `-timeout` so a receive loop that stops making progress shows up as a
//! hang.

#![no_main]

use std::collections::BTreeMap;
use std::io::{Read, Write};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::{Arc, OnceLock};

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;
use rustls::client::Resumption;
use rustls::pki_types::{PrivatePkcs8KeyDer, ServerName};
use rustls::{ClientConfig, RootCertStore, ServerConfig, ServerConnection};
use sansio_dns::hickory_proto::op::{Message, ResponseCode};
use sansio_dns::hickory_proto::rr::rdata::opt::{EdnsCode, EdnsOption};
use sansio_dns::hickory_proto::rr::{Name, RecordType};
use sansio_dns::{Config, ConnectionId, Transport};
use sansio_dns_fuzz::{Code, Harness, flip, frame, name, reply};

/// Name servers on the DNS over TLS port, one of each address family.
const T1: SocketAddr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), 853);
const T2: SocketAddr = SocketAddr::new(
    IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 2)),
    853,
);

#[derive(Arbitrary, Debug)]
enum Step {
    /// Raw bytes on an open connection, instead of the server's.
    Raw {
        connection: u8,
        bytes: Vec<u8>,
    },
    /// Pass on up to `len` bytes the server wrote (all for 0), tampered with.
    Deliver {
        connection: u8,
        len: u16,
        flips: Vec<(u16, u8)>,
    },
    /// The server answers the queries it has read with an address.
    Answer {
        connection: u8,
    },
    /// The server answers the queries it has read with `code`, and without
    /// an OPT record unless `edns`.
    AnswerWith {
        connection: u8,
        code: Code,
        edns: bool,
    },
    /// The server sends arbitrary plaintext inside the session.
    Write {
        connection: u8,
        plaintext: Vec<u8>,
    },
    CloseNotify {
        connection: u8,
    },
    /// The server takes in a record that doesn't decrypt, so its session
    /// fails and it queues a fatal alert for the resolver.
    Reject {
        connection: u8,
    },
    Closed {
        connection: u8,
    },
    Failed {
        connection: u8,
    },
    Query,
    Elapse(u16),
    /// The driver stops (`Resolver::shutdown`).
    Shutdown,
}

/// A client trusting a self-signed `dns.example` certificate, and a server
/// presenting it. Made once: generating keys is slow. Resumption is off so
/// no state carries over between runs.
fn configs() -> &'static (Arc<ClientConfig>, Arc<ServerConfig>) {
    static CONFIGS: OnceLock<(Arc<ClientConfig>, Arc<ServerConfig>)> = OnceLock::new();
    CONFIGS.get_or_init(|| {
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let cert = rcgen::generate_simple_self_signed(vec!["dns.example".to_owned()])
            .expect("a certificate");
        let mut roots = RootCertStore::empty();
        roots.add(cert.cert.der().clone()).expect("a root");
        let mut client = ClientConfig::builder_with_provider(Arc::clone(&provider))
            .with_safe_default_protocol_versions()
            .expect("ring supports TLS 1.2 and 1.3")
            .with_root_certificates(roots)
            .with_no_client_auth();
        client.resumption = Resumption::disabled();
        let key = PrivatePkcs8KeyDer::from(cert.signing_key.serialize_der());
        let mut server = ServerConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .expect("ring supports TLS 1.2 and 1.3")
            .with_no_client_auth()
            .with_single_cert(vec![cert.cert.der().clone()], key.into())
            .expect("a matching key");
        server.send_tls13_tickets = 0;
        (Arc::new(client), Arc::new(server))
    })
}

/// How often the servers decrypted each query, by message ID and name, in
/// all and per server. Every query asks a different name, so a reused
/// message ID can't add to another query's count.
struct Sends {
    max: usize,
    counts: BTreeMap<(u16, Name), usize>,
    per_server: BTreeMap<(u16, Name, SocketAddr), usize>,
}

impl Sends {
    fn check(&mut self, query: &[u8], server: SocketAddr) -> Message {
        let request = Message::from_vec(query).expect("the resolver sent garbage");
        let edns = request.edns.as_ref().expect("query without EDNS over TLS");
        assert_eq!(query.len() % 128, 0, "query not padded to 128 octets");
        let options = edns.options().as_ref();
        assert!(
            matches!(
                options,
                [(EdnsCode::Subnet, EdnsOption::Subnet(subnet)), (EdnsCode::Padding, _)]
                    if subnet.source_prefix() == 0
                        && subnet.scope_prefix() == 0
                        && subnet.addr().is_ipv6() == server.is_ipv6()
            ),
            "not a Client Subnet privacy election, then padding: {options:?}"
        );
        let name = request.queries.first().map(|q| q.name().clone());
        let (id, name) = (request.metadata.id, name.unwrap_or_default());
        let count = self
            .per_server
            .entry((id, name.clone(), server))
            .or_default();
        *count += 1;
        assert!(*count <= 3, "query sent to {server} a fourth time");
        let count = self.counts.entry((id, name)).or_default();
        *count += 1;
        assert!(
            *count <= self.max,
            "query sent more than {} times",
            self.max
        );
        request
    }
}

/// The server's end of one connection.
struct Peer {
    server: SocketAddr,
    session: ServerConnection,
    /// Decrypted bytes from the resolver not yet split into queries.
    plaintext: Vec<u8>,
    /// Queries read and not yet answered.
    queries: Vec<Message>,
    /// Bytes written to the resolver but not yet delivered.
    outbox: Vec<u8>,
    /// Whether the session failed, so it takes no more input.
    failed: bool,
    /// Whether the resolver ended the session, with close_notify or an
    /// alert. An alert the server can't decrypt, because tampered
    /// handshake bytes left the two ends with different keys, fails the
    /// session instead: the bytes from the resolver are never tampered
    /// with, so a failure on them comes from such an alert.
    ended: bool,
    /// Whether the server has decrypted application data from the
    /// resolver, which rustls sends only once its handshake is done: the
    /// client has then decrypted a record, and takes no plaintext alert any
    /// more.
    secure: bool,
    /// Whether the resolver was fed bytes other than the server's own, in
    /// order, on this connection.
    garbled: bool,
    /// Whether it was fed them before `secure`, so they may have held a
    /// plaintext fatal alert the client took.
    tampered: bool,
    /// After `Step::Reject` on a connection that was never garbled and had
    /// finished its handshake: how many bytes of `outbox` are left to
    /// deliver up to the end of the server's alert.
    alert_end: Option<usize>,
    /// Whether that alert reached the resolver whole, after which it may
    /// write nothing more to the connection (RFC 8446 §6.2).
    alerted: bool,
    /// Whether the server sent close_notify, after which its session may
    /// send no alert (a debug assertion of rustls').
    notified: bool,
}

impl Peer {
    fn receive(&mut self, mut data: &[u8], sends: &mut Sends) {
        while !data.is_empty() && !self.failed {
            match self.session.read_tls(&mut data) {
                Ok(0) | Err(_) => self.failed = true,
                Ok(_) => match self.session.process_new_packets() {
                    Ok(state) => self.ended |= state.peer_has_closed(),
                    Err(error) => {
                        self.failed = true;
                        self.ended |= matches!(error, rustls::Error::AlertReceived(_));
                    }
                },
            }
        }
        // EOF and WouldBlock both just mean nothing more for now.
        let before = self.plaintext.len();
        let _ = self.session.reader().read_to_end(&mut self.plaintext);
        self.secure |= self.plaintext.len() > before;
        while let Some((len, rest)) = self.plaintext.split_first_chunk::<2>() {
            let len = usize::from(u16::from_be_bytes(*len));
            let Some(query) = rest.get(..len) else {
                break;
            };
            self.queries.push(sends.check(query, self.server));
            self.plaintext.drain(..2 + len);
        }
        self.flush();
    }

    fn answer(&mut self, code: ResponseCode, edns: bool) {
        for request in std::mem::take(&mut self.queries) {
            let mut response = reply(&request, code);
            if !edns {
                response.edns = None;
            }
            if let Ok(answer) = response.to_vec() {
                self.write(&frame(&answer));
            }
        }
    }

    fn write(&mut self, plaintext: &[u8]) {
        if self.session.writer().write_all(plaintext).is_ok() {
            self.flush();
        }
    }

    /// Note that the resolver was fed bytes other than the server's own.
    fn garble(&mut self) {
        self.garbled = true;
        self.tampered |= !self.secure;
        self.alert_end = None;
    }

    /// Note that the first `len` bytes of `outbox` were delivered intact.
    fn delivered(&mut self, len: usize) {
        if let Some(end) = self.alert_end {
            if len >= end {
                self.alerted = true;
                self.alert_end = None;
            } else {
                self.alert_end = Some(end - len);
            }
        }
    }

    fn flush(&mut self) {
        while self.session.wants_write() {
            if self.session.write_tls(&mut self.outbox).is_err() {
                break;
            }
        }
    }
}

/// Check the resolver and hand what it wrote to the servers.
fn pump(harness: &mut Harness, peers: &mut BTreeMap<ConnectionId, Peer>, sends: &mut Sends) {
    for t in harness.check() {
        match t.transport {
            Transport::TcpConnect(c) => {
                let Ok(session) = ServerConnection::new(Arc::clone(&configs().1)) else {
                    continue;
                };
                let mut peer = Peer {
                    server: t.destination,
                    session,
                    plaintext: Vec::new(),
                    queries: Vec::new(),
                    outbox: Vec::new(),
                    failed: false,
                    ended: false,
                    secure: false,
                    garbled: false,
                    tampered: false,
                    alert_end: None,
                    alerted: false,
                    notified: false,
                };
                peer.receive(&t.payload, sends);
                peers.insert(c, peer);
            }
            Transport::TcpWrite(c) => {
                if let Some(peer) = peers.get_mut(&c) {
                    assert!(
                        !peer.alerted,
                        "{c:?} written after the server's fatal alert"
                    );
                    peer.receive(&t.payload, sends);
                }
            }
            Transport::TcpClose(c) => {
                if let Some(peer) = peers.remove(&c) {
                    assert!(
                        peer.ended || peer.failed || peer.tampered,
                        "{c:?} closed without close_notify or an alert"
                    );
                }
            }
            Transport::Udp(_) => panic!("a DoT resolver sent a datagram"),
        }
    }
}

fuzz_target!(|steps: Vec<Step>| {
    let (client, _) = configs();
    let server_name = ServerName::try_from("dns.example").expect("a valid name");
    let config = Config::new(T1, [T2])
        .with_tls(Arc::clone(client), server_name)
        .expect("a valid DNS over TLS configuration");
    let mut sends = Sends {
        max: config.attempts.get() + 3,
        counts: BTreeMap::new(),
        per_server: BTreeMap::new(),
    };
    let mut harness = Harness::new(config, vec![T1, T2], None).tls();
    let mut peers = BTreeMap::new();
    let mut queries = 0;
    let mut query = |harness: &mut Harness| {
        harness.query(name(&format!("q{queries}.example.com.")), RecordType::A);
        queries += 1;
    };
    query(&mut harness);
    pump(&mut harness, &mut peers, &mut sends);
    for step in steps.iter().take(128) {
        let now = harness.now;
        match step {
            Step::Raw { connection, bytes } => {
                if let Some(c) = harness.open(*connection) {
                    if let Some(peer) = peers.get_mut(&c) {
                        peer.garble();
                    }
                    harness.resolver.handle_stream_data(c, bytes, now);
                }
            }
            Step::Deliver {
                connection,
                len,
                flips,
            } => {
                let Some(c) = harness.open(*connection) else {
                    continue;
                };
                let Some(peer) = peers.get_mut(&c) else {
                    continue;
                };
                let len = match usize::from(*len) {
                    0 => peer.outbox.len(),
                    len => len.min(peer.outbox.len()),
                };
                let mut bytes: Vec<u8> = peer.outbox.drain(..len).collect();
                let untouched = bytes.clone();
                flip(&mut bytes, flips);
                if bytes == untouched {
                    peer.delivered(len);
                } else {
                    peer.garble();
                }
                harness.resolver.handle_stream_data(c, &bytes, now);
            }
            Step::Answer { connection } => {
                let peer = harness.open(*connection).and_then(|c| peers.get_mut(&c));
                if let Some(peer) = peer {
                    peer.answer(ResponseCode::NoError, true);
                }
            }
            Step::AnswerWith {
                connection,
                code,
                edns,
            } => {
                let peer = harness.open(*connection).and_then(|c| peers.get_mut(&c));
                if let Some(peer) = peer {
                    peer.answer((*code).into(), *edns);
                }
            }
            Step::Write {
                connection,
                plaintext,
            } => {
                let peer = harness.open(*connection).and_then(|c| peers.get_mut(&c));
                if let Some(peer) = peer {
                    peer.write(plaintext);
                }
            }
            Step::CloseNotify { connection } => {
                // Not during the handshake: a rustls server that sent
                // close_notify then and gets the resolver's close_notify
                // trips a debug assertion of its own.
                let peer = harness.open(*connection).and_then(|c| peers.get_mut(&c));
                if let Some(peer) = peer.filter(|p| !p.session.is_handshaking()) {
                    peer.session.send_close_notify();
                    peer.notified = true;
                    peer.flush();
                }
            }
            Step::Reject { connection } => {
                let peer = harness.open(*connection).and_then(|c| peers.get_mut(&c));
                if let Some(peer) = peer.filter(|p| !p.failed && !p.notified) {
                    let armed = !peer.garbled && !peer.session.is_handshaking();
                    // An application data record of 20 zero bytes.
                    let record: Vec<u8> = [0x17, 3, 3, 0, 20].into_iter().chain([0; 20]).collect();
                    if peer.session.read_tls(&mut &record[..]).is_ok() {
                        peer.failed = peer.session.process_new_packets().is_err();
                    }
                    peer.flush();
                    if armed && peer.failed {
                        peer.alert_end = Some(peer.outbox.len());
                    }
                }
            }
            Step::Closed { connection } => {
                if let Some(c) = harness.open(*connection) {
                    harness.lose(c, false);
                    peers.remove(&c);
                }
            }
            Step::Failed { connection } => {
                if let Some(c) = harness.open(*connection) {
                    harness.lose(c, true);
                    peers.remove(&c);
                }
            }
            Step::Query => query(&mut harness),
            Step::Elapse(millis) => harness.elapse(*millis),
            Step::Shutdown => harness.shutdown(),
        }
        pump(&mut harness, &mut peers, &mut sends);
    }
});
