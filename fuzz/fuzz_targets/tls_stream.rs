//! DNS over TLS connections fed arbitrary bytes, or the records of an
//! in-process rustls server that the input steers and tampers with: what
//! it says inside the session, when it sends close_notify, and what
//! follows. The server checks each query it decrypts: padded to a multiple
//! of 128 octets while it has an OPT record (RFC 8467 §4.1), and sent at
//! most `attempts + 3` times. Run with `-timeout` so a receive loop that
//! stops making progress shows up as a hang.

#![no_main]

use std::collections::BTreeMap;
use std::io::{Read, Write};
use std::sync::{Arc, OnceLock};

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;
use rustls::client::Resumption;
use rustls::pki_types::{PrivatePkcs8KeyDer, ServerName};
use rustls::{ClientConfig, RootCertStore, ServerConfig, ServerConnection};
use sansio_dns::hickory_proto::op::{Message, ResponseCode};
use sansio_dns::hickory_proto::rr::{Name, RecordType};
use sansio_dns::{Config, ConnectionId, Transport};
use sansio_dns_fuzz::{Code, Harness, S1, S2, flip, frame, name, reply};

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
    Closed {
        connection: u8,
    },
    Failed {
        connection: u8,
    },
    Query,
    Elapse(u16),
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

/// How often the servers decrypted each query, by message ID and name.
/// Every query asks a different name, so a reused message ID can't add to
/// another query's count.
struct Sends {
    max: usize,
    counts: BTreeMap<(u16, Name), usize>,
}

impl Sends {
    fn check(&mut self, query: &[u8]) -> Message {
        let request = Message::from_vec(query).expect("the resolver sent garbage");
        if request.edns.is_some() {
            assert_eq!(query.len() % 128, 0, "query not padded to 128 octets");
        }
        let name = request.queries.first().map(|q| q.name().clone());
        let key = (request.metadata.id, name.unwrap_or_default());
        let count = self.counts.entry(key).or_default();
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
    session: ServerConnection,
    /// Decrypted bytes from the resolver not yet split into queries.
    plaintext: Vec<u8>,
    /// Queries read and not yet answered.
    queries: Vec<Message>,
    /// Bytes written to the resolver but not yet delivered.
    outbox: Vec<u8>,
    /// Whether the session failed, so it takes no more input.
    failed: bool,
}

impl Peer {
    fn receive(&mut self, mut data: &[u8], sends: &mut Sends) {
        while !data.is_empty() && !self.failed {
            match self.session.read_tls(&mut data) {
                Ok(0) | Err(_) => self.failed = true,
                Ok(_) => self.failed = self.session.process_new_packets().is_err(),
            }
        }
        // EOF and WouldBlock both just mean nothing more for now.
        let _ = self.session.reader().read_to_end(&mut self.plaintext);
        while let Some((len, rest)) = self.plaintext.split_first_chunk::<2>() {
            let len = usize::from(u16::from_be_bytes(*len));
            let Some(query) = rest.get(..len) else {
                break;
            };
            self.queries.push(sends.check(query));
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
                    session,
                    plaintext: Vec::new(),
                    queries: Vec::new(),
                    outbox: Vec::new(),
                    failed: false,
                };
                peer.receive(&t.payload, sends);
                peers.insert(c, peer);
            }
            Transport::TcpWrite(c) => {
                if let Some(peer) = peers.get_mut(&c) {
                    peer.receive(&t.payload, sends);
                }
            }
            Transport::TcpClose(c) => {
                peers.remove(&c);
            }
            Transport::Udp(_) => panic!("a DoT resolver sent a datagram"),
        }
    }
}

fuzz_target!(|steps: Vec<Step>| {
    let (client, _) = configs();
    let server_name = ServerName::try_from("dns.example").expect("a valid name");
    let Ok(config) = Config::new(S1, [S2]).with_tls(Arc::clone(client), server_name) else {
        return;
    };
    let mut sends = Sends {
        max: config.attempts.get() + 3,
        counts: BTreeMap::new(),
    };
    let mut harness = Harness::new(config, vec![S1, S2], None).tls();
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
                flip(&mut bytes, flips);
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
                let peer = harness.open(*connection).and_then(|c| peers.get_mut(&c));
                if let Some(peer) = peer {
                    peer.session.send_close_notify();
                    peer.flush();
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
        }
        pump(&mut harness, &mut peers, &mut sends);
    }
});
