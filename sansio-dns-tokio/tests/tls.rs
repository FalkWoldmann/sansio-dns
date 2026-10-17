//! DNS over TLS through the driver: how its connections end (RFC 8446
//! §6.1).

use std::io::{ErrorKind, Read, Write};
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use crate::common::answer;
use rustls::pki_types::{PrivatePkcs8KeyDer, ServerName};
use rustls::{ClientConfig, RootCertStore, ServerConfig, ServerConnection};
use sansio_dns::Config;
use sansio_dns::hickory_proto::rr::Name;
use sansio_dns_tokio::Resolver;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::sync::oneshot;

/// A DNS over TLS name server for `app.example.` on localhost, for one
/// connection, and a resolver that trusts its certificate. With `close`, the
/// server sends close_notify and closes its side once it has answered the
/// lookup's two queries. Reports whether the resolver ended the session
/// with close_notify.
async fn tls_resolver(close: bool) -> (Resolver, oneshot::Receiver<bool>) {
    let key = rcgen::generate_simple_self_signed(vec!["dns.example".to_owned()]).unwrap();
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let mut roots = RootCertStore::empty();
    roots.add(key.cert.der().clone()).unwrap();
    let client = ClientConfig::builder_with_provider(Arc::clone(&provider))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_root_certificates(roots)
        .with_no_client_auth();
    let server = ServerConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(
            vec![key.cert.der().clone()],
            PrivatePkcs8KeyDer::from(key.signing_key.serialize_der()).into(),
        )
        .unwrap();
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let address: SocketAddr = listener.local_addr().unwrap();
    let (report, ended) = oneshot::channel();
    tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut session = ServerConnection::new(Arc::new(server)).unwrap();
        let host = Name::from_ascii("app.example.").unwrap();
        let mut plaintext = Vec::new();
        let mut answered = 0;
        let mut buf = [0; 4096];
        let notified = 'serve: loop {
            let n = stream.read(&mut buf).await.unwrap_or(0);
            if n == 0 {
                break false;
            }
            let mut data = &buf[..n];
            while !data.is_empty() {
                session.read_tls(&mut data).unwrap();
                let state = session.process_new_packets().unwrap();
                if state.peer_has_closed() {
                    break 'serve true;
                }
                if let Err(e) = session.reader().read_to_end(&mut plaintext) {
                    assert_eq!(e.kind(), ErrorKind::WouldBlock);
                }
            }
            while plaintext.len() >= 2 {
                let len = usize::from(u16::from_be_bytes([plaintext[0], plaintext[1]]));
                if plaintext.len() < 2 + len {
                    break;
                }
                let query: Vec<u8> = plaintext.drain(..2 + len).skip(2).collect();
                let answer = answer(&host, &query, false);
                let len = u16::try_from(answer.len()).unwrap();
                session.writer().write_all(&len.to_be_bytes()).unwrap();
                session.writer().write_all(&answer).unwrap();
                answered += 1;
            }
            if close && answered == 2 {
                answered += 1;
                session.send_close_notify();
            }
            let mut out = Vec::new();
            while session.wants_write() {
                session.write_tls(&mut out).unwrap();
            }
            stream.write_all(&out).await.unwrap();
            if close && answered > 2 {
                // close_notify and FIN together, as servers send them.
                stream.shutdown().await.unwrap();
            }
        };
        report.send(notified).ok();
    });
    let config = Config::new(address, [])
        .with_tls(
            Arc::new(client),
            ServerName::try_from("dns.example").unwrap(),
        )
        .unwrap();
    (Resolver::new(config), ended)
}

/// The resolver answers the server's close_notify with its own, even when
/// the server closes the connection right after it.
#[tokio::test]
async fn server_close_notify_is_answered() {
    let (resolver, ended) = tls_resolver(true).await;

    resolver.lookup_ip("app.example").await.unwrap();

    let notified = tokio::time::timeout(Duration::from_secs(5), ended).await;
    assert!(notified.unwrap().unwrap());
    drop(resolver);
}

#[tokio::test]
async fn dropping_the_resolver_sends_close_notify() {
    let (resolver, ended) = tls_resolver(false).await;
    resolver.lookup_ip("app.example").await.unwrap();

    drop(resolver);

    let notified = tokio::time::timeout(Duration::from_secs(5), ended).await;
    assert!(notified.unwrap().unwrap());
}
