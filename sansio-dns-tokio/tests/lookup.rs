//! `Resolver::lookup_ip` against a name server on localhost.

use std::future::{Future, poll_fn};
use std::io::ErrorKind;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::pin::pin;
use std::sync::atomic::Ordering;
use std::task::Poll;
use std::time::Duration;

use crate::common::{V4, V6, counting_name_server, name_server, name_server_on};
use rstest::rstest;
use sansio_dns::Config;
use sansio_dns::hickory_proto::op::{Message, OpCode};
use sansio_dns::hickory_proto::rr::rdata::{A, AAAA};
use sansio_dns::hickory_proto::rr::{RData, Record, RecordType};
use sansio_dns_tokio::{Error, Resolver};
use tokio::net::UdpSocket;

#[rstest]
#[case::over_udp(false)]
#[case::truncated_then_over_tcp(true)]
#[tokio::test]
async fn finds_both_families(#[case] truncate_udp: bool) {
    let server = name_server("app.example.", truncate_udp).await;
    let resolver = Resolver::new(Config::new(server, []));

    let addresses = resolver.lookup_ip("app.example").await.unwrap();

    assert_eq!(addresses, [IpAddr::V6(V6), IpAddr::V4(V4)]);
}

#[tokio::test]
async fn non_ascii_name_is_looked_up_in_its_ascii_form() {
    let server = name_server("xn--bcher-kva.example.", false).await;
    let resolver = Resolver::new(Config::new(server, []));

    let addresses = resolver.lookup_ip("bücher.example").await.unwrap();

    assert_eq!(addresses, [IpAddr::V6(V6), IpAddr::V4(V4)]);
}

#[tokio::test]
async fn underscore_name_is_looked_up_as_given() {
    let server = name_server("my_host.example.", false).await;
    let resolver = Resolver::new(Config::new(server, []));

    let addresses = resolver.lookup_ip("my_host.example").await.unwrap();

    assert_eq!(addresses, [IpAddr::V6(V6), IpAddr::V4(V4)]);
}

#[tokio::test]
async fn unknown_name_is_not_found() {
    let server = name_server("app.example.", false).await;
    let resolver = Resolver::new(Config::new(server, []));

    let result = resolver.lookup_ip("other.example").await;

    assert!(matches!(result, Err(Error::NotFound)), "{result:?}");
}

/// The lookup starts the queries for the next search candidate itself
/// after the first one doesn't exist, and the driver sends them at once and
/// routes their events.
#[tokio::test]
async fn search_moves_on_to_the_next_candidate() {
    let server = name_server("app.corp.example.", false).await;
    let mut config = Config::new(server, []);
    config.search = ["other.example.", "corp.example."]
        .map(|domain| sansio_dns::hickory_proto::rr::Name::from_ascii(domain).unwrap())
        .to_vec();
    let resolver = Resolver::new(config);

    let lookup = resolver.lookup_ip("app");
    let addresses = tokio::time::timeout(Duration::from_secs(1), lookup).await;

    let addresses = addresses.expect("no deadline waited out").unwrap();
    assert_eq!(addresses, [IpAddr::V6(V6), IpAddr::V4(V4)]);
}

/// Sending to the broadcast address without `SO_BROADCAST` fails at once,
/// so the lookup moves to the next server without waiting out the
/// timeout, and fails with the send error when no server is left.
#[rstest]
#[case::next_server_answers(true)]
#[case::no_server_left(false)]
#[tokio::test]
async fn unsendable_datagram_moves_on_at_once(#[case] working_server: bool) {
    let broadcast = SocketAddr::from((Ipv4Addr::BROADCAST, 53));
    let more = if working_server {
        vec![name_server("app.example.", false).await]
    } else {
        Vec::new()
    };
    let resolver = Resolver::new(Config::new(broadcast, more));

    let lookup = resolver.lookup_ip("app.example");
    let result = tokio::time::timeout(Duration::from_secs(1), lookup).await;

    match result.expect("no deadline waited out") {
        Ok(addresses) => {
            assert!(working_server);
            assert_eq!(addresses, [IpAddr::V6(V6), IpAddr::V4(V4)]);
        }
        Err(error) => {
            assert!(!working_server, "{error:?}");
            assert!(
                matches!(error, Error::Resolve(sansio_dns::Error::Io(_))),
                "{error:?}"
            );
        }
    }
}

/// A datagram to a closed port draws an ICMP port unreachable, which the
/// connected socket reports as `ConnectionRefused`: the lookup moves to the
/// next server without waiting out the five-second timeout, and fails with
/// that error when no server is left (RFC 1123 §6.1.3.3). One query with
/// one attempt to the closed port, since kernels rate-limit ICMP errors.
#[rstest]
#[case::next_server_answers(true)]
#[case::no_server_left(false)]
#[tokio::test]
async fn refused_datagram_moves_on_at_once(#[case] working_server: bool) {
    let closed = UdpSocket::bind("127.0.0.1:0")
        .await
        .unwrap()
        .local_addr()
        .unwrap();
    let more = if working_server {
        vec![name_server("app.example.", false).await]
    } else {
        Vec::new()
    };
    let mut config = Config::new(closed, more);
    config.ip_strategy = sansio_dns::IpStrategy::Ipv4Only;
    if !working_server {
        config.attempts = std::num::NonZeroUsize::MIN;
    }
    let resolver = Resolver::new(config);

    let lookup = resolver.lookup_ip("app.example");
    let result = tokio::time::timeout(Duration::from_secs(1), lookup).await;

    match result.expect("no deadline waited out") {
        Ok(addresses) => {
            assert!(working_server);
            assert_eq!(addresses, [IpAddr::V4(V4)]);
        }
        Err(error) => {
            assert!(!working_server, "{error:?}");
            assert!(
                matches!(
                    error,
                    Error::Resolve(sansio_dns::Error::Io(ErrorKind::ConnectionRefused))
                ),
                "{error:?}"
            );
        }
    }
}

/// A receive error doesn't end the socket: with one server, the second
/// attempt goes out on the same connected socket, and its ICMP port
/// unreachable is reported too, so the lookup fails at once instead of
/// waiting out the timeout. macOS doesn't report a second port
/// unreachable on one socket that comes within a few hundred milliseconds
/// of the first, so there the second attempt waits out its deadline.
#[tokio::test]
#[cfg_attr(
    target_os = "macos",
    ignore = "macOS reports no second port unreachable this soon"
)]
async fn socket_works_after_a_receive_error() {
    let closed = UdpSocket::bind("127.0.0.1:0")
        .await
        .unwrap()
        .local_addr()
        .unwrap();
    let mut config = Config::new(closed, []);
    config.ip_strategy = sansio_dns::IpStrategy::Ipv4Only;
    config.attempts = std::num::NonZeroUsize::new(2).unwrap();
    let resolver = Resolver::new(config);

    let lookup = resolver.lookup_ip("app.example");
    let result = tokio::time::timeout(Duration::from_secs(1), lookup).await;

    let error = result.expect("no deadline waited out").unwrap_err();
    assert!(
        matches!(
            error,
            Error::Resolve(sansio_dns::Error::Io(ErrorKind::ConnectionRefused))
        ),
        "{error:?}"
    );
}

/// An answer from another address doesn't complete the lookup, and the
/// genuine one still does (RFC 5452 §9.1).
#[tokio::test]
async fn datagram_from_another_address_is_not_received() {
    let server = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let spoofer = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let mut config = Config::new(server.local_addr().unwrap(), []);
    config.ip_strategy = sansio_dns::IpStrategy::Ipv4Only;
    let resolver = Resolver::new(config);
    let lookup = tokio::spawn(async move { resolver.lookup_ip("app.example").await });
    let mut buf = [0; 512];
    let (n, from) = server.recv_from(&mut buf).await.unwrap();
    let query = Message::from_vec(&buf[..n]).unwrap();
    let mut spoofed = Message::response(query.metadata.id, OpCode::Query);
    spoofed.add_query(query.queries[0].clone());
    spoofed.add_answer(Record::from_rdata(
        query.queries[0].name().clone(),
        300,
        RData::A(A(Ipv4Addr::new(192, 0, 2, 66))),
    ));
    spoofer
        .send_to(&spoofed.to_vec().unwrap(), from)
        .await
        .unwrap();
    tokio::time::sleep(Duration::from_millis(50)).await;

    let mut genuine = Message::response(query.metadata.id, OpCode::Query);
    genuine.add_query(query.queries[0].clone());
    genuine.add_answer(Record::from_rdata(
        query.queries[0].name().clone(),
        300,
        RData::A(A(V4)),
    ));
    server
        .send_to(&genuine.to_vec().unwrap(), from)
        .await
        .unwrap();

    let addresses = lookup.await.unwrap().unwrap();
    assert_eq!(addresses, [IpAddr::V4(V4)]);
}

#[tokio::test]
async fn refused_tcp_fallback_fails_with_the_connect_error() {
    let server = truncating_udp_server().await;
    let resolver = Resolver::new(Config::new(server, []));

    let result = resolver.lookup_ip("app.example").await;

    assert!(
        matches!(
            result,
            Err(Error::Resolve(sansio_dns::Error::Io(
                ErrorKind::ConnectionRefused
            )))
        ),
        "{result:?}"
    );
}

#[tokio::test]
async fn lookups_share_one_connection() {
    let (server, connections) = counting_name_server("app.example.", true).await;
    let resolver = Resolver::new(Config::new(server, []));

    resolver.lookup_ip("app.example").await.unwrap();
    let (a, b, c) = tokio::join!(
        resolver.lookup_ip("app.example"),
        resolver.lookup_ip("app.example"),
        resolver.lookup_ip("app.example"),
    );

    assert!(a.is_ok() && b.is_ok() && c.is_ok());
    assert_eq!(connections.opened.load(Ordering::Relaxed), 1);
}

#[tokio::test]
async fn dropping_the_resolver_closes_its_connections() {
    let (server, connections) = counting_name_server("app.example.", true).await;
    let resolver = Resolver::new(Config::new(server, []));
    resolver.lookup_ip("app.example").await.unwrap();

    drop(resolver);

    tokio::time::timeout(Duration::from_secs(5), async {
        while connections.closed.load(Ordering::Relaxed) == 0 {
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn dropped_lookup_sends_no_retries() {
    let silent = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let mut config = Config::new(silent.local_addr().unwrap(), []);
    // The shortest wait the core allows; a retry would come after it.
    config.timeout = Duration::from_secs(1);
    let resolver = Resolver::new(config);
    let mut buf = [0; 512];

    tokio::select! {
        _ = resolver.lookup_ip("app.example") => panic!("nothing answers"),
        _ = async {
            silent.recv_from(&mut buf).await.unwrap();
            silent.recv_from(&mut buf).await.unwrap();
        } => {}
    }
    tokio::time::sleep(Duration::from_millis(1500)).await;

    let nothing = silent.try_recv_from(&mut buf).unwrap_err();
    assert_eq!(nothing.kind(), ErrorKind::WouldBlock);
}

/// The first runtime takes the background task with it; the next lookup
/// starts another.
#[test]
fn resolver_outlives_the_runtime_of_its_first_lookup() {
    let servers = tokio::runtime::Runtime::new().unwrap();
    let server = servers.block_on(name_server("app.example.", false));
    let resolver = Resolver::new(Config::new(server, []));

    for _ in 0..2 {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let addresses = runtime.block_on(resolver.lookup_ip("app.example")).unwrap();
        assert_eq!(addresses, [IpAddr::V6(V6), IpAddr::V4(V4)]);
    }
}

/// Lookups of one name in flight together share one A and one AAAA query.
#[tokio::test]
async fn concurrent_lookups_of_one_name_share_their_queries() {
    let server = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let resolver = Resolver::new(Config::new(server.local_addr().unwrap(), []));
    let lookups: Vec<_> = (0..5)
        .map(|_| {
            let resolver = resolver.clone();
            tokio::spawn(async move { resolver.lookup_ip("app.example").await })
        })
        .collect();
    let mut buf = [0; 512];
    let mut queries = Vec::new();
    for _ in 0..2 {
        let (n, from) = server.recv_from(&mut buf).await.unwrap();
        queries.push((Message::from_vec(&buf[..n]).unwrap(), from));
    }

    tokio::time::sleep(Duration::from_millis(100)).await;
    let nothing = server.try_recv_from(&mut buf).unwrap_err();
    assert_eq!(nothing.kind(), ErrorKind::WouldBlock);
    for (query, from) in queries {
        let question = query.queries[0].clone();
        let data = match question.query_type() {
            RecordType::A => RData::A(A(V4)),
            _ => RData::AAAA(AAAA(V6)),
        };
        let mut response = Message::response(query.metadata.id, OpCode::Query);
        response.add_answer(Record::from_rdata(question.name().clone(), 300, data));
        response.add_query(question);
        server
            .send_to(&response.to_vec().unwrap(), from)
            .await
            .unwrap();
    }

    for lookup in lookups {
        let addresses = lookup.await.unwrap().unwrap();
        assert_eq!(addresses, [IpAddr::V6(V6), IpAddr::V4(V4)]);
    }
}

/// A lookup whose task stopped with its runtime goes to a task on its own
/// runtime, not to one another runtime started meanwhile and left idle.
#[test]
fn retry_runs_on_the_lookups_own_runtime() {
    let servers = tokio::runtime::Runtime::new().unwrap();
    let (server, connections) = servers.block_on(counting_name_server("app.example.", true));
    let resolver = Resolver::new(Config::new(server, []));
    let [a, b, c] = [(); 3].map(|()| {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
    });
    a.block_on(resolver.lookup_ip("app.example")).unwrap();
    let mut waiting = pin!(resolver.lookup_ip("app.example"));
    b.block_on(poll_fn(|cx| {
        assert!(waiting.as_mut().poll(cx).is_pending());
        Poll::Ready(())
    }));

    drop(a);
    c.block_on(resolver.lookup_ip("app.example")).unwrap();

    let addresses = b
        .block_on(async { tokio::time::timeout(Duration::from_secs(1), waiting).await })
        .unwrap()
        .unwrap();
    assert_eq!(addresses, [IpAddr::V6(V6), IpAddr::V4(V4)]);

    // c's task stays the shared one: its connection serves c's next lookup.
    let opened = connections.opened.load(Ordering::Relaxed);
    c.block_on(async {
        tokio::time::timeout(Duration::from_secs(1), resolver.lookup_ip("app.example")).await
    })
    .unwrap()
    .unwrap();
    assert_eq!(connections.opened.load(Ordering::Relaxed), opened);
}

/// A retry that rotates from an IPv4 server to an IPv6 one gets a socket
/// that can reach it.
#[tokio::test]
async fn retry_reaches_a_server_of_the_other_family() {
    let silent = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let (server, _) = name_server_on(IpAddr::V6(Ipv6Addr::LOCALHOST), "app.example.", false).await;
    let mut config = Config::new(silent.local_addr().unwrap(), [server]);
    config.timeout = Duration::from_secs(1);
    let resolver = Resolver::new(config);

    let addresses = resolver.lookup_ip("app.example").await.unwrap();

    assert_eq!(addresses, [IpAddr::V6(V6), IpAddr::V4(V4)]);
}

/// An address needs no lookup; the server here doesn't exist.
#[rstest]
#[case::v4(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 7)))]
#[case::v6(IpAddr::V6(Ipv6Addr::LOCALHOST))]
#[tokio::test]
async fn addresses_are_returned_as_they_are(#[case] ip: IpAddr) {
    let nowhere = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 9);
    let resolver = Resolver::new(Config::new(nowhere, []));

    let addresses = resolver.lookup_ip(&ip.to_string()).await.unwrap();

    assert_eq!(addresses, [ip]);
}

/// Answers every query over UDP truncated, with nothing listening on TCP, so
/// the fallback to TCP is refused.
async fn truncating_udp_server() -> SocketAddr {
    let udp = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let address = udp.local_addr().unwrap();
    tokio::spawn(async move {
        let mut buf = [0; 4096];
        while let Ok((n, from)) = udp.recv_from(&mut buf).await {
            let query = Message::from_vec(&buf[..n]).unwrap();
            let mut response = Message::response(query.metadata.id, OpCode::Query);
            response.add_query(query.queries[0].clone());
            response.metadata.truncation = true;
            udp.send_to(&response.to_vec().unwrap(), from)
                .await
                .unwrap();
        }
    });
    address
}
