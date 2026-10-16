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

    assert_eq!(addresses, [IpAddr::V4(V4), IpAddr::V6(V6)]);
}

#[tokio::test]
async fn unknown_name_is_not_found() {
    let server = name_server("app.example.", false).await;
    let resolver = Resolver::new(Config::new(server, []));

    let result = resolver.lookup_ip("other.example").await;

    assert!(matches!(result, Err(Error::NotFound)), "{result:?}");
}

#[tokio::test]
async fn refused_tcp_fallback_fails_with_the_connect_error() {
    let server = truncating_udp_server().await;
    let resolver = Resolver::new(Config::new(server, []));

    let result = resolver.lookup_ip("app.example").await;

    assert!(
        matches!(
            result,
            Err(Error::Resolve(sansio_dns::Error::Connection(
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
    config.timeout = Duration::from_millis(500);
    let resolver = Resolver::new(config);
    let mut buf = [0; 512];

    tokio::select! {
        _ = resolver.lookup_ip("app.example") => panic!("nothing answers"),
        _ = async {
            silent.recv_from(&mut buf).await.unwrap();
            silent.recv_from(&mut buf).await.unwrap();
        } => {}
    }
    tokio::time::sleep(Duration::from_millis(800)).await;

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
        assert_eq!(addresses, [IpAddr::V4(V4), IpAddr::V6(V6)]);
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
    assert_eq!(addresses, [IpAddr::V4(V4), IpAddr::V6(V6)]);

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
    config.timeout = Duration::from_millis(200);
    let resolver = Resolver::new(config);

    let addresses = resolver.lookup_ip("app.example").await.unwrap();

    assert_eq!(addresses, [IpAddr::V4(V4), IpAddr::V6(V6)]);
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
