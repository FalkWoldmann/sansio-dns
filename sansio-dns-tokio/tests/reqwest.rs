//! reqwest resolving through `Resolver`, against local DNS and HTTP servers.

#![expect(
    clippy::indexing_slicing,
    clippy::unwrap_used,
    reason = "helpers outside #[test] may panic"
)]

mod common;

use sansio_dns::Config;
use sansio_dns_tokio::Resolver;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

#[tokio::test]
async fn get_resolves_through_the_resolver() {
    let http = TcpListener::bind((common::V4, 0)).await.unwrap();
    let port = http.local_addr().unwrap().port();
    tokio::spawn(async move {
        let (mut stream, _) = http.accept().await.unwrap();
        let mut request = [0; 1024];
        let n = stream.read(&mut request).await.unwrap();
        assert!(request[..n].starts_with(b"GET /hello HTTP/1.1\r\n"));
        stream
            .write_all(b"HTTP/1.1 200 OK\r\ncontent-length: 2\r\nconnection: close\r\n\r\nok")
            .await
            .unwrap();
    });
    let config = Config::new(common::name_server("app.example.", false).await, []);
    let client = reqwest::Client::builder()
        .dns_resolver(Resolver::new(config))
        .no_proxy()
        .build()
        .unwrap();

    let body = client
        .get(format!("http://app.example:{port}/hello"))
        .send()
        .await
        .unwrap()
        .text()
        .await
        .unwrap();

    assert_eq!(body, "ok");
}
