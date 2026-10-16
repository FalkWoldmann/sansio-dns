//! Shared setup for comparing `sansio-dns-tokio` with `hickory-resolver` on
//! the job a command-line HTTP client gives its resolver: look up one host's
//! addresses, then connect.
//!
//! - `cargo bench -p compare`: lookup and request latency, and how long a
//!   batch of concurrent lookups takes
//! - `cargo run -p compare --release --bin allocs`: allocations per lookup
//! - `get-sansio`, `get-hickory`, `get-system`: the same HTTP client with
//!   each resolver, to compare binary sizes

#![expect(
    clippy::unwrap_used,
    clippy::missing_panics_doc,
    reason = "benchmark setup fails loudly"
)]

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::atomic::{AtomicUsize, Ordering};

use hickory_resolver::TokioResolver;
use hickory_resolver::config::{
    ConnectionConfig, LookupIpStrategy, NameServerConfig, ResolveHosts, ResolverConfig,
};
use hickory_resolver::net::runtime::TokioRuntimeProvider;
use reqwest::dns::{Addrs, Name, Resolve, Resolving};
use sansio_dns::Config;
use sansio_dns::hickory_proto::op::{Message, OpCode};
use sansio_dns::hickory_proto::rr::rdata::{A, AAAA};
use sansio_dns::hickory_proto::rr::{RData, Record, RecordType};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, UdpSocket};

/// The name every benchmark looks up. Any name gets the same answer.
pub const HOST: &str = "app.example.";

/// Queries the name servers have answered, over either transport.
pub static QUERIES: AtomicUsize = AtomicUsize::new(0);

/// Run `serve` on a thread of its own with its own runtime, so the server
/// never competes with the client for its executor.
fn background<F: Future<Output = ()> + Send + 'static>(serve: F) {
    std::thread::spawn(move || {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(serve);
    });
}

/// A name server on localhost answering every A query with 127.0.0.1 and
/// every AAAA query with ::1, over UDP and TCP on the same port. With
/// `truncate_udp`, UDP answers are empty with TC set, so clients retry
/// over TCP.
pub fn name_server(truncate_udp: bool) -> SocketAddr {
    let (bound, address) = std::sync::mpsc::channel();
    background(async move {
        // Find a port free for both transports.
        let (udp, tcp) = loop {
            let udp = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            if let Ok(tcp) = TcpListener::bind(udp.local_addr().unwrap()).await {
                break (udp, tcp);
            }
        };
        bound.send(udp.local_addr().unwrap()).unwrap();
        tokio::spawn(async move {
            while let Ok((mut stream, _)) = tcp.accept().await {
                // Answers to pipelined queries must not wait for the
                // client's delayed ACK of the previous one.
                stream.set_nodelay(true).unwrap();
                tokio::spawn(async move {
                    while let Ok(len) = stream.read_u16().await {
                        let mut query = vec![0; len.into()];
                        stream.read_exact(&mut query).await.unwrap();
                        let answer = answer(&query, false);
                        let len = u16::try_from(answer.len()).unwrap();
                        let framed = [&len.to_be_bytes()[..], &answer].concat();
                        stream.write_all(&framed).await.unwrap();
                    }
                });
            }
        });
        let mut buf = vec![0; 4096];
        while let Ok((n, from)) = udp.recv_from(&mut buf).await {
            let answer = answer(buf.get(..n).unwrap(), truncate_udp);
            udp.send_to(&answer, from).await.unwrap();
        }
    });
    address.recv().unwrap()
}

fn answer(query: &[u8], truncate: bool) -> Vec<u8> {
    QUERIES.fetch_add(1, Ordering::Relaxed);
    let query = Message::from_vec(query).unwrap();
    let question = query.queries.first().unwrap().clone();
    let mut response = Message::response(query.metadata.id, OpCode::Query);
    response.metadata.recursion_desired = query.metadata.recursion_desired;
    response.metadata.recursion_available = true;
    response.add_query(question.clone());
    if truncate {
        response.metadata.truncation = true;
    } else {
        let data = match question.query_type() {
            RecordType::A => Some(RData::A(A(Ipv4Addr::LOCALHOST))),
            RecordType::AAAA => Some(RData::AAAA(AAAA(Ipv6Addr::LOCALHOST))),
            _ => None,
        };
        if let Some(data) = data {
            response.add_answer(Record::from_rdata(question.name().clone(), 300, data));
        }
    }
    response.to_vec().unwrap()
}

/// An HTTP/1.1 server on 127.0.0.1 answering every request with `ok` and
/// closing the connection.
pub fn http_server() -> SocketAddr {
    let (bound, address) = std::sync::mpsc::channel();
    background(async move {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        bound.send(listener.local_addr().unwrap()).unwrap();
        while let Ok((mut stream, _)) = listener.accept().await {
            tokio::spawn(async move {
                let mut request = vec![0; 4096];
                if stream.read(&mut request).await.is_ok() {
                    stream
                        .write_all(
                            b"HTTP/1.1 200 OK\r\ncontent-length: 2\r\nconnection: close\r\n\r\nok",
                        )
                        .await
                        .ok();
                }
            });
        }
    });
    address.recv().unwrap()
}

/// sansio-dns-tokio using only `server`.
pub fn sansio(server: SocketAddr) -> sansio_dns_tokio::Resolver {
    sansio_dns_tokio::Resolver::new(Config::new(server, []))
}

/// hickory-resolver using only `server`, made to match sansio-dns-tokio:
/// A and AAAA in parallel, IPv4 first, no hosts file. With `cache` false
/// its response cache holds nothing, so every lookup asks the server.
///
/// Call inside a Tokio runtime: hickory takes the runtime's handle.
pub fn hickory(server: SocketAddr, cache: bool) -> TokioResolver {
    let mut udp = ConnectionConfig::udp();
    udp.port = server.port();
    let mut tcp = ConnectionConfig::tcp();
    tcp.port = server.port();
    let name_server = NameServerConfig::new(server.ip(), true, vec![udp, tcp]);
    let config = ResolverConfig::from_parts(None, vec![], vec![name_server]);
    let mut builder = TokioResolver::builder_with_config(config, TokioRuntimeProvider::default());
    let options = builder.options_mut();
    options.ip_strategy = LookupIpStrategy::Ipv4AndIpv6;
    options.use_hosts_file = ResolveHosts::Never;
    if !cache {
        options.cache_size = 0;
    }
    builder.build().unwrap()
}

/// hickory-resolver as reqwest's resolver, as reqwest's own `hickory-dns`
/// feature does it.
#[derive(Clone, Debug)]
pub struct Hickory(pub TokioResolver);

impl Resolve for Hickory {
    fn resolve(&self, name: Name) -> Resolving {
        let resolver = self.0.clone();
        Box::pin(async move {
            let lookup = resolver.lookup_ip(name.as_str()).await?;
            Ok(Box::new(lookup.into_iter().map(|ip| SocketAddr::new(ip, 0))) as Addrs)
        })
    }
}

/// What both resolvers should find for [`HOST`].
pub const EXPECTED: [IpAddr; 2] = [
    IpAddr::V4(Ipv4Addr::LOCALHOST),
    IpAddr::V6(Ipv6Addr::LOCALHOST),
];
