//! A name server on localhost, answering over UDP and TCP from a fixed list.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use sansio_dns::hickory_proto::op::{Message, OpCode, ResponseCode};
use sansio_dns::hickory_proto::rr::rdata::{A, AAAA};
use sansio_dns::hickory_proto::rr::{Name, RData, Record, RecordType};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, UdpSocket};

/// Loopback, so an HTTP server on localhost can be found by name.
pub const V4: Ipv4Addr = Ipv4Addr::LOCALHOST;
pub const V6: Ipv6Addr = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1);

/// TCP connections a name server has accepted, and how many of them the
/// client has closed since.
#[derive(Debug, Default)]
pub struct Connections {
    pub opened: AtomicUsize,
    pub closed: AtomicUsize,
}

/// Serve `host` with the addresses V4 and V6, over UDP and TCP on the same
/// port. With `truncate_udp`, UDP answers are empty with TC set.
pub async fn name_server(host: &str, truncate_udp: bool) -> SocketAddr {
    counting_name_server(host, truncate_udp).await.0
}

/// [`name_server`], counting its TCP connections.
pub async fn counting_name_server(
    host: &str,
    truncate_udp: bool,
) -> (SocketAddr, Arc<Connections>) {
    name_server_on(IpAddr::V4(Ipv4Addr::LOCALHOST), host, truncate_udp).await
}

/// [`counting_name_server`] on `ip`.
pub async fn name_server_on(
    ip: IpAddr,
    host: &str,
    truncate_udp: bool,
) -> (SocketAddr, Arc<Connections>) {
    let connections = Arc::new(Connections::default());
    let counts = Arc::clone(&connections);
    let host = Name::from_ascii(host).unwrap();
    // The UDP port may be taken on TCP; try another until both are free.
    let (udp, tcp) = loop {
        let udp = UdpSocket::bind((ip, 0)).await.unwrap();
        if let Ok(tcp) = TcpListener::bind(udp.local_addr().unwrap()).await {
            break (udp, tcp);
        }
    };
    let address = udp.local_addr().unwrap();

    let name = host.clone();
    tokio::spawn(async move {
        let mut buf = [0; 4096];
        while let Ok((n, from)) = udp.recv_from(&mut buf).await {
            let answer = answer(&name, &buf[..n], truncate_udp);
            udp.send_to(&answer, from).await.unwrap();
        }
    });
    tokio::spawn(async move {
        while let Ok((mut stream, _)) = tcp.accept().await {
            counts.opened.fetch_add(1, Ordering::Relaxed);
            let counts = Arc::clone(&counts);
            let name = host.clone();
            tokio::spawn(async move {
                while let Ok(len) = stream.read_u16().await {
                    let mut query = vec![0; len.into()];
                    stream.read_exact(&mut query).await.unwrap();
                    let answer = answer(&name, &query, false);
                    let len = u16::try_from(answer.len()).unwrap();
                    stream
                        .write_all(&[&len.to_be_bytes(), &answer[..]].concat())
                        .await
                        .unwrap();
                }
                counts.closed.fetch_add(1, Ordering::Relaxed);
            });
        }
    });
    (address, connections)
}

fn answer(host: &Name, query: &[u8], truncate: bool) -> Vec<u8> {
    let query = Message::from_vec(query).unwrap();
    let question = query.queries[0].clone();
    let mut response = Message::response(query.metadata.id, OpCode::Query);
    response.metadata.recursion_available = true;
    response.add_query(question.clone());
    if question.name() != host {
        response.metadata.response_code = ResponseCode::NXDomain;
    } else if truncate {
        response.metadata.truncation = true;
    } else {
        let data = if question.query_type() == RecordType::A {
            RData::A(A(V4))
        } else {
            RData::AAAA(AAAA(V6))
        };
        response.add_answer(Record::from_rdata(host.clone(), 300, data));
    }
    response.to_vec().unwrap()
}
