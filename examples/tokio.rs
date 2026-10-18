//! Tokio driver: `cargo run --example tokio -- example.com [1.1.1.1:53]`
//!
//! Handles one query, so it keeps one UDP socket, connected to the server
//! of the query's current attempt and bound anew when the query moves to
//! another server, as sansio-dns-tokio does for each query. A connected
//! socket only takes datagrams from that server to the address the query
//! went out from (RFC 5452 §9.1), and reports an ICMP error such as port
//! unreachable. While a TCP connection is open it reads only from that,
//! since the resolver ignores UDP replies once a query has switched to TCP.

#![expect(
    clippy::disallowed_methods,
    clippy::disallowed_types,
    clippy::indexing_slicing,
    clippy::print_stdout,
    reason = "a driver owns the sockets, the clock and the output; read and recv_from never return more than buf.len()"
)]

use std::io::ErrorKind;
use std::net::SocketAddr;
use std::time::{Duration, Instant};

use sansio_dns::hickory_proto::rr::{Name, RecordType};
use sansio_dns::{Config, ConnectionId, Event, Resolver, Transmit, Transport};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};
use tokio::time::{sleep_until, timeout, timeout_at};

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut args = std::env::args().skip(1);
    let name = Name::from_ascii(args.next().unwrap_or_else(|| "example.com.".into()))?;
    let server = args.next().unwrap_or_else(|| "1.1.1.1:53".into()).parse()?;

    let mut udp: Option<(SocketAddr, UdpSocket)> = None;
    let mut tcp: Option<(ConnectionId, TcpStream)> = None;
    let mut resolver = Resolver::new(Config::new(server, []));
    let query = resolver.query(name, RecordType::A, Instant::now())?;

    // Holds any datagram: a server may send more than the 1232 bytes queries advertise.
    let mut buf = vec![0; 65535];
    loop {
        while let Some(t) = resolver.poll_transmit() {
            match t.transport {
                Transport::Udp(q) => {
                    if let Err(e) = send(&mut udp, &t).await {
                        resolver.handle_udp_error(q, t.destination, e.kind(), Instant::now());
                    }
                }
                Transport::TcpConnect(c) => match timeout(Duration::from_secs(2), open(&t)).await {
                    Ok(Ok(stream)) => tcp = Some((c, stream)),
                    Ok(Err(e)) => resolver.handle_stream_error(c, e.kind(), Instant::now()),
                    Err(_elapsed) => {
                        resolver.handle_stream_error(c, ErrorKind::TimedOut, Instant::now());
                    }
                },
                Transport::TcpWrite(c) => {
                    if let Some((_, stream)) = tcp.as_mut().filter(|(open, _)| *open == c)
                        && let Err(e) = stream.write_all(&t.payload).await
                    {
                        resolver.handle_stream_error(c, e.kind(), Instant::now());
                    }
                }
                Transport::TcpClose(c) => {
                    tcp.take_if(|(open, _)| *open == c);
                }
            }
        }
        if let Some(event) = resolver.poll_event() {
            return match event {
                Event::Response { response, .. } => {
                    response.answers.iter().for_each(|r| println!("{r}"));
                    Ok(())
                }
                Event::Failed { error, .. } => Err(error.into()),
            };
        }
        let Some(deadline) = resolver.poll_timeout() else {
            return Err("no query in flight".into());
        };

        if let Some((connection, mut stream)) = tcp.take() {
            match timeout_at(deadline.into(), stream.read(&mut buf)).await {
                Ok(Ok(n)) if n > 0 => {
                    resolver.handle_stream_data(connection, &buf[..n], Instant::now());
                    tcp = Some((connection, stream));
                }
                Ok(Ok(_)) => resolver.handle_stream_closed(connection, Instant::now()),
                Ok(Err(e)) => {
                    resolver.handle_stream_error(connection, e.kind(), Instant::now());
                }
                Err(_elapsed) => {
                    resolver.handle_timeout(Instant::now());
                    tcp = Some((connection, stream));
                }
            }
            continue;
        }

        let Some((server, socket)) = &udp else {
            sleep_until(deadline.into()).await;
            resolver.handle_timeout(Instant::now());
            continue;
        };
        tokio::select! {
            received = socket.recv(&mut buf) => match received {
                Ok(n) => resolver.handle_datagram(query, *server, &buf[..n], Instant::now()),
                Err(e) => resolver.handle_udp_error(query, *server, e.kind(), Instant::now()),
            },
            () = sleep_until(deadline.into()) => resolver.handle_timeout(Instant::now()),
        }
    }
}

/// Send the datagram `t` from a socket connected to its destination, bound
/// anew for each server.
async fn send(udp: &mut Option<(SocketAddr, UdpSocket)>, t: &Transmit) -> std::io::Result<()> {
    if udp
        .as_ref()
        .is_none_or(|(server, _)| *server != t.destination)
    {
        let any = if t.destination.is_ipv4() {
            "0.0.0.0:0"
        } else {
            "[::]:0"
        };
        let socket = UdpSocket::bind(any).await?;
        socket.connect(t.destination).await?;
        *udp = Some((t.destination, socket));
    }
    if let Some((_, socket)) = udp {
        socket.send(&t.payload).await?;
    }
    Ok(())
}

/// Connect to the transmit's destination and send its (length-prefixed) payload.
async fn open(t: &Transmit) -> std::io::Result<TcpStream> {
    let mut stream = TcpStream::connect(t.destination).await?;
    stream.set_nodelay(true)?;
    stream.write_all(&t.payload).await?;
    Ok(stream)
}
