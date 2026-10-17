//! Blocking driver: `cargo run --example std -- example.com [1.1.1.1:53]`
//!
//! Without a server argument, settings come from `/etc/resolv.conf`.
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

use std::io::{ErrorKind, Read, Write};
use std::net::{SocketAddr, TcpStream, UdpSocket};
use std::time::{Duration, Instant};

use sansio_dns::hickory_proto::rr::{Name, RecordType};
use sansio_dns::{Config, ConnectionId, Event, Resolver, Transmit, Transport};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut args = std::env::args().skip(1);
    let name = Name::from_ascii(args.next().unwrap_or_else(|| "example.com.".into()))?;

    let mut udp: Option<(SocketAddr, UdpSocket)> = None;
    let mut tcp: Option<(ConnectionId, TcpStream)> = None;
    let config = match args.next() {
        Some(server) => Config::new(server.parse()?, []),
        None => Config::from_resolv_conf(&std::fs::read("/etc/resolv.conf")?),
    };
    let mut resolver = Resolver::new(config);
    let query = resolver.query(name, RecordType::A, Instant::now())?;

    let mut buf = [0; 4096];
    loop {
        while let Some(t) = resolver.poll_transmit() {
            match t.transport {
                Transport::Udp(q) => {
                    let sent = connect(&mut udp, t.destination).and_then(|s| s.send(&t.payload));
                    if let Err(e) = sent {
                        resolver.handle_udp_error(q, t.destination, e.kind(), Instant::now());
                    }
                }
                Transport::TcpConnect(c) => match open(&t) {
                    Ok(stream) => tcp = Some((c, stream)),
                    Err(e) => resolver.handle_stream_error(c, e.kind(), Instant::now()),
                },
                Transport::TcpWrite(c) => {
                    if let Some((_, stream)) = tcp.as_mut().filter(|(open, _)| *open == c)
                        && let Err(e) = stream.write_all(&t.payload)
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
            return print(event);
        }
        let Some(deadline) = resolver.poll_timeout() else {
            return Err("no query in flight".into());
        };
        let wait = deadline
            .saturating_duration_since(Instant::now())
            .max(Duration::from_millis(1));

        if let Some((connection, mut stream)) = tcp.take() {
            stream.set_read_timeout(Some(wait))?;
            match stream.read(&mut buf) {
                Ok(0) => resolver.handle_stream_closed(connection, Instant::now()),
                Ok(n) => {
                    resolver.handle_stream_data(connection, &buf[..n], Instant::now());
                    tcp = Some((connection, stream));
                }
                Err(e) if matches!(e.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut) => {
                    resolver.handle_timeout(Instant::now());
                    tcp = Some((connection, stream));
                }
                Err(e) => resolver.handle_stream_error(connection, e.kind(), Instant::now()),
            }
            continue;
        }

        let Some((server, socket)) = &udp else {
            std::thread::sleep(wait);
            resolver.handle_timeout(Instant::now());
            continue;
        };
        socket.set_read_timeout(Some(wait))?;
        match socket.recv(&mut buf) {
            Ok(n) => resolver.handle_datagram(query, *server, &buf[..n], Instant::now()),
            Err(e) if matches!(e.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut) => {
                resolver.handle_timeout(Instant::now());
            }
            Err(e) => resolver.handle_udp_error(query, *server, e.kind(), Instant::now()),
        }
    }
}

/// The socket connected to `to`, bound anew for each server.
fn connect(
    udp: &mut Option<(SocketAddr, UdpSocket)>,
    to: SocketAddr,
) -> std::io::Result<&UdpSocket> {
    if udp.as_ref().is_none_or(|(server, _)| *server != to) {
        let socket = UdpSocket::bind(if to.is_ipv4() { "0.0.0.0:0" } else { "[::]:0" })?;
        socket.connect(to)?;
        *udp = Some((to, socket));
    }
    udp.as_ref()
        .map(|(_, socket)| socket)
        .ok_or_else(|| ErrorKind::NotConnected.into())
}

/// Connect to the transmit's destination and send its (length-prefixed) payload.
fn open(t: &Transmit) -> std::io::Result<TcpStream> {
    let mut stream = TcpStream::connect_timeout(&t.destination, Duration::from_secs(2))?;
    stream.set_nodelay(true)?;
    stream.write_all(&t.payload)?;
    Ok(stream)
}

fn print(event: Event) -> Result<(), Box<dyn std::error::Error>> {
    match event {
        Event::Response { response, .. } => {
            response.answers.iter().for_each(|r| println!("{r}"));
            Ok(())
        }
        Event::Failed { error, .. } => Err(error.into()),
    }
}
