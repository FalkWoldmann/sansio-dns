//! Blocking driver: `cargo run --example std -- example.com [1.1.1.1:53]`
//!
//! Without a server argument, settings come from `/etc/resolv.conf`.
//!
//! Handles one query, so the socket bound up front stands in for that
//! query's own; a driver with several binds one per `Transport::Udp` query,
//! in the server's address family, as sansio-dns-tokio does. While a TCP
//! connection is open it reads only from that, since the resolver ignores
//! UDP replies once a query has switched to TCP.

#![expect(
    clippy::disallowed_methods,
    clippy::disallowed_types,
    clippy::indexing_slicing,
    clippy::print_stdout,
    reason = "a driver owns the sockets, the clock and the output; read and recv_from never return more than buf.len()"
)]

use std::io::{ErrorKind, Read, Write};
use std::net::{TcpStream, UdpSocket};
use std::time::{Duration, Instant};

use sansio_dns::hickory_proto::rr::{Name, RecordType};
use sansio_dns::{Config, ConnectionId, Event, Resolver, Transmit, Transport};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut args = std::env::args().skip(1);
    let name = Name::from_ascii(args.next().unwrap_or_else(|| "example.com.".into()))?;

    let socket = UdpSocket::bind("0.0.0.0:0")?;
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
                    if let Err(e) = socket.send_to(&t.payload, t.destination) {
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

        socket.set_read_timeout(Some(wait))?;
        match socket.recv_from(&mut buf) {
            Ok((n, from)) => resolver.handle_datagram(query, from, &buf[..n], Instant::now()),
            Err(e) if matches!(e.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut) => {
                resolver.handle_timeout(Instant::now());
            }
            Err(e) => return Err(e.into()),
        }
    }
}

/// Connect to the transmit's destination and send its (length-prefixed) payload.
fn open(t: &Transmit) -> std::io::Result<TcpStream> {
    let mut stream = TcpStream::connect_timeout(&t.destination, Duration::from_secs(2))?;
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
