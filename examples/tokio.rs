//! Tokio driver: `cargo run --example tokio -- example.com [1.1.1.1:53]`
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

use std::io::ErrorKind;
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

    let socket = UdpSocket::bind("0.0.0.0:0").await?;
    let mut tcp: Option<(ConnectionId, TcpStream)> = None;
    let mut resolver = Resolver::new(Config::new(server, []));
    let query = resolver.query(name, RecordType::A, Instant::now())?;

    let mut buf = [0; 4096];
    loop {
        while let Some(t) = resolver.poll_transmit() {
            match t.transport {
                Transport::Udp(q) => {
                    if let Err(e) = socket.send_to(&t.payload, t.destination).await {
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

        tokio::select! {
            received = socket.recv_from(&mut buf) => {
                let (n, from) = received?;
                resolver.handle_datagram(query, from, &buf[..n], Instant::now());
            }
            () = sleep_until(deadline.into()) => resolver.handle_timeout(Instant::now()),
        }
    }
}

/// Connect to the transmit's destination and send its (length-prefixed) payload.
async fn open(t: &Transmit) -> std::io::Result<TcpStream> {
    let mut stream = TcpStream::connect(t.destination).await?;
    stream.write_all(&t.payload).await?;
    Ok(stream)
}
