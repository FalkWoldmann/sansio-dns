//! compio driver: `cargo run --example compio -- example.com [1.1.1.1:53]`
//!
//! compio is completion-based, so buffers are moved into each operation and
//! handed back with the result. The resolver doesn't care: it only sees bytes.
//!
//! Handles one query. While a TCP connection is open it reads only from that,
//! since the resolver ignores UDP replies once a query has switched to TCP.

#![expect(
    clippy::disallowed_methods,
    clippy::disallowed_types,
    clippy::indexing_slicing,
    clippy::print_stdout,
    reason = "a driver owns the sockets, the clock and the output; read and recv_from never return more than buf.len()"
)]

use std::time::{Duration, Instant};

use compio::BufResult;
use compio::io::{AsyncRead, AsyncWriteExt};
use compio::net::{TcpStream, UdpSocket};
use compio::time::{timeout, timeout_at};
use sansio_dns::hickory_proto::rr::{Name, RecordType};
use sansio_dns::{Config, ConnectionId, Event, Resolver, Transmit, Transport};

#[compio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut args = std::env::args().skip(1);
    let name = Name::from_ascii(args.next().unwrap_or_else(|| "example.com.".into()))?;
    let server = args.next().unwrap_or_else(|| "1.1.1.1:53".into()).parse()?;

    let socket = UdpSocket::bind("0.0.0.0:0").await?;
    let mut tcp: Option<(ConnectionId, TcpStream)> = None;
    let mut resolver = Resolver::new(Config::new(server, []));
    resolver.query(name, RecordType::A, Instant::now())?;

    let mut buf = Vec::with_capacity(4096);
    loop {
        while let Some(t) = resolver.poll_transmit() {
            match t.transport {
                Transport::Udp(_) => {
                    let BufResult(sent, _) = socket.send_to(t.payload, t.destination).await;
                    sent?;
                }
                Transport::TcpConnect(c) => match timeout(Duration::from_secs(2), open(&t)).await {
                    Ok(Ok(stream)) => tcp = Some((c, stream)),
                    _ => resolver.handle_stream_closed(c, Instant::now()),
                },
                Transport::TcpWrite(c) => {
                    if let Some((_, stream)) = tcp.as_mut().filter(|(open, _)| *open == c) {
                        let BufResult(written, _) = stream.write_all(t.payload).await;
                        if written.is_err() {
                            resolver.handle_stream_closed(c, Instant::now());
                        }
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
        buf.clear();

        if let Some((connection, mut stream)) = tcp.take() {
            match timeout_at(deadline, stream.read(buf)).await {
                Ok(BufResult(read, returned)) => {
                    buf = returned;
                    match read {
                        Ok(n) if n > 0 => {
                            resolver.handle_stream_data(connection, &buf[..n], Instant::now());
                            tcp = Some((connection, stream));
                        }
                        _ => resolver.handle_stream_closed(connection, Instant::now()),
                    }
                }
                Err(_elapsed) => {
                    buf = Vec::with_capacity(4096);
                    resolver.handle_timeout(Instant::now());
                    tcp = Some((connection, stream));
                }
            }
            continue;
        }

        match timeout_at(deadline, socket.recv_from(buf)).await {
            Ok(BufResult(received, returned)) => {
                buf = returned;
                let (n, from) = received?;
                resolver.handle_datagram(from, &buf[..n], Instant::now());
            }
            Err(_elapsed) => {
                buf = Vec::with_capacity(4096);
                resolver.handle_timeout(Instant::now());
            }
        }
    }
}

/// Connect to the transmit's destination and send its (length-prefixed) payload.
async fn open(t: &Transmit) -> std::io::Result<TcpStream> {
    let mut stream = TcpStream::connect(t.destination).await?;
    let BufResult(written, _) = stream.write_all(t.payload.clone()).await;
    written?;
    Ok(stream)
}
