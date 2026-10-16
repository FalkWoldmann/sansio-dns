//! Blocking driver: `cargo run --example std -- example.com [1.1.1.1:53]`

#![expect(
    clippy::disallowed_methods,
    clippy::disallowed_types,
    clippy::indexing_slicing,
    clippy::print_stdout,
    reason = "a driver owns the socket, the clock and the output; recv_from never returns more than buf.len()"
)]

use std::io::ErrorKind;
use std::net::UdpSocket;
use std::time::Instant;

use sansio_dns::hickory_proto::rr::{Name, RecordType};
use sansio_dns::{Config, Event, Resolver};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut args = std::env::args().skip(1);
    let name = Name::from_ascii(args.next().unwrap_or_else(|| "example.com.".into()))?;
    let server = args.next().unwrap_or_else(|| "1.1.1.1:53".into()).parse()?;

    let socket = UdpSocket::bind("0.0.0.0:0")?;
    let mut resolver = Resolver::new(Config::new(server, []));
    resolver.query(name, RecordType::A, Instant::now())?;

    let mut buf = [0; 1232];
    loop {
        while let Some(t) = resolver.poll_transmit() {
            socket.send_to(&t.payload, t.destination)?;
        }
        if let Some(event) = resolver.poll_event() {
            return print(event);
        }
        let Some(deadline) = resolver.poll_timeout() else {
            return Err("no query in flight".into());
        };
        socket.set_read_timeout(Some(
            deadline
                .saturating_duration_since(Instant::now())
                .max(std::time::Duration::from_millis(1)),
        ))?;
        match socket.recv_from(&mut buf) {
            Ok((n, from)) => resolver.handle_datagram(from, &buf[..n], Instant::now()),
            Err(e) if matches!(e.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut) => {
                resolver.handle_timeout(Instant::now());
            }
            Err(e) => return Err(e.into()),
        }
    }
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
