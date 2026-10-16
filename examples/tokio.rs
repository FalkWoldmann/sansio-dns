//! Tokio driver: `cargo run --example tokio -- example.com [1.1.1.1:53]`

#![expect(
    clippy::disallowed_methods,
    clippy::disallowed_types,
    clippy::indexing_slicing,
    clippy::print_stdout,
    reason = "a driver owns the socket, the clock and the output; recv_from never returns more than buf.len()"
)]

use std::time::Instant;

use sansio_dns::hickory_proto::rr::{Name, RecordType};
use sansio_dns::{Config, Event, Resolver};
use tokio::net::UdpSocket;
use tokio::time::sleep_until;

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut args = std::env::args().skip(1);
    let name = Name::from_ascii(args.next().unwrap_or_else(|| "example.com.".into()))?;
    let server = args.next().unwrap_or_else(|| "1.1.1.1:53".into()).parse()?;

    let socket = UdpSocket::bind("0.0.0.0:0").await?;
    let mut resolver = Resolver::new(Config::new(server, []));
    resolver.query(name, RecordType::A, Instant::now())?;

    let mut buf = [0; 1232];
    loop {
        while let Some(t) = resolver.poll_transmit() {
            socket.send_to(&t.payload, t.destination).await?;
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
        tokio::select! {
            received = socket.recv_from(&mut buf) => {
                let (n, from) = received?;
                resolver.handle_datagram(from, &buf[..n], Instant::now());
            }
            () = sleep_until(deadline.into()) => resolver.handle_timeout(Instant::now()),
        }
    }
}
