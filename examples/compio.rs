//! compio driver: `cargo run --example compio -- example.com [1.1.1.1:53]`
//!
//! compio is completion-based, so buffers are moved into each operation and
//! handed back with the result. The resolver doesn't care: it only sees bytes.

use std::time::Instant;

use compio::BufResult;
use compio::net::UdpSocket;
use compio::time::timeout_at;
use sansio_dns::hickory_proto::rr::{Name, RecordType};
use sansio_dns::{Config, Event, Resolver};

#[compio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut args = std::env::args().skip(1);
    let name = Name::from_ascii(args.next().unwrap_or("example.com.".into()))?;
    let server = args.next().unwrap_or("1.1.1.1:53".into()).parse()?;

    let socket = UdpSocket::bind("0.0.0.0:0").await?;
    let mut resolver = Resolver::new(Config::new(vec![server]));
    resolver.query(name, RecordType::A, Instant::now())?;

    let mut buf = Vec::with_capacity(1232);
    loop {
        while let Some(t) = resolver.poll_transmit() {
            let BufResult(sent, _) = socket.send_to(t.payload, t.destination).await;
            sent?;
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
        let deadline = resolver.poll_timeout().expect("query in flight");
        buf.clear();
        match timeout_at(deadline, socket.recv_from(buf)).await {
            Ok(BufResult(received, returned)) => {
                buf = returned;
                let (n, from) = received?;
                resolver.handle_datagram(from, &buf[..n], Instant::now());
            }
            Err(_elapsed) => {
                buf = Vec::with_capacity(1232);
                resolver.handle_timeout(Instant::now());
            }
        }
    }
}
