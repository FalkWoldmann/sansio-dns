//! DNS over TLS with a blocking driver:
//! `cargo run --example dot --features tls -- example.com [1.1.1.1:853 cloudflare-dns.com]`
//!
//! The crate picks no crypto provider or root store; this example uses ring
//! and the webpki root certificates.

#![expect(
    clippy::disallowed_methods,
    clippy::disallowed_types,
    clippy::indexing_slicing,
    clippy::print_stdout,
    reason = "a driver owns the socket, the clock and the output; read never returns more than buf.len()"
)]

use std::io::{ErrorKind, Read, Write};
use std::net::TcpStream;
use std::sync::Arc;
use std::time::{Duration, Instant};

use sansio_dns::hickory_proto::rr::{Name, RecordType};
use sansio_dns::rustls::crypto::ring;
use sansio_dns::rustls::pki_types::ServerName;
use sansio_dns::rustls::{ClientConfig, RootCertStore};
use sansio_dns::{Config, Event, QueryId, Resolver, Transport};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut args = std::env::args().skip(1);
    let name = Name::from_ascii(args.next().unwrap_or_else(|| "example.com.".into()))?;
    let server = args
        .next()
        .unwrap_or_else(|| "1.1.1.1:853".into())
        .parse()?;
    let tls_name =
        ServerName::try_from(args.next().unwrap_or_else(|| "cloudflare-dns.com".into()))?;

    let provider = Arc::new(ring::default_provider());
    let roots = RootCertStore {
        roots: webpki_roots::TLS_SERVER_ROOTS.into(),
    };
    let client = ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()?
        .with_root_certificates(roots)
        .with_no_client_auth();
    let mut resolver = Resolver::new(Config::new(server, []).with_tls(Arc::new(client), tls_name)?);
    resolver.query(name, RecordType::A, Instant::now())?;

    let mut tcp: Option<(QueryId, TcpStream)> = None;
    let mut buf = [0; 4096];
    loop {
        while let Some(t) = resolver.poll_transmit() {
            let written = match t.transport {
                Transport::Tcp => {
                    TcpStream::connect_timeout(&t.destination, Duration::from_secs(2)).and_then(
                        |mut stream| {
                            stream.write_all(&t.payload)?;
                            tcp = Some((t.query, stream));
                            Ok(())
                        },
                    )
                }
                Transport::TcpContinue => match tcp.as_mut().filter(|(q, _)| *q == t.query) {
                    Some((_, stream)) => stream.write_all(&t.payload),
                    None => Ok(()),
                },
                Transport::Udp => return Err("DNS over TLS never uses UDP".into()),
            };
            if written.is_err() {
                resolver.handle_stream_closed(t.query, Instant::now());
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
        let Some((query, mut stream)) = tcp.take() else {
            resolver.handle_timeout(deadline);
            continue;
        };
        let wait = deadline
            .saturating_duration_since(Instant::now())
            .max(Duration::from_millis(1));
        stream.set_read_timeout(Some(wait))?;
        match stream.read(&mut buf) {
            Ok(0) => resolver.handle_stream_closed(query, Instant::now()),
            Ok(n) => {
                resolver.handle_stream_data(query, &buf[..n], Instant::now());
                tcp = Some((query, stream));
            }
            Err(e) if matches!(e.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut) => {
                resolver.handle_timeout(Instant::now());
                tcp = Some((query, stream));
            }
            Err(_) => resolver.handle_stream_closed(query, Instant::now()),
        }
    }
}
