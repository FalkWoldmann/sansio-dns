//! A tiny HTTP client that resolves with sansio-dns:
//! `cargo run -p sansio-dns-tokio --features reqwest --example get -- https://example.com`

#![expect(
    clippy::print_stdout,
    clippy::print_stderr,
    reason = "a command-line tool prints its output"
)]

use sansio_dns_tokio::Resolver;

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let url = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "https://example.com".to_owned());
    let client = reqwest::Client::builder()
        .dns_resolver(Resolver::from_system_conf()?)
        .build()?;
    let response = client.get(url).send().await?;
    eprintln!("{}", response.status());
    print!("{}", response.text().await?);
    Ok(())
}
