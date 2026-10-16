//! The `get` example's HTTP client, resolving with hickory-resolver from the
//! system configuration, as reqwest's `hickory-dns` feature does.

#![expect(clippy::print_stdout, reason = "a command-line tool prints its output")]

use hickory_resolver::TokioResolver;

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let url = std::env::args().nth(1).unwrap_or_default();
    let resolver = TokioResolver::builder_tokio()?.build()?;
    let client = reqwest::Client::builder()
        .dns_resolver(compare::Hickory(resolver))
        .build()?;
    print!("{}", client.get(url).send().await?.text().await?);
    Ok(())
}
