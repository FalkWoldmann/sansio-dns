//! The `get` example's HTTP client, resolving with sansio-dns-tokio. Built
//! next to `get-hickory` to compare binary sizes.

#![expect(clippy::print_stdout, reason = "a command-line tool prints its output")]

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let url = std::env::args().nth(1).unwrap_or_default();
    let client = reqwest::Client::builder()
        .dns_resolver(sansio_dns_tokio::Resolver::from_system_conf()?)
        .build()?;
    print!("{}", client.get(url).send().await?.text().await?);
    Ok(())
}
