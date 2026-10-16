//! The same HTTP client with reqwest's default resolver (getaddrinfo on a
//! blocking thread): the baseline for the binary-size comparison.

#![expect(clippy::print_stdout, reason = "a command-line tool prints its output")]

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let url = std::env::args().nth(1).unwrap_or_default();
    let client = reqwest::Client::builder().build()?;
    print!("{}", client.get(url).send().await?.text().await?);
    Ok(())
}
