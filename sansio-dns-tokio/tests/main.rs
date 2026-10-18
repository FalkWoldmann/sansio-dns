//! The integration tests, built as one crate.

#![expect(
    clippy::indexing_slicing,
    clippy::unwrap_used,
    reason = "helpers outside #[test] may panic"
)]

mod common;
mod lookup;
#[cfg(feature = "reqwest")]
mod reqwest;
mod system_conf;
#[cfg(feature = "tls")]
mod tls;
