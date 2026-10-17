//! The integration tests, built as one crate: one module per RFC or feature.

#![expect(clippy::disallowed_methods, reason = "tests stand in for the driver")]
#![allow(
    clippy::indexing_slicing,
    clippy::panic,
    clippy::unwrap_used,
    reason = "helpers may panic; allow, since newer clippy skips tests/ (rust-clippy#16786)"
)]

mod coalescing;
mod common;
mod hosts;
mod lookup;
mod resolv_conf;
mod rfc1035;
mod rfc1123;
mod rfc5452;
mod rfc6761;
mod rfc6891;
mod rfc7766;
#[cfg(feature = "tls")]
mod rfc7858;
mod state_machine;
