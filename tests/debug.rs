//! `Resolver`'s `Debug` output: the settings and counts, not internal state.

use std::time::Instant;

use crate::common::*;

#[test]
fn resolver_shows_counts_not_internals() {
    let mut resolver = resolver();
    start(&mut resolver, Instant::now());
    let debug = format!("{resolver:?}");
    assert!(debug.starts_with("Resolver { config: Config {"), "{debug}");
    assert!(
        debug.ends_with("queries: 1, connections: 0, transmits: 0, events: 0, .. }"),
        "{debug}"
    );
    assert!(!debug.contains("Pending"), "{debug}");
}
