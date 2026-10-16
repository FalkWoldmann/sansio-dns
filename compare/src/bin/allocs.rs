//! Heap allocations and queries per lookup, for each resolver:
//! `cargo run -p compare --release --bin allocs`

#![expect(
    clippy::print_stdout,
    clippy::unwrap_used,
    clippy::cast_precision_loss,
    reason = "a measuring tool that prints averages"
)]

use std::alloc::System;

use compare::{HOST, QUERIES, hickory, name_server, sansio};
use stats_alloc::{INSTRUMENTED_SYSTEM, Region, StatsAlloc};
use std::sync::atomic::Ordering;

#[global_allocator]
static GLOBAL: &StatsAlloc<System> = &INSTRUMENTED_SYSTEM;

const LOOKUPS: usize = 1000;

/// Run `lookup` LOOKUPS times after a warm-up, and print the averages.
/// Counts include the name server's own allocations for the queries it
/// answers, the same for both clients.
fn measure<F: Future<Output = ()>>(
    label: &str,
    rt: &tokio::runtime::Runtime,
    lookup: impl Fn() -> F,
) {
    rt.block_on(lookup());
    let queries = QUERIES.load(Ordering::Relaxed);
    let region = Region::new(GLOBAL);
    for _ in 0..LOOKUPS {
        rt.block_on(lookup());
    }
    let stats = region.change();
    let per = |n: usize| n as f64 / LOOKUPS as f64;
    println!(
        "{label:<24} {:>8.1} allocations {:>10.0} bytes {:>4.1} queries per lookup",
        per(stats.allocations + stats.reallocations),
        per(stats.bytes_allocated + stats.bytes_reallocated.max(0).unsigned_abs()),
        per(QUERIES.load(Ordering::Relaxed) - queries),
    );
}

fn main() {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let _in_runtime = rt.enter();
    for (transport, truncate_udp) in [("udp", false), ("tcp_fallback", true)] {
        let server = name_server(truncate_udp);
        let ours = sansio(server);
        let theirs = hickory(server, false);
        measure(&format!("sansio-dns/{transport}"), &rt, || async {
            ours.lookup_ip(HOST).await.unwrap();
        });
        measure(&format!("hickory/{transport}"), &rt, || async {
            theirs.lookup_ip(HOST).await.unwrap();
        });
    }
}
