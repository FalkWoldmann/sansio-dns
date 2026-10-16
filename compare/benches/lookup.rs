//! sansio-dns-tokio and hickory-resolver resolving for an HTTP client,
//! against a name server on localhost: `cargo bench -p compare`
//!
//! Both clients run on one current-thread runtime; the servers each have a
//! thread of their own.

#![expect(clippy::unwrap_used, reason = "a benchmark fails loudly on bad setup")]

use std::hint::black_box;

use compare::{EXPECTED, HOST, Hickory, hickory, http_server, name_server, sansio};
use criterion::{BenchmarkId, Criterion, criterion_group, criterion_main};
use hickory_resolver::TokioResolver;
use hickory_resolver::net::runtime::TokioRuntimeProvider;
use tokio::runtime::Runtime;

fn runtime() -> Runtime {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
}

/// One `lookup_ip` per iteration; hickory's cache is off unless noted.
fn lookup_ip(c: &mut Criterion) {
    let rt = runtime();
    let _in_runtime = rt.enter();
    let mut group = c.benchmark_group("lookup_ip");
    for (transport, truncate_udp) in [("udp", false), ("tcp_fallback", true)] {
        let server = name_server(truncate_udp);
        let ours = sansio(server);
        let theirs = hickory(server, false);
        assert_eq!(rt.block_on(ours.lookup_ip(HOST)).unwrap(), EXPECTED);
        let found: Vec<_> = rt
            .block_on(theirs.lookup_ip(HOST))
            .unwrap()
            .iter()
            .collect();
        assert_eq!(found, EXPECTED);

        group.bench_function(BenchmarkId::new("sansio-dns", transport), |b| {
            b.iter(|| black_box(rt.block_on(ours.lookup_ip(HOST)).unwrap()));
        });
        group.bench_function(BenchmarkId::new("hickory", transport), |b| {
            b.iter(|| black_box(rt.block_on(theirs.lookup_ip(HOST)).unwrap()));
        });
    }
    let cached = hickory(name_server(false), true);
    group.bench_function(BenchmarkId::new("hickory", "cached"), |b| {
        b.iter(|| black_box(rt.block_on(cached.lookup_ip(HOST)).unwrap()));
    });
    group.finish();
}

/// Building a resolver, as a CLI does once at startup.
fn construct(c: &mut Criterion) {
    let rt = runtime();
    let _in_runtime = rt.enter();
    let server = name_server(false);
    let mut group = c.benchmark_group("construct");
    group.bench_function(BenchmarkId::new("sansio-dns", "config"), |b| {
        b.iter(|| black_box(sansio(black_box(server))));
    });
    group.bench_function(BenchmarkId::new("hickory", "config"), |b| {
        b.iter(|| black_box(hickory(black_box(server), false)));
    });
    group.bench_function(BenchmarkId::new("sansio-dns", "system"), |b| {
        b.iter(|| black_box(sansio_dns_tokio::Resolver::from_system_conf().unwrap()));
    });
    group.bench_function(BenchmarkId::new("hickory", "system"), |b| {
        b.iter(|| {
            let builder = TokioResolver::builder(TokioRuntimeProvider::default()).unwrap();
            black_box(builder.build().unwrap())
        });
    });
    group.finish();
}

/// A GET on a new connection each time, so every request resolves the
/// host. The IP-literal row needs no lookup at all.
fn reqwest_get(c: &mut Criterion) {
    let rt = runtime();
    let _in_runtime = rt.enter();
    let server = name_server(false);
    let port = http_server().port();
    let by_name = format!("http://app.example:{port}/");
    let by_ip = format!("http://127.0.0.1:{port}/");
    let client = |builder: reqwest::ClientBuilder| {
        builder
            .no_proxy()
            .pool_max_idle_per_host(0)
            .build()
            .unwrap()
    };
    let clients = [
        (
            "sansio-dns",
            client(reqwest::Client::builder().dns_resolver(sansio(server))),
            by_name.as_str(),
        ),
        (
            "hickory",
            client(reqwest::Client::builder().dns_resolver(Hickory(hickory(server, false)))),
            by_name.as_str(),
        ),
        (
            "ip-literal",
            client(reqwest::Client::builder()),
            by_ip.as_str(),
        ),
    ];
    let mut group = c.benchmark_group("reqwest_get");
    for (label, client, url) in &clients {
        let get = || async { client.get(*url).send().await?.bytes().await };
        assert_eq!(rt.block_on(get()).unwrap(), "ok");
        group.bench_function(*label, |b| {
            b.iter(|| black_box(rt.block_on(get()).unwrap()));
        });
    }
    group.finish();
}

criterion_group!(benches, lookup_ip, construct, reqwest_get);
criterion_main!(benches);
