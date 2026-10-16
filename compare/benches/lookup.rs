//! sansio-dns-tokio and hickory-resolver resolving for an HTTP client,
//! against a name server on localhost: `cargo bench -p compare`
//!
//! Both clients run on one current-thread runtime, and also on a
//! multi-thread one for the concurrent lookups; the servers each have a
//! thread of their own.

#![expect(clippy::unwrap_used, reason = "a benchmark fails loudly on bad setup")]

use std::hint::black_box;
use std::net::{IpAddr, SocketAddr};
use std::sync::LazyLock;
use std::time::Duration;

use compare::{EXPECTED, HOST, Hickory, hickory, http_server, name_server, sansio};
use criterion::measurement::WallTime;
use criterion::{
    BenchmarkGroup, BenchmarkId, Criterion, Throughput, criterion_group, criterion_main,
};
use hickory_resolver::TokioResolver;
use hickory_resolver::net::runtime::TokioRuntimeProvider;
use sansio_dns::hickory_proto::op::{Message, Query};
use sansio_dns::hickory_proto::rr::{Name, RecordType};
use tokio::net::UdpSocket;
use tokio::runtime::Runtime;
use tokio::task::JoinSet;

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

/// `n` lookups at once, each on a task of its own, so a multi-thread
/// runtime can spread them over its workers. One iteration is the whole
/// batch; hickory's cache is off. The lookups are all of one name, as when
/// an HTTP client opens several connections to a host, or of `n` different
/// names. hickory merges a query with an identical one in flight, so a
/// batch of one name mostly sends it one A and one AAAA query.
///
/// hickory keeps its default limit of 32 requests in flight per
/// connection, so over the TCP fallback with 100 different names it gets
/// `Busy` and backs off for 20 ms: that row measures hickory under its own
/// limit.
///
/// `raw_udp` is the name server's floor: per lookup, an A and an AAAA query
/// on a fresh UDP socket, with no resolver. Every bench gets a name server
/// of its own, but timings still move between benches, so compare the rows
/// of one `n` within a run and read absolute numbers loosely.
fn concurrent(c: &mut Criterion) {
    let multi_thread = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .unwrap();
    for (flavor, rt) in [
        ("current_thread", runtime()),
        ("multi_thread", multi_thread),
    ] {
        let _in_runtime = rt.enter();
        for (transport, truncate_udp) in [("udp", false), ("tcp_fallback", true)] {
            let mut group = c.benchmark_group(format!("concurrent/{transport}/{flavor}"));
            for (names, name) in [
                ("same_name", same_name as fn(u64) -> String),
                ("distinct_names", distinct_name),
            ] {
                for n in [1, 10, 100] {
                    group.throughput(Throughput::Elements(n));
                    let id = |resolver| BenchmarkId::new(format!("{resolver}/{names}"), n);
                    let ours = sansio(name_server(truncate_udp));
                    bench_batch(&mut group, &rt, id("sansio-dns"), n, |i| {
                        let resolver = ours.clone();
                        let name = name(i);
                        async move { resolver.lookup_ip(&name).await.unwrap() }
                    });
                    let theirs = hickory(name_server(truncate_udp), false);
                    bench_batch(&mut group, &rt, id("hickory"), n, |i| {
                        let resolver = theirs.clone();
                        let name = name(i);
                        async move { resolver.lookup_ip(name).await.unwrap().iter().collect() }
                    });
                }
            }
            if !truncate_udp {
                for n in [1, 10, 100] {
                    group.throughput(Throughput::Elements(n));
                    let server = name_server(false);
                    group.bench_function(BenchmarkId::new("raw_udp", n), |b| {
                        b.iter(|| black_box(rt.block_on(batch(n, |_| raw_lookup(server)))));
                    });
                }
            }
            group.finish();
        }
    }
}

/// Check that a batch of `n` finds [`EXPECTED`] every time, then time it.
fn bench_batch<F>(
    group: &mut BenchmarkGroup<'_, WallTime>,
    rt: &Runtime,
    id: BenchmarkId,
    n: u64,
    lookup: impl Fn(u64) -> F,
) where
    F: Future<Output = Vec<IpAddr>> + Send + 'static,
{
    let found = rt.block_on(batch(n, &lookup));
    assert!(found.iter().all(|found| found == &EXPECTED));
    group.bench_function(id, |b| {
        b.iter(|| black_box(rt.block_on(batch(n, &lookup))));
    });
}

fn same_name(_: u64) -> String {
    HOST.to_owned()
}

fn distinct_name(i: u64) -> String {
    format!("{i}.{HOST}")
}

/// Spawn lookups `0..n` and wait for all of them.
async fn batch<T, F>(n: u64, lookup: impl Fn(u64) -> F) -> Vec<T>
where
    T: Send + 'static,
    F: Future<Output = T> + Send + 'static,
{
    let mut tasks = JoinSet::new();
    for i in 0..n {
        tasks.spawn(lookup(i));
    }
    tasks.join_all().await
}

/// An A and an AAAA query for [`HOST`].
static RAW_QUERIES: LazyLock<[Vec<u8>; 2]> = LazyLock::new(|| {
    [RecordType::A, RecordType::AAAA].map(|record_type| {
        let mut query = Message::query();
        query.metadata.recursion_desired = true;
        query.add_query(Query::query(Name::from_ascii(HOST).unwrap(), record_type));
        query.to_vec().unwrap()
    })
});

/// [`RAW_QUERIES`] on a fresh UDP socket, returning the answers' total size.
async fn raw_lookup(server: SocketAddr) -> usize {
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    socket.connect(server).await.unwrap();
    for query in &*RAW_QUERIES {
        socket.send(query).await.unwrap();
    }
    let mut answer = [0; 512];
    let mut size = 0;
    // A lost datagram fails the bench instead of hanging it.
    for _ in &*RAW_QUERIES {
        let received = tokio::time::timeout(Duration::from_secs(1), socket.recv(&mut answer));
        size += received.await.unwrap().unwrap();
    }
    size
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

criterion_group!(benches, lookup_ip, concurrent, construct, reqwest_get);
criterion_main!(benches);
