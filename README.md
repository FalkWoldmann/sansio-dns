# sansio-dns

A sans-IO DNS stub resolver built on [`hickory-proto`](https://crates.io/crates/hickory-proto).
It owns no sockets, timers or tasks, so the same state machine runs on blocking std,
Tokio, compio, or an embedded event loop.

```rust
let mut resolver = Resolver::new(Config::new("1.1.1.1:53".parse()?, []));
resolver.query(Name::from_ascii("example.com")?, RecordType::A, Instant::now())?;

loop {
    while let Some(t) = resolver.poll_transmit() { /* send t.payload to t.destination */ }
    if let Some(event) = resolver.poll_event() { /* Response or Failed */ break; }
    // wait for a datagram or until resolver.poll_timeout(), then call
    // resolver.handle_datagram(query, from, &bytes, now) or resolver.handle_timeout(now)
}
```

Complete drivers are in `examples/` (`std`, `tokio`, `compio`), about 100 lines each including TCP.

For hostnames, `IpLookup` runs the A and AAAA queries and merges the addresses, following
CNAMEs. `Config::ip_strategy` picks the families and their order: IPv6 first by default, or
IPv4 first, or only one family. With search domains, the lookup starts the queries for the
next candidate itself: send the transmits it queues, and route events by `lookup.queries()`
again after each one.

```rust
let mut lookup = IpLookup::start(&mut resolver, Name::from_ascii("example.com")?, now)?;
// in the event loop:
while let Some(event) = resolver.poll_event() {
    lookup = match lookup.handle_event(&mut resolver, &event, now) {
        Progress::Waiting(lookup) => lookup,
        Progress::Done(result) => { /* Ok(addresses) or Err(error) */ }
    };
}
```

`addresses(&message)` does the CNAME-following part for any single response.

A query for the same name and type as one already in flight joins it instead of being sent,
and gets the same outcome as its own event, so parallel lookups of one host share their
queries. One that joins late doesn't inherit the first one's spent attempts: if that one runs
out, the later query starts over with its own. Cancelling the first hands the query to the next.

### Tokio and reqwest

[`sansio-dns-tokio`](sansio-dns-tokio) is a ready-made driver: `lookup_ip(host)` runs an
`IpLookup` on a background task shared by all clones of the resolver. Each UDP query gets its
own socket, and TCP or TLS connections stay open between lookups until they go idle. With its
`reqwest` feature, it plugs into reqwest as the DNS resolver:

```rust
let client = reqwest::Client::builder()
    .dns_resolver(sansio_dns_tokio::Resolver::from_system_conf()?)
    .build()?;
```

`cargo run -p sansio-dns-tokio --features reqwest --example get -- https://example.com` is a
small HTTP client built this way.

### DNS over TLS

With the `tls` feature, `Config::with_tls(client, server_name)` sends every query over TLS
(RFC 7858) and authenticates the servers as `server_name` (RFC 8310 strict profile). The crate
brings rustls without a crypto provider or root store: build the `ClientConfig` with the ones
you want. `examples/dot.rs` uses ring and the webpki roots:

```sh
cargo run --example dot --features tls -- example.com 1.1.1.1:853 cloudflare-dns.com
```

### Configuration

`Config::hosts = Hosts::parse(&bytes)` adds static entries from a hosts file (you read the
file). Listed names are answered locally for A and AAAA, with the addresses of that family,
before any DNS query, as glibc's `hosts: files dns` does.


`Config::from_resolv_conf(&bytes)` reads the text of a `resolv.conf` (you read the file) with
the [`resolv-conf`](https://crates.io/crates/resolv-conf) crate and applies glibc's rules:
the first three nameservers, `search`/`domain`, `ndots`, `timeout` and `attempts`, skipping
lines it can't use instead of failing; `options no-aaaa` asks for IPv4 addresses only. With
search domains, a name without a trailing dot is tried with each of them, before the name as
given if it has fewer than `ndots` dots and after it otherwise. For `Resolver::query` the
search moves on after NXDOMAIN and after NODATA (the name exists without records of the type
asked for at the end of its CNAME chain), until a candidate has data (RFC 1123 §6.1.4.3, RFC
2308 §2.2); when it runs out the outcome is the first NODATA, else the last NXDOMAIN. glibc
moves on after NODATA only when the answer section is empty, so it stops at a CNAME whose
target has no data. `IpLookup` asks each candidate for both families and moves on when
neither has an address, as glibc's `getaddrinfo` does, so its addresses are always those of
one name.

## Compared with hickory-resolver

[hickory-resolver](https://crates.io/crates/hickory-resolver) is the established async
resolver for Rust, and the one behind reqwest's `hickory-dns` feature. The `compare/` crate
measures both on the job a reqwest client gives them, against a name server on localhost
(`cargo bench -p compare`, `cargo run -p compare --release --bin allocs`). On an M3 Pro, with
hickory-resolver 0.26.3 and its cache off:

| | sansio-dns-tokio | hickory-resolver |
|---|---|---|
| `lookup_ip` over UDP | 226 µs | 311 µs |
| `lookup_ip` after a truncated answer, over TCP | 305 µs | 396 µs |
| reqwest GET on a new connection | 396 µs | 425 µs |
| Heap allocations per UDP lookup, incl. 18 by the test server | 57 | 145 |
| Stripped binary size over reqwest's default resolver | +0.58 MB | +1.44 MB |

On localhost the times are mostly task wakeups; on a real network the round trip to the
server dominates. With its cache on, hickory answers a repeated lookup in about 1 µs, and
sansio-dns has no cache yet.

Where the two behave differently:

| | sansio-dns | hickory-resolver |
|---|---|---|
| Runtime | Sans-IO core for any runtime, plus a Tokio driver | Tokio; its `RuntimeProvider` needs `Send + Sync` |
| EDNS | Always on at 1232 bytes, dropped once on `FORMERR` | From the system config only with `options edns0` |
| Truncated answer over TCP | Used as it is | The lookup fails |
| Hosts entry with only an IPv4 address | Empty AAAA answer, as glibc does | AAAA asked from DNS |
| Address families | Both, IPv6 first, by default; or IPv4 first, or one family | The same, plus asking for the second family only when the first has no address |
| Names with `_` | Resolved | Rejected |
| Cache | None | Positive and negative, 8192 entries |
| Server order | As configured; one that failed to answer goes after the others for a minute | By measured latency, two servers raced |
| Transports | UDP, TCP, DoT | Also DoH, DoH3, DoQ and DNSSEC validation |
| System configuration | `resolv.conf` and hosts | Also Windows, and macOS through SystemConfiguration |
| Tokio lookups | `lookup_ip` | Any record type, reverse lookups, typed helpers |

## Spec coverage

Behavior follows the RFCs as listed and annotated at
[rfc-annotations.research.icann.org](https://rfc-annotations.research.icann.org/).
Tests mostly live in `tests/rfc<number>.rs`, with one module per section. The exceptions:
RFC 1034 is in `tests/lookup.rs`, except §4.3.1, tested with the RA bit and RFC 2308 §2.2's
authority-section rule in `rfc1035.rs`'s §4.1.1 module, which also has the extended RCODEs of
RFC 6891 §6.1.3 and RFC 7873 §5.3; RFC 2308 §2.2's NODATA is in `rfc1123.rs`'s §6.1.4.3
module, and RFC 6895, 8482 and 9824 in its §6.1.3.2 module; RFC 6762 and 7686 are tested in `rfc6761.rs`'s §6.4 module;
`rfc7858.rs` holds the RFC 7858, 8310 and 8467 tests as plain functions, without section
modules; and `rfc7766.rs` also has `stream_timeout` and `lost_connection` modules.
`tests/main.rs` builds them all as one crate.

| RFC | Section | Behavior |
|---|---|---|
| 1035 | §2.3.3 | Question names are compared case-insensitively |
| 1035 | §3.1 | Names are absolute: without search domains, `example.com` and `example.com.` ask the same question |
| 1035 | §4.1.1 | `RD` set; only `NOERROR` and `NXDOMAIN` answer the question; every other code fails over, the codes 6 to 15 and extended ones included |
| 1035 | §4.2.1 | `TC` set → retry over TCP (RFC 7766) |
| 1035 | §7.2 | Retransmit on timeout, or at once when the datagram can't be sent, rotating through servers; new queries start after a server that recently failed to answer |
| 1035 | §7.2 | A server that answers with an error code, a reply that doesn't decode or an empty answer without AA or RA is removed from the query's list until the next search candidate; once every server is removed, the query fails with the last error |
| 1035 | §7.3 | Non-responses (`QR=0`) and wrong opcodes are discarded; a matching reply whose records don't decode moves on to the next server at once |
| 1034 | §4.3.1 | An empty `NOERROR` answer with neither AA nor RA, from a server that doesn't recurse and isn't authoritative (such as a referral), fails over (`Error::NoRecursion` on the last), as glibc does; with AA or RA it is NODATA |
| 1123 | §6.1.3.2 | Zone transfer and meta query types (AXFR, IXFR, OPT, TSIG, TKEY, MAILA, MAILB, NXNAME, TYPE 0; RFC 6895 §3.1, RFC 9824 §3.5) are rejected by `query`; ANY is allowed (RFC 8482) |
| 1123 | §6.1.3.3 | Retries back off exponentially: each round through the servers waits twice as long, starting at 5 s by default |
| 1123 | §6.1.4.3 | Search candidates are tried until one has data of the type asked for: NXDOMAIN and NODATA (RFC 2308 §2.2) move on; then the first NODATA is the outcome, else the last NXDOMAIN; a failure ends the search. `IpLookup` asks each candidate for A and AAAA and moves on when neither has an address, so both families come from the same name (§6.1.4.3 (b)) |
| 2181 | §8 | TTLs with the most significant bit set are passed on as zero |
| 2181 | §9 | A truncated UDP reply switches to TCP even when it is cut off mid-record and doesn't decode; over TCP a truncated reply is used as it is |
| 3597 | §3 | Records of unknown type are kept as opaque data. hickory rejects a message with an empty-RDATA record outside UPDATE, although `\# 0` is valid; such a reply moves on to the next server at once |
| 5452 | §9.1 | Responses must match source address, port, ID, QNAME, QTYPE and QCLASS, also when their records don't decode |
| 5452 | §4.6 | The first answer that ends the query wins, and later copies are ignored. A copy of an error answer counts again while the query is still on that server: after a `FORMERR` without OPT made it drop EDNS, a second copy counts as the answer to the query without EDNS |
| 5452 | §9.2 | IDs from a CSPRNG, avoiding those of outstanding queries (up to 16 picks); per-query source ports are the driver's job (see below) |
| 6891 | §6.1.3 | BADVERS fails over like any server error: version 0 is the lowest there is |
| 6891 | §6.2.3 | One OPT record, 1232-byte payload (DNS Flag Day 2020) |
| 6891 | §7, §6.2.2 | `FORMERR` without OPT → same server once more without EDNS (over TLS: fail over, since EDNS carries the padding); with OPT → fail over |
| 7873 | §5.3 | No cookie is sent, so BADCOOKIE is a server error and fails over |
| 7766 | §5 | Truncated UDP response → same server over TCP; later attempts stay on TCP; UDP replies then ignored |
| 7766 | §6.2.1 | One connection per server, reused and pipelined; answers matched in any order |
| 7766 | §6.2.3 | Idle connections closed after `idle_timeout`; a timeout closes the connection |
| 7766 | §8 | Two-byte length prefix; replies reassembled from any chunking |
| 1034 | §3.6.2 | `addresses` follows the CNAME chain and ignores records owned by other names |
| 6761 | §6.3 | `localhost` names → loopback for A/AAAA, empty answer otherwise; nothing sent |
| 6761 | §6.4 | `invalid.` → NXDOMAIN; nothing sent |
| 6762 | §3 | `local.` names are sent to the name servers like any other, as glibc does without nss-mdns; mDNS is up to the caller |
| 7686 | §2 | `onion.` → NXDOMAIN; nothing sent |
| 7858 | §3 | With `tls`: every query over TLS on a stream, never UDP; TLS errors fail the attempt |
| 7858 | §3.4 | The TLS session is reused for later queries; queries wait out a handshake in progress |
| 8310 | §5 | Strict profile: the certificate must match the configured name |
| 8467 | §4.1 | Queries padded to a multiple of 128 octets |

### Driver obligations

RFC 5452 §9.2 requires an unpredictable source port per outstanding query. A sans-IO core
can't pick ports, so `Transport::Udp(query)` names the query: bind a fresh ephemeral socket
per query, and pass that query along with each datagram the socket receives to `handle_datagram`.

Stream connections are named by a `ConnectionId`: `TcpConnect(id)` means open a connection
to the destination and write the payload, `TcpWrite(id)` write to it, `TcpClose(id)` close
it. Payloads are already length-prefixed or TLS-encrypted. Pass everything read to
`handle_stream_data(id, …)`. Call `handle_stream_closed(id, …)` if the server closes the
connection, and `handle_stream_error(id, kind, …)` if connecting, reading or writing fails,
so a query out of attempts fails with that error. The resolver keeps one connection per
server and pipelines queries over it; it closes the connection after `Config::idle_timeout`
(10 s) without queries, when a query on it times out, or, with `tls`, when TLS rejects bytes
received on it.

A `TcpWrite` can follow its `TcpConnect` before connecting has finished, so queue it. After
reporting a connection closed or failed, forget it: no `TcpClose` follows. When binding a
query's socket or sending its datagram fails, call `handle_udp_error(query, to, kind, …)`,
so the query moves on at once instead of waiting out its deadline. Bind each socket in the
destination's address family, pass the source address as received (an IPv4 server seen as
`::ffff:a.b.c.d` won't match), and read datagrams into a buffer of at least 1232 bytes.

### Not implemented

- Opportunistic (unauthenticated) TLS.
- EDNS TCP keepalive (RFC 7828) to negotiate the idle timeout with the server.
- DoH/DoQ, caching.
- DNS cookies (RFC 7873): queries carry no COOKIE option.
- `resolv.conf` options other than the ones above (`rotate`, `use-vc`, `sortlist`, …).
- Sorting addresses by the host's own ones (RFC 6724 §6); `IpLookup` lists them by family,
  in the server's order within each.
- Once EDNS is dropped for a query, it stays off for that query's remaining attempts,
  including other servers, until the search moves to the next candidate.

## Testing

```sh
cargo nextest run              # unit, rstest cases and proptest properties
PROPTEST_CASES=10000 cargo nextest run
```

Parameterized cases use [rstest](https://crates.io/crates/rstest); properties such as
"arbitrary bytes never complete a query" and "any ID bit flip is rejected" use
[proptest](https://crates.io/crates/proptest).

The `fuzz/` crate has [cargo-fuzz](https://crates.io/crates/cargo-fuzz) targets that
drive the resolver with arbitrary datagrams (`datagram`), TCP bytes (`stream`), DoT
records (`tls_stream`), hosts and resolv.conf files (`system_files`) and call sequences
(`driver_ops`). After every step they check one event per query, transmits only for live
queries and open connections, and a timer exactly while something is pending; `datagram`,
`stream` and `driver_ops` also bound the sends per query. `system_files` checks the local
answers for hosts and special-use names, the order of the search candidates and the answer
the search ends on, and
`tls_stream` checks that every query the server decrypts keeps EDNS, is padded to a multiple
of 128 octets and is sent at most `attempts + 3` times. They need nightly:

```sh
cd fuzz && cargo fuzz run driver_ops -- -max_total_time=60 -timeout=5
```

## Benchmarks

[Criterion](https://crates.io/crates/criterion) benchmarks run without a network:

```sh
cargo bench --bench resolver              # UDP round trip and spoof rejection with 0/16/256
                                          # queries in flight, TCP reassembly, CNAME chains,
                                          # resolv.conf parsing
cargo bench --bench tls --features tls    # DoT against an in-process rustls server: a query
                                          # on an open connection vs. new connections with a
                                          # resumed or a full handshake
```

The TLS numbers include the server's half of each exchange. On a network, a new
connection also costs two extra round trips (TCP and TLS) before the query's own.

## License

Licensed under either of [Apache License, Version 2.0](LICENSE-APACHE) or
[MIT license](LICENSE-MIT) at your option. Unless you explicitly state otherwise, any
contribution you submit for inclusion in this crate, as defined in the Apache-2.0 license,
is dual licensed as above, without any additional terms or conditions.
