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
    // resolver.handle_datagram(from, &bytes, now) or resolver.handle_timeout(now)
}
```

Complete drivers are in `examples/` (`std`, `tokio`, `compio`), about 100 lines each including TCP.

For hostnames, `IpLookup` runs the A and AAAA queries and merges the addresses, following
CNAMEs:

```rust
let mut lookup = IpLookup::start(&mut resolver, Name::from_ascii("example.com")?, now)?;
// in the event loop:
while let Some(event) = resolver.poll_event() { lookup.handle_event(&event); }
if let Some(result) = lookup.result() { /* Ok(addresses) or Err(error) */ }
```

`addresses(&message)` does the CNAME-following part for any single response.

### DNS over TLS

With the `tls` feature, `Config::with_tls(client, server_name)` sends every query over TLS
(RFC 7858) and authenticates the servers as `server_name` (RFC 8310 strict profile). The crate
brings rustls without a crypto provider or root store: build the `ClientConfig` with the ones
you want. `examples/dot.rs` uses ring and the webpki roots:

```sh
cargo run --example dot --features tls -- example.com 1.1.1.1:853 cloudflare-dns.com
```

### Configuration

`Config::from_resolv_conf(&bytes)` reads the text of a `resolv.conf` (you read the file) with
the [`resolv-conf`](https://crates.io/crates/resolv-conf) crate and applies glibc's rules:
nameservers, `search`/`domain`, `ndots`, `timeout` and `attempts`. With search domains, a name
without a trailing dot is tried with each of them, before the name as given if it has fewer
than `ndots` dots and after it otherwise; the search moves on only on NXDOMAIN.

## Spec coverage

Behavior follows the RFCs as listed and annotated at
[rfc-annotations.research.icann.org](https://rfc-annotations.research.icann.org/).
Tests live in `tests/rfc<number>.rs`, with one module per section.

| RFC | Section | Behavior |
|---|---|---|
| 1035 | §2.3.3 | Question names are compared case-insensitively |
| 1035 | §3.1 | Names are absolute; `example.com` and `example.com.` are the same query |
| 1035 | §4.1.1 | `RD` set; `NOERROR`/`NXDOMAIN` end the query; `SERVFAIL`/`NOTIMP`/`REFUSED` fail over |
| 1035 | §4.2.1 | `TC` set → retry over TCP (RFC 7766) |
| 1035 | §7.2 | Retransmit on timeout, rotating through servers |
| 1035 | §7.3 | Non-responses (`QR=0`) and wrong opcodes are discarded |
| 5452 | §9.1 | Responses must match source address, port, ID, QNAME, QTYPE and QCLASS |
| 5452 | §4.6 | Only the first matching response is accepted |
| 5452 | §9.2 | IDs from a CSPRNG, unique among outstanding queries; per-query source ports are the driver's job (see below) |
| 6891 | §6.2.3 | One OPT record, 1232-byte payload (DNS Flag Day 2020) |
| 6891 | §7, §6.2.2 | `FORMERR` without OPT → same server once more without EDNS; with OPT → fail over |
| 7766 | §5 | Truncated UDP response → same server over TCP; later attempts stay on TCP; UDP replies then ignored |
| 7766 | §6.2.1 | One connection per server, reused and pipelined; answers matched in any order |
| 7766 | §6.2.3 | Idle connections closed after `idle_timeout`; a timeout closes the connection |
| 7766 | §8 | Two-byte length prefix; replies reassembled from any chunking |
| 1034 | §3.6.2 | `addresses` follows the CNAME chain and ignores records owned by other names |
| 6761 | §6.3 | `localhost` names → loopback for A/AAAA, empty answer otherwise; nothing sent |
| 6761 | §6.4 | `invalid.` → NXDOMAIN; nothing sent |
| 6762 | §3 | `local.` → NXDOMAIN; nothing sent (resolve with mDNS instead) |
| 7686 | §2 | `onion.` → NXDOMAIN; nothing sent |
| 7858 | §3 | With `tls`: every query over TLS on a stream, never UDP; TLS errors fail the attempt |
| 7858 | §3.4 | The TLS session is reused for later queries; queries wait out a handshake in progress |
| 8310 | §5 | Strict profile: the certificate must match the configured name |
| 8467 | §4.1 | Queries padded to a multiple of 128 octets |

### Driver obligations

RFC 5452 §9.2 requires an unpredictable source port per outstanding query. A sans-IO core
can't pick ports, so `Transport::Udp(query)` names the query: bind a fresh ephemeral socket
per query, and only pass datagrams received on that socket to `handle_datagram`.

Stream connections are named by a `ConnectionId`: `TcpConnect(id)` means open a connection
to the destination and write the payload, `TcpWrite(id)` write to it, `TcpClose(id)` close
it. Payloads are already length-prefixed or TLS-encrypted. Pass everything read to
`handle_stream_data(id, …)`, and call `handle_stream_closed(id, …)` if the connection ends
on its own. The resolver keeps one connection per server and pipelines queries over it;
it closes the connection after `Config::idle_timeout` (10 s) without queries, or when a
query on it times out.

### Not implemented

- Opportunistic (unauthenticated) TLS.
- EDNS TCP keepalive (RFC 7828) to negotiate the idle timeout with the server.
- DoH/DoQ, caching, DNS cookies (RFC 7873).
- `resolv.conf` options other than the ones above (`rotate`, `use-vc`, `sortlist`, …).
- `IpLookup` searches A and AAAA independently, so the two could end on different candidates.
- Once EDNS is dropped for a query, it stays off for that query's remaining attempts,
  including other servers.

## Testing

```sh
cargo nextest run              # unit, rstest cases and proptest properties
PROPTEST_CASES=10000 cargo nextest run
```

Parameterized cases use [rstest](https://crates.io/crates/rstest); properties such as
"arbitrary bytes never complete a query" and "any ID bit flip is rejected" use
[proptest](https://crates.io/crates/proptest).

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
