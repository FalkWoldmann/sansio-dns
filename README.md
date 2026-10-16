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
| 7766 | §8 | Two-byte length prefix; replies reassembled from any chunking |

### Driver obligations

RFC 5452 §9.2 requires an unpredictable source port per outstanding query. A sans-IO core
can't pick ports, so each `Transmit` carries its `QueryId`: bind a fresh ephemeral socket
per query, and only pass datagrams received on that socket to `handle_datagram`.

A `Transmit` with `Transport::Tcp` means: open a new connection to its destination
(replacing any earlier one for that query) and write the payload, which is already
length-prefixed. Pass everything read to `handle_stream_data`, and call
`handle_stream_closed` on end of stream or error. One connection per query; no pipelining.

### Not implemented

- TCP connection reuse and pipelining (RFC 7766 §6.2.1); each TCP attempt is a new connection.
- DoT/DoH/DoQ, caching, `/etc/resolv.conf`, search domains, DNS cookies (RFC 7873).
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
