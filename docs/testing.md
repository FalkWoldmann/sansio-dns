# Testing and benchmarks

## Running the tests

```sh
cargo nextest run --workspace                 # unit, rstest cases and proptest properties
cargo nextest run --workspace --all-features  # also the DoT and reqwest modules
cargo test --workspace --doc --all-features   # doctests, the README's examples included
PROPTEST_CASES=10000 cargo nextest run -p sansio-dns --test integration state_machine
```

Parameterized cases use [rstest](https://crates.io/crates/rstest); properties such as
"arbitrary bytes never complete a query" and "any ID bit flip is rejected" use
[proptest](https://crates.io/crates/proptest). `tests/state_machine.rs` is a
proptest-state-machine test: random driver-call sequences against a reference model, with
invariants checked after every step and failures shrunk to short call sequences.

Tests of a query's lifecycle render each input, its events, its transmits and the next
deadline as text and assert it as an [insta](https://crates.io/crates/insta) inline
snapshot. After a deliberate behaviour change, run `cargo insta test --review` and read
every changed snapshot against the crate docs' "How a query moves on" table before
accepting it.

## Where the tests live

Each package builds its integration tests as one crate, `integration` (`tests/main.rs`
with the other files as modules). `tests/rfc<number>.rs` mostly hold one module per RFC
section, pinning the rows of [spec-coverage.md](spec-coverage.md). The exceptions:

- RFC 1034 is in `tests/lookup.rs`, except §4.3.1, which is tested with the RA bit and RFC
  2308 §2.2's authority-section rule in `rfc1035.rs`'s §4.1.1 module, which also has the
  extended RCODEs of RFC 6891 §6.1.3 and RFC 7873 §5.3.
- `tests/lookup.rs` also has RFC 3596 §2.3, CNAME chains into special-use names and RFC
  6762 §22.1 for `Resolver::lookup_ip`.
- RFC 2308 §2.2's NODATA and RFC 1035 §7.4's records of another class are in
  `rfc1123.rs`'s §6.1.4.3 module, and RFC 6895, 8482 and 9824 in its §6.1.3.2 module.
- RFC 2308 §7.2's cap is in `rfc9520.rs`'s §3.2 module. RFC 1123 §6.1.3.3 (3) and (4) are
  covered by the tests of RFC 9520 §3.2 and RFC 2308 §5, RFC 2308 §8 by `rfc2308.rs`'s §5
  and §6 modules, and RFC 4343 §3 for cache keys by both.
- RFC 1123 §6.1.4.3 (b)'s `no-tld-query` is in `resolv_conf.rs`'s `search` and `options`
  modules, and that file also has RFC 1122 §3.2.1.3's unspecified address as a name server.
- `rfc6761.rs` has RFC 7686 in its §6.4 module, RFC 6762 in its `rfc6762_section_22_1`
  module, and RFC 6761 §6.1, §6.2, §6.5, RFC 8375 and RFC 9476 in its
  `not_special_to_resolvers` module.
- `rfc7858.rs` (`tls` feature) holds the RFC 7858, 8310, 8467, 7830, 7871 and 8446 tests
  as plain functions, without section modules, against an in-process rustls server.
- `rfc7766.rs` also has a `stream_timeout` module for queries that time out on a
  connection.

The Tokio driver's tests: `sansio-dns-tokio/tests/tls.rs` checks that its DNS over TLS
connections end with close_notify (RFC 8446 §6.1), when the server closes first and when
the resolver is dropped; `sansio-dns-tokio/tests/lookup.rs` has the host name rules of
`lookup_ip` (RFC 1123 §2.1, RFC 4343 §4, RFC 5891); and
`sansio-dns-tokio/tests/system_conf.rs` checks that `from_system_conf` applies
`LOCALDOMAIN` and `RES_OPTIONS`.

## Fuzzing

The `fuzz/` crate has [cargo-fuzz](https://crates.io/crates/cargo-fuzz) targets that drive
the resolver with arbitrary datagrams (`datagram`), TCP bytes (`stream`), DoT records
(`tls_stream`), hosts and resolv.conf files (`system_files`) and call sequences
(`driver_ops`). After every step they check one event per query, transmits only for live
queries and open connections, nothing sent for a question within a second of its failure,
and a timer exactly while something is pending; `datagram`, `stream` and `driver_ops` also
bound the sends per query and check that queries for one name never start over.
`system_files` checks the local answers for hosts, special-use and link-local names, the
order of the search candidates, `no-tld-query` included, the answer the search ends on, and
that `LOCALDOMAIN`, `RES_OPTIONS` and the host name apply as glibc applies them.
`tls_stream` checks that every query the server decrypts keeps EDNS, carries the Client
Subnet privacy option for the server's address family and then one padding option to a
multiple of 128 octets, and is sent at most `attempts + 3` times, and at most three times
to one server, that every connection the resolver closes ends its session with close_notify
or an alert first, unless an alert from the server that rustls reports as the error ended
it, and that the resolver writes nothing to a connection once the server's fatal alert
reached it. They need nightly:

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

The TLS numbers include the server's half of each exchange. On a network, a new connection
also costs two extra round trips (TCP and TLS) before the query's own.

The `compare/` crate (not published) measures `sansio-dns-tokio` and hickory-resolver on
the job a reqwest client gives them, against a name server on localhost:

```sh
cargo bench -p compare --bench lookup        # filter e.g. -- 'lookup_ip/'
cargo run -p compare --release --bin allocs  # heap allocations per lookup
```

The benches that open a TCP connection per iteration (`tcp_fallback`, `reqwest_get`) can
exhaust local ports on macOS (TIME_WAIT); run them with a shorter `--measurement-time` and
let TIME_WAIT drain between groups.
