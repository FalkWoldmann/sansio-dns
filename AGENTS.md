# AGENTS.md

This file provides guidance to coding agents (Claude Code reads it through the `CLAUDE.md` symlink) when working with code in this repository.

## What this is

A sans-IO DNS stub resolver built on `hickory-proto`. The core crate (`src/`) owns no sockets,
timers or tasks: callers pass `now: Instant` into every call and carry out the `Transmit`s it
returns. `clippy.toml` enforces this by banning `Instant::now`, `thread::sleep` and socket types
in the core; drivers, tests, benches and examples opt out with a crate-level
`#![expect(clippy::disallowed_methods, ...)]`. The workspace also has `sansio-dns-tokio/` (a Tokio
driver with an optional reqwest resolver) and `compare/` (benchmarks against hickory-resolver,
not published). `fuzz/` is a separate cargo-fuzz crate, excluded from the workspace.

## Commands

CI (`.github/workflows/ci.yml`) runs on stable, plus a 1.88 MSRV check:

```sh
cargo fmt --check
cargo clippy --workspace --all-targets -- -D warnings
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo nextest run --workspace --profile ci            # also with --all-features
cargo test --workspace --doc --all-features
```

Always check both feature sets: `tls` gates DoT in the core and the `rfc7858` test module, and
`reqwest` gates the Tokio driver's `Resolve` impl and its test module.

Each package builds its integration tests as one crate, `integration` (`tests/main.rs` with the
other files as modules, `autotests = false`). A single test or module:

```sh
cargo test -p sansio-dns --all-features --test integration rfc7766::stream_timeout
cargo test -p sansio-dns-tokio --all-features --test integration lookup::lookups_share_one_connection
PROPTEST_CASES=10000 cargo test -p sansio-dns --test integration state_machine
```

Benchmarks and profiling:

```sh
cargo bench --bench resolver                 # core, no network
cargo bench --bench tls --features tls
cargo bench -p compare --bench lookup        # vs hickory; filter e.g. -- 'lookup_ip/'
cargo run -p compare --release --bin allocs  # heap allocations per lookup
cd fuzz && cargo fuzz run driver_ops -- -max_total_time=60 -timeout=5   # nightly
```

The `compare` benches that open a TCP connection per iteration (`tcp_fallback`, `reqwest_get`)
can exhaust local ports on macOS (TIME_WAIT); run them with a shorter
`--measurement-time` and let TIME_WAIT drain between groups.

Locally the global cargo config needs nightly, while CI is stable. Nightly clippy skips lints in
files under `tests/` (rust-clippy#16786) but stable doesn't, so the root `tests/main.rs` uses
`#![allow(...)]` for the panic-style lints, while `sansio-dns-tokio/tests/main.rs` (whose path
doesn't start with `tests/`) keeps `#![expect(...)]`.

## Architecture

The core is split into `src/lib.rs` (crate docs and public types), `src/config.rs`,
`src/wire.rs` (framing, padding, reply matching, special-use answers) and `src/resolver.rs`.
The `Resolver` is a state machine over two maps: pending queries
(`QueryId` -> `Pending`) and stream connections (`ConnectionId` -> `Connection`). Inputs are
`query`, `handle_datagram(query, from, ..)`, `handle_stream_data/closed/error`, `handle_timeout`
and `cancel`; outputs are drained with `poll_transmit`, `poll_event` and `poll_timeout`.

- A query's `attempt` index picks its server (`Config::server` rotates through the list) and is
  bounded by `Config::attempts`. Its `Route` is `Udp` or `Stream(Option<ConnectionId>)`.
- Streams: one connection per server, shared and pipelined by all queries to it (RFC 7766), with
  answers matched by ID and question. DoT sessions live inside `Connection` and are driven
  in memory through `src/tls.rs`; the driver only moves bytes.
- How a query moves on is spread over several functions with different accounting: `retry`
  (next server, uses an attempt), `switch_to_tcp` and `drop_edns` (same server, free), `resend`
  (same server, free once per query via `forgive`, used by `lost` and `time_out_stream`),
  `next_candidate` (next search name, fresh attempts), `give_up` and `fail`. The crate docs'
  "How a query moves on" table states the rules (at most `attempts + 3` sends per name): change
  these functions together and keep the table in sync.
- A query for the same name (as given) and type as a pending one joins it as a follower
  (`Pending::followers`) and gets its outcome. When the leader runs out of attempts, followers
  that joined after it started start over (`give_up`); `cancel(id, now)` hands a query with
  followers to the first of them, re-sending a UDP attempt from the follower's own socket.
- Special-use names (`localhost.`, `invalid.`, `onion.`) and `Config::hosts` entries are answered
  without a transmit. `IpLookup` (`src/lookup.rs`) runs the A and AAAA queries on a `Resolver`
  and merges the addresses from the events it is fed.
- Driver obligations (also in the README): bind a fresh UDP socket per query (RFC 5452 §9.2)
  and pass that query with each datagram; report a stream that the server closed with
  `handle_stream_closed` and an I/O failure with `handle_stream_error`.

`sansio-dns-tokio` runs one background task per `Resolver` (shared by its clones), spawned on
the runtime of the first lookup. It owns the core resolver and all I/O: a UDP socket and
forwarding task per query, and a task per stream connection. Lookups send a request over a
channel with a `oneshot` reply; `CancelOnDrop` cancels a lookup whose future is dropped. If the
task's runtime shuts down, the next lookup (or a waiting one) restarts it on its own runtime.
A resolver shared with an idle current-thread runtime can hang lookups from other runtimes;
that limitation is documented, not handled.

## Tests

`tests/rfc<number>.rs` hold one module per RFC section, and the README's spec coverage table
lists the behaviour each section pins: keep the table in sync when behaviour changes.
`tests/common/mod.rs` has the fixtures (a resolver with servers `S1`, `S2`, and helpers to
start a query, build replies, frame and encode them; `start_distinct` for queries that must
not coalesce) and `Trace`, which drives a resolver and renders each input, its events, its
transmits and the next deadline as text. Tests of a query's lifecycle assert that text as an
insta inline snapshot (`assert_snapshot!(trace, @"...")`): after a deliberate behaviour change,
run `cargo insta test --review` (or `--accept`) and read every changed snapshot against the
crate docs' lifecycle table before accepting it. `tests/state_machine.rs` is a
proptest-state-machine test: random driver-call sequences against a reference model, with
invariants checked after every step and failures shrunk to short call sequences. It doesn't
check deadlines; the snapshots pin those.

## Conventions

- Workspace lints are strict: clippy denies `unwrap`, `expect`, indexing, `panic` and more, and
  `allow_attributes`, so use `#[expect(..., reason = "...")]` instead of `#[allow]`.
- Dependency versions are pinned to the major version only (`tokio = "1"`, `rustls = "0.23"`);
  `Cargo.lock` holds the exact ones.
- Error types derive `thiserror::Error`; the core's `Error` stays `Clone + Eq` plain data.
