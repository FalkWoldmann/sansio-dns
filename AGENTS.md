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

Always check both feature sets: `tls` gates DoT in the core and the `rfc7858` test module (and
the Tokio driver's `tls` test module, through its own `tls` feature), and `reqwest` gates the
Tokio driver's `Resolve` impl and its test module.

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

The core has eight modules: `src/lib.rs` (crate docs and public types), `src/config.rs`
(`Config`, and its own resolv.conf parser, which follows glibc's `res_init`, with
`ResolvEnv` for `LOCALDOMAIN`, `RES_OPTIONS` and the host name), `src/hosts.rs` (hosts file
entries), `src/wire.rs` (framing, padding, reply matching, special-use answers),
`src/resolver.rs` (the state machine), `src/cache.rs` (failures and negative answers),
`src/lookup.rs` (`IpLookup`) and `src/tls.rs` (DoT sessions driven in memory, `tls`
feature).
The `Resolver` is a state machine over two maps: pending queries
(`QueryId` -> `Pending`) and stream connections (`ConnectionId` -> `Connection`), plus the
`Cache`. Inputs are `query`, `handle_datagram(query, from, ..)`, `handle_udp_error`,
`handle_stream_data/closed/error`, `handle_timeout`, `cancel`, `flush_cache` and `shutdown`;
outputs are drained with `poll_transmit`, `poll_event` and `poll_timeout`. The module docs of
`src/resolver.rs` say where each entity documents its states (`Pending`'s table, the ways a
`Connection` ends, `tls::Session`, the cache's `Entry`, `IpLookup`), what `poll_timeout` is
made of, and where map order shows in the outputs; keep them and the invariants on the
fields in sync with the code.

- A query's current server is `Config::server(position)` (the list, rotated). `position`
  starts at `first`, the first server not in `Resolver::failed` (no answer within
  `Config::failure_memory`), and moves on by one per attempt, past the servers in
  `Pending::excluded`; how often it has wrapped around sets the backoff round. `attempt`
  counts the attempts used, bounded by `Config::attempts`. Its `Route` (how the current
  attempt went out) is `Udp` or `Stream { connection, written_after }`, set by `emit`: every
  send goes to the open connection to its server if there is one (RFC 7766 §5), else over a
  new connection if `Pending::stream_only` (after a truncated answer, or with TLS), else over
  UDP.
- Streams: one connection per server, shared and pipelined by all queries to it (RFC 7766), with
  answers matched by ID and question, or by ID alone when they have no question (§7). A query
  that leaves a connection before its answer (cancelled, or timed out while the connection
  had answered since it was written) leaves an `Orphan` there: its ID stays in use
  (`new_message` avoids it, §6.2.1) until the answer comes or the connection ends, it keeps
  the connection busy until its old deadline, and `emit` takes it back instead of writing the
  ID again if a later attempt returns to that connection. A connection holding
  `MAX_ORPHANS` (256) of them is closed when another would join them (`time_out_stream`),
  so a busy connection can't use up the ID space. `Connection::responses` counts complete
  responses; `Route::Stream`'s `written_after` records it at write time and again when `emit`
  takes an orphan back, so a timeout closes the connection only if no response arrived
  since, and a lost connection gives a free resend whenever it answered since. Only writes
  and complete responses reset the idle timer. DoT
  sessions (`tls::Session`) live inside `Connection` and are driven in memory through
  `src/tls.rs`; the driver only moves bytes. Queries written during the handshake wait in the
  session's own queue, not rustls' 64 KiB buffer, and `Session::receive` drains the plaintext
  after every record batch (rustls holds 16 KiB), and also after a TLS error, so the answers
  decrypted before it count. Every close the resolver starts goes through `shut`, which sends
  the alert rustls queued for a TLS error, or else the session's close_notify, as a `TcpWrite`
  before the `TcpClose` (RFC 8446 §6), and nothing after the server's fatal alert
  (`Session::alerted`, §6.2). A TLS error on received bytes (after the answers decrypted
  before it, which can't send on the connection either) or a refused write aborts the
  connection: `abort` calls `shut`, then `retry` for each query on it. The server's
  close_notify retires the connection like `handle_stream_closed` (`retire`: `shut`, then
  `move_off`), after the answers decrypted with it, which can't send on it
  (`Connection::closing`, skipped by `emit` and `channel` through `Connection::is_open_to`).
  `shutdown` drops every query and shuts every connection, for a driver that stops. Over TLS,
  `wire::protect` adds the EDNS Client Subnet privacy option (prefix 0, FAMILY of the
  server's address, RFC 8310 §11.1) and then the padding, last; `emit` runs it again when a
  query moves to a server of the other family. `Config::with_tls_names` holds an
  authentication name per server.
- Replies go through `handle_reply`. A truncated one over UDP switches the query to TCP
  (`switch_to_tcp`), even if its records don't decode. Any other reply whose header and
  question match but whose records don't decode (`wire::Reply::Broken`) is a server error
  and goes to `reject`; one whose records decode goes to `handle_response`, even a truncated
  one on a stream. There `NOERROR` with data finishes a query; `NXDOMAIN` and NODATA go to
  `search_on`, which tries the next candidate and finishes the query once none is left;
  every other code and an empty `NOERROR` without AA and RA (`wire::is_referral`) go to
  `reject`.
- How a query moves on is spread over several functions with different accounting: `retry`
  (no answer: next server, uses an attempt, marks the server failed for new queries),
  `reject` (error answer: excludes the server for this search candidate, then the same),
  both through `advance`, which gives up once out of attempts or servers; `switch_to_tcp`
  and `drop_edns` (same server, free), the resends in `move_off` (same server, free every time
  if the connection answered after the query was written, else once per query via
  `use_free_resend`) and `time_out_stream` (once, via the same `use_free_resend`),
  `next_candidate` (next search name, fresh attempts, no exclusions), `give_up` and
  `finish`. `emit` counts every send in `Pending::sends`: a search candidate goes at most
  three times to a server over one transport (RFC 9520 §3.1), so `advance` skips servers
  without room (in `try_advance`), and the free sends, a cancel hand-over's resend included,
  check `Pending::may_send` first (`cancel` directly, the others through `may_resend`) and
  move on instead. Only `emit` sets a query's deadline (`Config::deadline`; `new_pending`
  leaves a placeholder): every caller passes `Deadline::Fresh` except `time_out_stream`'s
  free resend, which passes `Deadline::Kept`. The crate docs' "How a query moves on" table
  states the rules (at most `attempts + 3` sends per search candidate, not counting a cancel
  hand-over's resend or the resends after a lost connection that answered since, and at most
  three per server and transport, all of those included), and a comment above `retry` maps
  each row to its function: change these functions together and keep the table in sync.
- Every wait is bounded (RFC 1123 §6.1.3.3): `Config::wait` keeps a deadline between 1 s
  and 300 s after backoff, and `Config::failed_for` caps the failure memory at 5
  minutes (RFC 9520 §3.2). Deadlines are plain `Instant`s; nothing waits forever.
- A query for the same name (as given) and type as a pending one joins it as a
  follower (`Pending::followers`) and gets its outcome, failures included however late it
  joined; `cancel(id, now)` hands a query with followers to the first of them, re-sending a
  UDP attempt from the follower's own socket. An heir with no room left moves on by
  `try_advance` (`advance` without `give_up`), and with no server left fails without caching
  the `Timeout`: the server may have answered the cancelled queries' sockets.
- `src/cache.rs` caches resolution failures (RFC 9520 §3.2) and negative answers (RFC 2308
  §5) in a `BTreeMap` keyed by the question as sent: the lowercased absolute candidate, the
  class, and the type, or `None` for an NXDOMAIN, which holds for every type. `Entry` is
  `Negative(Stored)` or `Failed(Failure)`; a positive answer would be one more variant like
  `Negative`. It reads time only from `now`, so `poll_timeout` doesn't change: an expired
  negative entry is dropped on lookup, an expired failure stays for the backoff (until its
  `forget`, which `Cache::failed` compares with `Pending::started`), and the
  `Config::cache_entries` bound drops expired entries first, then the oldest by `serial`. Lookups: `start` and `search_on` run `walk` over the search
  candidates before joining or sending (a cached NXDOMAIN or NODATA goes into the `Outcome`
  and moves on, a cached failure ends the search), and `emit` refuses to send a question
  with a cached failure, failing the query instead. Stores: `give_up` (every failure,
  `Cache::failed`, with the backoff judged by `Pending::started`), and `handle_response`
  (`Cache::answered` for data, `Cache::negative` for NXDOMAIN and NODATA, which also ends a
  failure's backoff; error codes and referrals don't). `flush_cache` also clears `Resolver::failed`.
- Some names are answered without a transmit, in this order: `localhost.`, `invalid.` and
  `onion.` names as given (`wire::is_special_use`), then `Config::hosts` entries as given,
  then names under `local.` and the link-local reverse zones (RFC 6762 §22.1) unless they are
  under a search domain below one of those zones or under `Config::unicast_local_zones`
  (`Config::never_sent`, which filters every search candidate, the name as given included;
  `Config::never_sent_as_given` answers a relative name locally only when no candidate is
  left, since RFC 6762 §3 judges the name actually queried). `IpLookup`
  (`src/lookup.rs`) walks the search candidates itself: per candidate it starts an A and an
  AAAA query for the absolute name (`Resolver::query_candidate`, which skips `Config::hosts`;
  the lookup checks the name as given with `Resolver::is_local` first, and the cache applies
  as for any query), merges the addresses from the events it is fed, and moves on when
  neither has one, so `handle_event` takes the resolver. `addresses` follows the CNAME chain, stops at a special-use name, keeps only the
  question's type and class, and reports a loop as `Error::CnameLoop`.
- The Tokio driver's `lookup_ip` turns a host into a `Name` itself (`host_name`): UTS 46 over
  the whole name for non-ASCII input (the `idna` crate), A-label checks for ASCII input, which
  is otherwise used as given, and RFC 1123 §2.1 rejections of empty and numeric hosts.
- Driver obligations (also in the README): bind a fresh UDP socket per query (RFC 5452 §9.2),
  connected to its server, with a new one for each server (§9.1), and pass that query with
  each datagram; report a failed bind, connect, send or receive (ICMP errors) with
  `handle_udp_error`, a stream that the server closed with `handle_stream_closed` and an I/O
  failure with `handle_stream_error`; receive datagrams into a buffer that holds any (65535
  bytes), since a server may send more than the 1232 the queries advertise; write each stream
  payload in one call, with `TCP_NODELAY` set (RFC 7766 §8, §6.2.1.1), and carry out a
  `TcpClose` only after the writes before it, which over TLS end with the close_notify alert
  (a connection still connecting may be dropped at once). After reporting a stream closed,
  still write what was queued for it before the report (the reply to the server's
  close_notify), and call `shutdown` and carry out its transmits before stopping. Call
  `flush_cache` when the host's network changes.

`sansio-dns-tokio` runs one background task per `Resolver` (shared by its clones), spawned on
the runtime of the first lookup. It owns the core resolver and all I/O: a UDP socket per query
and server, connected to it, with a task forwarding datagrams (received into one 65535-byte
buffer per socket) and receive errors, and a task per stream connection. `from_system_conf`
reads `/etc/resolv.conf`, `/etc/hosts`, `LOCALDOMAIN`, `RES_OPTIONS` and the host name
(`uname` through rustix) and hands them to `Config::from_resolv_conf_with_env`. A `TcpClose`
drops the connection's write queue, so its task writes what is queued (the close_notify over
TLS), shuts the stream down and reads until the server closes, aborted after `CLOSE_GRACE`
(5 s) at the latest; a connection still connecting is aborted at once. A task whose server
closed the connection reports it and keeps writing until its queue is dropped, which
`Io::drop_ended` does only after the transmits queued before the report are carried out.
When the last clone is dropped, the task calls `shutdown`, carries out its transmits and
gives the connections `CLOSE_GRACE` to finish.
Lookups send a request over a channel with a `oneshot` reply; `CancelOnDrop` cancels a lookup
whose future is dropped, and `Resolver::flush_cache` sends a request that empties the core's
cache. If the task's runtime shuts down, the next lookup (or a waiting one)
restarts it on its own runtime.
A resolver shared with an idle current-thread runtime can hang lookups from other runtimes;
that limitation is documented, not handled.

## Tests

`tests/rfc<number>.rs` mostly hold one module per RFC section (the README lists the
exceptions), and the README's spec coverage table lists the behaviour each section pins: keep
the table in sync when behaviour changes.
`tests/common/mod.rs` has the fixtures (a resolver with servers `S1`, `S2`, and helpers to
start a query, build replies, frame and encode them; `start_distinct` for queries that must
not coalesce; `reply` answers as a recursive server does, with RA set, so an empty answer is
NODATA rather than a referral; `no_data`, `referral`, `with_soa` and `cut` make NODATA,
referrals, negative answers and undecodable replies) and
`Trace`, which drives a resolver and renders each input, its events, its transmits and the
next deadline as text (`answer_bytes` sends raw message bytes, framed on a stream, and
`stream_bytes` unframed bytes on a connection; a response shows `AA` and `no RA` when they
differ from a recursive server's). Tests of a query's lifecycle assert that text as an
insta inline snapshot (`assert_snapshot!(trace, @"...")`): after a deliberate behaviour change,
run `cargo insta test --review` (or `--accept`) and read every changed snapshot against the
crate docs' lifecycle table before accepting it. `Trace` decodes plaintext DNS only, so the
DoT lifecycle tests in `tests/rfc7858.rs` (`tls` feature) use their in-process rustls server
and plain assertions; `sansio-dns-tokio/tests/tls.rs` runs a rustls server on localhost to
check how the driver's DoT connections end. `tests/state_machine.rs` is a proptest-state-machine test: random
driver-call sequences against a reference model, with invariants checked after every step and
failures shrunk to short call sequences. Its harness also models the cache from the outcomes
it sees (nothing sent for a name within a second of its failure or while its negative answer
lasts, cached outcomes delivered at once with the SOA TTL counted down, a name with nothing
cached sent). Of the deadlines it only checks that there is one exactly when queries are
pending or connections are open, and that it is in the future; the snapshots pin their
values. `tests/rfc2308.rs` and `rfc9520.rs`'s §3.2 module hold the cache lifecycles.

## Conventions

- Workspace lints are strict: clippy denies `unwrap`, `expect`, indexing, `panic` and more, and
  `allow_attributes`, so use `#[expect(..., reason = "...")]` instead of `#[allow]`.
- Dependency versions are pinned to the major version only (`tokio = "1"`, `rustls = "0.23"`);
  `Cargo.lock` holds the exact ones.
- Error types derive `thiserror::Error`; the core's `Error` stays `Clone + Eq` plain data.
