# sansio-dns

[![crates.io](https://img.shields.io/crates/v/sansio-dns.svg)](https://crates.io/crates/sansio-dns)
[![docs.rs](https://docs.rs/sansio-dns/badge.svg)](https://docs.rs/sansio-dns)

> [!WARNING]
> This is an experiment: me trying out sans-IO and the DNS RFCs. It is incomplete and
> probably incorrect in places, so don't rely on it for anything that matters.

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

Complete drivers are in `examples/` (`std`, `tokio`, `compio`), about 150 lines each including TCP.

For hostnames, `Resolver::lookup_ip` runs the A and AAAA queries and merges the addresses,
following CNAMEs. `Config::ip_strategy` picks the families and their order: IPv6 first by
default, or IPv4 first, or only one family. IPv6 comes first even on a host without a global
IPv6 address, such as a container with only a ULA, where `getaddrinfo` puts IPv4 first (RFC
6724 §6): there, race the connections (Happy Eyeballs, RFC 8305), as hyper does, or use
`IpStrategy::Ipv4First`. The resolver runs the lookup itself, the next search candidate's
queries included: send the transmits as usual, and its outcome comes out of `poll_lookup`. Its
queries still end with events of their own, so the driver can close their sockets.

```rust
let lookup = resolver.lookup_ip(Name::from_ascii("example.com")?, now)?;
// in the event loop, after draining poll_transmit and poll_event:
while let Some((id, result)) = resolver.poll_lookup() {
    /* id == lookup: Ok(addresses) or Err(error) */
}
```

`addresses(&message)` does the CNAME-following part for any single response, and reports a
CNAME loop as `Error::CnameLoop`.

A query for the same name and type as one already in flight joins it instead of being sent,
and gets the same outcome as its own event, however late it joined, so parallel lookups of one
host share their queries. Cancelling the first hands the query to the next.

Failures and negative answers are cached by question: name, type and class (RFC 9520 §3.2,
RFC 2308 §5). A question that no server answered usefully isn't sent again for
`Config::failure_cache_min` (1 s by default, never less), and twice as long each time it fails
again soon after, up to `Config::failure_cache_max` (30 s, at most 5 minutes); queries for it
fail at once with the cached error. NXDOMAIN, for every type of the name, and NODATA, for its
type, are cached when the authority section has an SOA record, for the lesser of its TTL and
MINIMUM, at most `Config::max_negative_ttl` (1 hour), and answered from the cache with their
TTLs counted down; a search moves past such a candidate without sending it. The cache holds
`Config::cache_entries` (1024) entries and needs no timer. Answers with data aren't cached.
Call `Resolver::flush_cache()` when the host's network changes.

### Tokio and reqwest

[`sansio-dns-tokio`](https://crates.io/crates/sansio-dns-tokio)
([docs](https://docs.rs/sansio-dns-tokio)) is a ready-made driver: `lookup_ip(host)` runs
the core's `Resolver::lookup_ip` on a background task shared by all clones of the resolver. Each
UDP query gets its own socket, connected to its server, and TCP or TLS connections stay open
between lookups until they go idle; when the last clone is dropped, it closes them, over TLS
after close_notify. Its `flush_cache()` empties the cache, for a network change. Its `tls`
feature turns on DNS over TLS in `sansio-dns`. With its `reqwest` feature, it plugs into
reqwest as the DNS resolver:

```rust
let client = reqwest::Client::builder()
    .dns_resolver(sansio_dns_tokio::Resolver::from_system_conf()?)
    .build()?;
```

`cargo run -p sansio-dns-tokio --features reqwest --example get -- https://example.com` is a
small HTTP client built this way.

### DNS over TLS

With the `tls` feature, `Config::with_tls(client, server_name)` sends every query over TLS
(RFC 7858) and authenticates the servers as `server_name` (RFC 8310 strict profile).
`Config::with_tls_names(client, names)` gives each server its own name, so servers of
different operators can be mixed (RFC 8310 §7.1). Servers on port 53 are refused: DNS over TLS
uses port 853 or another agreed port, never 53 (RFC 7858 §3.1). Queries are padded to a multiple
of 128 octets (RFC 8467) and carry an EDNS Client Subnet option with source prefix length 0, which
asks the server not to pass the client's address on (RFC 8310 §11.1, RFC 7871).

The crate brings rustls without a crypto provider or root store: build the `ClientConfig` with
the ones you want. For the strict profile, keep rustls' default WebPKI verifier (a custom
verifier that accepts more gives the profile up), TLS 1.3, session resumption and SNI, and set
`alpn_protocols` to `[b"dot"]`, the ALPN identifier IANA registered for DNS over TLS (RFC 9325
§3.8). A `ServerName::IpAddress` is matched against the certificate's IP addresses, which is not
one of RFC 8310's authentication mechanisms. `examples/dot.rs` uses ring and the webpki roots:

```sh
cargo run --example dot --features tls -- example.com 1.1.1.1:853 cloudflare-dns.com
```

### Configuration

`Config::hosts = Hosts::parse(&bytes)` adds static entries from a hosts file (you read the
file). Listed names are answered locally for A and AAAA, with the addresses of that family,
before any DNS query, as glibc's `hosts: files dns` does.

Names under `localhost.`, `invalid.` and `onion.` are always answered locally (RFC 6761, RFC
7686). Names under `local.` and the link-local reverse zones belong to multicast DNS (RFC 6762),
so they get NXDOMAIN without a query unless the name servers serve them: names under a search
domain that is itself under one of these zones, such as Kubernetes' `cluster.local`, or under
a zone in `Config::unicast_local_zones`, go to the servers. The rule applies to each search
candidate (RFC 6762 §3), so with search domain `cluster.local` the relative `db.local` is
sent as `db.local.cluster.local`. mDNS itself is up to the caller.

`Config::from_resolv_conf(&bytes)` reads the text of a `resolv.conf` (you read the file) the way
glibc's `res_init` does, skipping lines it can't use instead of failing. A keyword counts only
at the start of a line, so indented lines are ignored. It takes the first three nameservers,
IPv4 ones in any form `inet_aton` reads (`127.1` is 127.0.0.1), with `0.0.0.0` and `::` asking
the local host; `search` or `domain`; and the options `ndots`, `timeout`, `attempts`,
`no-aaaa` and `no-tld-query` (also spelled `no_tld_query`), each known by how it starts, with
its number read as `strtol` reads it. Unlike glibc, it takes at most 3 attempts per server
instead of 5, since RFC 9520 §3.1 allows no more than three sends of a query to one server
over one transport, reads `#` and `;` as starting a comment anywhere on a line, and takes CRLF
line ends.

`Config::from_resolv_conf_with_env(&bytes, &env)` also applies what glibc reads from the
environment and the host: `LOCALDOMAIN` replaces the search domains, `RES_OPTIONS` adds options
after the file's, and without a search list or `LOCALDOMAIN`, the host name's domain (the part
after its first dot) is the search domain. sansio-dns-tokio's `from_system_conf` fills these in.

`options no-aaaa` asks for IPv4 addresses only. With search domains, a name without a trailing
dot is tried with each of them, before the name as given if it has fewer than `ndots` dots and
after it otherwise. `options no-tld-query` (`Config::tld_query`) leaves out a name of one label
as given, so with search domains `db` never asks for a top-level domain. For `Resolver::query`
the search moves on after NXDOMAIN and after NODATA (the name exists without records of the
type and class asked for at the end of its CNAME chain), until a candidate has data (RFC 1123
§6.1.4.3, RFC 2308 §2.2); when it runs out the outcome is the first NODATA, else the last
NXDOMAIN. glibc moves on after NODATA only when the answer section is empty, so it stops at a
CNAME whose target has no data. A failure on a candidate, such as SERVFAIL or REFUSED, ends the
search with that error, as musl does, so that a temporary failure for the name meant doesn't
turn into an answer for another name. glibc goes on to the search domains after any failure on
the name as given when that comes first; among the search domains it moves on only after
SERVFAIL, and after another failure it stops and still tries the name as given if that comes
last, unless no server could be reached at all. `Resolver::lookup_ip` asks each candidate for
both families and moves on when neither has an address, as glibc's `getaddrinfo` does, so its
addresses are always those of one name.

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
| Heap allocations per UDP lookup, incl. 18 by the test server | 67 | 145 |
| Stripped binary size over reqwest's default resolver | +0.58 MB | +1.44 MB |

On localhost the times are mostly task wakeups; on a real network the round trip to the
server dominates. With its cache on, hickory answers a repeated lookup in about 1 µs, and
sansio-dns caches no answers with data yet.

Where the two behave differently:

| | sansio-dns | hickory-resolver |
|---|---|---|
| Runtime | Sans-IO core for any runtime, plus a Tokio driver | Tokio; its `RuntimeProvider` needs `Send + Sync` |
| EDNS | Always on at 1232 bytes, dropped once on `FORMERR` | From the system config only with `options edns0` |
| Truncated answer over TCP | Used as it is | The lookup fails |
| Hosts entry with only an IPv4 address | Empty AAAA answer, as glibc does | AAAA asked from DNS |
| Address families | Both, IPv6 first, by default; or IPv4 first, or one family | The same, plus asking for the second family only when the first has no address |
| Names with `_` | Resolved | Rejected |
| Non-ASCII names | UTS 46 over the whole name, as browsers do: `bücher。example` asks for `xn--bcher-kva.example` | Converted label by label, so `。` ends up inside a label |
| `local.` names | NXDOMAIN without a query, unless under a search domain such as `cluster.local` or a configured zone | Sent to the name servers |
| Cache | Failures (1 s, backing off to 30 s) and negative answers, 1024 entries | Positive and negative, 8192 entries |
| Server order | As configured; one that failed to answer goes after the others for a minute | By measured latency, two servers raced |
| Transports | UDP, TCP, DoT | Also DoH, DoH3, DoQ and DNSSEC validation |
| System configuration | `resolv.conf` as glibc reads it, `LOCALDOMAIN`, `RES_OPTIONS`, the host name's domain, and hosts | Also Windows, and macOS through SystemConfiguration; no `LOCALDOMAIN` or `RES_OPTIONS` |
| Tokio lookups | `lookup_ip` | Any record type, reverse lookups, typed helpers |

## Spec coverage

Behavior follows the RFCs as listed and annotated at
[rfc-annotations.research.icann.org](https://rfc-annotations.research.icann.org/).
Tests mostly live in `tests/rfc<number>.rs`, with one module per section. The exceptions:
RFC 1034 is in `tests/lookup.rs`, except §4.3.1, which is tested with the RA bit and RFC 2308
§2.2's authority-section rule in `rfc1035.rs`'s §4.1.1 module, which also has the extended
RCODEs of RFC 6891 §6.1.3 and RFC 7873 §5.3; `tests/lookup.rs` also has RFC 3596 §2.3,
CNAME chains into special-use names and RFC 6762 §22.1 for `Resolver::lookup_ip`; RFC 2308
§2.2's NODATA and RFC 1035 §7.4's records of another class are in `rfc1123.rs`'s §6.1.4.3
module, and RFC 6895, 8482 and 9824 in its §6.1.3.2 module; RFC 2308 §7.2's cap is in
`rfc9520.rs`'s §3.2 module; RFC 1123 §6.1.3.3 (3) and (4) are covered by the tests of RFC 9520
§3.2 and RFC 2308 §5, RFC 2308 §8 by `rfc2308.rs`'s §5 and §6 modules, and RFC 4343 §3 for
cache keys by both; RFC 1123 §6.1.4.3 (b)'s `no-tld-query` is in `resolv_conf.rs`'s `search`
and `options` modules, and that file also has RFC 1122 §3.2.1.3's unspecified address as a
name server; `rfc6761.rs` has RFC 7686 in its §6.4 module, RFC 6762 in its
`rfc6762_section_22_1` module, and RFC 6761 §6.1, §6.2, §6.5, RFC 8375 and RFC 9476 in its
`not_special_to_resolvers` module;
`rfc7858.rs` holds the RFC 7858, 8310, 8467, 7830, 7871 and 8446 tests as plain functions,
without section modules; and `rfc7766.rs` also has a `stream_timeout` module for queries that
time out on a connection. `tests/main.rs` builds them all as one crate. The Tokio driver's
`sansio-dns-tokio/tests/tls.rs` checks that its DNS over TLS connections end with close_notify (RFC 8446
§6.1), when the server closes first and when the resolver is dropped, and
`sansio-dns-tokio/tests/lookup.rs` has the host name rules of `lookup_ip` (RFC 1123 §2.1, RFC
4343 §4, RFC 5891), and `sansio-dns-tokio/tests/system_conf.rs` checks that
`from_system_conf` applies `LOCALDOMAIN` and `RES_OPTIONS`.

| RFC | Section | Behavior |
|---|---|---|
| 1035 | §2.3.3 | Question names are compared case-insensitively |
| 1035 | §3.1 | Names are absolute: without search domains, `example.com` and `example.com.` ask the same question |
| 1035 | §4.1.1 | `RD` set; only `NOERROR` and `NXDOMAIN` answer the question; every other code fails over, the codes 6 to 15 and extended ones included |
| 1035 | §4.2.1 | `TC` set → retry over TCP (RFC 1123 §6.1.3.2) |
| 1035 | §7.2 | Retransmit on timeout, or at once when the datagram can't be sent, rotating through servers; new queries start after a server that recently failed to answer |
| 1035 | §7.2 | A server that answers with an error code, a reply that doesn't decode or an empty answer without AA or RA is removed from the query's list until the next search candidate; once every server is removed, the query fails with the last error |
| 1035 | §7.3 | Non-responses (`QR=0`) and wrong opcodes are discarded; a matching reply whose records don't decode moves on to the next server at once |
| 1034 | §4.3.1 | An empty `NOERROR` answer with neither AA nor RA, from a server that doesn't recurse and isn't authoritative (such as a referral), fails over (`Error::NoRecursion` on the last), as glibc does; with AA or RA it is NODATA |
| 1123 | §6.1.3.2 | Zone transfer and meta query types (AXFR, IXFR, OPT, TSIG, TKEY, MAILA, MAILB, NXNAME, TYPE 0; RFC 6895 §3.1, RFC 9824 §3.5) are rejected by `query`; ANY is allowed (RFC 8482) |
| 1123 | §6.1.3.3 | Retries back off exponentially: each round through the servers waits twice as long, starting at 5 s by default. Each wait lasts at least 1 s and at most 300 s, above the 240 s (twice TCP's maximum segment lifetime) that any limit must exceed, so every query gives up in finite time |
| 1123 | §6.1.3.3 (3) | Temporary failures are cached (RFC 9520 §3.2 below): 1 s at first and up to 30 s by default, configurable up to 5 minutes; (3) suggests minutes |
| 1123 | §6.1.3.3 (4) | Negative answers are cached (RFC 2308 §5 below) |
| 1123 | §6.1.4.3 | Search candidates are tried until one has data of the type and class asked for: NXDOMAIN and NODATA (RFC 2308 §2.2) move on; then the first NODATA is the outcome, else the last NXDOMAIN; a failure ends the search. `Resolver::lookup_ip` asks each candidate for A and AAAA and moves on when neither has an address, so both families come from the same name (§6.1.4.3 (b)) |
| 1123 | §6.1.4.3 (a) | A candidate with a cached NXDOMAIN or NODATA is passed over without a query, and one with a cached failure ends the search, for `Resolver::query` and `Resolver::lookup_ip` alike |
| 1123 | §6.1.4.3 (b) | `options no-tld-query` or `no_tld_query` (`Config::tld_query`) keeps a name of one label from being sent as given when there are search domains, as glibc does: a weaker rule than (b)'s two interior dots |
| 2308 | §5 | NXDOMAIN is cached for every type of the name, NODATA for its type, under the last name of the CNAME chain (§1, §2.1), when the authority section has an SOA record, for the lesser of its TTL and MINIMUM, at most `max_negative_ttl` (1 hour). Not cached: an answer without an SOA, a truncated one (RFC 1123 §6.1.3.2), one with a zero TTL (RFC 1123 §6.1.2.1), a looping chain. RFC 8020's NXDOMAIN cut isn't applied |
| 2308 | §6 | An answer from the cache asks the question asked and has the authority section as received, every TTL counted down by the whole seconds it was cached, AA clear and no OPT record (RFC 6891 §6.2.1) |
| 2308 | §7 | No single server's failure is cached for a question: a server that answered with an error is asked first again by the next query; one that didn't answer goes after the others for `failure_memory`, at most 5 minutes (§7.2) |
| 2308 | §8 | Since failures are cached, so are negative answers, with their SOA record, which is returned with them |
| 4343 | §3 | The cache compares names without regard to ASCII case |
| 2181 | §8 | TTLs with the most significant bit set are passed on as zero |
| 2181 | §9 | A truncated UDP reply switches to TCP even when it is cut off mid-record and doesn't decode; over TCP a truncated reply is used as it is |
| 3597 | §3 | Records of unknown type are kept as opaque data. hickory rejects a message with an empty-RDATA record outside UPDATE, although `\# 0` is valid; such a reply moves on to the next server at once |
| 5452 | §9.1 | Datagrams must match source address, port, ID, QNAME, QTYPE and QCLASS, also when their records don't decode; the driver's socket per query, connected to the server, checks destination address and port. On a stream, a response without a question section matches by ID alone (RFC 7766 §7) |
| 5452 | §4.6 | The first answer that ends the query wins, and later copies are ignored. A copy of an error answer counts again while the query is still on that server: after a `FORMERR` without OPT made it drop EDNS, a second copy counts as the answer to the query without EDNS |
| 5452 | §9.2 | IDs from a CSPRNG, avoiding those of outstanding queries, cancelled ones still outstanding on a connection included (16 random picks, then the next free ID); per-query source ports are the driver's job (see below) |
| 1122 | §3.2.1.3 | A name server at the unspecified address, `0.0.0.0` or `::`, which no datagram may be sent to (RFC 4291 §2.5.2), is asked at the loopback address on its port, as Linux does for glibc, so its replies pass the source check |
| 6891 | §6.1.3 | BADVERS fails over like any server error: version 0 is the lowest there is |
| 6891 | §6.2.3 | One OPT record, 1232-byte payload (DNS Flag Day 2020); a larger UDP answer that arrives whole is used |
| 6891 | §7, §6.2.2 | `FORMERR` without OPT → same server once more without EDNS (over TLS: fail over, since EDNS carries the padding); with OPT → fail over |
| 7873 | §5.3 | No cookie is sent, so BADCOOKIE is a server error and fails over |
| 7766 | §5 | An open connection to a server carries every query to it, new ones and retries included; a query on it only for that goes back to UDP once it is gone. TCP is supported: a truncated UDP response sends the query to the same server over TCP, and its later attempts stay on TCP (RFC 1123 §6.1.3.2); UDP replies are then ignored |
| 7766 | §6.2.1 | Connections reused and pipelined; no two queries outstanding on one share a message ID: a query cancelled or timed out there keeps its ID until its answer comes or the connection ends, and a later attempt on that connection waits for that answer instead of writing the ID again. A connection holding 256 such requests is closed when another would join them (§6.2.4 lets either end close under unusual conditions), which frees their IDs |
| 7766 | §6.2.2 | At most one connection per server; when it fails, the queries on it that must use a stream share one new connection |
| 7766 | §6.2.3 | Idle connections closed after `idle_timeout`, counted from the last write or complete response, or from the deadline of a query that left the connection before its answer came (cancelled, or moved on after a timeout); partial messages don't count |
| 7766 | §6.2.4 | Queries on a lost connection that had answered go to the same server again without using an attempt: every time if it answered after they were written, else once per query |
| 7766 | §7 | Answers matched in any order, by message ID and question, or by ID alone without a question section; a query that times out closes the connection only if no complete response, matched or not, arrived on it since the query was written |
| 7766 | §8 | Two-byte length prefix; replies reassembled from any chunking, up to 65535 octets |
| 1034 | §3.6.2, §5.2.2 | `addresses` follows the CNAME chain and ignores records owned by other names; a loop is `Error::CnameLoop`, also for `Resolver::lookup_ip` |
| 3596 | §2.3 | `addresses` takes only records of the type and class asked for at the end of the chain: no A record in an AAAA answer (RFC 1035 §7.4). Records of another class don't count as data for the search either, so an answer with only those is NODATA |
| 1123 | §2.1 | The Tokio driver's `lookup_ip` takes labels that start with a digit and names of up to 255 octets. It rejects empty names, one to four dotted numbers that aren't an IP address (`127.1`, `01.2.3.4`, `0x7f.0.0.1`, `1.2.3.256`), absolute names whose last label is all digits, and names with a `\` (which would be read as an escape) instead of looking them up. Relative names like `host.123` or `1.2.3.4.5` are looked up, since a search domain may complete them |
| 4343 | §4 | The Tokio driver's `lookup_ip` sends an ASCII name in the case given |
| 5891 | §5.3, §5.4 | The Tokio driver's `lookup_ip` converts a non-ASCII name with UTS 46 non-transitional processing over the whole name, as browsers do (`bücher。example` is two labels), rejects `--` in the third and fourth positions of a U-label, and checks `xn--` labels in ASCII names. UTS 46 accepts some code points that IDNA2008 marks DISALLOWED, such as `☃`, which §5.4 asks to reject |
| 6761 | §6.1, §6.2, §6.5 | Private reverse zones, `test.` and `example.` are sent like any other name |
| 6761 | §6.3 | `localhost` names → loopback for A/AAAA, empty answer otherwise, whatever the hosts file says; nothing sent, and relative ones aren't searched. A CNAME chain that reaches one gives loopback |
| 6761 | §6.4 | `invalid.` → NXDOMAIN; nothing sent, and relative ones aren't searched |
| 6762 | §22.1 | Names under `local.`, `254.169.in-addr.arpa.` and `8.e.f` to `b.e.f.ip6.arpa.` (§3, §4) are not sent to the name servers (item 3) and get NXDOMAIN (item 4), after the hosts file, unless they are under a search domain that is under one of these zones (Kubernetes' `cluster.local`, an Active Directory `corp.local`) or under `Config::unicast_local_zones`. The rule applies to each search candidate, the name as given among them (§3), so a relative name gets NXDOMAIN at once only when none of its candidates is sent. mDNS itself is up to the caller |
| 7686 | §2 | `onion.` → NXDOMAIN, whatever the hosts file says; nothing sent, and relative ones aren't searched |
| 8375 | §4 | `home.arpa.` names are sent like any other |
| 9476 | §3.2 | `alt.` names are sent like any other |
| 7858 | §3 | With `tls`: every query over TLS on a stream, never UDP; TLS errors fail the attempt |
| 7858 | §3.1 | Servers on port 53 are refused |
| 7858 | §3.3 | Queries written during the handshake wait for it in the resolver, any number of them, and go out whole after it; replies of any size come through the session in any chunking; an answer that arrived intact counts even when a record after it in the same read doesn't decrypt or is an alert from the server that rustls reports as the error |
| 7858 | §3.4 | The TLS session is reused for later queries, and resumed on a new connection; the server's close_notify closes the connection and its queries go to a new one, as after any close, and so does a query that an answer arriving with the close_notify moves on to the same server |
| 8446 | §6.1 | Every connection the resolver closes gets close_notify first, written by the driver before it closes, unless an error alert, the resolver's or the server's, already ended the session (§6.2); `shutdown` closes them all this way when the driver stops, and the server's close_notify is answered with the resolver's own |
| 8446 | §6.2 | On a TLS error the resolver detects, such as a bad certificate or a record that doesn't decrypt, the alert rustls queued is sent before the connection closes; after an alert from the server that rustls reports as the error (`AlertReceived`), taken for an error alert (§6), nothing is sent, not even close_notify, and the connection closes at once |
| 8310 | §5, §8.1 | Strict profile: the certificate must chain to a trusted root and match the configured name (with the default WebPKI verifier) |
| 8310 | §7.1 | One authentication name per server (`with_tls_names`) |
| 8310 | §11.1 | Queries over TLS carry an EDNS Client Subnet option with SOURCE PREFIX-LENGTH 0, FAMILY that of the transport (RFC 7871 §7.1.2) |
| 8467 | §4.1 | Queries padded to a multiple of 128 octets, the padding option last (§3) |
| 7830 | §3, §6 | One padding option per query, and none on UDP or TCP without TLS |
| 9520 | §3.1 | A search candidate is sent at most three times to each server over each transport (UDP, and TCP or TLS), free resends and cancel hand-overs included; a send that would be the fourth goes to the next server as a new attempt, and the query fails when no server is left. `resolv.conf` attempts are capped at 3 per server |
| 9520 | §3.2 | Every failure (§2: timeouts, network and TLS errors, error codes, replies that don't decode) is cached for the question, and so are referrals, which §2 counts as useful but a stub can't follow: nothing is sent for it, and queries for it, the ones that joined it and ones in flight that would send it again fail at once with the cached error. 1 s the first time (`failure_cache_min`, at least 1 s), twice as long when a query first sent soon after the last one expired fails too, up to `failure_cache_max` (30 s, at most 5 minutes); a useful answer (data, NXDOMAIN or NODATA) resets the backoff. A cancel hand-over that runs out of servers fails with `Timeout` uncached, since the server may have answered the cancelled queries' sockets. At most `cache_entries` (1024) entries, expired ones dropped first, then the oldest; `flush_cache` empties it. Separately, a server that failed to answer goes after the others for at most 5 minutes (`failure_memory`, 60 s by default), kept per server address (RFC 2308 §7.2 caps it too) |

### Driver obligations

RFC 5452 §9.2 requires an unpredictable source port per outstanding query, and §9.1 a reply's
destination address and port to match the query's source. A sans-IO core can't pick ports or
see where a datagram was sent to, so `Transport::Udp(query)` names the query: bind a fresh
ephemeral socket per query, connect it to the destination (a new socket when the query moves
to another server), and pass that query along with each datagram the socket receives to
`handle_datagram`. The kernel then delivers only datagrams from that server to that address
and port.

Stream connections are named by a `ConnectionId`: `TcpConnect(id)` means open a connection
to the destination and write the payload, `TcpWrite(id)` write to it, `TcpClose(id)` close
it once the writes before it are done. With TLS the last of them carries the close_notify
alert, which must reach the server before the close (RFC 8446 §6.1), or, after a TLS error,
the alert rustls queued for it instead, if it queued one (§6.2). After an alert from the
server that rustls reports as the error (`rustls::Error::AlertReceived`) there is none, as
after an error alert (§6). A connection still connecting when its `TcpClose` comes can be
dropped at once, since nothing written to it has gone out. Payloads are already
length-prefixed or TLS-encrypted: write each in one call (RFC 7766 §8), and disable Nagle's
algorithm (`TCP_NODELAY`) so pipelined queries go out at once (§6.2.1.1). Pass everything
read to `handle_stream_data(id, …)`. Call
`handle_stream_closed(id, …)` if the server closes the connection, and
`handle_stream_error(id, kind, …)` if connecting, reading or writing fails, so a query out of
attempts fails with that error. The resolver keeps one connection per server and pipelines
queries over it; it closes the connection after `Config::idle_timeout` (10 s) without
queries, when a query on it times out with no response since it was written, when 256
requests on it went unanswered, or, with `tls`, when TLS rejects bytes received on it or a
write to it, or the server sent close_notify.

A `TcpWrite` can follow its `TcpConnect` before connecting has finished, so queue it. After
reporting a connection closed or failed, no transmit for it follows, `TcpClose` included, but
still carry out the ones queued before the report and then close it: over TLS they can hold
the resolver's reply to the server's close_notify, which a driver that reads the end of the
stream first must not drop. A report for a connection the resolver already closed is
ignored. A driver that stops calls `shutdown` and carries out its transmits before dropping
its connections, so every TLS session ends with close_notify. When binding,
connecting or sending on a query's socket fails, or receiving on it reports an error such as
an ICMP port unreachable (RFC 1122 §4.1.3.3), call `handle_udp_error(query, to, kind, …)`,
so the query moves on at once instead of waiting out its deadline. Not every refused datagram
draws an error: macOS rate-limits ICMP port unreachable messages, so a datagram refused soon
after another may get none, and its query waits out its deadline. An error doesn't end the
socket: keep receiving on it while the query's attempts go to that server, and bind a new one
when an attempt goes to another. Bind each socket in the destination's address family, pass
the source address as received (an IPv4 server seen as `::ffff:a.b.c.d` won't match), and
read datagrams into a buffer that holds any UDP datagram, 65535 bytes, not just the 1232 the
queries advertise: a server may send more, and the resolver uses such an answer. When the
host's network changes, call
`flush_cache()`: failures and negative answers from the old network shouldn't hold on the new
one.

### Not implemented

- Opportunistic (unauthenticated) TLS.
- SPKI pin sets (RFC 7858 §4.2) and raw public keys (RFC 8310 §9), and DANE authentication
  (RFC 8310 §8.2), which needs DNSSEC validation.
- EDNS TCP keepalive (RFC 7828) to negotiate the idle timeout with the server.
- DoH/DoQ.
- A cache of answers with data: only failures and negative answers are cached.
- DNS cookies (RFC 7873): queries carry no COOKIE option.
- `resolv.conf` options other than the ones above (`rotate`, `use-vc`, `sortlist`, …).
- Sorting addresses by the host's own ones (RFC 6724 §6); `Resolver::lookup_ip` lists them by
  family, in the server's order within each.
- Once EDNS is dropped for a query, it stays off for that query's remaining attempts,
  including other servers, until the search moves to the next candidate.
- Multicast DNS (RFC 6762) for `local.` names.
- Rejecting the code points that IDNA2008 marks DISALLOWED (RFC 5891 §5.4, RFC 5892):
  the Tokio driver's `lookup_ip` follows UTS 46, as browsers do, and accepts some of them,
  such as `☃`.
- IPv6 addresses with a zone (`fe80::1%eth0`, RFC 4007 §11) in the Tokio driver's
  `lookup_ip`.

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
queries and open connections, nothing sent for a question within a second of its failure, and
a timer exactly while something is pending; `datagram`, `stream` and `driver_ops` also bound
the sends per query and check that queries for one name never start over. `system_files`
checks the local answers for hosts, special-use and link-local names, the order of the search
candidates, `no-tld-query` included, the answer the search ends on, and that `LOCALDOMAIN`,
`RES_OPTIONS` and the host name apply as glibc applies them. `tls_stream` checks that every
query the server decrypts keeps EDNS, carries the Client Subnet privacy option for the
server's address family and then one padding option to a multiple of 128 octets, and is sent
at most `attempts + 3` times, and at most three times to one server, that every connection the
resolver closes ends its session with close_notify or an alert first, unless an alert from the
server that rustls reports as the error ended it (the server's own fatal alert, or one that raw
or tampered bytes may hold before the client has decrypted anything), and that the resolver
writes nothing to a connection once the server's fatal alert reached it. They need nightly:

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
