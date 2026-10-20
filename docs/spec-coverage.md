# Spec coverage

Behavior follows the RFCs as listed and annotated at
[rfc-annotations.research.icann.org](https://rfc-annotations.research.icann.org/). Each row
names the behavior a test pins; [testing.md](testing.md) says where the tests live.

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
| 9520 | §3.2 | Every failure (§2: timeouts, network and TLS errors, error codes, replies that don't decode) is cached for the question, and so are referrals, which §2 counts as useful but a stub can't follow: nothing is sent for it, and queries for it, the ones that joined it and ones in flight that would send it again fail at once with the cached error. 1 s the first time (`FailureCache::shortest`, at least 1 s), twice as long when a query first sent soon after the last one expired fails too, up to `FailureCache::longest` (30 s, at most 5 minutes); a useful answer (data, NXDOMAIN or NODATA) resets the backoff. A cancel hand-over that runs out of servers fails with `Timeout` uncached, since the server may have answered the cancelled queries' sockets. At most `cache_entries` (1024) entries, expired ones dropped first, then the oldest; `flush_cache` empties it. Separately, a server that failed to answer goes after the others for at most 5 minutes (`failure_memory`, 60 s by default), kept per server address (RFC 2308 §7.2 caps it too) |
