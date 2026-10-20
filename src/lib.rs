//! A sans-IO DNS stub resolver built on [`hickory_proto`].
//!
//! [`Resolver`] is a state machine. It owns no sockets, timers or tasks: every
//! call takes `now: Instant`, nothing blocks, and the caller (the driver) does
//! the I/O it asks for. So one resolver runs on blocking std, Tokio, compio or
//! an embedded event loop, and in tests without a network. [`sansio_dns_tokio`]
//! is a ready-made Tokio driver; use it if you just want addresses.
//!
//! [`sansio_dns_tokio`]: https://docs.rs/sansio-dns-tokio
//!
//! # Driving the resolver
//!
//! 1. Start a query with [`Resolver::query`] (any record type), or an address
//!    lookup with [`Resolver::lookup_ip`] (A and AAAA, merged).
//! 2. Send every [`Transmit`] from [`Resolver::poll_transmit`], over the
//!    [`Transport`] it names.
//! 3. Feed received datagrams to [`Resolver::handle_datagram`] and bytes read
//!    from stream connections to [`Resolver::handle_stream_data`]; report
//!    errors with [`Resolver::handle_udp_error`],
//!    [`Resolver::handle_stream_closed`] and [`Resolver::handle_stream_error`].
//! 4. Call [`Resolver::handle_timeout`] once the instant from
//!    [`Resolver::poll_timeout`] has passed.
//! 5. Collect outcomes from [`Resolver::poll_event`], and those of address
//!    lookups from [`Resolver::poll_lookup`].
//! 6. Before stopping, call [`Resolver::shutdown`] and send its transmits,
//!    which close the open connections.
//!
//! A blocking driver for one query over UDP, in full:
//!
//! ```no_run
//! use std::io::ErrorKind;
//! use std::net::UdpSocket;
//! use std::time::{Duration, Instant};
//!
//! use sansio_dns::hickory_proto::rr::{Name, RecordType};
//! use sansio_dns::{Config, Event, Resolver, Transport};
//!
//! fn main() -> Result<(), Box<dyn std::error::Error>> {
//!     let server = "1.1.1.1:53".parse()?;
//!     let mut resolver = Resolver::new(Config::new(server, []));
//!     let name = Name::from_ascii("example.com")?;
//!     let query = resolver.query(name, RecordType::A, Instant::now())?;
//!
//!     // A fresh socket per query, connected to its server (RFC 5452 §9), and a
//!     // buffer that holds any datagram: a server may send more than the 1232
//!     // bytes the query asks for.
//!     let socket = UdpSocket::bind("0.0.0.0:0")?;
//!     socket.connect(server)?;
//!     let mut buf = vec![0; 65535];
//!
//!     loop {
//!         while let Some(t) = resolver.poll_transmit() {
//!             match t.transport {
//!                 Transport::Udp(_) => {
//!                     if let Err(e) = socket.send(&t.payload) {
//!                         resolver.handle_udp_error(query, server, e.kind(), Instant::now());
//!                     }
//!                 }
//!                 // A truncated answer switches the query to TCP; see below.
//!                 _ => return Err("TCP needed".into()),
//!             }
//!         }
//!         match resolver.poll_event() {
//!             Some(Event::Response { response, .. }) => {
//!                 println!("{:?}", sansio_dns::addresses(&response)?);
//!                 return Ok(());
//!             }
//!             Some(Event::Failed { error, .. }) => return Err(error.into()),
//!             None => {}
//!         }
//!         let deadline = resolver.poll_timeout().ok_or("nothing pending")?;
//!         let wait = deadline.saturating_duration_since(Instant::now());
//!         socket.set_read_timeout(Some(wait.max(Duration::from_millis(1))))?;
//!         match socket.recv(&mut buf) {
//!             Ok(n) => resolver.handle_datagram(query, server, &buf[..n], Instant::now()),
//!             Err(e) if matches!(e.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut) => {
//!                 resolver.handle_timeout(Instant::now());
//!             }
//!             Err(e) => resolver.handle_udp_error(query, server, e.kind(), Instant::now()),
//!         }
//!     }
//! }
//! ```
//!
//! The repository's `examples/` directory has drivers with TCP for std, Tokio
//! and compio, and one for DNS over TLS, about 150 lines each. [Driver
//! obligations](#driver-obligations) lists what a driver must do for the
//! resolver's checks to hold.
//!
//! An [`Event::Response`] holds the server's answer as a hickory [`Message`];
//! [`addresses`] takes the addresses out of it, following the CNAME chain.
//! Empty answers (`NXDOMAIN`, NODATA) arrive there too, with their code in
//! `response.metadata.response_code`. An [`Event::Failed`] carries an
//! [`Error`].
//!
//! # What the resolver does
//!
//! Queries go over UDP, with EDNS at 1232 bytes, or over the open connection
//! to their server if there is one (RFC 7766 §5). A truncated response
//! switches that query to TCP (RFC 1123 §6.1.3.2, RFC 9210 §3). The resolver
//! keeps one connection per server, shared and pipelined by every query to
//! it. With the `tls` feature, `Config::with_tls` and `Config::with_tls_names`
//! send every query over DNS over TLS (RFC 7858) instead: the resolver drives
//! the TLS session in memory, and the driver still only moves bytes.
//!
//! Names under `localhost.`, `invalid.` and `onion.` never reach the network,
//! and neither do names under `local.` and the link-local reverse zones
//! unless the configuration says the name servers serve them; other
//! special-use names, such as `test.` or `home.arpa.`, are sent like any
//! other. [`Config::hosts`] answers names from a hosts file, and
//! [`Config::search`] appends search domains. See [`Resolver::query`].
//!
//! For host names, [`Resolver::lookup_ip`] runs the A and AAAA queries and
//! collects the addresses, following CNAMEs; [`Config::ip_strategy`] picks
//! the families and their order.
//!
//! A query for the same name and type as one in flight joins it instead of
//! being sent, and gets its outcome; see [Joining queries](#joining-queries).
//! Failures and negative answers are cached for a while, so the same question
//! isn't sent again at once; see [Cache](#cache).
//!
//! # Driver obligations
//!
//! The resolver checks what it can see of a reply: source address and port,
//! message ID and question (RFC 5452 §9.1). What it can't see or choose is
//! the driver's job.
//!
//! ## UDP
//!
//! RFC 5452 §9.2 requires an unpredictable source port, and a different one
//! for each outstanding query, and §9.1 requires a reply's destination
//! address and port to match the query's source address and port. The
//! resolver can neither choose ports nor see where a datagram was sent to,
//! so:
//!
//! - Bind a fresh ephemeral socket per query ([`Transport::Udp`] names it),
//!   in the destination's address family, and connect it to the destination.
//!   Bind a new socket when the query moves to another server: connecting the
//!   old one again keeps the local address its first connect picked, on Linux
//!   at least. The kernel then delivers only datagrams from that server to
//!   that address and port.
//! - Pass that query along with every datagram the socket receives to
//!   [`Resolver::handle_datagram`], with the source address as received: an
//!   IPv4 server seen as `::ffff:a.b.c.d` on a dual-stack socket won't match.
//! - Read into a buffer that holds any UDP datagram, 65535 bytes, not just
//!   the 1232 the queries advertise as their payload size: a server may send
//!   more, and the resolver uses such an answer, which a smaller buffer would
//!   cut off so that it doesn't decode.
//! - When binding or connecting a query's socket or sending its datagram
//!   fails, or receiving on it reports an error, typically an ICMP port or
//!   host unreachable for the datagram (RFC 1122 §4.1.3.3), call
//!   [`Resolver::handle_udp_error`], so the query moves on at once instead of
//!   waiting out its deadline. An error doesn't end the socket: keep receiving
//!   on it while the query's attempts go to that server, and bind a new one
//!   when an attempt goes to another. Not every refused datagram draws an
//!   error: macOS, for one, rate-limits ICMP port unreachable messages, so a
//!   datagram refused soon after another may get none, and its query then
//!   waits out its deadline.
//!
//! ## Streams
//!
//! Stream connections (TCP, and TLS on top of it) are named by a
//! [`ConnectionId`].
//!
//! - For [`Transport::TcpConnect`], open a TCP connection to the destination
//!   under that id and write the payload. For [`Transport::TcpWrite`], write
//!   the payload to that connection; it can follow its `TcpConnect` before
//!   connecting has finished, so queue it. For [`Transport::TcpClose`], close
//!   the connection once the payloads before it are written.
//! - Payloads are already length-prefixed (RFC 7766 §8) or TLS-encrypted:
//!   write each one in a single call, so a message and its length go out
//!   together (§8), and disable Nagle's algorithm (`TCP_NODELAY`) on every
//!   connection, so a query written while earlier ones wait for their answers
//!   goes out at once (§6.2.1.1).
//! - Pass everything read from a connection to
//!   [`Resolver::handle_stream_data`]. Call [`Resolver::handle_stream_closed`]
//!   when the server closes it, and [`Resolver::handle_stream_error`] when
//!   connecting, reading or writing fails.
//! - After reporting a connection closed or failed, no transmit for it
//!   follows, `TcpClose` included, but still carry out the ones queued before
//!   the report and then close it. A report for a connection the resolver
//!   already closed is ignored.
//!
//! The resolver keeps one connection per server open (RFC 7766 §6.2.2) and
//! sends further queries over it, several at a time (§6.2.1, RFC 7858 §3.4).
//! No two queries outstanding on a connection share a message ID (§6.2.1): a
//! query that leaves a connection before its answer comes, cancelled or moved
//! on after a timeout, keeps its ID in use there until the answer arrives,
//! which is then dropped, or the connection ends. Answers are matched by
//! message ID and question, or by message ID alone if they have no question
//! section (§7). The resolver asks for the connection to be closed once it
//! has been idle for [`Config::idle_timeout`] (§6.2.3), when a query on it
//! times out with no response on it since being written, when it holds 256
//! requests that left it unanswered and another would join them, or, with
//! `tls`, when TLS rejects bytes received on it or a write to it, or the
//! server sent close_notify (RFC 7858 §3.4).
//!
//! ## Over TLS
//!
//! With TLS, the last transmit before a `TcpClose` carries the close_notify
//! alert, which must go out before the connection closes (RFC 8446 §6.1), or,
//! after a TLS error, the alert rustls queued for it instead, if it queued
//! one (§6.2). After an alert from the server that rustls reports as the
//! error (`rustls::Error::AlertReceived`), nothing is written before the
//! close, as after an error alert (§6). A connection still connecting when
//! its `TcpClose` comes can be dropped at once: nothing written to it has
//! gone out. The transmits queued before a close report can hold the
//! resolver's reply to the server's close_notify, which a driver that reads
//! the end of the stream before carrying them out must not drop.
//!
//! ## Stopping, and network changes
//!
//! A driver that stops calls [`Resolver::shutdown`] and carries out the
//! transmits it queues before dropping its connections, so that every TLS
//! session ends with close_notify.
//!
//! When the host's network changes, such as a new address or a new default
//! route, call [`Resolver::flush_cache`]: failures and negative answers from
//! the old network shouldn't hold for the new one.
//!
//! # How a query moves on
//!
//! A query tries its servers in turn, waiting longer on each round, until one
//! answers or it runs out of attempts. With [`Config::new`]'s defaults and
//! two servers, the four attempts wait 5, 5, 10 and 10 seconds, so a query
//! that nobody answers fails after 30 seconds; with one server, after 15.
//! The [table](#the-rules) below has every rule, and the sections around it
//! the details.
//!
//! ## Servers and attempts
//!
//! Each query has [`Config::attempts`] attempts. Its first goes to the first
//! server in the list that hasn't failed to answer within
//! [`Config::failure_memory`], and each next attempt to the server after
//! that, wrapping around, so with one server every attempt goes to it. A
//! server that answered with an error is skipped for the rest of the search
//! candidate, as RFC 1035 §7.2 removes it from the list of servers to ask;
//! one that didn't answer isn't, since a later, longer wait may reach it. A
//! server is skipped too once the search candidate was sent to it three
//! times over the transport the next send would take (RFC 9520 §3.1; see
//! [Bounds](#bounds-on-sends-and-waits)).
//!
//! Answers are matched by message ID and question, which are the same for
//! every attempt. So an answer to an earlier attempt still counts if it
//! arrives where the current attempt waits for one: as a datagram from the
//! current server, while that attempt went there over UDP and the query's
//! socket for that server is still open (the driver binds a new one when the
//! query moves to another server), or on the connection the current attempt
//! was written to. While the current attempt waits on a connection,
//! datagrams are ignored.
//!
//! ## Transports
//!
//! Every send goes over the open connection to its server if there is one
//! (RFC 7766 §5). Otherwise it goes over UDP, unless the query got a
//! truncated answer for this search candidate or uses TLS: then it opens a
//! connection. So a query that went over a stream only because a connection
//! was open goes back to UDP for a server without one. A query "sent again"
//! in the table goes to the same server by this rule: over its open
//! connection, else over a new one if the query must use a stream, else over
//! UDP.
//!
//! ## Deadlines
//!
//! A fresh deadline is [`Config::timeout`] from now, doubled for each round
//! the attempts have made through the servers not skipped (exponential
//! backoff, RFC 1123 §6.1.3.3). Each wait is at least one second and at most
//! 300, the bounds §6.1.3.3 (5) asks for, so no query waits forever.
//!
//! ## Answers and errors
//!
//! Only `NOERROR` and `NXDOMAIN` answer the question (RFC 1035 §4.1.1). Every
//! other code is a server error: `SERVFAIL`, `REFUSED`, `NOTIMP`, the codes
//! 6 to 15 and extended codes such as BADVERS (RFC 6891 §6.1.3) and
//! BADCOOKIE (RFC 7873 §5.3; no cookie is sent). So are a reply whose header
//! and question match but whose records don't decode, and `NOERROR` with no
//! answer and neither AA nor RA set: the server neither recursed nor is
//! authoritative, so the answer is typically a referral, which a stub
//! resolver can't follow (RFC 1034 §4.3.1, §5.3.1).
//!
//! A `NOERROR` answer with records of the type and class asked for ends the
//! query. So does `NXDOMAIN` or NODATA with no search candidate left; see
//! [Search domains](#search-domains). If a TLS session can't be started, the query fails at
//! once with [`Error::Tls`].
//!
//! ## The rules
//!
//! In the table, "next" is the next server in the rotation that isn't
//! skipped. A send to the "same" server that would be the fourth over that
//! transport isn't made: the query sends its next attempt to the next server
//! instead, using an attempt, and if that send was to drop EDNS, it keeps
//! EDNS.
//!
//! | What happens | What the query does next | Server | Uses an attempt | Deadline |
//! |---|---|---|---|---|
//! | No answer by its deadline (on a stream, see below), or its datagram couldn't be sent or drew an ICMP error | sends its next attempt | next | yes | fresh |
//! | A server error, an empty answer without AA or RA, `FORMERR` with OPT, or a second `FORMERR` without it | skips this server for the rest of the search candidate, and sends its next attempt | next not skipped | yes | fresh |
//! | Truncated answer over UDP, even one that doesn't decode (RFC 2181 §9) | switches to TCP; later attempts stay on TCP | same | no | fresh |
//! | `FORMERR` without OPT to a query that still has EDNS (not over TLS) | drops EDNS, once; later attempts stay without it | same | no | fresh |
//! | The server closes, or I/O fails on, a connection that answered something after the query was written to it, or the server sends close_notify on it over TLS | is sent again | same | no | fresh |
//! | The same, for a connection that had only answered before | is sent again, once per query | same | no | fresh |
//! | Its connection is closed because another query on it timed out with no response on it since being written, or because it holds too many unanswered requests (see below) | is sent again, once per query, shared with the row above | same | no | kept |
//! | Either of the two rows above, a second time | sends its next attempt | next | yes | fresh |
//! | A connection that never answered is lost, or TLS rejects bytes received on any connection or refuses a write to it | sends its next attempt | next | yes | fresh |
//! | `NXDOMAIN`, or NODATA (`NOERROR` without records of the type and class asked for), with search candidates left | starts over with the next candidate: new message ID, with EDNS, over UDP unless a connection is open or over TLS, no server skipped, a new free resend | first that hasn't failed | fresh attempts | fresh |
//! | Its next search candidate, or its first, has a cached `NXDOMAIN` or NODATA (see [Cache](#cache)) | takes that as the candidate's answer and moves on to the candidate after it, or ends as with no candidate left | none | no | |
//! | Its search candidate has a cached failure: when the query starts or reaches that candidate, or would send it again | fails with the cached error, and so do the queries that joined it | none | | |
//! | It was the first to join a query that is cancelled (see [Joining queries](#joining-queries)) | takes the query over; over UDP the current attempt is sent again, from its own socket | same | no | fresh over UDP, kept on a stream |
//! | The same, when that datagram would be the fourth to the server | sends its next attempt, or with none left fails with [`Error::Timeout`], and so do the queries that joined it; the failure isn't cached, since the server may have answered the cancelled queries' sockets | next | yes | fresh |
//! | Out of attempts, or every server skipped | fails with the last error, or [`Error::Timeout`] when a query has no server left after a truncated answer, and so do the queries that joined it; the failure is cached | | | |
//!
//! ## Timeouts on a stream
//!
//! A query that times out on a stream closes the connection only if no
//! complete response, matched or not, has arrived on it since the query was
//! written there; the other queries on it then move as the table says. If a
//! response has arrived, the server is only slow with this query, which RFC
//! 7766 §7 expects of pipelined queries: the connection stays open, and the
//! query's request stays outstanding on it. If a later attempt comes back to
//! that connection, it waits for that answer instead of writing the message
//! ID there a second time (RFC 7766 §6.2.1): it uses an attempt and gets a
//! fresh deadline, but sends nothing. If no response arrives on the
//! connection by that deadline, it is closed as above. A connection that
//! holds 256 requests left unanswered this way or by [`Resolver::cancel`] is
//! closed when another would join them, as RFC 7766 §6.2.4 lets either end
//! do under unusual conditions, which frees their message IDs; its other
//! queries move as when one times out.
//!
//! ## Search domains
//!
//! With search domains, a name is tried as several candidates (see
//! [`Config::search`] and [`Config::ndots`]). `NXDOMAIN` or NODATA moves on
//! to the next candidate; with none left, the outcome is the first NODATA
//! answer if a candidate gave one, else the last `NXDOMAIN` (see
//! [`Resolver::query`]). A query that fails on a candidate, with `SERVFAIL`,
//! `REFUSED` or any other failure, ends the search with that error, as
//! musl's resolver does: a temporary failure for the name meant must not turn
//! into an answer for another name. glibc's `res_search` goes on to the
//! search domains after any failure on the name as given when that comes
//! first; among the search domains it moves on only after `SERVFAIL`, and
//! after another failure it stops and still tries the name as given if that
//! comes last, unless no server could be reached at all.
//!
//! [`Resolver::lookup_ip`] walks the candidates itself, with an A and an AAAA
//! query per candidate, and moves on when neither has an address; a failure,
//! or an answer whose CNAME chain loops ([`Error::CnameLoop`]), ends its
//! search.
//!
//! ## Bounds on sends and waits
//!
//! Each search candidate is sent at most three times to each server over
//! each transport, UDP and TCP, or TLS (RFC 9520 §3.1). Every send counts:
//! attempts, the free ones, and the datagram a query sends again when it
//! takes over a cancelled one. So with n servers a search candidate is sent
//! at most 3n times over UDP and 3n over a stream, and attempts beyond three
//! per server are only used over a stream. Within that, it is sent at most
//! `attempts + 3` times: once per attempt, plus at most one switch to TCP,
//! one EDNS drop and one free resend. That leaves out the hand-over
//! datagrams, and the resends after losing a connection that answered
//! something after the query was written to it: those are bounded only by
//! the three sends per server. Skipping servers only lowers that: with one
//! server, a server error ends the query. With k candidates that is k times
//! as many, and a candidate the cache answers sends nothing.
//!
//! Every attempt and every free send waits at most 300 seconds for its
//! answer, and a send that keeps its deadline adds no time. So with n servers
//! a search candidate makes at most `min(attempts + 3 + h + r, 6n)` sends,
//! where h is the number of hand-over datagrams and r the number of resends
//! after a lost connection that answered since, and waits at most 300
//! seconds per attempt or send. Over TLS, which sends no datagrams and
//! neither switches to TCP nor drops EDNS, that is `min(attempts + 1 + r, 3n)`
//! sends. With [`Config::new`]'s defaults, a query that no server answers
//! fails after 15 seconds per server (5 and then 10), so 30 with two servers.
//! With `timeout:30` and `attempts:3`, the most [`Config::from_resolv_conf`]
//! takes, each server waits 30, 60 and 120 seconds: 210 per server.
//!
//! ## Joining queries
//!
//! A query for the same name (as given, trailing dot included, case ignored)
//! and type as one in flight joins it instead of being sent, unless the cache
//! answers it, and gets its outcome. [`Resolver::lookup_ip`] asks for each
//! candidate by its absolute name, so its queries join, and are joined by,
//! queries for that name. If the first one runs out of attempts or servers,
//! every query that joined it fails with it, however late it joined: the
//! failure is cached, so a query issued just after would fail the same way,
//! without being sent (RFC 9520 §3.2). [`Resolver::cancel`] hands a query
//! that others joined to the first of them.
//!
//! # Cache
//!
//! The resolver caches resolution failures (RFC 9520 §3.2) and negative
//! answers (RFC 2308 §5), but no answers with data. An entry is keyed by a
//! question: an absolute name, compared without regard to ASCII case (RFC
//! 4343 §3), a type and a class. A failure is cached for the search candidate
//! as sent, a negative answer for the name it denies (see below). Every
//! search candidate is looked up before it is sent, for [`Resolver::query`]
//! and [`Resolver::lookup_ip`] alike. The cache reads time only from the
//! `now` passed in, so it adds no deadline: an expired negative answer is
//! dropped when it is looked up, and an expired failure is kept for the
//! backoff below until it is replaced, an answer ends it or the cache needs
//! room.
//!
//! ## Failures
//!
//! A search candidate fails to resolve (RFC 9520 §2) when its query runs out
//! of attempts or servers, or its TLS session can't start, whatever the last
//! error was: no answer by the deadline, a datagram that couldn't be sent or
//! drew an ICMP error, a lost connection or a TLS error (§2.3), an error code
//! such as `SERVFAIL` (§2.1), `REFUSED` (§2.2) or `FORMERR` (§2.7), a reply
//! that doesn't decode, or an empty answer with neither AA nor RA. §2 counts
//! a referral as a useful answer, to a resolver that can follow it; a stub
//! resolver asks for recursion and can't, so here it is a failure like the
//! others. `NXDOMAIN` and NODATA are answers, not failures. Nor is a query
//! that took over a cancelled one and may send to no server any more (see
//! the table): the server may have answered the cancelled queries' sockets.
//!
//! Each failure is cached for the candidate's question, for
//! [`FailureCache::shortest`] (one second by default, and never less) the
//! first time. If the question fails again and was first sent within
//! [`FailureCache::longest`] after its cached failure expired, it is
//! cached twice as long as the time before (§3.2's backoff), however long its
//! retries took, up to that maximum: 30 seconds by default, and never more
//! than five minutes (§3.2). A useful answer for the question, data,
//! `NXDOMAIN` or NODATA, ends the backoff; an error code or a referral
//! doesn't. While a failure is cached, nothing is sent for its question
//! (§3.2): a query for it, a search that reaches it, and a query in flight
//! that would send it again all fail at once with the cached error.
//!
//! ## Negative answers
//!
//! An `NXDOMAIN` answer is cached for every type of the name, a NODATA answer
//! for its type only (RFC 2308 §5), under the last name of the answer's CNAME
//! chain (§1, §2.1, §2.2): the alias exists, its target doesn't. It lasts the
//! lesser of the TTL and the MINIMUM field of the SOA record in the authority
//! section (§5), at most [`Config::max_negative_ttl`] (one hour by default).
//! Not cached: an answer without an SOA record (§5), a truncated one (RFC
//! 1123 §6.1.3.2), one that would last zero seconds (RFC 1123 §6.1.2.1), a
//! chain that loops, and the answers given locally. Nor is the `NXDOMAIN` cut
//! of RFC 8020 applied: a stub resolver may sit behind servers that see the
//! namespace differently.
//!
//! A query the cache answers gets the server's answer for the question it
//! asks, with the authority section the server sent (the SOA record, and NS
//! or NSEC records if any), no answer or additional section and no OPT
//! record (RFC 6891 §6.2.1), AA clear, message ID 0, since no message was
//! sent for it, and each TTL less the whole seconds the answer has been
//! cached, none above the entry's lifetime (RFC 2308 §6). In a search, such
//! an answer moves on to the next candidate without a transmit, so a search
//! list doesn't ask the servers about the same nonexistent names again and
//! again, which meets RFC 1123 §6.1.4.3 (a) here rather than relying on the
//! name servers' caches.
//!
//! ## Size, flushing and failed servers
//!
//! The cache holds at most [`Config::cache_entries`] entries (1024 by
//! default). A full cache drops its expired entries first, then the oldest,
//! which bounds the memory a flood of failing names can take (RFC 9520 §3.2,
//! §5). [`Resolver::flush_cache`] empties it, and forgets which servers
//! failed to answer: a driver should call it when the host's network changes.
//!
//! A single server's failure is not cached for a question, which RFC 2308
//! §7.1 and §7.2 would key by the server's address: a server that answers
//! with an error is skipped for the rest of the search candidate only, and
//! one that doesn't answer goes after the others for
//! [`Config::failure_memory`], kept by server address as RFC 9520 §3.2
//! allows, which orders the servers but withholds no query.

use std::io;
use std::net::SocketAddr;

pub use hickory_proto;
use hickory_proto::op::{Message, ResponseCode};

/// Compiles the README's Rust examples as doctests, without showing them in
/// the docs.
#[cfg(doctest)]
#[doc = include_str!("../README.md")]
mod readme {}

mod cache;
mod config;
mod hosts;
mod lookup;
mod resolver;
#[cfg(feature = "tls")]
mod tls;
mod wire;

pub use config::{Config, FailureCache, FailureMemory, IpStrategy, ResolvEnv, Timeout};
pub use hosts::Hosts;
pub use lookup::addresses;
pub use resolver::Resolver;
#[cfg(feature = "tls")]
pub use rustls;
#[cfg(feature = "tls")]
pub use tls::TlsConfigError;

/// Handle for an in-flight query.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct QueryId(u64);

/// Handle for an address lookup started with [`Resolver::lookup_ip`].
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct LookupId(u64);

/// Handle for a stream connection; see [Streams](#streams).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ConnectionId(u64);

/// How a [`Transmit`] must be sent.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Transport {
    /// As one UDP datagram, from the socket bound for this query.
    Udp(QueryId),
    /// Open a new TCP connection to the destination, named by this id, and
    /// write the payload.
    TcpConnect(ConnectionId),
    /// Write the payload to this open connection.
    TcpWrite(ConnectionId),
    /// Close this connection, once the payloads of the transmits before it
    /// are written: over TLS, the last one carries the close_notify alert,
    /// or, after a TLS error, the alert rustls queued for it instead, if it
    /// queued one (RFC 8446 §6.1, §6.2). After an alert from the server
    /// that rustls reports as the error (`rustls::Error::AlertReceived`)
    /// there is none, as after an error alert: the connection closes at
    /// once (§6). A connection still connecting can be dropped at once. The
    /// payload is empty.
    TcpClose(ConnectionId),
}

/// Something the caller must do on the network.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Transmit {
    /// How to send it, and which socket or connection it belongs to.
    pub transport: Transport,
    /// The name server to send it to.
    pub destination: SocketAddr,
    /// The bytes to send: a DNS message, length-prefixed or TLS-encrypted
    /// on streams.
    pub payload: Vec<u8>,
}

/// Outcome of a query.
#[derive(Debug)]
pub enum Event {
    /// A server answered with `NOERROR` or `NXDOMAIN`, or the name was
    /// answered locally or from the cache. Empty answers arrive here too;
    /// inspect `response.metadata.response_code`. TTLs received with the
    /// most significant bit set are zero here (RFC 2181 §8). An answer
    /// given locally or from the cache has message ID 0: no message was
    /// sent for it.
    Response {
        /// The query that completed.
        query: QueryId,
        /// The server's answer.
        response: Message,
    },
    /// The query gave up, or its question has a cached failure.
    Failed {
        /// The query that failed.
        query: QueryId,
        /// Why it failed.
        error: Error,
    },
}

/// Why a query failed. An error in an [`Event::Failed`] is a resolution
/// failure (RFC 9520 §2), cached for the question that failed; see the
/// crate docs. Two exceptions: [`Error::NoRecursion`], a referral, which
/// §2 counts as a useful answer but a stub resolver can't follow, is
/// cached like a failure; and the [`Error::Timeout`] of a query that took
/// over a cancelled one and may send to no server any more isn't cached.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// The last attempt got no answer by its deadline, or its connection was
    /// closed because another query on it timed out. Also when a query may
    /// send to no server any more (RFC 9520 §3.1) after it took over a
    /// cancelled one, which isn't cached, or after a truncated answer.
    #[error("no response from any name server")]
    Timeout,
    /// The last TCP connection closed before a complete response arrived.
    #[error("connection closed before a response")]
    ConnectionClosed,
    /// The last attempt failed with this I/O error: its TCP connection
    /// failed, for example when connecting was refused, or its datagram
    /// couldn't be sent, for example to an unreachable network, or drew an
    /// ICMP error, such as a refused port.
    #[error("network I/O failed: {0}")]
    Io(io::ErrorKind),
    /// The last TLS session failed, for example on an invalid certificate.
    /// Only with the `tls` feature.
    #[error("TLS failed: {0}")]
    Tls(String),
    /// The last server answered with this error code: any code other than
    /// `NOERROR` and `NXDOMAIN`, such as `SERVFAIL` or `REFUSED`.
    #[error("name server returned {0}")]
    Server(ResponseCode),
    /// The last server sent a reply to the query whose header and question
    /// matched but whose records couldn't be decoded. Carries the decoding
    /// error.
    #[error("name server sent a reply that couldn't be decoded: {0}")]
    Malformed(String),
    /// The last server answered `NOERROR` with no answer records and
    /// neither the AA nor the RA flag: it doesn't recurse and isn't
    /// authoritative for the name, so the answer is typically a referral,
    /// which a stub resolver can't follow (RFC 1034 §4.3.1, §5.3.1).
    #[error("name server doesn't offer recursion")]
    NoRecursion,
    /// The answer's CNAME chain comes back to a name on it, which RFC 1034
    /// §3.6.2 and §5.2.2 ask to report as an error. Only from
    /// [`addresses`] and [`Resolver::lookup_ip`]; [`Resolver::query`] passes
    /// the answer on as it is.
    #[error("CNAME chain loops")]
    CnameLoop,
}
