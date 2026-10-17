//! A sans-IO DNS stub resolver built on [`hickory_proto`].
//!
//! [`Resolver`] owns no sockets, timers or tasks. The caller drives it:
//!
//! 1. Start a lookup with [`Resolver::query`].
//! 2. Send everything returned by [`Resolver::poll_transmit`], over the
//!    [`Transport`] it names.
//! 3. Feed received datagrams to [`Resolver::handle_datagram`], and bytes
//!    read from TCP connections to [`Resolver::handle_stream_data`].
//! 4. Call [`Resolver::handle_timeout`] once the instant from
//!    [`Resolver::poll_timeout`] has passed.
//! 5. Collect results from [`Resolver::poll_event`].
//! 6. Before stopping, call [`Resolver::shutdown`] and send its transmits,
//!    which close the open connections.
//!
//! Queries go over UDP, or over the connection to their server if one is
//! open (RFC 7766 §5). A truncated response switches that query to TCP (RFC
//! 1123 §6.1.3.2, RFC 9210 §3). Special-use names never reach the network;
//! see [`Resolver::query`].
//!
//! For hostnames, [`IpLookup`] runs the A and AAAA queries and collects the
//! addresses, following CNAMEs; [`Config::ip_strategy`] picks the families
//! and their order.
//!
//! With the `tls` feature, `Config::with_tls` and `Config::with_tls_names`
//! send every query over DNS over TLS (RFC 7858) instead.
//!
//! # How a query moves on
//!
//! Each query has [`Config::attempts`] attempts. Its first goes to the first
//! server in the list that hasn't failed to answer within
//! [`Config::failure_memory`], and each next attempt to the server after
//! that, wrapping around, so with one server every attempt goes to it. A
//! server that answered with an error is skipped for the rest of the
//! search candidate, as RFC 1035 §7.2 removes it from the list of servers
//! to ask; one that didn't answer isn't, since a later, longer wait may
//! reach it. A server is skipped too once the search candidate was sent to
//! it three times over the transport the next send would take (RFC 9520
//! §3.1; see below).
//! Answers are matched by message ID and question, which are the same for
//! every attempt. So an answer to an earlier attempt still counts if it
//! arrives where the current attempt waits for one: as a datagram from the
//! current server, while that attempt went there over UDP and the query's
//! socket for that server is still open (the driver binds a new one when
//! the query moves to another server), or on the connection the current
//! attempt was written to. While the current attempt waits on a
//! connection, datagrams are ignored.
//!
//! Every send goes over the open connection to its server if there is one
//! (RFC 7766 §5). Otherwise it goes over UDP, unless the query got a
//! truncated answer for this search candidate or uses TLS: then it opens a
//! connection. So a query that went over a stream only because a
//! connection was open goes back to UDP for a server without one.
//!
//! A fresh deadline is [`Config::timeout`] from now, doubled for each round
//! the attempts have made through the servers not skipped (exponential
//! backoff, RFC 1123 §6.1.3.3): with two servers and the defaults, the four
//! attempts wait 5, 5, 10 and 10 seconds, and a query that gets no answer
//! fails after 30. Each wait is at least one second and at most 300, the
//! bounds §6.1.3.3 (5) asks for, so no query waits forever.
//!
//! Only `NOERROR` and `NXDOMAIN` answer the question (RFC 1035 §4.1.1).
//! Every other code is a server error: `SERVFAIL`, `REFUSED`, `NOTIMP`, the
//! codes 6 to 15 and extended codes such as BADVERS (RFC 6891 §6.1.3) and
//! BADCOOKIE (RFC 7873 §5.3; no cookie is sent). So are a reply whose
//! header and question match but whose records don't decode, and
//! `NOERROR` with no answer and neither AA nor RA set: the server neither
//! recursed nor is authoritative, so the answer is typically a referral,
//! which a stub resolver can't follow (RFC 1034 §4.3.1, §5.3.1).
//!
//! In the table, "next" is the next server in the rotation that isn't
//! skipped. A send to the "same" server that would be the fourth over that
//! transport isn't made: the query sends its next attempt to the next
//! server instead, using an attempt, and if that send was to drop EDNS, it
//! keeps EDNS.
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
//! | `NXDOMAIN`, or NODATA (`NOERROR` without records of the type asked for), with search candidates left | starts over with the next candidate: new message ID, with EDNS, over UDP unless a connection is open or over TLS, no server skipped, a new free resend | first that hasn't failed | fresh attempts | fresh |
//! | It was the first to join a query that is cancelled (see below) | takes the query over; over UDP the current attempt is sent again, from its own socket | same | no | fresh over UDP, kept on a stream |
//! | Out of attempts, or every server skipped | fails with the last error, or [`Error::Timeout`] when a query has no server left after it took over a cancelled one or got a truncated answer; a query that joined after the search candidate started starts over instead (see below) | | | |
//!
//! A query "sent again" goes to the same server by the rule above: over its
//! open connection, else over a new one if the query must use a stream,
//! else over UDP.
//!
//! A query that times out on a stream closes the connection only if no
//! response has arrived on it since the query was written there; the other
//! queries on it then move as the table says. If a response has arrived,
//! the server is only slow with this query, which RFC 7766 §7 expects of
//! pipelined queries: the connection stays open, and the query's request
//! stays outstanding on it. If a later attempt comes back to that
//! connection, it waits for that answer instead of writing the message ID
//! there a second time (RFC 7766 §6.2.1): it uses an attempt and gets a
//! fresh deadline, but sends nothing. If no response arrives on the
//! connection by that deadline, it is closed as above. A connection that
//! holds 256 requests left unanswered this way or by
//! [`Resolver::cancel`] is closed when another would join them, as RFC
//! 7766 §6.2.4 lets either end do under unusual conditions, which frees
//! their message IDs; its other queries move as when one times out.
//!
//! If a TLS session can't be started, the query fails at once with
//! [`Error::Tls`]. A `NOERROR` answer with records of the type asked
//! for ends the query. So does `NXDOMAIN` or NODATA with no candidate left:
//! the outcome is then the first NODATA answer if a candidate gave one,
//! else the last `NXDOMAIN` (see [`Resolver::query`]). A query that fails
//! on a candidate ends the search with that error. [`IpLookup`] walks the
//! candidates itself, with an A and an AAAA query per candidate, and moves
//! on when neither has an address.
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
//! as many. A late joiner starting over has attempts and sends of its own.
//!
//! Every attempt and every free send waits at most 300 seconds for its
//! answer, and a send that keeps its deadline adds no time. So with n
//! servers a search candidate makes at most `min(attempts + 3 + h + r, 6n)`
//! sends, where h is the number of hand-over datagrams and r the number of
//! resends after a lost connection that answered since, and waits at most
//! 300 seconds per attempt or send. Over TLS, which sends no datagrams and
//! neither switches to TCP nor drops EDNS, that is
//! `min(attempts + 1 + r, 3n)` sends. With [`Config::new`]'s
//! defaults, a query that no server answers fails after 15 seconds per
//! server (5 and then 10), so 30 with two servers. With `timeout:30` and
//! `attempts:3`, the most [`Config::from_resolv_conf`] takes, each server
//! waits 30, 60 and 120 seconds: 210 per server.
//!
//! A query for the same name (as given, trailing dot included, case ignored)
//! and type as one in flight joins it instead of being sent, and gets its
//! outcome. An [`IpLookup`] asks for each candidate by its absolute name,
//! so its queries join, and are joined by, queries for that name. If the
//! first one runs out of attempts or servers, the queries that joined
//! after its current search candidate started don't share the failure:
//! the first of them starts over as a new query, with every server to
//! ask, and the others join it. [`Resolver::cancel`] hands a query that
//! others joined to the first of them, which keeps its own join time: if
//! it joined late, it starts over too rather than fail.
//!
//! # Driver obligations
//!
//! Stream connections (TCP, and TLS on top of it) are named by a
//! [`ConnectionId`]. For [`Transport::TcpConnect`], open a TCP connection to
//! the destination under that id and write the payload; for
//! [`Transport::TcpWrite`], write the payload to that connection; for
//! [`Transport::TcpClose`], close it once the payloads before it are
//! written. With TLS the last of them carries the close_notify alert, which
//! must go out before the connection closes (RFC 8446 §6.1), or the alert
//! that ends a session that failed (§6.2). A connection still connecting
//! when its `TcpClose` comes can be dropped at once: nothing written to it
//! has gone out. Pass everything read from a
//! connection to [`Resolver::handle_stream_data`]. Call
//! [`Resolver::handle_stream_closed`] when the server closes it, and
//! [`Resolver::handle_stream_error`] when connecting, reading or writing
//! fails. Payloads are already length-prefixed (RFC 7766 §8) or
//! TLS-encrypted: write each one in a single call, so a message and its
//! length go out together (§8), and disable Nagle's algorithm
//! (`TCP_NODELAY`) on every connection, so a query written while earlier
//! ones wait for their answers goes out at once (§6.2.1.1).
//!
//! The resolver keeps one connection per server open (RFC 7766 §6.2.2) and
//! sends further queries over it, several at a time (§6.2.1, RFC 7858
//! §3.4). No two queries outstanding on a connection share a message ID
//! (§6.2.1): a query that leaves a connection before its answer comes,
//! cancelled or moved on after a timeout, keeps its ID in use there until
//! the answer arrives, which is then dropped, or the connection ends.
//! Answers are matched by message ID and question, or by message ID alone
//! if they have no question section (§7). The resolver asks for the
//! connection to be closed once it has been idle for
//! [`Config::idle_timeout`] (§6.2.3), when a query on it times out with no
//! response on it since being written, when it holds 256 requests that
//! left it unanswered and another would join them, or, with `tls`, when
//! TLS rejects bytes received on it or a write to it, or the server sent
//! close_notify (RFC 7858 §3.4).
//!
//! A [`Transport::TcpWrite`] can follow its [`Transport::TcpConnect`]
//! before connecting has finished: queue it. After reporting a connection
//! closed or failed, no transmit for it follows, [`Transport::TcpClose`]
//! included, but still carry out the ones queued before the report and
//! then close it. Over TLS they can hold the resolver's reply to the
//! server's close_notify (RFC 8446 §6.1), which a driver that reads the end
//! of the stream before carrying them out must not drop. A report for a
//! connection the resolver already closed is ignored. A driver that stops
//! calls [`Resolver::shutdown`] and carries out the transmits it queues
//! before dropping its connections, so that every TLS session ends with
//! close_notify.
//!
//! For UDP, [RFC 5452 §9.2] requires an unpredictable source port, and a
//! different one for each outstanding query, and §9.1 requires a reply's
//! destination address and port to match the query's source address and
//! port. The resolver can neither choose ports nor see where a datagram
//! was sent to, so the driver must bind a fresh ephemeral socket per query
//! ([`Transport::Udp`] names it), in the destination's address family, and
//! connect it to the destination, binding a new socket when the query
//! moves to another server (connecting the old one again keeps the local
//! address its first connect picked, on Linux at least). The kernel then
//! delivers only datagrams from that server to that address and port.
//! Pass that query along with every datagram the socket receives to
//! [`Resolver::handle_datagram`]; the resolver checks the rest of §9.1:
//! source address and port, message ID and question. Pass the source
//! address as received (an IPv4 server seen as `::ffff:a.b.c.d` on a
//! dual-stack socket won't match), and read into a buffer of at least 1232
//! bytes, the payload size the queries advertise.
//!
//! When binding or connecting a query's socket or sending its datagram
//! fails, or receiving on it reports an error, typically an ICMP port or
//! host unreachable for the datagram (RFC 1122 §4.1.3.3), call
//! [`Resolver::handle_udp_error`], so the query moves on at once instead of
//! waiting out its deadline. An error doesn't end the socket: keep
//! receiving on it while the query's attempts go to that server, and bind
//! a new one when an attempt goes to another.
//!
//! [RFC 5452 §9.2]: https://rfc-annotations.research.icann.org/rfc5452.html

use std::io;
use std::net::SocketAddr;

pub use hickory_proto;
use hickory_proto::op::{Message, ResponseCode};

mod config;
mod hosts;
mod lookup;
mod resolver;
#[cfg(feature = "tls")]
mod tls;
mod wire;

pub use config::{Config, IpStrategy};
pub use hosts::Hosts;
pub use lookup::{IpLookup, Progress, addresses};
pub use resolver::Resolver;
#[cfg(feature = "tls")]
pub use rustls;
#[cfg(feature = "tls")]
pub use tls::TlsConfigError;

/// Handle for an in-flight query.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct QueryId(u64);

/// Handle for a stream connection; see the crate docs.
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
    /// or after a TLS error the alert for that error (RFC 8446 §6.1, §6.2).
    /// A connection still connecting can be dropped at once. The payload is
    /// empty.
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
    /// answered locally. Empty answers arrive here too; inspect
    /// `response.metadata.response_code`. TTLs received with the most
    /// significant bit set are zero here (RFC 2181 §8).
    Response {
        /// The query that completed.
        query: QueryId,
        /// The server's answer.
        response: Message,
    },
    /// The query gave up.
    Failed {
        /// The query that failed.
        query: QueryId,
        /// Why it failed.
        error: Error,
    },
}

/// Why a query failed.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// The last attempt got no answer by its deadline, or its connection was
    /// closed because another query on it timed out. Also when a query may
    /// send to no server any more (RFC 9520 §3.1) after it took over a
    /// cancelled one, or after a truncated answer.
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
}
