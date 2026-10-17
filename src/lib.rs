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
//!
//! Queries go over UDP. A truncated response switches that query to TCP,
//! as RFC 7766 §5 requires. Special-use names never reach the network; see
//! [`Resolver::query`].
//!
//! For hostnames, [`IpLookup`] runs the A and AAAA queries and collects the
//! addresses, following CNAMEs; [`Config::ip_strategy`] picks the families
//! and their order.
//!
//! With the `tls` feature, `Config::with_tls` sends every query over DNS
//! over TLS (RFC 7858) instead.
//!
//! # How a query moves on
//!
//! Each query has [`Config::attempts`] attempts. Its first goes to the first
//! server in the list that hasn't failed to answer within
//! [`Config::failure_memory`], and each next attempt to the server after
//! that, wrapping around, so with one server every attempt goes to it.
//! Answers are matched by message ID and question, which are the same for
//! every attempt, so an answer to an earlier attempt still counts if it
//! comes from the server of the current one.
//!
//! A fresh deadline is [`Config::timeout`] from now, doubled for each round
//! the attempts have made through the servers (exponential backoff, RFC
//! 1123 §6.1.3.3): with two servers and the defaults, the four attempts
//! wait 5, 5, 10 and 10 seconds.
//!
//! | What happens | What the query does next | Server | Uses an attempt | Deadline |
//! |---|---|---|---|---|
//! | No answer by its deadline, or its datagram couldn't be sent | sends its next attempt | next | yes | fresh |
//! | `SERVFAIL`, `REFUSED`, `NOTIMP`, or any other `FORMERR` | sends its next attempt | next | yes | fresh |
//! | Truncated answer over UDP | switches to TCP; later attempts stay on TCP | same | no | fresh |
//! | `FORMERR` without OPT to a query that still has EDNS (not over TLS) | drops EDNS, once; later attempts stay without it | same | no | fresh |
//! | The server closes, or I/O fails on, a connection that had answered | is sent again over another connection to that server, once per query | same | no | fresh |
//! | Another query on its connection times out | is sent again over another connection, once per query, shared with the row above | same | no | kept |
//! | The same, a second time | sends its next attempt | next | yes | fresh |
//! | A connection that never answered is lost, or TLS rejects bytes received on any connection | sends its next attempt | next | yes | fresh |
//! | `NXDOMAIN` with search candidates left | starts over with the next candidate: new message ID, with EDNS, back on UDP unless over TLS, a new free resend | first that hasn't failed | fresh attempts | fresh |
//! | It was the first to join a query that is cancelled (see below) | takes the query over; over UDP the current attempt is sent again from its own socket | same | no | fresh over UDP, kept on a stream |
//! | Out of attempts | fails with the last error | | | |
//!
//! If a TLS session can't be started or written to, the query fails at once
//! with [`Error::Tls`]. Any answer other than those above (`NOERROR`, or
//! `NXDOMAIN` with no candidate left) ends the query, and so does a server
//! error on the last attempt: the search moves on only on `NXDOMAIN`.
//!
//! Each search candidate is sent at most `attempts + 3` times: once per
//! attempt, plus at most one switch to TCP, one EDNS drop and one free
//! resend. With k candidates that is k × (`attempts` + 3). Not counted are
//! the datagram a query sends again when it takes over a cancelled one, and
//! a late joiner starting over with attempts of its own.
//!
//! A query for the same name (as given, trailing dot included, case ignored)
//! and type as one in flight joins it instead of being sent, and gets its
//! outcome. If the first one runs out of attempts, the queries that joined
//! after its current search candidate started don't share the failure: the
//! first of them starts over as a new query, and the others join it.
//! [`Resolver::cancel`] hands a query that others joined to the first of
//! them.
//!
//! # Driver obligations
//!
//! Stream connections (TCP, and TLS on top of it) are named by a
//! [`ConnectionId`]. For [`Transport::TcpConnect`], open a TCP connection to
//! the destination under that id and write the payload; for
//! [`Transport::TcpWrite`], write the payload to that connection; for
//! [`Transport::TcpClose`], close it. Pass everything read from a connection
//! to [`Resolver::handle_stream_data`]. Call
//! [`Resolver::handle_stream_closed`] when the server closes it, and
//! [`Resolver::handle_stream_error`] when connecting, reading or writing
//! fails. Payloads are already length-prefixed (RFC 7766 §8) or TLS-encrypted.
//!
//! The resolver keeps one connection per server open and sends further
//! queries over it, several at a time (RFC 7766 §6.2.1, RFC 7858 §3.4). It
//! asks for the connection to be closed once it has been idle for
//! [`Config::idle_timeout`], when a query on it times out, or, with `tls`,
//! when TLS rejects bytes received on it.
//!
//! A [`Transport::TcpWrite`] can follow its [`Transport::TcpConnect`]
//! before connecting has finished: queue it. After reporting a connection
//! closed or failed, forget it; no [`Transport::TcpClose`] follows. When
//! binding a query's socket or sending its datagram fails, call
//! [`Resolver::handle_udp_error`], so the query moves on at once instead of
//! waiting out its deadline.
//!
//! For UDP, [RFC 5452 §9.2] requires an unpredictable source port, and a
//! different one for each outstanding query. The resolver can't choose
//! ports, so the driver must bind a fresh ephemeral socket per query
//! ([`Transport::Udp`] names it) and pass that query along with every
//! datagram the socket receives to [`Resolver::handle_datagram`]. The
//! resolver checks everything else §9.1 asks for: source address and port,
//! message ID and question. Bind each socket in the destination's address
//! family, pass the source address as received (an IPv4 server seen as
//! `::ffff:a.b.c.d` on a dual-stack socket won't match), and read into a
//! buffer of at least 1232 bytes, the payload size the queries advertise.
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
    /// Close this connection. The payload is empty.
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
    /// A server answered. `NXDOMAIN` and empty answers arrive here too;
    /// inspect `response.metadata.response_code`.
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
    /// closed because another query on it timed out.
    #[error("no response from any name server")]
    Timeout,
    /// The last TCP connection closed before a complete response arrived.
    #[error("connection closed before a response")]
    ConnectionClosed,
    /// The last attempt failed with this I/O error: its TCP connection
    /// failed, for example when connecting was refused, or its datagram
    /// couldn't be sent, for example to an unreachable network.
    #[error("network I/O failed: {0}")]
    Io(io::ErrorKind),
    /// The last TLS session failed, for example on an invalid certificate.
    /// Only with the `tls` feature.
    #[error("TLS failed: {0}")]
    Tls(String),
    /// The last server answered with this error code (e.g. `SERVFAIL`).
    #[error("name server returned {0}")]
    Server(ResponseCode),
}
