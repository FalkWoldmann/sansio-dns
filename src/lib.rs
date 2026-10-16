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
//! addresses, following CNAMEs.
//!
//! With the `tls` feature, `Config::with_tls` sends every query over DNS
//! over TLS (RFC 7858) instead.
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
//! [`Config::idle_timeout`], or when a query on it times out.
//!
//! For UDP, [RFC 5452 §9.2] requires an unpredictable source port, and a
//! different one for each outstanding query. The resolver can't choose
//! ports, so the driver must bind a fresh ephemeral socket per query
//! ([`Transport::Udp`] names it) and pass that query along with every
//! datagram the socket receives to [`Resolver::handle_datagram`]. The
//! resolver checks everything else §9.1 asks for: source address and port,
//! message ID and question.
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

pub use config::Config;
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
pub enum Error {
    /// No server answered within the configured attempts.
    #[error("no response from any name server")]
    Timeout,
    /// The last TCP connection closed before a complete response arrived.
    #[error("connection closed before a response")]
    ConnectionClosed,
    /// The last TCP connection failed with this I/O error, for example
    /// when connecting was refused.
    #[error("connection failed: {0}")]
    Connection(io::ErrorKind),
    /// The last TLS session failed, for example on an invalid certificate.
    /// Only with the `tls` feature.
    #[error("TLS failed: {0}")]
    Tls(String),
    /// The last server answered with this error code (e.g. `SERVFAIL`).
    #[error("name server returned {0}")]
    Server(ResponseCode),
}
