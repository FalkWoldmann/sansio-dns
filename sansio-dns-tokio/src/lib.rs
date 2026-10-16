//! A [Tokio](https://tokio.rs) driver for [`sansio_dns`]: look up the
//! addresses of a host name.
//!
//! ```no_run
//! # async fn run() -> Result<(), Box<dyn std::error::Error>> {
//! let resolver = sansio_dns_tokio::Resolver::from_system_conf()?;
//! let addresses = resolver.lookup_ip("example.com").await?;
//! # Ok(())
//! # }
//! ```
//!
//! Each lookup runs its own [`sansio_dns::Resolver`], with a fresh UDP
//! socket per query (RFC 5452 §9.2) and its own TCP or TLS connections.
//! Dropping the future stops everything it started.
//!
//! With the `reqwest` feature, [`Resolver`] also implements
//! `reqwest::dns::Resolve`:
//!
//! ```ignore
//! let client = reqwest::Client::builder()
//!     .dns_resolver(sansio_dns_tokio::Resolver::from_system_conf()?)
//!     .build()?;
//! ```

#[cfg(feature = "reqwest")]
mod reqwest;

use std::collections::HashMap;
use std::collections::hash_map::Entry;
use std::fmt;
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use std::time::Instant;

use sansio_dns::hickory_proto::ProtoError;
use sansio_dns::hickory_proto::rr::Name;
use sansio_dns::{Config, ConnectionId, Hosts, IpLookup, QueryId, Transmit, Transport};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};
use tokio::sync::mpsc;
use tokio::task::{AbortHandle, JoinSet};

/// Looks up host names with a fixed [`Config`]. Cheap to clone.
#[derive(Clone, Debug)]
pub struct Resolver {
    config: Arc<Config>,
}

/// Why a lookup found no addresses.
#[derive(Debug)]
#[non_exhaustive]
pub enum Error {
    /// The host is neither an IP address nor a valid domain name.
    InvalidName(ProtoError),
    /// No name server gave a usable answer.
    Resolve(sansio_dns::Error),
    /// The name exists but has no addresses, or doesn't exist.
    NotFound,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidName(e) => write!(f, "invalid host name: {e}"),
            Self::Resolve(e) => write!(f, "{e}"),
            Self::NotFound => f.write_str("no addresses found"),
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::InvalidName(e) => Some(e),
            Self::Resolve(e) => Some(e),
            Self::NotFound => None,
        }
    }
}

impl Resolver {
    /// A resolver using `config`.
    pub fn new(config: Config) -> Self {
        Self {
            config: Arc::new(config),
        }
    }

    /// A resolver configured like the system's: name servers and search
    /// domains from `/etc/resolv.conf`, static entries from `/etc/hosts` if
    /// it can be read.
    pub fn from_system_conf() -> io::Result<Self> {
        let resolv_conf = std::fs::read("/etc/resolv.conf")?;
        let mut config = Config::from_resolv_conf(&resolv_conf)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
        if let Ok(hosts) = std::fs::read("/etc/hosts") {
            config.hosts = Hosts::parse(&hosts);
        }
        Ok(Self::new(config))
    }

    /// The IPv4 and then the IPv6 addresses of `host`, which may also be an
    /// IP address itself.
    pub async fn lookup_ip(&self, host: &str) -> Result<Vec<IpAddr>, Error> {
        if let Ok(ip) = host.parse() {
            return Ok(vec![ip]);
        }
        let name = Name::from_ascii(host).map_err(Error::InvalidName)?;
        let mut resolver = sansio_dns::Resolver::new(Config::clone(&self.config));
        let mut lookup =
            IpLookup::start(&mut resolver, name, Instant::now()).map_err(Error::InvalidName)?;
        let (input, mut received) = mpsc::unbounded_channel();
        let mut io = Io {
            tasks: JoinSet::new(),
            sockets: HashMap::new(),
            streams: HashMap::new(),
            input,
        };
        loop {
            while let Some(transmit) = resolver.poll_transmit() {
                if let Some(closed) = io.send(transmit).await {
                    resolver.handle_stream_closed(closed, Instant::now());
                }
            }
            while let Some(event) = resolver.poll_event() {
                lookup.handle_event(&event);
            }
            if let Some(result) = lookup.result() {
                let addresses = result.map_err(Error::Resolve)?;
                return if addresses.is_empty() {
                    Err(Error::NotFound)
                } else {
                    Ok(addresses)
                };
            }
            let deadline = resolver.poll_timeout();
            tokio::select! {
                Some(input) = received.recv() => match input {
                    Input::Datagram(query, from, data) => {
                        resolver.handle_datagram(query, from, &data, Instant::now());
                    }
                    Input::Stream(connection, data) => {
                        resolver.handle_stream_data(connection, &data, Instant::now());
                    }
                    Input::Closed(connection) => {
                        resolver.handle_stream_closed(connection, Instant::now());
                    }
                },
                () = sleep_until(deadline) => resolver.handle_timeout(Instant::now()),
            }
        }
    }
}

async fn sleep_until(deadline: Option<Instant>) {
    match deadline {
        Some(deadline) => tokio::time::sleep_until(deadline.into()).await,
        None => std::future::pending().await,
    }
}

/// What the socket and connection tasks report back to the lookup.
enum Input {
    Datagram(QueryId, SocketAddr, Vec<u8>),
    Stream(ConnectionId, Vec<u8>),
    Closed(ConnectionId),
}

/// The sockets and connections of one lookup. Dropping it aborts their tasks.
struct Io {
    tasks: JoinSet<()>,
    sockets: HashMap<QueryId, Arc<UdpSocket>>,
    streams: HashMap<ConnectionId, (mpsc::UnboundedSender<Vec<u8>>, AbortHandle)>,
    input: mpsc::UnboundedSender<Input>,
}

impl Io {
    /// Carry out `transmit`. Returns a connection to report as closed, when
    /// a write finds it already gone.
    async fn send(&mut self, transmit: Transmit) -> Option<ConnectionId> {
        match transmit.transport {
            Transport::Udp(query) => {
                // A datagram that can't be sent is lost like any other: the
                // query times out and moves on to the next server.
                if let Ok(socket) = self.socket(query, transmit.destination).await {
                    socket
                        .send_to(&transmit.payload, transmit.destination)
                        .await
                        .ok();
                }
                None
            }
            Transport::TcpConnect(connection) => {
                let (writes, queued) = mpsc::unbounded_channel();
                let task = stream(
                    connection,
                    transmit.destination,
                    transmit.payload,
                    queued,
                    self.input.clone(),
                );
                let handle = self.tasks.spawn(task);
                self.streams.insert(connection, (writes, handle));
                None
            }
            Transport::TcpWrite(connection) => {
                let sent = self
                    .streams
                    .get(&connection)
                    .is_some_and(|(writes, _)| writes.send(transmit.payload).is_ok());
                (!sent).then_some(connection)
            }
            Transport::TcpClose(connection) => {
                if let Some((_, task)) = self.streams.remove(&connection) {
                    task.abort();
                }
                None
            }
        }
    }

    /// The socket for `query`, bound on first use, with a task forwarding
    /// what it receives.
    async fn socket(&mut self, query: QueryId, to: SocketAddr) -> io::Result<Arc<UdpSocket>> {
        if let Entry::Occupied(entry) = self.sockets.entry(query) {
            return Ok(Arc::clone(entry.get()));
        }
        let any = match to {
            SocketAddr::V4(_) => IpAddr::V4(Ipv4Addr::UNSPECIFIED),
            SocketAddr::V6(_) => IpAddr::V6(Ipv6Addr::UNSPECIFIED),
        };
        let socket = Arc::new(UdpSocket::bind((any, 0)).await?);
        self.tasks
            .spawn(datagrams(query, Arc::clone(&socket), self.input.clone()));
        self.sockets.insert(query, Arc::clone(&socket));
        Ok(socket)
    }
}

/// Forward every datagram `socket` receives, until the lookup is over.
async fn datagrams(query: QueryId, socket: Arc<UdpSocket>, input: mpsc::UnboundedSender<Input>) {
    loop {
        let mut data = Vec::with_capacity(4096);
        let Ok((_, from)) = socket.recv_buf_from(&mut data).await else {
            return;
        };
        if input.send(Input::Datagram(query, from, data)).is_err() {
            return;
        }
    }
}

/// Open a connection, send `first` on it, then forward what it reads and
/// write what is queued, until either side closes.
async fn stream(
    connection: ConnectionId,
    to: SocketAddr,
    first: Vec<u8>,
    queued: mpsc::UnboundedReceiver<Vec<u8>>,
    input: mpsc::UnboundedSender<Input>,
) {
    // However the connection ended, the resolver only needs to know it did.
    let _ended = carry(connection, to, first, queued, &input).await;
    input.send(Input::Closed(connection)).ok();
}

async fn carry(
    connection: ConnectionId,
    to: SocketAddr,
    first: Vec<u8>,
    mut queued: mpsc::UnboundedReceiver<Vec<u8>>,
    input: &mpsc::UnboundedSender<Input>,
) -> io::Result<()> {
    let mut stream = TcpStream::connect(to).await?;
    stream.write_all(&first).await?;
    loop {
        let mut data = Vec::with_capacity(4096);
        tokio::select! {
            read = stream.read_buf(&mut data) => {
                if read? == 0 || input.send(Input::Stream(connection, data)).is_err() {
                    return Ok(());
                }
            }
            Some(payload) = queued.recv() => stream.write_all(&payload).await?,
        }
    }
}
