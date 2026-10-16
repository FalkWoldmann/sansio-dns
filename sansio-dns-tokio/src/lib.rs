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
//! Clones of a [`Resolver`] share one [`sansio_dns::Resolver`], run by a
//! background task that the first lookup spawns on its runtime. TCP and TLS
//! connections stay open between lookups and are shared by concurrent ones,
//! until they have been idle for `Config::idle_timeout`. Each UDP query still
//! gets a fresh socket (RFC 5452 §9.2). Dropping a lookup's future cancels
//! its queries.
//!
//! The task runs on the runtime of the lookup that started it, so keep a
//! resolver within one runtime. Used from several, a lookup waits on
//! whichever runtime runs the task, and a current-thread runtime only runs
//! it while some thread is blocked on it: while that runtime sits idle,
//! lookups from the others hang. When the task's runtime shuts down, the
//! next lookup, or one that was waiting on it, starts a new task on its own
//! runtime. The task ends when the last clone is dropped.
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
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Instant;

use sansio_dns::hickory_proto::ProtoError;
use sansio_dns::hickory_proto::rr::Name;
use sansio_dns::{
    Config, ConnectionId, Event, Hosts, IpLookup, Progress, QueryId, Transmit, Transport,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};
use tokio::sync::{mpsc, oneshot};
use tokio::task::{AbortHandle, JoinSet};

/// Looks up host names with a fixed [`Config`]. Cheap to clone; clones share
/// one background task and its connections.
#[derive(Clone, Debug)]
pub struct Resolver {
    shared: Arc<Shared>,
}

#[derive(Debug)]
struct Shared {
    config: Config,
    next_lookup: AtomicU64,
    /// Where to send requests to the background task, once one runs.
    task: Mutex<Option<mpsc::UnboundedSender<Request>>>,
}

/// Why a lookup found no addresses.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    /// The host is neither an IP address nor a valid domain name.
    #[error("invalid host name: {0}")]
    InvalidName(#[source] ProtoError),
    /// No name server gave a usable answer.
    #[error("{0}")]
    Resolve(#[source] sansio_dns::Error),
    /// The name exists but has no addresses, or doesn't exist.
    #[error("no addresses found")]
    NotFound,
    /// The background task stopped without answering, even after the lookup
    /// restarted it on its own runtime: it panicked.
    #[error("resolver task stopped before answering")]
    Stopped,
}

impl Resolver {
    /// A resolver using `config`. Its task starts with the first lookup.
    pub fn new(config: Config) -> Self {
        Self {
            shared: Arc::new(Shared {
                config,
                next_lookup: AtomicU64::new(0),
                task: Mutex::new(None),
            }),
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
        // A task that stops with its runtime drops the lookup unanswered;
        // the second try runs on a task of this lookup's own runtime.
        let mut stopped = None;
        for _ in 0..2 {
            let name = Name::from_ascii(host).map_err(Error::InvalidName)?;
            let (reply, answer) = oneshot::channel();
            let id = self.shared.next_lookup.fetch_add(1, Ordering::Relaxed);
            let request = Request::Lookup { id, name, reply };
            let requests = match &stopped {
                None => self.shared.send(request),
                Some(stale) => self.shared.restart(stale, request),
            };
            let mut cancel = CancelOnDrop {
                id,
                requests: Some(requests),
            };
            if let Ok(result) = answer.await {
                cancel.requests = None;
                return result;
            }
            stopped = cancel.requests.take();
        }
        Err(Error::Stopped)
    }
}

impl Shared {
    /// Hand `request` to the background task, starting one on the current
    /// runtime if none is running. Returns the task's request channel.
    fn send(&self, request: Request) -> mpsc::UnboundedSender<Request> {
        let mut task = self.task.lock().unwrap_or_else(PoisonError::into_inner);
        let request = match &*task {
            Some(requests) => match requests.send(request) {
                Ok(()) => return requests.clone(),
                // The task stopped with its runtime.
                Err(mpsc::error::SendError(request)) => request,
            },
            None => request,
        };
        let requests = self.spawn(request);
        *task = Some(requests.clone());
        requests
    }

    /// Hand `request` to a new task on the current runtime, since the task
    /// behind `stale` stopped without answering. Another lookup may have
    /// replaced that task already, on a runtime that might sit idle, so the
    /// new task is used either way; it becomes the shared one if `stale`'s
    /// still is.
    fn restart(
        &self,
        stale: &mpsc::UnboundedSender<Request>,
        request: Request,
    ) -> mpsc::UnboundedSender<Request> {
        let requests = self.spawn(request);
        let mut task = self.task.lock().unwrap_or_else(PoisonError::into_inner);
        if task
            .as_ref()
            .is_none_or(|current| current.same_channel(stale) || current.is_closed())
        {
            *task = Some(requests.clone());
        }
        requests
    }

    /// Start a task on the current runtime with `request` as its first.
    fn spawn(&self, request: Request) -> mpsc::UnboundedSender<Request> {
        let (requests, received) = mpsc::unbounded_channel();
        tokio::spawn(run(self.config.clone(), received));
        // The task holds the receiver, so this can't fail.
        requests.send(request).ok();
        requests
    }
}

/// What a lookup asks of the background task.
enum Request {
    Lookup {
        id: u64,
        name: Name,
        reply: oneshot::Sender<Result<Vec<IpAddr>, Error>>,
    },
    /// The lookup's future was dropped before its answer arrived.
    Cancel(u64),
}

/// Cancels the lookup `id` unless disarmed by taking `requests`.
struct CancelOnDrop {
    id: u64,
    requests: Option<mpsc::UnboundedSender<Request>>,
}

impl Drop for CancelOnDrop {
    fn drop(&mut self) {
        if let Some(requests) = self.requests.take() {
            requests.send(Request::Cancel(self.id)).ok();
        }
    }
}

/// A lookup the background task is running.
struct Running {
    lookup: IpLookup,
    reply: oneshot::Sender<Result<Vec<IpAddr>, Error>>,
}

/// The background task: run every lookup sent over `requests` on one
/// resolver, until no sender is left.
async fn run(config: Config, mut requests: mpsc::UnboundedReceiver<Request>) {
    let mut resolver = sansio_dns::Resolver::new(config);
    let (input, mut received) = mpsc::unbounded_channel();
    let mut io = Io {
        tasks: JoinSet::new(),
        sockets: HashMap::new(),
        streams: HashMap::new(),
        input,
    };
    let mut lookups: HashMap<u64, Running> = HashMap::new();
    let mut owners: HashMap<QueryId, u64> = HashMap::new();
    loop {
        while io.tasks.try_join_next().is_some() {}
        while let Some(transmit) = resolver.poll_transmit() {
            io.send(transmit).await;
        }
        while let Some(event) = resolver.poll_event() {
            let (Event::Response { query, .. } | Event::Failed { query, .. }) = &event;
            io.forget(*query);
            let Some(running) = owners.remove(query).and_then(|id| {
                let running = lookups.remove(&id)?;
                Some((id, running))
            }) else {
                continue;
            };
            let (id, Running { lookup, reply }) = running;
            match lookup.handle_event(&event) {
                Progress::Waiting(lookup) => {
                    lookups.insert(id, Running { lookup, reply });
                }
                Progress::Done(result) => {
                    reply.send(outcome(result)).ok();
                }
            }
        }
        let deadline = resolver.poll_timeout();
        tokio::select! {
            request = requests.recv() => match request {
                Some(Request::Lookup { id, name, reply }) => {
                    // Take in connections that already ended, so the new
                    // queries don't go to one of them.
                    while let Ok(input) = received.try_recv() {
                        take_in(&mut resolver, &mut io, input);
                    }
                    match IpLookup::start(&mut resolver, name, Instant::now()) {
                        Ok(lookup) => {
                            owners.extend(lookup.queries().map(|query| (query, id)));
                            lookups.insert(id, Running { lookup, reply });
                        }
                        Err(error) => {
                            reply.send(Err(Error::InvalidName(error))).ok();
                        }
                    }
                }
                Some(Request::Cancel(id)) => {
                    if let Some(Running { lookup, .. }) = lookups.remove(&id) {
                        for query in lookup.queries() {
                            resolver.cancel(query, Instant::now());
                            owners.remove(&query);
                            io.forget(query);
                        }
                    }
                }
                None => return,
            },
            Some(input) = received.recv() => take_in(&mut resolver, &mut io, input),
            () = sleep_until(deadline) => resolver.handle_timeout(Instant::now()),
        }
    }
}

/// Pass what a socket or connection task reported to the resolver.
fn take_in(resolver: &mut sansio_dns::Resolver, io: &mut Io, input: Input) {
    match input {
        Input::Datagram(query, from, data) => {
            resolver.handle_datagram(query, from, &data, Instant::now());
        }
        Input::Stream(connection, data) => {
            resolver.handle_stream_data(connection, &data, Instant::now());
        }
        Input::Closed(connection, ended) => {
            io.streams.remove(&connection);
            match ended {
                Ok(()) => resolver.handle_stream_closed(connection, Instant::now()),
                Err(error) => resolver.handle_stream_error(connection, error, Instant::now()),
            }
        }
    }
}

/// A finished lookup's addresses, or why there are none.
fn outcome(result: Result<Vec<IpAddr>, sansio_dns::Error>) -> Result<Vec<IpAddr>, Error> {
    let addresses = result.map_err(Error::Resolve)?;
    if addresses.is_empty() {
        Err(Error::NotFound)
    } else {
        Ok(addresses)
    }
}

async fn sleep_until(deadline: Option<Instant>) {
    match deadline {
        Some(deadline) => tokio::time::sleep_until(deadline.into()).await,
        None => std::future::pending().await,
    }
}

/// What the socket and connection tasks report back to the background task.
enum Input {
    Datagram(QueryId, SocketAddr, Vec<u8>),
    Stream(ConnectionId, Vec<u8>),
    /// The connection ended: closed by the server, or with an I/O error.
    Closed(ConnectionId, Result<(), io::ErrorKind>),
}

/// The sockets and connections of the background task. Dropping it aborts
/// their tasks.
struct Io {
    tasks: JoinSet<()>,
    sockets: HashMap<QueryId, (Arc<UdpSocket>, AbortHandle)>,
    streams: HashMap<ConnectionId, (mpsc::UnboundedSender<Vec<u8>>, AbortHandle)>,
    input: mpsc::UnboundedSender<Input>,
}

impl Io {
    /// Carry out `transmit`.
    async fn send(&mut self, transmit: Transmit) {
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
            }
            // If the connection's task has ended, it reports how; the
            // payload is lost with it.
            Transport::TcpWrite(connection) => {
                if let Some((writes, _)) = self.streams.get(&connection) {
                    writes.send(transmit.payload).ok();
                }
            }
            Transport::TcpClose(connection) => {
                if let Some((_, task)) = self.streams.remove(&connection) {
                    task.abort();
                }
            }
        }
    }

    /// The socket for `query`, bound on first use and again when the query
    /// moves to a server of the other address family, with a task
    /// forwarding what it receives.
    async fn socket(&mut self, query: QueryId, to: SocketAddr) -> io::Result<Arc<UdpSocket>> {
        if let Entry::Occupied(entry) = self.sockets.entry(query) {
            let (socket, _) = entry.get();
            if socket
                .local_addr()
                .is_ok_and(|local| local.is_ipv4() == to.is_ipv4())
            {
                return Ok(Arc::clone(socket));
            }
            // A retry rotated to a server of the other address family.
            entry.remove().1.abort();
        }
        let any = match to {
            SocketAddr::V4(_) => IpAddr::V4(Ipv4Addr::UNSPECIFIED),
            SocketAddr::V6(_) => IpAddr::V6(Ipv6Addr::UNSPECIFIED),
        };
        let socket = Arc::new(UdpSocket::bind((any, 0)).await?);
        let task = self
            .tasks
            .spawn(datagrams(query, Arc::clone(&socket), self.input.clone()));
        self.sockets.insert(query, (Arc::clone(&socket), task));
        Ok(socket)
    }

    /// Close the socket of `query`, which is over.
    fn forget(&mut self, query: QueryId) {
        if let Some((_, task)) = self.sockets.remove(&query) {
            task.abort();
        }
    }
}

/// Forward every datagram `socket` receives, until its query is over. Each
/// is copied out at its size, so a queue of them holds no spare capacity.
async fn datagrams(query: QueryId, socket: Arc<UdpSocket>, input: mpsc::UnboundedSender<Input>) {
    let mut buf = [0; 4096];
    loop {
        let Ok((n, from)) = socket.recv_from(&mut buf).await else {
            return;
        };
        let data = buf.get(..n).map(<[u8]>::to_vec).unwrap_or_default();
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
    let ended = carry(connection, to, first, queued, &input).await;
    input
        .send(Input::Closed(connection, ended.map_err(|e| e.kind())))
        .ok();
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
    let mut buf = [0; 4096];
    loop {
        tokio::select! {
            read = stream.read(&mut buf) => {
                let data = buf.get(..read?).map(<[u8]>::to_vec).unwrap_or_default();
                if data.is_empty() || input.send(Input::Stream(connection, data)).is_err() {
                    return Ok(());
                }
            }
            Some(payload) = queued.recv() => stream.write_all(&payload).await?,
        }
    }
}
