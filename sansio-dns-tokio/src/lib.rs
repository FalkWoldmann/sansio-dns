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
//! until they have been idle for `Config::idle_timeout`, with Nagle's
//! algorithm off so pipelined queries go out at once (RFC 7766 §6.2.1.1).
//! Each UDP query gets a fresh socket of its own (RFC 5452 §9.2), connected
//! to its server, and a new one when it moves to another server: the
//! kernel then only delivers datagrams from that server to the address the
//! query was sent from (§9.1), and reports an ICMP error such as port
//! unreachable, which moves the query on at once. Dropping a lookup's future
//! cancels its queries.
//!
//! The background task's [`sansio_dns::Resolver`] caches failures and
//! negative answers (see `sansio_dns`'s crate docs), so a lookup that just
//! failed fails again at once for a second or more. Call
//! [`Resolver::flush_cache`] when the host's network changes.
//!
//! The task runs on the runtime of the lookup that started it, so keep a
//! resolver within one runtime. Used from several, a lookup waits on
//! whichever runtime runs the task, and a current-thread runtime only runs
//! it while some thread is blocked on it: while that runtime sits idle,
//! lookups from the others hang. When the task's runtime shuts down, the
//! next lookup, or one that was waiting on it, starts a new task on its own
//! runtime; only a stopped task is ever replaced. Connections and queries
//! in flight on a stopped task are lost. A waiting lookup that finds its
//! stopped task already replaced by one that still runs gets a task of its
//! own, not shared with the clones, which ends with that lookup. The shared
//! task ends when the last clone is dropped: a lookup borrows its resolver
//! (and reqwest's holds a clone), so no lookup can outlive every clone and
//! keep it going. Before it ends, it closes its connections, over TLS
//! after the close_notify alert (RFC 8446 §6.1), and gives them up to five
//! seconds to finish.
//!
//! The `tls` feature turns on `sansio_dns`'s, for DNS over TLS through
//! `Config::with_tls`.
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

use std::borrow::Cow;
use std::collections::HashMap;
use std::collections::hash_map::Entry;
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, Instant};

use idna::uts46::{AsciiDenyList, DnsLength, Hyphens, Uts46};
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
    /// restarted it on its own runtime: it panicked, or that runtime shut
    /// down while another one polled the lookup.
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
    /// it can be read. Without `/etc/resolv.conf`, the local host is asked,
    /// as glibc does; any other error reading it is returned.
    pub fn from_system_conf() -> io::Result<Self> {
        let resolv_conf = match std::fs::read("/etc/resolv.conf") {
            Err(e) if e.kind() == io::ErrorKind::NotFound => Vec::new(),
            read => read?,
        };
        let mut config = Config::from_resolv_conf(&resolv_conf);
        if let Ok(hosts) = std::fs::read("/etc/hosts") {
            config.hosts = Hosts::parse(&hosts);
        }
        Ok(Self::new(config))
    }

    /// The addresses of `host`, which may also be an IP address itself, in
    /// the families and order of `Config::ip_strategy` (by default IPv6
    /// first).
    ///
    /// A name with non-ASCII characters is converted to its ASCII form as a
    /// whole, by UTS 46 non-transitional processing, as browsers and the
    /// WHATWG URL standard do: it is mapped (lowercased, normalized to NFC,
    /// and the ideographic and full-width full stops become dots), checked
    /// (combining marks, CONTEXTJ, the Bidi rule of RFC 5893 across the
    /// whole name, DNS lengths) and its labels converted to A-labels, so
    /// `bücher。example` asks for `xn--bcher-kva.example`. A U-label with
    /// `--` in its third and fourth positions is rejected (RFC 5891 §5.4);
    /// other hyphens and `_` are allowed. UTS 46 accepts some code points
    /// that IDNA2008 marks DISALLOWED, such as symbols (`☃.example`), which
    /// RFC 5891 §5.4 asks a lookup to reject; such names are looked up as
    /// browsers look them up.
    ///
    /// An ASCII name is used as given, in its case (RFC 4343 §4), so names
    /// like `my_host.example` and `r3---sn-abc.example` work too. If one of
    /// its labels starts with `xn--`, the name must pass the same checks,
    /// so each such label must be a valid A-label (RFC 5891 §5.3).
    ///
    /// # Errors
    ///
    /// [`Error::InvalidName`] for a host that is neither an IP address nor
    /// a valid name: empty or `.`; one to four dotted numbers that aren't
    /// an IP address, the forms `inet_aton` reads as IPv4, such as
    /// `127.1`, `01.2.3.4` or `0x7f.0.0.1`, or would but for a part out of
    /// range, such as `1.2.3.256` (RFC 1123 §2.1: no host name has them,
    /// since its top-level label is alphabetic); an absolute name whose
    /// last label is all digits; a host with a `\`, which no host name has
    /// and which would otherwise be read as a master-file escape; a name
    /// that fails the IDNA checks above, or a label or name too long for
    /// DNS. A relative name of five or more numbers, or one with a last
    /// label of digits, is looked up, since a search domain may complete
    /// it. IPv6 addresses with a zone (`fe80::1%eth0`) aren't accepted
    /// either.
    pub async fn lookup_ip(&self, host: &str) -> Result<Vec<IpAddr>, Error> {
        if let Ok(ip) = host.parse() {
            return Ok(vec![ip]);
        }
        let name = host_name(host).map_err(Error::InvalidName)?;
        // A task that stops with its runtime drops the lookup unanswered;
        // the second try runs on a task of this lookup's own runtime.
        let mut stopped = None;
        for _ in 0..2 {
            let (reply, answer) = oneshot::channel();
            let id = self.shared.next_lookup.fetch_add(1, Ordering::Relaxed);
            let request = Request::Lookup {
                id,
                name: name.clone(),
                reply,
            };
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
            // The task is gone, so there's nothing to cancel; its channel
            // tells the retry which task to replace.
            stopped = cancel.requests.take();
        }
        Err(Error::Stopped)
    }

    /// Forget the failures and negative answers the resolver has cached,
    /// and which name servers failed to answer recently: call it when the
    /// host's network changes, such as on a new address or default route,
    /// since what failed or didn't exist on the old network may work on the
    /// new one. Lookups started after this call don't see the old entries;
    /// lookups in flight go on. Without a running background task there is
    /// nothing to forget.
    pub fn flush_cache(&self) {
        let task = self
            .shared
            .task
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        if let Some(requests) = &*task {
            // A task that stopped with its runtime took its cache with it.
            requests.send(Request::FlushCache).ok();
        }
    }
}

/// `host`, which isn't an IP address, as the name to look up; see
/// [`Resolver::lookup_ip`].
fn host_name(host: &str) -> Result<Name, ProtoError> {
    let labels = host.strip_suffix('.').unwrap_or(host);
    if labels.is_empty() {
        return Err(ProtoError::Message("empty host name"));
    }
    // `Name::from_ascii` reads `\` as a master-file escape, so the labels
    // checked here wouldn't be the ones sent.
    if host.contains('\\') {
        return Err(ProtoError::Message("a backslash in a host name"));
    }
    let ascii = if host.is_ascii() {
        if labels.split('.').any(|label| {
            label
                .get(..4)
                .is_some_and(|prefix| prefix.eq_ignore_ascii_case("xn--"))
        }) {
            to_ascii(host)?;
        }
        Cow::Borrowed(host)
    } else {
        to_ascii(host)?
    };
    if is_numeric(&ascii) {
        return Err(ProtoError::Message(
            "dotted numbers that aren't an IP address, or a last label of digits",
        ));
    }
    Name::from_ascii(&*ascii)
}

/// `host` converted by UTS 46 non-transitional processing, with no ASCII
/// character denied and no hyphen rule of its own, then checked for the
/// one hyphen rule of RFC 5891 §5.4: no `--` in the third and fourth
/// positions of a U-label.
fn to_ascii(host: &str) -> Result<Cow<'_, str>, ProtoError> {
    let ascii = Uts46::new()
        .to_ascii(
            host.as_bytes(),
            AsciiDenyList::EMPTY,
            Hyphens::Allow,
            DnsLength::VerifyAllowRootDot,
        )
        .map_err(|_| ProtoError::Message("not a valid internationalized domain name"))?;
    let hyphens = ascii
        .split('.')
        .filter_map(|label| label.strip_prefix("xn--"))
        .filter_map(idna::punycode::decode)
        .any(|label| label.get(2..4) == Some(&['-', '-']));
    if hyphens {
        return Err(ProtoError::Message(
            "a label has \"--\" in its third and fourth positions",
        ));
    }
    Ok(ascii)
}

/// Whether `host` is one to four numbers, decimal or hexadecimal, the form
/// of an IPv4 address to `inet_aton`, or is absolute with a last label of
/// digits: no host name has either form, since its top-level label is
/// alphabetic (RFC 1123 §2.1).
fn is_numeric(host: &str) -> bool {
    let trimmed = host.strip_suffix('.');
    let absolute = trimmed.is_some();
    let labels = trimmed.unwrap_or(host);
    let digits = |label: &str| !label.is_empty() && label.bytes().all(|b| b.is_ascii_digit());
    let number = |label: &str| {
        let hex = label
            .strip_prefix("0x")
            .or_else(|| label.strip_prefix("0X"));
        hex.map_or_else(
            || digits(label),
            |hex| hex.bytes().all(|b| b.is_ascii_hexdigit()),
        )
    };
    let last = labels.rsplit('.').next().unwrap_or(labels);
    let parts = labels.split('.').count();
    ((1..=4).contains(&parts) && labels.split('.').all(number)) || (absolute && digits(last))
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
    /// behind `stale` stopped without answering. The new task is used for
    /// this lookup in any case, and becomes the shared one when the shared
    /// slot:
    ///
    /// - is empty or still holds `stale`: nobody replaced it yet;
    /// - holds a task that has stopped since: it's no better than `stale`.
    ///
    /// If another lookup already replaced it with a live task, possibly on
    /// a runtime that sits idle, that one stays shared, and the new task
    /// serves only this lookup and ends with it.
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
    /// Empty the resolver's cache.
    FlushCache,
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
        grace: JoinSet::new(),
        sockets: HashMap::new(),
        streams: HashMap::new(),
        ended: Vec::new(),
        input,
    };
    let mut lookups: HashMap<u64, Running> = HashMap::new();
    let mut owners: HashMap<QueryId, u64> = HashMap::new();
    loop {
        while io.tasks.try_join_next().is_some() {}
        while io.grace.try_join_next().is_some() {}
        // Sending can queue events, and handling an event can queue
        // transmits: a lookup moving on to its next search candidate.
        let mut busy = true;
        while busy {
            busy = false;
            while let Some(transmit) = resolver.poll_transmit() {
                busy = true;
                let to = transmit.destination;
                if let Err((query, error)) = io.send(transmit).await {
                    resolver.handle_udp_error(query, to, error, Instant::now());
                }
            }
            while let Some(event) = resolver.poll_event() {
                busy = true;
                let (Event::Response { query, .. } | Event::Failed { query, .. }) = &event;
                io.forget(*query);
                let Some(running) = owners.remove(query).and_then(|id| {
                    let running = lookups.remove(&id)?;
                    Some((id, running))
                }) else {
                    continue;
                };
                let (id, Running { lookup, reply }) = running;
                match lookup.handle_event(&mut resolver, &event, Instant::now()) {
                    Progress::Waiting(lookup) => {
                        // Moving on to the next search candidate starts new
                        // queries.
                        owners.extend(lookup.queries().map(|query| (query, id)));
                        lookups.insert(id, Running { lookup, reply });
                    }
                    Progress::Done(result) => {
                        reply.send(outcome(result)).ok();
                    }
                }
            }
        }
        io.drop_ended();
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
                Some(Request::FlushCache) => resolver.flush_cache(),
                None => {
                    resolver.shutdown();
                    while let Some(transmit) = resolver.poll_transmit() {
                        io.send(transmit).await.ok();
                    }
                    io.close().await;
                    return;
                }
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
        Input::UdpError(query, to, error) => {
            resolver.handle_udp_error(query, to, error, Instant::now());
        }
        Input::Stream(connection, data) => {
            resolver.handle_stream_data(connection, &data, Instant::now());
        }
        Input::Closed(connection, ended) => {
            io.ended.push(connection);
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

/// How long a connection that has ended gets to write what is queued on it
/// and shut down before its task is aborted.
const CLOSE_GRACE: Duration = Duration::from_secs(5);

/// What the socket and connection tasks report back to the background task.
enum Input {
    Datagram(QueryId, SocketAddr, Vec<u8>),
    /// Receiving on the query's socket, connected to this server, failed:
    /// typically an ICMP error for an earlier datagram.
    UdpError(QueryId, SocketAddr, io::ErrorKind),
    Stream(ConnectionId, Vec<u8>),
    /// The connection ended: closed by the server, or with an I/O error.
    /// Its task still writes what the resolver queues for it until its
    /// write queue is dropped.
    Closed(ConnectionId, Result<(), io::ErrorKind>),
}

/// The sockets and connections of the background task. Dropping it aborts
/// their tasks.
struct Io {
    tasks: JoinSet<()>,
    /// Timers that abort the tasks of connections that take longer than
    /// `CLOSE_GRACE` to close.
    grace: JoinSet<()>,
    /// Each query's socket, the server it is connected to, and the task
    /// forwarding what it receives.
    sockets: HashMap<QueryId, (Arc<UdpSocket>, SocketAddr, AbortHandle)>,
    streams: HashMap<ConnectionId, Stream>,
    /// Connections whose task reported their end. Their write queues are
    /// dropped once the transmits queued before the report are carried
    /// out: over TLS, those can hold the resolver's reply to the server's
    /// close_notify.
    ended: Vec<ConnectionId>,
    input: mpsc::UnboundedSender<Input>,
}

/// A connection's write queue and task.
struct Stream {
    writes: mpsc::UnboundedSender<Vec<u8>>,
    task: AbortHandle,
    /// Whether connecting has finished: until then nothing written to it
    /// has gone out, so closing it may abort the task at once.
    connected: Arc<AtomicBool>,
}

impl Io {
    /// Carry out `transmit`. Fails with its query if a datagram's socket
    /// can't be bound or the datagram can't be sent; stream failures are
    /// reported by the connection's task.
    async fn send(&mut self, transmit: Transmit) -> Result<(), (QueryId, io::ErrorKind)> {
        match transmit.transport {
            Transport::Udp(query) => {
                return self
                    .send_datagram(query, transmit.destination, &transmit.payload)
                    .await
                    .map_err(|error| (query, error.kind()));
            }
            Transport::TcpConnect(connection) => {
                let (writes, queued) = mpsc::unbounded_channel();
                let connected = Arc::new(AtomicBool::new(false));
                let task = stream(
                    connection,
                    transmit.destination,
                    transmit.payload,
                    queued,
                    Arc::clone(&connected),
                    self.input.clone(),
                );
                let task = self.tasks.spawn(task);
                let stream = Stream {
                    writes,
                    task,
                    connected,
                };
                self.streams.insert(connection, stream);
            }
            // If the connection's task has ended, it reports how; the
            // payload is lost with it.
            Transport::TcpWrite(connection) => {
                if let Some(stream) = self.streams.get(&connection) {
                    stream.writes.send(transmit.payload).ok();
                }
            }
            Transport::TcpClose(connection) => {
                if let Some(stream) = self.streams.remove(&connection) {
                    self.close_stream(stream);
                }
            }
        }
        Ok(())
    }

    /// Close a connection the resolver is done with. Dropping the write
    /// queue lets the task write what is queued, with TLS the close_notify
    /// alert last (RFC 8446 §6.1), and then shut the stream down. A server
    /// that stops reading can't keep it open past `CLOSE_GRACE`. A
    /// connection still connecting has sent nothing yet: its task is
    /// aborted at once.
    fn close_stream(&mut self, stream: Stream) {
        let Stream {
            writes,
            task,
            connected,
        } = stream;
        drop(writes);
        if connected.load(Ordering::Acquire) {
            self.grace.spawn(async move {
                tokio::time::sleep(CLOSE_GRACE).await;
                task.abort();
            });
        } else {
            task.abort();
        }
    }

    /// Drop the write queues of the connections that reported their end,
    /// now that the transmits queued for them before the report are
    /// carried out, so their tasks finish.
    fn drop_ended(&mut self) {
        for connection in std::mem::take(&mut self.ended) {
            if let Some(stream) = self.streams.remove(&connection) {
                self.close_stream(stream);
            }
        }
    }

    /// Stop: close every socket and connection, giving the connections up
    /// to `CLOSE_GRACE` to write what is queued on them, then abort what is
    /// left. Called once the resolver's last transmits, which close its
    /// connections, are carried out.
    async fn close(mut self) {
        for (_, (_, _, task)) in self.sockets.drain() {
            task.abort();
        }
        self.ended.clear();
        let streams: Vec<Stream> = self.streams.drain().map(|(_, stream)| stream).collect();
        for stream in streams {
            self.close_stream(stream);
        }
        let tasks = &mut self.tasks;
        tokio::time::timeout(CLOSE_GRACE, async {
            while tasks.join_next().await.is_some() {}
        })
        .await
        .ok();
    }

    async fn send_datagram(
        &mut self,
        query: QueryId,
        to: SocketAddr,
        payload: &[u8],
    ) -> io::Result<()> {
        self.socket(query, to).await?.send(payload).await?;
        Ok(())
    }

    /// The socket for `query`, connected to `to`, with a task forwarding
    /// what it receives. A query that moves to another server gets a new
    /// socket rather than connecting its old one again: Linux keeps the
    /// local address the first connect picked, which may not reach the new
    /// server.
    async fn socket(&mut self, query: QueryId, to: SocketAddr) -> io::Result<Arc<UdpSocket>> {
        if let Entry::Occupied(entry) = self.sockets.entry(query) {
            let (socket, peer, _) = entry.get();
            if *peer == to {
                return Ok(Arc::clone(socket));
            }
            entry.remove().2.abort();
        }
        let any = match to {
            SocketAddr::V4(_) => IpAddr::V4(Ipv4Addr::UNSPECIFIED),
            SocketAddr::V6(_) => IpAddr::V6(Ipv6Addr::UNSPECIFIED),
        };
        let socket = Arc::new(UdpSocket::bind((any, 0)).await?);
        socket.connect(to).await?;
        let task = self.tasks.spawn(datagrams(
            query,
            Arc::clone(&socket),
            to,
            self.input.clone(),
        ));
        self.sockets.insert(query, (Arc::clone(&socket), to, task));
        Ok(socket)
    }

    /// Close the socket of `query`, which is over.
    fn forget(&mut self, query: QueryId) {
        if let Some((_, _, task)) = self.sockets.remove(&query) {
            task.abort();
        }
    }
}

/// Forward every datagram `socket`, connected to `server`, receives, and
/// every error receiving reports, until its query is over. Each datagram is
/// copied out at its size, so a queue of them holds no spare capacity. An
/// error, such as an ICMP port unreachable for the last datagram, doesn't
/// end the socket: it serves the query's attempts to `server` until one
/// goes to another server.
async fn datagrams(
    query: QueryId,
    socket: Arc<UdpSocket>,
    server: SocketAddr,
    input: mpsc::UnboundedSender<Input>,
) {
    let mut buf = [0; 4096];
    loop {
        let received = match socket.recv_from(&mut buf).await {
            Ok((n, from)) => {
                let data = buf.get(..n).map(<[u8]>::to_vec).unwrap_or_default();
                Input::Datagram(query, from, data)
            }
            Err(error) => Input::UdpError(query, server, error.kind()),
        };
        if input.send(received).is_err() {
            return;
        }
    }
}

/// Open a connection, send `first` on it, then forward what it reads and
/// write what is queued, until either side closes. Once the resolver has
/// closed it and everything queued is written, shut the writing side down
/// and read until the server closes too. Once the server has closed it or
/// it failed, report that, and still write what the resolver queues for
/// it until the queue is dropped: over TLS, the resolver answers the
/// server's close_notify with its own (RFC 8446 §6.1).
async fn stream(
    connection: ConnectionId,
    to: SocketAddr,
    first: Vec<u8>,
    mut queued: mpsc::UnboundedReceiver<Vec<u8>>,
    connected: Arc<AtomicBool>,
    input: mpsc::UnboundedSender<Input>,
) {
    let report = |ended: io::Result<()>| {
        input
            .send(Input::Closed(connection, ended.map_err(|e| e.kind())))
            .ok();
    };
    let mut tcp = match TcpStream::connect(to).await {
        Ok(tcp) => tcp,
        Err(error) => return report(Err(error)),
    };
    connected.store(true, Ordering::Release);
    let mut buf = [0; 4096];
    match carry(connection, &mut tcp, first, &mut queued, &input, &mut buf).await {
        Ended::ByResolver => {
            if tcp.shutdown().await.is_ok() {
                while tcp.read(&mut buf).await.is_ok_and(|n| n > 0) {}
            }
        }
        Ended::ByServer(ended) => {
            report(ended);
            while let Some(payload) = queued.recv().await {
                if tcp.write_all(&payload).await.is_err() {
                    return;
                }
            }
            tcp.shutdown().await.ok();
        }
        Ended::Stopped => {}
    }
}

/// How [`carry`] ended.
enum Ended {
    /// The resolver closed the connection, and everything it queued is
    /// written.
    ByResolver,
    /// The server closed the connection, or reading or writing failed.
    ByServer(io::Result<()>),
    /// The background task is gone.
    Stopped,
}

async fn carry(
    connection: ConnectionId,
    tcp: &mut TcpStream,
    first: Vec<u8>,
    queued: &mut mpsc::UnboundedReceiver<Vec<u8>>,
    input: &mpsc::UnboundedSender<Input>,
    buf: &mut [u8],
) -> Ended {
    // Each payload is one whole message, written in one call (RFC 7766
    // §8); without Nagle a pipelined one goes out before the answers to the
    // earlier ones are in (§6.2.1.1).
    if let Err(error) = tcp.set_nodelay(true) {
        return Ended::ByServer(Err(error));
    }
    if let Err(error) = tcp.write_all(&first).await {
        return Ended::ByServer(Err(error));
    }
    loop {
        tokio::select! {
            read = tcp.read(buf) => match read {
                Ok(0) => return Ended::ByServer(Ok(())),
                Ok(n) => {
                    let data = buf.get(..n).map(<[u8]>::to_vec).unwrap_or_default();
                    if input.send(Input::Stream(connection, data)).is_err() {
                        return Ended::Stopped;
                    }
                }
                Err(error) => return Ended::ByServer(Err(error)),
            },
            payload = queued.recv() => match payload {
                Some(payload) => {
                    if let Err(error) = tcp.write_all(&payload).await {
                        return Ended::ByServer(Err(error));
                    }
                }
                None => return Ended::ByResolver,
            },
        }
    }
}
