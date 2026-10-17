//! The resolver state machine: queries in flight, stream connections, and
//! how a query moves on.

use std::collections::{BTreeMap, VecDeque};
use std::io;
use std::net::SocketAddr;
use std::time::Instant;

use hickory_proto::ProtoError;
use hickory_proto::op::{Edns, Message, Query, ResponseCode};
use hickory_proto::rr::{Name, RecordType};

use crate::config::MAX_SENDS_PER_SERVER;
#[cfg(feature = "tls")]
use crate::tls;
#[cfg(feature = "tls")]
use crate::wire::pad;
use crate::wire::{
    EDNS_PAYLOAD, Reply, clamp_ttls, frame, has_data, is_meta_type, is_referral, is_special_use,
    special_use,
};
use crate::{Config, ConnectionId, Error, Event, QueryId, Transmit, Transport};

/// How many requests that left a connection unanswered (`Orphan`s) it may
/// hold. One more closes it, which frees their message IDs: a server that
/// drops some queries on a busy connection, which never goes idle, would
/// otherwise use up the ID space (RFC 7766 §6.2.1, §6.2.4).
const MAX_ORPHANS: usize = 256;

#[derive(Debug)]
struct Pending {
    request: Message,
    payload: Vec<u8>,
    /// Where in the server list its attempts start, so it skips servers
    /// that failed recently.
    first: usize,
    /// Where in the rotation its current attempt is: it goes to
    /// `Config::server(position)`. Starts at `first` and moves on by one
    /// per attempt, past the servers in `excluded`, so how often it has
    /// wrapped around is the number of rounds made.
    position: usize,
    /// How many attempts it has used up before the current one.
    attempt: usize,
    /// Servers that answered this search candidate with an error, a reply
    /// that couldn't be decoded, or a referral: later attempts skip them
    /// (RFC 1035 §7.2, RFC 1034 §5.3.3 step 4d).
    excluded: Vec<SocketAddr>,
    /// When the current attempt times out.
    deadline: Instant,
    /// How the current attempt went out; set by `Resolver::emit`.
    route: Route,
    /// Whether every send goes over a stream: after a truncated answer
    /// over UDP, for the rest of the search candidate (RFC 1123 §6.1.3.2),
    /// and always with DNS over TLS (RFC 7858 §3). Otherwise a send goes
    /// over a stream only when a connection to its server is open (RFC
    /// 7766 §5).
    stream_only: bool,
    /// How many responses had arrived on the current attempt's connection
    /// (`Connection::responses`) when the attempt was written to it, or
    /// took its request back from an `Orphan`, so that later ones show the
    /// connection still works.
    written_after: u64,
    /// How often this search candidate was sent to each server over each
    /// channel, free sends included: at most `MAX_SENDS_PER_SERVER` times
    /// (RFC 9520 §3.1).
    sends: Vec<(SocketAddr, Channel, u8)>,
    /// Search candidates still to try if this name has no data of the type
    /// asked for.
    rest: VecDeque<Name>,
    /// The first NODATA answer of an earlier search candidate: the outcome
    /// if no later one has data.
    nodata: Option<Message>,
    /// Whether its attempt was already sent again for free, after losing a
    /// connection that had answered only before it was written, or being
    /// moved off a closed one (`Resolver::time_out_stream`). The two share
    /// it: after one free resend, from either, the next one from either
    /// uses up an attempt. Reset for each search candidate; see
    /// `Resolver::forgive`. A connection lost after any response arrived on
    /// it since this query was written gives a free resend without it.
    forgiven: bool,
    /// The name and type as asked, before search domains. A later query
    /// for the same two joins this one instead of being sent. hickory's
    /// `Name` equality ignores case but not the trailing dot.
    asked: Asked,
    /// When this query's current search candidate started; joiners from
    /// after this instant don't share its failure (`Resolver::give_up`).
    started: Instant,
    /// When the query it is filed under was issued, or joined if it took
    /// over from a cancelled one (`Resolver::cancel`). One that joined after
    /// `started` starts over rather than share the failure, as a follower
    /// would.
    joined: Instant,
    /// Queries that joined this one, and when; each gets its outcome too.
    /// Every `QueryId` in flight is in exactly one place: a key of
    /// `Resolver::pending`, or one leader's followers.
    followers: Vec<(QueryId, Instant)>,
}

impl Pending {
    /// The server of the current attempt.
    fn server(&self, config: &Config) -> SocketAddr {
        config.server(self.position)
    }

    /// The deadline of the current attempt sent at `now`: `Config::timeout`,
    /// doubled each time the attempts have gone round the server list
    /// (exponential backoff, RFC 1123 §6.1.3.3), within the bounds of
    /// `Config::wait`.
    fn deadline(&self, config: &Config, now: Instant) -> Instant {
        let round = self.position.saturating_sub(self.first) / config.servers().len();
        // Only an `Instant` within minutes of the end of its range
        // overflows; the attempt then times out at once.
        now.checked_add(config.wait(round)).unwrap_or(now)
    }

    /// Whether this search candidate may be sent to `server` over `channel`
    /// once more: RFC 9520 §3.1 allows three sends in all.
    fn may_send(&self, server: SocketAddr, channel: Channel) -> bool {
        self.sends
            .iter()
            .find(|(s, c, _)| *s == server && *c == channel)
            .is_none_or(|(_, _, sent)| *sent < MAX_SENDS_PER_SERVER)
    }

    /// Count a send to `server` over `channel`.
    fn count_send(&mut self, server: SocketAddr, channel: Channel) {
        match self
            .sends
            .iter_mut()
            .find(|(s, c, _)| *s == server && *c == channel)
        {
            Some((_, _, sent)) => *sent = sent.saturating_add(1),
            None => self.sends.push((server, channel, 1)),
        }
    }
}

/// What a query asks for: the name as given, before search domains, and
/// the type.
type Asked = (Name, RecordType);

/// How a query's current attempt went out.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Route {
    /// As a datagram, from the query's own socket.
    Udp,
    /// Written to this stream connection.
    Stream(ConnectionId),
}

/// A DNS transport, as RFC 9520 §3.1 counts sends to a server: UDP, or a
/// stream, which is TCP, or TLS with DNS over TLS. A resolver uses one kind
/// of stream, so the two never mix.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Channel {
    Udp,
    Stream,
}

/// A stream connection to one server, shared by its queries.
#[derive(Debug)]
struct Connection {
    server: SocketAddr,
    /// Decrypted bytes not yet split into messages.
    received: Vec<u8>,
    /// When a query was last written to it or a complete response last
    /// arrived on it; the idle timeout counts from here once nothing is
    /// outstanding on it (RFC 7766 §6.2.3, RFC 7828 §3). Partial messages
    /// and TLS records don't count.
    last_active: Instant,
    /// How many complete responses have arrived on it, matched or not.
    responses: u64,
    /// Queries written to it that left it before their answer came.
    orphans: Vec<Orphan>,
    /// The TLS session, when using DNS over TLS.
    #[cfg(feature = "tls")]
    tls: Option<Box<rustls::ClientConnection>>,
}

/// A query that left a connection before its answer came: it was
/// cancelled, or timed out and moved on while the connection stayed open.
/// The server may still answer it, so its message ID stays in use on the
/// connection until the answer arrives, which is then dropped, or the
/// connection ends (RFC 7766 §6.2.1).
#[derive(Debug)]
struct Orphan {
    id: u16,
    question: Vec<Query>,
    /// Until when it counts as outstanding, keeping the connection from
    /// going idle: the deadline the query had.
    until: Instant,
}

impl Orphan {
    /// The orphan `pending` leaves behind on its connection.
    fn of(pending: &Pending) -> Self {
        Self {
            id: pending.request.metadata.id,
            question: pending.request.queries.clone(),
            until: pending.deadline,
        }
    }

    /// Whether it is `pending`'s own request.
    fn is(&self, pending: &Pending) -> bool {
        self.id == pending.request.metadata.id && self.question == pending.request.queries
    }
}

/// What a response on a stream answers.
#[derive(Debug)]
enum Matched {
    Query(QueryId),
    /// The orphan at this index in `Connection::orphans`.
    Orphan(usize),
}

/// Which channel a send of `pending` to `server` takes: a stream if it
/// must use one or a connection to `server` is open, UDP otherwise.
fn channel(
    connections: &BTreeMap<ConnectionId, Connection>,
    pending: &Pending,
    server: SocketAddr,
) -> Channel {
    if pending.stream_only || connections.values().any(|c| c.server == server) {
        Channel::Stream
    } else {
        Channel::Udp
    }
}

/// The resolver state machine. See the crate docs for how to drive it.
#[derive(Debug)]
pub struct Resolver {
    config: Config,
    next_query: u64,
    pending: BTreeMap<QueryId, Pending>,
    next_connection: u64,
    connections: BTreeMap<ConnectionId, Connection>,
    /// Servers whose last attempt failed without an answer, and until when
    /// new queries start after them (`Config::failure_memory`).
    failed: BTreeMap<SocketAddr, Instant>,
    transmits: VecDeque<Transmit>,
    events: VecDeque<Event>,
}

impl Resolver {
    /// A resolver with no queries in flight.
    pub fn new(config: Config) -> Self {
        Self {
            config,
            next_query: 0,
            pending: BTreeMap::new(),
            next_connection: 0,
            connections: BTreeMap::new(),
            failed: BTreeMap::new(),
            transmits: VecDeque::new(),
            events: VecDeque::new(),
        }
    }

    /// The settings it was created with.
    pub(crate) fn config(&self) -> &Config {
        &self.config
    }

    /// Start a recursive lookup of `name`/`record_type`.
    ///
    /// A name ending in a dot is used as given. Other names are tried with
    /// the [`Config::search`] domains, ordered by [`Config::ndots`], until
    /// one has data of `record_type` (RFC 1123 §6.1.4.3): the next candidate
    /// is tried after NXDOMAIN and after NODATA, a `NOERROR` answer without
    /// records of that type at the end of the CNAME chain (RFC 2308 §2.2).
    /// glibc's `res_search` moves on after NODATA only when the answer
    /// section is empty, and stops at a CNAME whose target has no data.
    /// When the candidates run out, the event carries the first NODATA
    /// answer if there was one, else the last NXDOMAIN. A query that fails
    /// on a candidate, out of attempts or servers, ends the search with
    /// that error. Without search domains, `example.com` and
    /// `example.com.` send the same question, but only a query for the same
    /// name as given (trailing dot included, case ignored) joins one in
    /// flight.
    ///
    /// Special-use names are answered at once, without a transmit:
    /// `localhost` gets the loopback address (RFC 6761 §6.3), and names
    /// under `invalid.` and `onion.` get NXDOMAIN (RFC 6761 §6.4, RFC 7686
    /// §2). Names under `local.` go to the name servers like any other:
    /// RFC 6762 §3 reserves them for mDNS, but Kubernetes (`cluster.local`)
    /// and many corporate networks serve them over unicast DNS, which is
    /// what glibc does without nss-mdns. mDNS is up to the caller.
    ///
    /// Names listed in [`Config::hosts`] are answered from there for A and
    /// AAAA queries, with the addresses of that family (possibly none), as
    /// glibc's `hosts: files dns` does. The name is matched as given, before
    /// any search domain.
    ///
    /// A query for the same name and type as one still in flight (compared
    /// as given, before search domains) joins it: nothing is sent for it,
    /// and it gets the same response or error as its own event. If the
    /// first one runs out of attempts or servers, a query that joined it
    /// after its current search candidate started starts over with
    /// attempts of its own instead of sharing the failure.
    ///
    /// # Errors
    ///
    /// If `record_type` is a zone transfer or a meta type (AXFR, IXFR, OPT,
    /// TSIG, TKEY, MAILA, MAILB, NXNAME or TYPE 0; RFC 1123 §6.1.3.2, RFC
    /// 6895 §3.1, RFC 9824 §3.5), which a stub resolver doesn't ask for;
    /// ANY is allowed (RFC 8482). Or if the query can't be encoded.
    pub fn query(
        &mut self,
        name: Name,
        record_type: RecordType,
        now: Instant,
    ) -> Result<QueryId, ProtoError> {
        self.start(name, record_type, true, now)
    }

    /// Start `record_type` for one search candidate of an
    /// [`IpLookup`](crate::IpLookup): `name` is absolute and sent as it is,
    /// without [`Config::hosts`], which the lookup checked for the name as
    /// given. It joins, and is joined by, a query for the same name.
    pub(crate) fn query_candidate(
        &mut self,
        name: Name,
        record_type: RecordType,
        now: Instant,
    ) -> Result<QueryId, ProtoError> {
        self.start(name, record_type, false, now)
    }

    /// Whether `name`, as given, is answered without the network: a
    /// special-use name, or one listed in [`Config::hosts`].
    pub(crate) fn is_local(&self, name: &Name) -> bool {
        let mut absolute = name.clone();
        absolute.set_fqdn(true);
        is_special_use(&absolute) || self.config.hosts.lookup(&absolute).is_some()
    }

    /// [`Resolver::query`], with `hosts` deciding whether
    /// [`Config::hosts`] is consulted.
    fn start(
        &mut self,
        name: Name,
        record_type: RecordType,
        hosts: bool,
        now: Instant,
    ) -> Result<QueryId, ProtoError> {
        if is_meta_type(record_type) {
            return Err(ProtoError::Message(
                "zone transfer and meta query types aren't supported",
            ));
        }
        let asked = (name.clone(), record_type);
        let mut absolute = name;
        absolute.set_fqdn(true);
        let id = QueryId(self.next_query);
        self.next_query += 1;
        let local = special_use(&absolute, record_type).or_else(|| {
            hosts
                .then(|| self.config.hosts.answer(&absolute, record_type))
                .flatten()
        });
        if let Some(response) = local {
            self.events.push_back(Event::Response {
                query: id,
                response,
            });
            return Ok(id);
        }
        if let Some(leader) = self.pending.values_mut().find(|p| p.asked == asked) {
            leader.followers.push((id, now));
            return Ok(id);
        }
        let pending = self.begin(asked, now)?;
        self.pending.insert(id, pending);
        self.emit(id, now);
        Ok(id)
    }

    /// A new query for `asked`, at its first search candidate.
    fn begin(&self, asked: Asked, now: Instant) -> Result<Pending, ProtoError> {
        let (name, record_type) = &asked;
        let mut candidates = self.config.candidates(name);
        let first = candidates.pop_front().unwrap_or_else(|| {
            let mut absolute = name.clone();
            absolute.set_fqdn(true);
            absolute
        });
        self.new_pending(first, *record_type, candidates, asked, now)
    }

    /// A fresh first attempt for `name`, with its own message ID.
    fn new_pending(
        &self,
        name: Name,
        record_type: RecordType,
        rest: VecDeque<Name>,
        asked: Asked,
        now: Instant,
    ) -> Result<Pending, ProtoError> {
        let mut request = self.new_message();
        request.metadata.recursion_desired = true;
        request.add_query(Query::query(name, record_type));
        let mut edns = Edns::new();
        edns.set_max_payload(EDNS_PAYLOAD);
        request.set_edns(edns);
        #[cfg(feature = "tls")]
        if self.config.uses_tls() {
            pad(&mut request)?;
        }
        let payload = request.to_vec()?;
        let first = self.first_server(now);
        Ok(Pending {
            request,
            payload,
            first,
            position: first,
            attempt: 0,
            excluded: Vec::new(),
            deadline: now.checked_add(self.config.wait(0)).unwrap_or(now),
            route: Route::Udp,
            stream_only: self.config.uses_tls(),
            written_after: 0,
            sends: Vec::new(),
            rest,
            nodata: None,
            forgiven: false,
            asked,
            started: now,
            joined: now,
            followers: Vec::new(),
        })
    }

    /// The first server in the list that hasn't failed within
    /// `Config::failure_memory`, or the first of all if every one has.
    fn first_server(&self, now: Instant) -> usize {
        (0..self.config.servers().len())
            .find(|&i| {
                let until = self.failed.get(&self.config.server(i));
                !until.is_some_and(|until| *until > now)
            })
            .unwrap_or(0)
    }

    /// Replace `id`'s attempt with one for its next search candidate, with
    /// fresh attempts and no servers excluded. Returns `false` if there is
    /// none, so the current answer stands.
    fn next_candidate(&mut self, id: QueryId, now: Instant) -> bool {
        let Some((name, rest, record_type, asked)) = self.pending.get_mut(&id).and_then(|p| {
            let record_type = p.request.queries.first()?.query_type();
            let name = p.rest.pop_front()?;
            Some((
                name,
                std::mem::take(&mut p.rest),
                record_type,
                p.asked.clone(),
            ))
        }) else {
            return false;
        };
        let Ok(mut next) = self.new_pending(name, record_type, rest, asked, now) else {
            return false;
        };
        if let Some(previous) = self.pending.get_mut(&id) {
            next.followers = std::mem::take(&mut previous.followers);
            next.nodata = previous.nodata.take();
            next.joined = previous.joined;
        }
        self.pending.insert(id, next);
        self.emit(id, now);
        true
    }

    /// Process a datagram received from `from` on the socket of `query`,
    /// the one its [`Transport::Udp`] transmits were sent from.
    ///
    /// Datagrams that aren't a response to that query are ignored (RFC 5452
    /// §9.1, RFC 1035 §7.3): the source must be the server of the current
    /// attempt, and message ID, opcode and question must match, the name
    /// compared case-insensitively. Spoofed answers and answers from servers
    /// tried before can't complete it, but a late answer from the current
    /// server to an earlier attempt can, since attempts keep their message
    /// ID. For the same reason a duplicated answer is acted on again: a
    /// repeated `FORMERR` without OPT, after the first one made the query
    /// drop EDNS, counts as the server's answer to the query without it.
    /// Naming the socket keeps each query's source port its own (§9.2).
    /// While the query's current attempt is on a stream, UDP replies to it
    /// are ignored.
    ///
    /// A reply whose header and question match but whose records don't
    /// decode isn't dropped (RFC 1035 §7.2's "bizarre response"): with TC
    /// set, the query switches to TCP as for any truncated answer (RFC 2181
    /// §9); otherwise it moves on to the next server at once.
    pub fn handle_datagram(&mut self, query: QueryId, from: SocketAddr, data: &[u8], now: Instant) {
        // The cheap checks first, so stray datagrams cost no parsing.
        let Some(pending) = self.pending.get(&query) else {
            return;
        };
        if pending.route != Route::Udp || pending.server(&self.config) != from {
            return;
        }
        let Some(reply) = Reply::decode(data) else {
            return;
        };
        if reply.answers(pending.request.metadata.id, &pending.request.queries) {
            self.handle_reply(query, reply, now);
        }
    }

    /// Process bytes read from `connection`.
    ///
    /// Bytes may arrive in any chunking, and answers in any order: each
    /// complete message goes to the query on this connection it answers,
    /// and is ignored if there is none (RFC 7766 §7). A response is matched
    /// by message ID and question; one without a question section is
    /// matched by message ID alone, as RFC 7766 §7 and RFC 7858 §3.3 allow,
    /// if exactly one query on the connection has that ID, and is then
    /// taken as answering that query's question. Datagrams get no such
    /// leeway (RFC 5452 §9.1). The answer to a query that left the
    /// connection before it came, cancelled or moved on after a timeout,
    /// is dropped. One whose records don't decode moves that query on to
    /// the next server, as in [`Resolver::handle_datagram`].
    ///
    /// Only a complete response counts as activity for the idle timeout
    /// and shows the connection works (RFC 7766 §6.2.3): a server that
    /// trickles bytes can't keep it open. Over TLS, the bytes go through
    /// the session first, which may queue a [`Transport::TcpWrite`]; a TLS
    /// error closes the connection and moves its queries on to their next
    /// attempt.
    pub fn handle_stream_data(&mut self, connection: ConnectionId, data: &[u8], now: Instant) {
        let Some(conn) = self.connections.get_mut(&connection) else {
            return;
        };
        #[cfg(feature = "tls")]
        let decrypted;
        #[cfg(feature = "tls")]
        let data = match &mut conn.tls {
            None => data,
            Some(session) => match tls::receive(session, data) {
                Ok((reply, plaintext)) => {
                    if !reply.is_empty() {
                        self.transmits.push_back(Transmit {
                            transport: Transport::TcpWrite(connection),
                            destination: conn.server,
                            payload: reply,
                        });
                    }
                    decrypted = plaintext;
                    &decrypted[..]
                }
                Err(error) => {
                    self.close(connection, now, &Error::Tls(error));
                    return;
                }
            },
        };
        conn.received.extend_from_slice(data);
        // One message at a time: acting on an answer may change this
        // connection too.
        while let Some(message) = self.next_message(connection) {
            let Some(mut reply) = Reply::decode(&message) else {
                continue;
            };
            if !reply.is_response() {
                continue;
            }
            let Some(conn) = self.connections.get_mut(&connection) else {
                return;
            };
            conn.responses += 1;
            conn.last_active = now;
            match self.stream_match(connection, &reply) {
                Some(Matched::Query(id)) => {
                    if let Some(pending) = self.pending.get(&id) {
                        reply.fill_question(&pending.request.queries);
                    }
                    self.handle_reply(id, reply, now);
                }
                Some(Matched::Orphan(index)) => {
                    if let Some(conn) = self.connections.get_mut(&connection) {
                        conn.orphans.swap_remove(index);
                    }
                }
                None => {}
            }
        }
    }

    /// What the response `reply`, received on `connection`, answers: a
    /// query whose current attempt was written there, or an orphan of the
    /// connection.
    fn stream_match(&self, connection: ConnectionId, reply: &Reply) -> Option<Matched> {
        let conn = self.connections.get(&connection)?;
        let queries = self
            .pending
            .iter()
            .filter(|(_, p)| p.route == Route::Stream(connection));
        if reply.has_question() {
            let query = queries
                .filter(|(_, p)| reply.answers(p.request.metadata.id, &p.request.queries))
                .map(|(id, _)| Matched::Query(*id));
            let orphan = conn
                .orphans
                .iter()
                .position(|o| reply.answers(o.id, &o.question))
                .map(Matched::Orphan);
            return query.chain(orphan).next();
        }
        let mut candidates = queries
            .filter(|(_, p)| reply.responds_to(p.request.metadata.id))
            .map(|(id, _)| Matched::Query(*id))
            .chain(
                (0..conn.orphans.len())
                    .filter(|&i| conn.orphans.get(i).is_some_and(|o| reply.responds_to(o.id)))
                    .map(Matched::Orphan),
            );
        let only = candidates.next();
        candidates.next().map_or(only, |_| None)
    }

    /// Take the first complete length-prefixed message off `connection`'s
    /// buffer, or `None` if there is none yet.
    fn next_message(&mut self, connection: ConnectionId) -> Option<Vec<u8>> {
        let conn = self.connections.get_mut(&connection)?;
        let (len, rest) = conn.received.split_first_chunk::<2>()?;
        let len = usize::from(u16::from_be_bytes(*len));
        let message = rest.get(..len)?.to_vec();
        conn.received.drain(..2 + len);
        Some(message)
    }

    /// The server closed `connection`, or reading from it ended.
    ///
    /// If the connection had answered before, the server most likely closed
    /// it for being idle while a query was on its way (RFC 7766 §6.2.3), or
    /// after the number of queries it allows per connection (RFC 9210
    /// §4.2): each query on it is sent once more to the same server,
    /// without using up an attempt (RFC 7766 §6.2.4). That happens every
    /// time a connection is lost that answered something after the query
    /// was written to it, and otherwise once per query. Its deadline starts
    /// over: the close can come at any time, even just before the old
    /// deadline, and the query most likely never reached the server. The
    /// resend goes over a new connection if the query must use a stream
    /// and over UDP if not, unless a connection to the server is open again
    /// by then. Otherwise, and for a query already sent to the server
    /// three times over that channel (RFC 9520 §3.1), the query moves on to
    /// its next attempt, and a query out of attempts fails with
    /// [`Error::ConnectionClosed`]. No [`Transport::TcpClose`] follows.
    pub fn handle_stream_closed(&mut self, connection: ConnectionId, now: Instant) {
        self.lost(connection, now, &Error::ConnectionClosed);
    }

    /// Connecting, reading or writing failed on `connection` with `error`.
    /// Its queries move on exactly as with [`Resolver::handle_stream_closed`];
    /// the difference is that a query out of attempts fails with
    /// [`Error::Io`] carrying `error`.
    pub fn handle_stream_error(
        &mut self,
        connection: ConnectionId,
        error: io::ErrorKind,
        now: Instant,
    ) {
        self.lost(connection, now, &Error::Io(error));
    }

    /// Binding or connecting the socket of `query`, sending its datagram to
    /// `to`, or receiving on the socket connected to `to` failed with
    /// `error`, such as `ConnectionRefused` for an ICMP port unreachable
    /// (RFC 1122 §4.1.3.3). The query moves on to its next attempt at once
    /// instead of waiting out its deadline, and a query out of attempts
    /// fails with [`Error::Io`] carrying `error`.
    ///
    /// Ignored unless the query's current attempt goes over UDP to `to`, so
    /// a late report can't skip an attempt to another server. Report the
    /// failure as soon as it happens: with one server, a late one would
    /// still use up the current attempt.
    pub fn handle_udp_error(
        &mut self,
        query: QueryId,
        to: SocketAddr,
        error: io::ErrorKind,
        now: Instant,
    ) {
        let Some(pending) = self.pending.get(&query) else {
            return;
        };
        if pending.route == Route::Udp && pending.server(&self.config) == to {
            self.retry(query, now, Error::Io(error));
        }
    }

    /// `connection` went away without being asked to; see
    /// [`Resolver::handle_stream_closed`]. Emits no `TcpClose`: the driver
    /// reported the connection gone.
    fn lost(&mut self, connection: ConnectionId, now: Instant, error: &Error) {
        let Some(conn) = self.connections.remove(&connection) else {
            return;
        };
        for id in self.queries_on(connection) {
            let progress = self
                .pending
                .get(&id)
                .is_some_and(|p| conn.responses > p.written_after);
            if self.may_resend(id) && (progress || (conn.responses > 0 && self.forgive(id))) {
                if let Some(pending) = self.pending.get_mut(&id) {
                    pending.deadline = pending.deadline(&self.config, now);
                }
                self.emit(id, now);
            } else {
                self.retry(id, now, error.clone());
            }
        }
    }

    /// Act on a reply already matched to `id`.
    fn handle_reply(&mut self, id: QueryId, reply: Reply, now: Instant) {
        // Any answer, even an error code, shows the server is reachable.
        if let Some(pending) = self.pending.get(&id) {
            self.failed.remove(&pending.server(&self.config));
        }
        match reply {
            Reply::Whole(response) => self.handle_response(id, response, now),
            Reply::Broken {
                metadata, error, ..
            } => {
                if !(metadata.truncation && self.switch_to_tcp(id, now)) {
                    self.reject(id, now, Error::Malformed(error));
                }
            }
        }
    }

    /// Act on a decoded response already matched to `id`. Only `NOERROR`
    /// and `NXDOMAIN` say something about the name; any other code means
    /// this server couldn't answer (RFC 1035 §4.1.1 and §7.2), including
    /// codes 6 to 15, BADVERS (RFC 6891 §6.1.3) and BADCOOKIE, which can't
    /// be about a cookie since none is sent (RFC 7873 §5.3).
    fn handle_response(&mut self, id: QueryId, response: Message, now: Instant) {
        if response.metadata.truncation && self.switch_to_tcp(id, now) {
            return;
        }
        match response.metadata.response_code {
            // RFC 6891 §7: a server without EDNS answers FORMERR and no OPT;
            // §6.2.2 lets us ask the same server again without EDNS. Not over
            // TLS, where EDNS carries the padding (RFC 8467 §4.1).
            ResponseCode::FormErr if response.edns.is_none() && !self.config.uses_tls() => {
                self.drop_edns(id, now);
            }
            ResponseCode::NoError if is_referral(&response) => {
                self.reject(id, now, Error::NoRecursion);
            }
            ResponseCode::NoError if has_data(&response) => self.finish(id, response),
            ResponseCode::NoError | ResponseCode::NXDomain => self.search_on(id, response, now),
            code => self.reject(id, now, Error::Server(code)),
        }
    }

    /// The current search candidate has no data of the type asked for: it
    /// doesn't exist (`NXDOMAIN`), or `response` is NODATA. Try the next
    /// candidate; when there is none, the first NODATA answer is the
    /// outcome, as glibc reports NO_DATA over HOST_NOT_FOUND, and otherwise
    /// `response`.
    fn search_on(&mut self, id: QueryId, response: Message, now: Instant) {
        let Some(pending) = self.pending.get_mut(&id) else {
            return;
        };
        let nodata = response.metadata.response_code == ResponseCode::NoError;
        let mut current = Some(response);
        if nodata && pending.nodata.is_none() {
            pending.nodata = current.take();
        }
        if self.next_candidate(id, now) {
            return;
        }
        let first_nodata = self.pending.get_mut(&id).and_then(|p| p.nodata.take());
        if let Some(outcome) = first_nodata.or(current) {
            self.finish(id, outcome);
        }
    }

    /// End `id`, and the queries that joined it, with `response`.
    fn finish(&mut self, id: QueryId, mut response: Message) {
        clamp_ttls(&mut response);
        let followers = self.pending.remove(&id).map(|p| p.followers);
        let copies: Vec<Event> = followers
            .into_iter()
            .flatten()
            .map(|(query, _)| Event::Response {
                query,
                response: response.clone(),
            })
            .collect();
        self.events.push_back(Event::Response {
            query: id,
            response,
        });
        self.events.extend(copies);
    }

    /// Retry or fail every query whose deadline is at or before `now`, and
    /// close connections that have been idle for too long.
    ///
    /// A query that times out on a stream moves on to its next attempt. If
    /// no response has arrived on its connection since it was written
    /// there, the connection looks dead and is closed: the other queries
    /// that timed out move on too, and the rest are sent again to the same
    /// server, by the usual rule (a new connection if they must use a
    /// stream, else UDP), with their attempt and deadline unchanged, once
    /// per query and only if that isn't their fourth send to the server
    /// over that transport (RFC 9520 §3.1); otherwise they move on too. If
    /// a response has arrived since, the server is only slow with this
    /// one, which RFC 7766 §7 expects of pipelined queries: the connection
    /// stays open, and the query's request stays outstanding on it. Should
    /// a later attempt come back to that connection, it waits for that
    /// request's answer instead of writing the message ID again (RFC 7766
    /// §6.2.1), and the connection is closed as above if no response
    /// arrives by that attempt's deadline. A connection that already holds
    /// 256 requests left unanswered this way or by [`Resolver::cancel`] is
    /// closed instead of taking one more, which frees their IDs.
    ///
    /// Calling it before [`Resolver::poll_timeout`]'s instant does nothing.
    /// Calling it late handles every deadline that has passed in one step,
    /// with new deadlines counted from `now`; queries on a timed-out
    /// connection whose own deadline has also passed then use up an
    /// attempt instead of moving for free.
    pub fn handle_timeout(&mut self, now: Instant) {
        let expired: Vec<QueryId> = self
            .pending
            .iter()
            .filter(|(_, p)| p.deadline <= now)
            .map(|(id, _)| *id)
            .collect();
        for id in expired {
            // An earlier close may already have moved this query on.
            let Some(pending) = self.pending.get(&id) else {
                continue;
            };
            if pending.deadline > now {
                continue;
            }
            let Route::Stream(connection) = pending.route else {
                self.retry(id, now, Error::Timeout);
                continue;
            };
            match self.connections.get_mut(&connection) {
                Some(conn)
                    if conn.responses > pending.written_after
                        && conn.orphans.len() < MAX_ORPHANS =>
                {
                    conn.orphans.push(Orphan::of(pending));
                    self.retry(id, now, Error::Timeout);
                }
                Some(_) => self.time_out_stream(connection, now),
                // Can't happen: every path that removes a connection moves
                // its queries on first. Treated as a plain timeout to be
                // safe.
                None => self.retry(id, now, Error::Timeout),
            }
        }
        let idle: Vec<ConnectionId> = self
            .connections
            .keys()
            .filter(|c| self.idle_deadline(**c).is_some_and(|d| d <= now))
            .copied()
            .collect();
        for connection in idle {
            if let Some(conn) = self.connections.remove(&connection) {
                self.transmits.push_back(Transmit {
                    transport: Transport::TcpClose(connection),
                    destination: conn.server,
                    payload: Vec::new(),
                });
            }
        }
    }

    /// Next transmit to carry out, if any: a datagram, or a stream connect,
    /// write or close.
    pub fn poll_transmit(&mut self) -> Option<Transmit> {
        self.transmits.pop_front()
    }

    /// Earliest instant at which [`Resolver::handle_timeout`] must be called.
    /// `None` means no timer is needed: no query is pending and no open
    /// connection is waiting out [`Config::idle_timeout`]. An idle
    /// connection keeps a timer running after the last query is done.
    pub fn poll_timeout(&self) -> Option<Instant> {
        let queries = self.pending.values().map(|p| p.deadline);
        let idle = self
            .connections
            .keys()
            .filter_map(|c| self.idle_deadline(*c));
        queries.chain(idle).min()
    }

    /// When `connection` should close for being idle: `None` while a query
    /// uses it. An orphan keeps it busy until the deadline its query had.
    fn idle_deadline(&self, connection: ConnectionId) -> Option<Instant> {
        let conn = self.connections.get(&connection)?;
        if self
            .pending
            .values()
            .any(|p| p.route == Route::Stream(connection))
        {
            return None;
        }
        let busy = conn
            .orphans
            .iter()
            .map(|o| o.until)
            .fold(conn.last_active, Instant::max);
        busy.checked_add(self.config.idle_timeout)
    }

    /// Next completed query, if any.
    pub fn poll_event(&mut self) -> Option<Event> {
        self.events.pop_front()
    }

    /// Stop tracking a query. No event is queued for it from now on (one
    /// already queued, such as a special-use answer, still comes out of
    /// [`Resolver::poll_event`]), so the driver can close its socket now.
    ///
    /// Queries that joined it go on, and the first of them takes it over. If
    /// its attempt went over UDP, that attempt is sent again for the heir,
    /// to the same server, with a fresh deadline: as [`Transport::Udp`],
    /// from a new socket, or on the connection to that server if one has
    /// opened since. If that would be the fourth send of the search
    /// candidate to that server over that transport, the heir sends its
    /// next attempt to the next server instead (RFC 9520 §3.1). If it has
    /// none left, it fails with [`Error::Timeout`], unless it joined after
    /// the current search candidate started: then it starts over with
    /// attempts of its own, as [`Resolver::query`] promises. Over a stream
    /// nothing is sent; the answer still arrives on the same connection,
    /// and the heir keeps the deadline.
    ///
    /// A query cancelled with no one to take it over after its request was
    /// written to a connection keeps its message ID in use there until the
    /// answer arrives or the connection ends, and keeps the connection from
    /// going idle until the deadline it had (RFC 7766 §6.2.1, §6.2.3). If
    /// the connection already holds 256 such requests, it is closed instead
    /// and its other queries move as when one of them times out with no
    /// response since (see [`Resolver::handle_timeout`]).
    pub fn cancel(&mut self, id: QueryId, now: Instant) {
        let Some(mut pending) = self.pending.remove(&id) else {
            for p in self.pending.values_mut() {
                p.followers.retain(|&(follower, _)| follower != id);
            }
            return;
        };
        if pending.followers.is_empty() {
            // Its request is still outstanding on its connection.
            if let Route::Stream(connection) = pending.route
                && let Some(conn) = self.connections.get_mut(&connection)
            {
                if conn.orphans.len() < MAX_ORPHANS {
                    conn.orphans.push(Orphan::of(&pending));
                } else {
                    self.time_out_stream(connection, now);
                }
            }
            return;
        }
        let (heir, joined) = pending.followers.remove(0);
        pending.joined = joined;
        let udp = pending.route == Route::Udp;
        let server = pending.server(&self.config);
        let room = pending.may_send(server, channel(&self.connections, &pending, server));
        if udp && room {
            pending.deadline = pending.deadline(&self.config, now);
        }
        self.pending.insert(heir, pending);
        match (udp, room) {
            (true, true) => self.emit(heir, now),
            (true, false) => self.advance(heir, now, Error::Timeout),
            (false, _) => {}
        }
    }

    // How a query moves on, row by row of the crate docs' table, and the
    // state that keeps each free step bounded per search candidate:
    //
    // - no answer by its deadline, datagram not sent (`handle_udp_error`):
    //   `retry`; on a stream, `handle_timeout` closes the connection through
    //   `time_out_stream` only if no response arrived on it since the query
    //   was written (or since `emit` took the request back), or it holds
    //   `MAX_ORPHANS` orphans, and otherwise leaves an `Orphan` there,
    //   which `emit` takes back if a later attempt returns to that
    //   connection
    // - error code, FORMERR with OPT or a second one without, undecodable
    //   reply, referral: `reject`, which adds the server to `excluded`
    // - truncated over UDP: `switch_to_tcp`, once because `stream_only`
    //   keeps every later send off UDP
    // - FORMERR without OPT: `drop_edns`, once because `request.edns` is
    //   taken
    // - connection lost after it answered: `lost`, then `emit` again, for
    //   free every time if it answered after the query was written
    //   (`written_after`), else once by way of `forgive`
    // - neighbour timed out on the connection, or it was closed for holding
    //   too many orphans: `time_out_stream`, then `forgive` and `emit` (the
    //   same `forgiven` flag), else `retry`
    // - connection that never answered lost, TLS error on received bytes:
    //   `lost` or `close`, then `retry`
    // - NXDOMAIN or NODATA, with candidates left: `search_on`, then
    //   `next_candidate`, which resets all of the above with a new
    //   `Pending`
    // - joined query cancelled: `cancel`, limited only by the rule below
    //   (each hand-over over UDP sends again; the crate docs' `attempts + 3`
    //   bound leaves it out)
    // - out of attempts, or every server excluded or without room: `advance`
    //   calls `give_up`, then `fail`; `give_up` starts the late joiners
    //   over, the query itself too if it took over from a cancelled one
    //   after the search candidate started (`Pending::joined`)
    //
    // `emit` picks the channel of every send (`channel`: the open
    // connection to the server if there is one, RFC 7766 §5) and counts it
    // in `Pending::sends`, and no search candidate goes to a server over a
    // channel more than three times (RFC 9520 §3.1): `advance` skips
    // servers without room, and `drop_edns`, `lost`, `time_out_stream` and
    // `cancel` check `may_resend` before a free send, and so does
    // `switch_to_tcp`, since earlier attempts may have gone to an open
    // connection. They move on as `retry` (`lost`, `time_out_stream`) or
    // `advance` (`drop_edns`, `cancel`, `switch_to_tcp`) instead. That
    // check is all that bounds the resends after a lost connection that
    // answered since.

    /// The server of `id`'s current attempt gave no answer: new queries
    /// start after it for a while (`Config::failure_memory`). It stays in
    /// this query's rotation, since a later round waits longer and may
    /// reach it. Moves on as `advance` does.
    fn retry(&mut self, id: QueryId, now: Instant, error: Error) {
        let Some(pending) = self.pending.get(&id) else {
            return;
        };
        if let Some(until) = now.checked_add(self.config.failed_for()) {
            self.failed.insert(pending.server(&self.config), until);
        }
        self.advance(id, now, error);
    }

    /// The server of `id`'s current attempt answered, but with an error
    /// (`error`), so it is up but can't answer this question: skip it for
    /// the rest of this search candidate, as RFC 1035 §7.2 removes it from
    /// SLIST. Moves on as `advance` does.
    fn reject(&mut self, id: QueryId, now: Instant, error: Error) {
        let Some(pending) = self.pending.get_mut(&id) else {
            return;
        };
        let server = pending.server(&self.config);
        pending.excluded.push(server);
        self.advance(id, now, error);
    }

    /// Send `id`'s next attempt to the next server it hasn't excluded and
    /// may still send to over the channel the send would take, or fail it
    /// with `error` if it is out of attempts or no server is left. After a
    /// truncated answer later attempts also go over TCP, and with TLS every
    /// attempt stays off UDP (RFC 7858 §3): `emit` opens or reuses a
    /// connection to the new server.
    fn advance(&mut self, id: QueryId, now: Instant, error: Error) {
        let (config, connections) = (&self.config, &self.connections);
        let Some(pending) = self.pending.get_mut(&id) else {
            return;
        };
        pending.attempt += 1;
        let servers = config.servers().len();
        let next = (pending.position + 1..=pending.position + servers).find(|&p| {
            let server = config.server(p);
            !pending.excluded.contains(&server)
                && pending.may_send(server, channel(connections, pending, server))
        });
        let Some(position) = next.filter(|_| pending.attempt < config.attempts.get()) else {
            self.give_up(id, error, now);
            return;
        };
        pending.position = position;
        pending.deadline = pending.deadline(config, now);
        self.emit(id, now);
    }

    /// The queries whose current attempt was written to `connection`.
    fn queries_on(&self, connection: ConnectionId) -> Vec<QueryId> {
        self.pending
            .iter()
            .filter(|(_, p)| p.route == Route::Stream(connection))
            .map(|(id, _)| *id)
            .collect()
    }

    /// A query on `connection` timed out with no response on it since the
    /// query was written, which suggests the connection is dead, or the
    /// connection holds `MAX_ORPHANS` requests that left it unanswered:
    /// close it, as RFC 7766 §6.2.4 lets either end do under unusual
    /// conditions. The queries that timed out move on to their next
    /// attempt. The others are sent again to the same server, keeping
    /// their attempt, since another lookup's slow answer is no fault of
    /// theirs. They keep their deadline too: they have been waiting on the
    /// same unresponsive server, and a free move must not stretch how long
    /// it can hold them. Only once per query, so a server that stops
    /// answering costs each query a bounded number of sends.
    fn time_out_stream(&mut self, connection: ConnectionId, now: Instant) {
        let Some(conn) = self.connections.remove(&connection) else {
            return;
        };
        self.transmits.push_back(Transmit {
            transport: Transport::TcpClose(connection),
            destination: conn.server,
            payload: Vec::new(),
        });
        for id in self.queries_on(connection) {
            let expired = self.pending.get(&id).is_some_and(|p| p.deadline <= now);
            if !expired && self.may_resend(id) && self.forgive(id) {
                self.emit(id, now);
            } else {
                self.retry(id, now, Error::Timeout);
            }
        }
    }

    /// Whether `id`'s current attempt may go to its server once more, over
    /// the channel that send would take (RFC 9520 §3.1).
    fn may_resend(&self, id: QueryId) -> bool {
        self.pending.get(&id).is_some_and(|p| {
            let server = p.server(&self.config);
            p.may_send(server, channel(&self.connections, p, server))
        })
    }

    /// Whether `id` may send its attempt again for free, which it may once.
    fn forgive(&mut self, id: QueryId) -> bool {
        self.pending
            .get_mut(&id)
            .is_some_and(|p| !std::mem::replace(&mut p.forgiven, true))
    }

    /// Ask the driver to close `connection`, and move its queries on to
    /// their next attempt.
    #[cfg(feature = "tls")]
    fn close(&mut self, connection: ConnectionId, now: Instant, error: &Error) {
        let Some(conn) = self.connections.remove(&connection) else {
            return;
        };
        self.transmits.push_back(Transmit {
            transport: Transport::TcpClose(connection),
            destination: conn.server,
            payload: Vec::new(),
        });
        for id in self.queries_on(connection) {
            self.retry(id, now, error.clone());
        }
    }

    /// Re-send `id` to the same server over TCP, as RFC 1123 §6.1.3.2 asks
    /// after a truncated answer, and keep every later send of this search
    /// candidate on a stream. Doesn't consume an attempt. Returns `false`
    /// if the attempt already went over a stream, in which case the
    /// response is used as it is. If the server may not be sent the query
    /// over a stream again (RFC 9520 §3.1), which can happen after earlier
    /// attempts went to an open connection, the query sends its next
    /// attempt over TCP to the next server instead.
    fn switch_to_tcp(&mut self, id: QueryId, now: Instant) -> bool {
        let Some(pending) = self.pending.get_mut(&id) else {
            return false;
        };
        if pending.route != Route::Udp {
            return false;
        }
        pending.stream_only = true;
        if !self.may_resend(id) {
            self.advance(id, now, Error::Timeout);
            return true;
        }
        if let Some(pending) = self.pending.get_mut(&id) {
            pending.deadline = pending.deadline(&self.config, now);
        }
        self.emit(id, now);
        true
    }

    /// Re-send `id` to the same server without an OPT record. Doesn't consume
    /// an attempt. If EDNS was already dropped, FORMERR is a plain server error.
    /// If the server may not be sent the query again (RFC 9520 §3.1), the
    /// query keeps EDNS and sends its next attempt to the next server.
    fn drop_edns(&mut self, id: QueryId, now: Instant) {
        let room = self.may_resend(id);
        let Some(pending) = self.pending.get_mut(&id) else {
            return;
        };
        if pending.request.edns.is_none() {
            self.reject(id, now, Error::Server(ResponseCode::FormErr));
            return;
        }
        if !room {
            self.advance(id, now, Error::Server(ResponseCode::FormErr));
            return;
        }
        pending.request.edns = None;
        let Ok(payload) = pending.request.to_vec() else {
            self.fail(id, Error::Server(ResponseCode::FormErr));
            return;
        };
        pending.payload = payload;
        pending.deadline = pending.deadline(&self.config, now);
        self.emit(id, now);
    }

    /// Send `id`'s current attempt and count the send: on the open
    /// connection to its server if there is one (RFC 7766 §5), else over a
    /// new connection if it must use a stream, and as a datagram
    /// otherwise. If the query's own request is still outstanding on that
    /// connection, left there by a timeout, nothing is written: the attempt
    /// waits for that answer, since writing the message ID again would put
    /// it on the connection twice (RFC 7766 §6.2.1). Only responses from
    /// then on show the connection works: the ones before already kept it
    /// open at the last timeout. Fails the query if the bytes can't be
    /// produced.
    fn emit(&mut self, id: QueryId, now: Instant) {
        let Some(pending) = self.pending.get_mut(&id) else {
            return;
        };
        let server = pending.server(&self.config);
        let open = self
            .connections
            .iter_mut()
            .find(|(_, c)| c.server == server);
        let Some((&connection, conn)) = open else {
            if pending.stream_only {
                pending.count_send(server, Channel::Stream);
                let message = frame(&pending.payload);
                match self.connect(server, &message, now) {
                    Ok(connection) => self.written(id, connection),
                    Err(error) => self.fail(id, error),
                }
            } else {
                pending.route = Route::Udp;
                pending.count_send(server, Channel::Udp);
                self.transmits.push_back(Transmit {
                    transport: Transport::Udp(id),
                    destination: server,
                    payload: pending.payload.clone(),
                });
            }
            return;
        };
        if let Some(index) = conn.orphans.iter().position(|o| o.is(pending)) {
            conn.orphans.swap_remove(index);
            pending.route = Route::Stream(connection);
            pending.written_after = conn.responses;
            return;
        }
        pending.count_send(server, Channel::Stream);
        let message = frame(&pending.payload);
        match self.write(connection, &message, now) {
            Ok(()) => self.written(id, connection),
            Err(error) => self.fail(id, error),
        }
    }

    /// `id`'s current attempt was written to `connection`.
    fn written(&mut self, id: QueryId, connection: ConnectionId) {
        let responses = self.connections.get(&connection).map_or(0, |c| c.responses);
        if let Some(pending) = self.pending.get_mut(&id) {
            pending.route = Route::Stream(connection);
            pending.written_after = responses;
        }
    }

    /// Open a connection to `server` with `message` as its first query.
    #[cfg_attr(
        not(feature = "tls"),
        expect(
            clippy::unnecessary_wraps,
            reason = "only TLS settings can make connecting fail"
        )
    )]
    fn connect(
        &mut self,
        server: SocketAddr,
        message: &[u8],
        now: Instant,
    ) -> Result<ConnectionId, Error> {
        let connection = ConnectionId(self.next_connection);
        self.next_connection += 1;
        #[cfg(feature = "tls")]
        let (tls, payload) = match &self.config.tls {
            Some(settings) => {
                let (session, hello) = settings.connect(message).map_err(Error::Tls)?;
                (Some(Box::new(session)), hello)
            }
            None => (None, message.to_vec()),
        };
        #[cfg(not(feature = "tls"))]
        let payload = message.to_vec();
        let conn = Connection {
            server,
            received: Vec::new(),
            last_active: now,
            responses: 0,
            orphans: Vec::new(),
            #[cfg(feature = "tls")]
            tls,
        };
        self.connections.insert(connection, conn);
        self.transmits.push_back(Transmit {
            transport: Transport::TcpConnect(connection),
            destination: server,
            payload,
        });
        Ok(connection)
    }

    /// Write `message` to an open connection. Over TLS it may wait inside
    /// the session until the handshake is done.
    #[cfg_attr(
        not(feature = "tls"),
        expect(
            clippy::unnecessary_wraps,
            reason = "only a TLS session can refuse a write"
        )
    )]
    fn write(
        &mut self,
        connection: ConnectionId,
        message: &[u8],
        now: Instant,
    ) -> Result<(), Error> {
        let Some(conn) = self.connections.get_mut(&connection) else {
            return Ok(());
        };
        conn.last_active = now;
        #[cfg(feature = "tls")]
        let payload = match &mut conn.tls {
            Some(session) => tls::send(session, message).map_err(Error::Tls)?,
            None => message.to_vec(),
        };
        #[cfg(not(feature = "tls"))]
        let payload = message.to_vec();
        if !payload.is_empty() {
            self.transmits.push_back(Transmit {
                transport: Transport::TcpWrite(connection),
                destination: conn.server,
                payload,
            });
        }
        Ok(())
    }

    /// `id` is out of attempts, or every server is excluded. Queries that
    /// joined it after its current search candidate started haven't had
    /// attempts of their own yet: instead of sharing the failure they start
    /// over, the first as a new query that the others join. That includes
    /// `id` itself when it took over from a cancelled query it joined late
    /// (`Pending::joined`). The comparison is strict on purpose: a query
    /// that joined at the very instant the candidate started, such as a
    /// duplicate issued in the same tick, shares its failure.
    fn give_up(&mut self, id: QueryId, error: Error, now: Instant) {
        let Some(pending) = self.pending.get_mut(&id) else {
            return;
        };
        let started = pending.started;
        let (mut late, early): (Vec<_>, Vec<_>) = std::mem::take(&mut pending.followers)
            .into_iter()
            .partition(|&(_, joined)| joined > started);
        if pending.joined > started {
            late.insert(0, (id, pending.joined));
        }
        pending.followers = early;
        let asked = pending.asked.clone();
        let Some((&(heir, _), others)) = late.split_first() else {
            self.fail(id, error);
            return;
        };
        // Can't fail for a name that was already encoded once; if it did,
        // the late queries would share the failure.
        let Ok(mut fresh) = self.begin(asked, now) else {
            if let Some(pending) = self.pending.get_mut(&id) {
                pending
                    .followers
                    .extend(late.into_iter().filter(|&(query, _)| query != id));
            }
            self.fail(id, error);
            return;
        };
        if heir == id {
            // `id` starts over itself: only the queries that joined early
            // fail.
            let early = self.pending.remove(&id).map(|p| p.followers);
            self.events
                .extend(early.into_iter().flatten().map(|(query, _)| Event::Failed {
                    query,
                    error: error.clone(),
                }));
        } else {
            self.fail(id, error);
        }
        fresh.followers = others.to_vec();
        self.pending.insert(heir, fresh);
        self.emit(heir, now);
    }

    fn fail(&mut self, id: QueryId, error: Error) {
        let followers = self.pending.remove(&id).map(|p| p.followers);
        let copies: Vec<Event> = followers
            .into_iter()
            .flatten()
            .map(|(query, _)| Event::Failed {
                query,
                error: error.clone(),
            })
            .collect();
        self.events.push_back(Event::Failed { query: id, error });
        self.events.extend(copies);
    }

    /// A query message with an ID that is in use neither by a query in
    /// flight nor by an orphan on a connection, so no connection ever
    /// carries two outstanding queries with one ID (RFC 7766 §6.2.1).
    ///
    /// The ID comes from hickory-proto's `rand::random`, a CSPRNG, covering
    /// the full 16-bit range as RFC 5452 §9.2 requires. If a few random
    /// picks all hit IDs in use, the free ID that follows the last one is
    /// taken. Only with all 65536 in use is a used one kept: a datagram is
    /// matched by its query's own socket and a stream answer by ID and
    /// question, so a duplicate ID then only pairs queries whose answers
    /// are interchangeable.
    fn new_message(&self) -> Message {
        let used = |id: u16| {
            self.pending.values().any(|p| p.request.metadata.id == id)
                || self
                    .connections
                    .values()
                    .any(|c| c.orphans.iter().any(|o| o.id == id))
        };
        let mut message = Message::query();
        for _ in 0..16 {
            if !used(message.metadata.id) {
                return message;
            }
            message = Message::query();
        }
        let last = message.metadata.id;
        if let Some(free) = (1..=u16::MAX)
            .map(|i| last.wrapping_add(i))
            .find(|&id| !used(id))
        {
            message.metadata.id = free;
        }
        message
    }
}
