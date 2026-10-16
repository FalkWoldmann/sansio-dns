//! The resolver state machine: queries in flight, stream connections, and
//! how a query moves on.

use std::collections::{BTreeMap, VecDeque};
use std::io;
use std::net::SocketAddr;
use std::time::Instant;

use hickory_proto::ProtoError;
use hickory_proto::op::{Edns, Message, Query, ResponseCode};
use hickory_proto::rr::{Name, RecordType};
use hickory_proto::serialize::binary::DecodeError;

#[cfg(feature = "tls")]
use crate::tls;
#[cfg(feature = "tls")]
use crate::wire::pad;
use crate::wire::{EDNS_PAYLOAD, frame, is_reply, special_use};
use crate::{Config, ConnectionId, Error, Event, QueryId, Transmit, Transport};

#[derive(Debug)]
struct Pending {
    request: Message,
    payload: Vec<u8>,
    attempt: usize,
    /// `None` if `now + timeout` overflows: the query then waits forever.
    deadline: Option<Instant>,
    route: Route,
    /// Search candidates still to try if this name doesn't exist.
    rest: VecDeque<Name>,
    /// Whether its attempt was already sent again for free, after losing a
    /// working connection or being moved off a timed-out one. That happens
    /// once per query; see `Resolver::forgive`.
    forgiven: bool,
    /// The name and type as asked, before search domains. A later query
    /// for the same pair joins this one instead of being sent.
    asked: (Name, RecordType),
    /// When this query, or its current search candidate, started.
    started: Instant,
    /// Queries that joined this one, and when; each gets its outcome too.
    followers: Vec<(QueryId, Instant)>,
}

/// How a query's current attempt travels.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Route {
    /// As a datagram, from the query's own socket.
    Udp,
    /// Over a stream: after a truncated UDP answer, or always with DNS over
    /// TLS. Names the connection once the attempt has been written to one.
    Stream(Option<ConnectionId>),
}

/// A stream connection to one server, shared by its queries.
#[derive(Debug)]
struct Connection {
    server: SocketAddr,
    /// Decrypted bytes not yet split into messages.
    received: Vec<u8>,
    /// When it last carried data; the idle timeout counts from here once
    /// no query uses it.
    last_active: Instant,
    /// Whether an answer has arrived on it, so it is known to work.
    answered: bool,
    /// The TLS session, when using DNS over TLS.
    #[cfg(feature = "tls")]
    tls: Option<Box<rustls::ClientConnection>>,
}

/// The resolver state machine. See the crate docs for how to drive it.
#[derive(Debug)]
pub struct Resolver {
    config: Config,
    next_query: u64,
    pending: BTreeMap<QueryId, Pending>,
    next_connection: u64,
    connections: BTreeMap<ConnectionId, Connection>,
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
            transmits: VecDeque::new(),
            events: VecDeque::new(),
        }
    }

    /// Start a recursive lookup of `name`/`record_type`.
    ///
    /// A name ending in a dot is used as given. Other names are tried with
    /// the [`Config::search`] domains, ordered by [`Config::ndots`]; the next
    /// candidate is tried while the answer is NXDOMAIN, and the event carries
    /// the last answer. Any other answer, or a server error on the last
    /// attempt, ends the search. Without search domains, `example.com` and
    /// `example.com.` are the same query.
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
    /// first one runs out of attempts, a query that joined it later starts
    /// over with attempts of its own instead of sharing the failure.
    pub fn query(
        &mut self,
        name: Name,
        record_type: RecordType,
        now: Instant,
    ) -> Result<QueryId, ProtoError> {
        let asked = (name.clone(), record_type);
        let mut absolute = name;
        absolute.set_fqdn(true);
        let id = QueryId(self.next_query);
        self.next_query += 1;
        let local = special_use(&absolute, record_type)
            .or_else(|| self.config.hosts.answer(&absolute, record_type));
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
    fn begin(&self, asked: (Name, RecordType), now: Instant) -> Result<Pending, ProtoError> {
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
        asked: (Name, RecordType),
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
        Ok(Pending {
            request,
            payload,
            attempt: 0,
            deadline: now.checked_add(self.config.timeout),
            route: if self.config.uses_tls() {
                Route::Stream(None)
            } else {
                Route::Udp
            },
            rest,
            forgiven: false,
            asked,
            started: now,
            followers: Vec::new(),
        })
    }

    /// Replace `id`'s attempt with one for its next search candidate.
    /// Returns `false` if there is none, so the current answer stands.
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
    /// ID. Naming the socket keeps each query's source port its own (§9.2).
    /// Once the query has switched to TCP, UDP replies to it are ignored.
    pub fn handle_datagram(&mut self, query: QueryId, from: SocketAddr, data: &[u8], now: Instant) {
        // The cheap checks first, so stray datagrams cost no parsing.
        let Some(pending) = self.pending.get(&query) else {
            return;
        };
        if pending.route != Route::Udp || self.config.server(pending.attempt) != from {
            return;
        }
        let Ok(response) = Message::from_vec(data) else {
            return;
        };
        if is_reply(&pending.request, &response) {
            self.handle_response(query, response, now);
        }
    }

    /// Process bytes read from `connection`.
    ///
    /// Bytes may arrive in any chunking, and answers in any order: each
    /// complete message goes to the query on this connection it answers,
    /// and is ignored if there is none (RFC 7766 §6.2.1.1). Over TLS, the
    /// bytes go through the session first, which may queue a
    /// [`Transport::TcpWrite`]; a TLS error closes the connection and moves
    /// its queries on to their next attempt.
    pub fn handle_stream_data(&mut self, connection: ConnectionId, data: &[u8], now: Instant) {
        let Some(conn) = self.connections.get_mut(&connection) else {
            return;
        };
        conn.last_active = now;
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
        while let Some(decoded) = self.next_message(connection) {
            let Ok(response) = decoded else {
                continue;
            };
            let id = self
                .pending
                .iter()
                .find(|(_, p)| {
                    p.route == Route::Stream(Some(connection)) && is_reply(&p.request, &response)
                })
                .map(|(id, _)| *id);
            if let Some(id) = id {
                if let Some(conn) = self.connections.get_mut(&connection) {
                    conn.answered = true;
                }
                self.handle_response(id, response, now);
            }
        }
    }

    /// Take the first complete length-prefixed message off `connection`'s
    /// buffer and decode it, or `None` if there is none yet.
    fn next_message(&mut self, connection: ConnectionId) -> Option<Result<Message, DecodeError>> {
        let conn = self.connections.get_mut(&connection)?;
        let (len, rest) = conn.received.split_first_chunk::<2>()?;
        let len = usize::from(u16::from_be_bytes(*len));
        let decoded = Message::from_vec(rest.get(..len)?);
        conn.received.drain(..2 + len);
        Some(decoded)
    }

    /// The server closed `connection`, or reading from it ended.
    ///
    /// If the connection had answered before, the server most likely closed
    /// it for being idle while a query was on its way (RFC 7766 §6.2.3):
    /// each query on it is sent once more to the same server, on a new
    /// connection, with a fresh deadline and without using up an attempt.
    /// Otherwise, and for a query already resent this way, the query moves on
    /// to its next attempt, still over a stream, and a query out of attempts
    /// fails with [`Error::ConnectionClosed`].
    pub fn handle_stream_closed(&mut self, connection: ConnectionId, now: Instant) {
        self.lost(connection, now, &Error::ConnectionClosed);
    }

    /// Connecting, reading or writing failed on `connection` with `error`.
    /// Its queries move on exactly as with [`Resolver::handle_stream_closed`];
    /// the difference is that a query out of attempts fails with
    /// [`Error::Connection`] carrying `error`.
    pub fn handle_stream_error(
        &mut self,
        connection: ConnectionId,
        error: io::ErrorKind,
        now: Instant,
    ) {
        self.lost(connection, now, &Error::Connection(error));
    }

    /// `connection` went away without being asked to; see
    /// [`Resolver::handle_stream_error`].
    fn lost(&mut self, connection: ConnectionId, now: Instant, error: &Error) {
        let Some(conn) = self.connections.remove(&connection) else {
            return;
        };
        for id in self.queries_on(connection) {
            if conn.answered && self.forgive(id) {
                if let Some(pending) = self.pending.get_mut(&id) {
                    pending.deadline = now.checked_add(self.config.timeout);
                }
                self.resend(id, now);
            } else {
                self.retry(id, now, error.clone());
            }
        }
    }

    /// Act on a response already matched to `id`.
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
            ResponseCode::NXDomain if self.next_candidate(id, now) => {}
            code @ (ResponseCode::ServFail
            | ResponseCode::Refused
            | ResponseCode::NotImp
            | ResponseCode::FormErr) => self.retry(id, now, Error::Server(code)),
            _ => {
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
        }
    }

    /// Retry or fail every query whose deadline is at or before `now`, and
    /// close connections that have been idle for too long.
    ///
    /// A query that times out on a stream suggests the connection is dead,
    /// so the connection is closed. The queries that timed out move on to
    /// their next attempt, and the others go to a new connection to the same
    /// server with their attempt and deadline unchanged, once per query.
    pub fn handle_timeout(&mut self, now: Instant) {
        let expired: Vec<QueryId> = self
            .pending
            .iter()
            .filter(|(_, p)| p.deadline.is_some_and(|d| d <= now))
            .map(|(id, _)| *id)
            .collect();
        for id in expired {
            // An earlier close may already have moved this query on.
            let Some(pending) = self.pending.get(&id) else {
                continue;
            };
            if !pending.deadline.is_some_and(|d| d <= now) {
                continue;
            }
            match pending.route {
                Route::Stream(Some(connection)) if self.connections.contains_key(&connection) => {
                    self.time_out_stream(connection, now);
                }
                _ => self.retry(id, now, Error::Timeout),
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

    /// Next datagram to send, if any.
    pub fn poll_transmit(&mut self) -> Option<Transmit> {
        self.transmits.pop_front()
    }

    /// Earliest instant at which [`Resolver::handle_timeout`] must be called.
    pub fn poll_timeout(&self) -> Option<Instant> {
        let queries = self.pending.values().filter_map(|p| p.deadline);
        let idle = self
            .connections
            .keys()
            .filter_map(|c| self.idle_deadline(*c));
        queries.chain(idle).min()
    }

    /// When `connection` should close for being idle: `None` while a query
    /// uses it.
    fn idle_deadline(&self, connection: ConnectionId) -> Option<Instant> {
        let conn = self.connections.get(&connection)?;
        if self
            .pending
            .values()
            .any(|p| p.route == Route::Stream(Some(connection)))
        {
            return None;
        }
        conn.last_active.checked_add(self.config.idle_timeout)
    }

    /// Next completed query, if any.
    pub fn poll_event(&mut self) -> Option<Event> {
        self.events.pop_front()
    }

    /// Stop tracking a query. No event is emitted for it.
    ///
    /// Queries that joined it go on: the first of them takes it over. If it
    /// waits for a datagram, its current attempt is sent again from that
    /// query's own socket ([`Transport::Udp`]), to the same server, with a
    /// fresh deadline.
    pub fn cancel(&mut self, id: QueryId, now: Instant) {
        let Some(mut pending) = self.pending.remove(&id) else {
            for p in self.pending.values_mut() {
                p.followers.retain(|&(follower, _)| follower != id);
            }
            return;
        };
        if pending.followers.is_empty() {
            return;
        }
        let (heir, _) = pending.followers.remove(0);
        let resend = (pending.route == Route::Udp).then(|| Transmit {
            transport: Transport::Udp(heir),
            destination: self.config.server(pending.attempt),
            payload: pending.payload.clone(),
        });
        if resend.is_some() {
            pending.deadline = now.checked_add(self.config.timeout);
        }
        self.pending.insert(heir, pending);
        self.transmits.extend(resend);
    }

    /// Send `id` to the next server, or fail it with `error` if it is out of
    /// attempts. The route stays: after a truncated answer, later attempts
    /// also go over TCP.
    fn retry(&mut self, id: QueryId, now: Instant, error: Error) {
        let Some(pending) = self.pending.get_mut(&id) else {
            return;
        };
        pending.attempt += 1;
        if pending.attempt >= self.config.attempts.get() {
            self.give_up(id, error, now);
            return;
        }
        pending.deadline = now.checked_add(self.config.timeout);
        self.emit(id, now);
    }

    /// The queries whose current attempt was written to `connection`.
    fn queries_on(&self, connection: ConnectionId) -> Vec<QueryId> {
        self.pending
            .iter()
            .filter(|(_, p)| p.route == Route::Stream(Some(connection)))
            .map(|(id, _)| *id)
            .collect()
    }

    /// A query on `connection` timed out, which suggests the connection is
    /// dead: close it. The queries that timed out move on to their next
    /// attempt. The others are sent again on a new connection to the same
    /// server, keeping their attempt and deadline, since another lookup's
    /// slow answer is no fault of theirs; but only once per query, so a
    /// server that stops answering costs each query a bounded number of
    /// sends.
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
            let expired = self
                .pending
                .get(&id)
                .is_some_and(|p| p.deadline.is_some_and(|d| d <= now));
            if !expired && self.forgive(id) {
                self.resend(id, now);
            } else {
                self.retry(id, now, Error::Timeout);
            }
        }
    }

    /// Whether `id` may send its attempt again for free, which it may once.
    fn forgive(&mut self, id: QueryId) -> bool {
        self.pending
            .get_mut(&id)
            .is_some_and(|p| !std::mem::replace(&mut p.forgiven, true))
    }

    /// Send `id`'s current attempt again over a stream to the same server,
    /// without using up an attempt.
    fn resend(&mut self, id: QueryId, now: Instant) {
        if let Some(pending) = self.pending.get_mut(&id) {
            pending.route = Route::Stream(None);
            self.emit(id, now);
        }
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

    /// Re-send `id` to the same server over TCP (RFC 7766 §5). Doesn't
    /// consume an attempt. Returns `false` if it already uses TCP, in which
    /// case the response is used as it is.
    fn switch_to_tcp(&mut self, id: QueryId, now: Instant) -> bool {
        let Some(pending) = self.pending.get_mut(&id) else {
            return false;
        };
        if pending.route != Route::Udp {
            return false;
        }
        pending.route = Route::Stream(None);
        pending.deadline = now.checked_add(self.config.timeout);
        self.emit(id, now);
        true
    }

    /// Re-send `id` to the same server without an OPT record. Doesn't consume
    /// an attempt. If EDNS was already dropped, FORMERR is a plain server error.
    fn drop_edns(&mut self, id: QueryId, now: Instant) {
        let Some(pending) = self.pending.get_mut(&id) else {
            return;
        };
        if pending.request.edns.take().is_none() {
            self.retry(id, now, Error::Server(ResponseCode::FormErr));
            return;
        }
        let Ok(payload) = pending.request.to_vec() else {
            self.fail(id, Error::Server(ResponseCode::FormErr));
            return;
        };
        pending.payload = payload;
        pending.deadline = now.checked_add(self.config.timeout);
        self.emit(id, now);
    }

    /// Send `id`'s current attempt: as a datagram, or on the open
    /// connection to its server, opening one if there is none. Fails the
    /// query if the bytes can't be produced.
    fn emit(&mut self, id: QueryId, now: Instant) {
        let Some(pending) = self.pending.get(&id) else {
            return;
        };
        let server = self.config.server(pending.attempt);
        if pending.route == Route::Udp {
            self.transmits.push_back(Transmit {
                transport: Transport::Udp(id),
                destination: server,
                payload: pending.payload.clone(),
            });
            return;
        }
        let message = frame(&pending.payload);
        let open = self
            .connections
            .iter()
            .find(|(_, c)| c.server == server)
            .map(|(c, _)| *c);
        let sent = match open {
            Some(connection) => self.write(connection, &message, now).map(|()| connection),
            None => self.connect(server, &message, now),
        };
        match (sent, self.pending.get_mut(&id)) {
            (Ok(connection), Some(pending)) => pending.route = Route::Stream(Some(connection)),
            (Err(error), _) => self.fail(id, error),
            (Ok(_), None) => {}
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
            answered: false,
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

    /// `id` is out of attempts. Queries that joined it after it started
    /// haven't had attempts of their own yet: instead of sharing the failure
    /// they start over, the first as a new query that the others join.
    fn give_up(&mut self, id: QueryId, error: Error, now: Instant) {
        let Some(pending) = self.pending.get_mut(&id) else {
            return;
        };
        let started = pending.started;
        let (late, early): (Vec<_>, Vec<_>) = std::mem::take(&mut pending.followers)
            .into_iter()
            .partition(|&(_, joined)| joined > started);
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
                pending.followers.extend(late);
            }
            self.fail(id, error);
            return;
        };
        self.fail(id, error);
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

    /// A query message, with an ID no in-flight query is using if one of a
    /// few random picks finds one.
    ///
    /// The ID comes from hickory-proto's `rand::random`, a CSPRNG, covering
    /// the full 16-bit range as RFC 5452 §9.2 requires. With nearly all
    /// 65536 IDs in use, the last pick is kept rather than looping forever:
    /// a datagram is matched by its query's own socket and a stream answer
    /// by ID and question, so a duplicate ID only pairs queries whose
    /// answers are interchangeable.
    fn new_message(&self) -> Message {
        let free = |message: &Message| {
            self.pending
                .values()
                .all(|p| p.request.metadata.id != message.metadata.id)
        };
        std::iter::repeat_with(Message::query)
            .take(16)
            .find(free)
            .unwrap_or_else(Message::query)
    }
}
