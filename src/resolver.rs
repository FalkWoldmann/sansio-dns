//! The resolver state machine: queries in flight, stream connections, and
//! how a query moves on.
//!
//! A query in flight is a `Pending`, under its `QueryId` in
//! `Resolver::pending`, or a `QueryId` that joined one
//! (`Pending::followers`). `Pending` has the table of a query's states. A
//! stream connection is a `Connection`, under its `ConnectionId` in
//! `Resolver::connections`. `Connection` lists the ways it ends, and over
//! TLS it holds a `tls::Session`, which lists its phases. The cache's
//! `Entry` documents its own where it is defined. The crate docs' "How a
//! query moves on" table says which server, attempt and deadline each move
//! of a query takes, and the comment above `Resolver::act_on` maps its rows
//! to `Pending::decide`, which picks the move for each thing that happens
//! to a query's current attempt, and to the functions here.
//!
//! An address lookup (`Resolver::lookup_ip`) is a `lookup::Lookup` in
//! `Resolver::lookups`, which says how it moves on: it waits for the
//! queries it started for its current search candidate. Every input that
//! can end a query ends with `Resolver::run_lookups`, which hands each
//! event queued during the input (those from `Resolver::handed` on) to the
//! lookup waiting for its query, in the order they were queued. A lookup
//! that moves on starts the next candidate's queries there, with the
//! input's `now`, and their events, if they end at once, are handed over in
//! turn. So the next candidate's transmits are queued after the input's own
//! but before the driver has carried those out: the retry of one whose send
//! fails (`Resolver::handle_udp_error`) comes after them, and the failed
//! server isn't yet in `Resolver::failed` when they pick theirs. The
//! queries still come out of `Resolver::poll_event` as any other, so a
//! driver can close their sockets.
//!
//! `Resolver::poll_timeout` is the earliest of the queries' deadlines
//! (`Pending::deadline`) and the connections' idle deadlines
//! (`Resolver::idle_deadline`). The cache and the failure memory
//! (`Resolver::failed`) read `now` only when they are used, so they add no
//! deadline.
//!
//! `Resolver::pending` and `Resolver::connections` are `BTreeMap`s, so the
//! order of their IDs shows in the outputs. `Resolver::handle_timeout`
//! takes the queries whose deadline has passed in `QueryId` order, the
//! queries on a connection that closes move on in that order, and
//! `Resolver::stream_match` tries a connection's queries in that order
//! before its orphans for a reply with a question; one without a question
//! matches only if exactly one of them could be its query. Idle
//! connections, and every connection at `Resolver::shutdown`, close in
//! `ConnectionId` order. `Resolver::lookups` is only searched, by query or
//! `LookupId`, so its order doesn't show.

use std::collections::{BTreeMap, VecDeque};
use std::fmt;
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::time::Instant;

use hickory_proto::ProtoError;
use hickory_proto::op::{Edns, Message, Query, ResponseCode};
use hickory_proto::rr::{Name, RecordType};

use crate::cache::{Cache, Hit};
use crate::config::MAX_SENDS_PER_SERVER;
use crate::lookup::{Lookup, Step};
#[cfg(feature = "tls")]
use crate::tls;
use crate::wire::{
    EDNS_PAYLOAD, Reply, clamp_ttls, frame, has_data, is_meta_type, is_referral, is_special_use,
    local_answer,
};
#[cfg(feature = "tls")]
use crate::wire::{is_protected_for, protect};
use crate::{Config, ConnectionId, Error, Event, LookupId, QueryId, Transmit, Transport};

/// How many requests that left a connection unanswered (`Orphan`s) it may
/// hold. One more closes it, which frees their message IDs: a server that
/// drops some queries on a busy connection, which never goes idle, would
/// otherwise use up the ID space (RFC 7766 §6.2.1, §6.2.4).
const MAX_ORPHANS: usize = 256;

/// A query in flight that is sent, for itself and the queries that joined
/// it.
///
/// A `QueryId` is in one of these states: none, an ID that `query` hasn't
/// issued yet; a leader, whose current attempt went over UDP (Udp,
/// `Route::Udp`) or to connection c (Stream(c), `Route::Stream`); a
/// follower, in one leader's `followers`; or gone. In the table, a query
/// that sends goes through `Resolver::emit`, which picks UDP or a stream,
/// and stays a leader. One that moves on (`Resolver::advance`) sends its
/// next attempt, or ends if it has no attempt or server left. One that ends
/// is gone, with its event queued and then one for each of its followers
/// (`Resolver::finish`). A send can end the query instead (a cached
/// failure, a TLS session that can't start, a message that doesn't encode)
/// or move it on (a write TLS refuses). For each input, the first row whose
/// guard holds applies; an input that no row matches, such as a datagram or
/// `handle_udp_error` for a query on a stream, is ignored. A lookup's
/// queries start as `query` starts one, through `Resolver::start`, from
/// `lookup_ip` or from any input whose `Resolver::run_lookups` moves the
/// lookup on, and `cancel_lookup` cancels them as `cancel` does. The crate
/// docs' "How a query moves on" table says which server, attempt and
/// deadline each move takes; for a leader's reply, deadline, datagram not
/// sent or connection that closes, `Pending::decide` picks the move.
///
/// | State | Input \[guard\] | Next | Also |
/// |---|---|---|---|
/// | none | `query` [a meta type] | none (`Err`) | |
/// | none | `query` [answered locally or by the cache] | ends | |
/// | none | `query` [a leader asks for the same name and type] | follower | |
/// | none | `query` [any other] | sends (none and `Err` if it doesn't encode) | |
/// | Udp | reply [a truncated one] | sends over TCP, or moves on | |
/// | leader | reply [records that don't decode] | moves on | |
/// | leader | reply [FORMERR without OPT, not over TLS] | sends without EDNS, or moves on | |
/// | leader | reply [a referral] | moves on | |
/// | leader | reply [NOERROR with data] | ends | |
/// | leader | reply [NXDOMAIN or NODATA, `Resolver::walk` finds a candidate to send] | sends that candidate | |
/// | leader | reply [NXDOMAIN or NODATA] | ends | |
/// | leader | reply | moves on | |
/// | Udp | its deadline, or `handle_udp_error` [its server] | moves on | |
/// | Stream(c) | its deadline [a response on c since `written_after`, room for an orphan] | moves on | an `Orphan` on c |
/// | Stream(c) | its deadline | moves on | c closes (`Connection`) |
/// | any | `shutdown` | gone | |
/// | Stream(c) | c closes for another reason | sends, or moves on | |
/// | follower | `cancel` | gone | |
/// | leader | `cancel` [no followers] | gone | on Stream(c), an `Orphan` on c, or c closes |
/// | Stream | `cancel` [with followers] | the first follower leads | |
/// | Udp | `cancel` [with followers] | the first follower leads, and sends or moves on | |
#[derive(Debug)]
struct Pending {
    // The search, carried over from one candidate to the next.
    /// The name and type as asked, before search domains. A later query
    /// for the same two joins this one instead of being sent. hickory's
    /// `Name` equality ignores case but not the trailing dot.
    asked: Asked,
    /// Search candidates still to try if this name has no data of the type
    /// asked for.
    rest: VecDeque<Name>,
    /// The first NODATA answer of an earlier search candidate: the outcome
    /// if no later one has data.
    nodata: Option<Message>,
    /// Queries that joined this one, in the order they joined; each gets
    /// its outcome too. Every `QueryId` in flight is in exactly one place:
    /// a key of `Resolver::pending`, or one leader's followers.
    followers: Vec<QueryId>,

    // The current search candidate: `Resolver::next_candidate` starts
    // these over, and the attempt below.
    request: Message,
    payload: Vec<u8>,
    /// Where in the server list its attempts start, so it skips servers
    /// that failed recently.
    first: usize,
    /// Servers that answered this search candidate with an error, a reply
    /// that couldn't be decoded, or a referral: later attempts skip them
    /// (RFC 1035 §7.2, RFC 1034 §5.3.3 step 4d). Between inputs the
    /// current server isn't one of them: `Resolver::reject` adds it and
    /// moves the query on to a server that isn't, or ends it.
    excluded: Vec<SocketAddr>,
    /// How often this search candidate was sent to each server over each
    /// channel, free sends included: at most `MAX_SENDS_PER_SERVER` times
    /// (RFC 9520 §3.1). `Resolver::emit` counts each send, and every send
    /// but a search candidate's first is checked with `Pending::may_send`
    /// before it, for the channel `emit` then takes.
    sends: Vec<(SocketAddr, Channel, u8)>,
    /// Whether every send goes over a stream: after a truncated answer
    /// over UDP, for the rest of the search candidate (RFC 1123 §6.1.3.2),
    /// and always with DNS over TLS (RFC 7858 §3). Otherwise a send goes
    /// over a stream only when a connection to its server is open (RFC
    /// 7766 §5). Between inputs a query with it set is on a stream
    /// (`Route::Stream`): it is set just before a send (`Pending::decide`
    /// sets it after a truncated answer), and `emit` sends such a query
    /// over nothing else.
    stream_only: bool,
    /// Whether its attempt was already sent again for free, after its
    /// connection, which had answered only before the attempt was written
    /// or took its request back, was lost or ended by the server's
    /// close_notify (`Input::Lost`), or after the resolver shut its
    /// connection (`Input::Shut`). The two share it: after one free
    /// resend, from either, the next one from either uses up an attempt.
    /// Reset for each search candidate; set by `Pending::use_free_resend`,
    /// from `Pending::decide`. A connection lost or ended by close_notify
    /// after a response arrived on it since then gives a free resend
    /// without it.
    free_resend_used: bool,
    /// When this query's current search candidate was first sent, which
    /// decides whether its failure backs off from a cached one
    /// (`Cache::failed`).
    started: Instant,

    // The current attempt.
    /// Where in the rotation its current attempt is: it goes to
    /// `Config::server(position)`. Starts at `first` and moves on by one
    /// per attempt, past the servers in `excluded`, so how often it has
    /// wrapped around is the number of rounds made.
    position: usize,
    /// How many attempts it has used up before the current one. Below
    /// `Config::attempts` between inputs: a query that would reach it ends
    /// (`Resolver::try_advance`).
    attempt: usize,
    /// When the current attempt times out. Only `Resolver::emit` sets it;
    /// `Resolver::new_pending` leaves a placeholder that the first `emit`
    /// replaces, or that goes with the query if a cached failure ends it
    /// there. `emit` starts it over (`Deadline::Fresh`) for every attempt
    /// and resend except the free resend after `Input::Shut`, which keeps
    /// it (`Deadline::Kept`). An heir that takes a cancelled query
    /// over on a stream sends nothing and keeps it too.
    deadline: Instant,
    /// How the current attempt went out; set by `Resolver::emit`. Between
    /// inputs a connection it names is in `Resolver::connections` and goes
    /// to the current server: every path that removes a connection moves
    /// its queries on in the same call.
    route: Route,
}

impl Pending {
    /// The server of the current attempt.
    fn server(&self, config: &Config) -> SocketAddr {
        config.server(self.position)
    }

    /// Whether its current attempt was written to `connection`.
    fn is_on(&self, connection: ConnectionId) -> bool {
        matches!(self.route, Route::Stream { connection: c, .. } if c == connection)
    }

    /// Start the current attempt's deadline over at `now`:
    /// `Config::timeout`, doubled each time the attempts have gone round
    /// the server list (exponential backoff, RFC 1123 §6.1.3.3), within
    /// the bounds of `Config::wait`.
    fn restart_deadline(&mut self, config: &Config, now: Instant) {
        let round = self.position.saturating_sub(self.first) / config.servers().len();
        self.deadline = config.deadline(round, now);
    }

    /// Whether this search candidate may be sent to `server` once more,
    /// over the channel `channel` picks for that send: RFC 9520 §3.1 allows
    /// three sends in all.
    fn may_send(
        &self,
        server: SocketAddr,
        connections: &BTreeMap<ConnectionId, Connection>,
    ) -> bool {
        let channel = channel(connections, self, server);
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

    /// Whether its current attempt may go to its server once more, over the
    /// channel that send would take (RFC 9520 §3.1).
    fn may_resend(
        &self,
        config: &Config,
        connections: &BTreeMap<ConnectionId, Connection>,
    ) -> bool {
        self.may_send(self.server(config), connections)
    }

    /// Use up its free resend (`free_resend_used`), which it has once per
    /// search candidate: true if it still had it.
    fn use_free_resend(&mut self) -> bool {
        !std::mem::replace(&mut self.free_resend_used, true)
    }

    /// What the query does next, now that `input` happened to its current
    /// attempt: the rows of the crate docs' "How a query moves on" table
    /// that a reply, a timeout, a UDP error, an abort or a connection's
    /// end takes, which the comment above `Resolver::act_on` maps to this
    /// `match`. Every free resend checks first that the query may go to its
    /// server once more (`may_resend`), and moves on if not. Sets
    /// `stream_only` after a truncated answer over UDP and uses up
    /// `free_resend_used`; the rest of the move is up to
    /// `Resolver::act_on`.
    ///
    /// A truncated reply is used as it is on a stream (RFC 2181 §9). Only
    /// `NOERROR` and `NXDOMAIN` say something about the name; any other
    /// code means this server couldn't answer (RFC 1035 §4.1.1 and §7.2),
    /// including codes 6 to 15, BADVERS (RFC 6891 §6.1.3) and BADCOOKIE,
    /// which can't be about a cookie since none is sent (RFC 7873 §5.3).
    fn decide(
        &mut self,
        input: Input,
        config: &Config,
        connections: &BTreeMap<ConnectionId, Connection>,
        now: Instant,
    ) -> Action {
        match input {
            // The same server over TCP (RFC 1123 §6.1.3.2), even for a reply
            // whose records don't decode (RFC 2181 §9). Earlier attempts may
            // have used up the room on an open connection.
            Input::Reply(reply) if reply.is_truncated() && self.route == Route::Udp => {
                self.stream_only = true;
                if self.may_resend(config, connections) {
                    Action::Resend(Deadline::Fresh)
                } else {
                    Action::Advance(Error::Timeout)
                }
            }
            Input::Reply(Reply::Broken { error, .. }) => Action::Reject(Error::Malformed(error)),
            Input::Reply(Reply::Whole(response)) => match response.metadata.response_code {
                // RFC 6891 §7: a server without EDNS answers FORMERR and no
                // OPT; §6.2.2 lets us ask the same server again without
                // EDNS, so a second one is a plain server error. Not over
                // TLS, where EDNS carries the padding (RFC 8467 §4.1).
                ResponseCode::FormErr if response.edns.is_none() && !config.uses_tls() => {
                    let error = Error::Server(ResponseCode::FormErr);
                    if self.request.edns.is_none() {
                        Action::Reject(error)
                    } else if self.may_resend(config, connections) {
                        Action::ResendWithoutEdns
                    } else {
                        Action::Advance(error)
                    }
                }
                ResponseCode::NoError if is_referral(&response) => {
                    Action::Reject(Error::NoRecursion)
                }
                ResponseCode::NoError if has_data(&response) => Action::Finish(response),
                ResponseCode::NoError | ResponseCode::NXDomain => Action::SearchOn(response),
                code => Action::Reject(Error::Server(code)),
            },
            Input::NoAnswer(error) => Action::Retry(error),
            // RFC 7766 §6.2.4: free every time if the connection answered
            // since the attempt was written or took its request back, and
            // once if it had only answered before.
            Input::Lost { responses, error } => {
                let progress = matches!(
                    self.route,
                    Route::Stream { written_after, .. } if responses > written_after
                );
                if self.may_resend(config, connections)
                    && (progress || (responses > 0 && self.use_free_resend()))
                {
                    Action::Resend(Deadline::Fresh)
                } else {
                    Action::Retry(error)
                }
            }
            // Free once, shared with `Lost`, and only before its own
            // deadline, which the resend keeps.
            Input::Shut => {
                if self.deadline > now
                    && self.may_resend(config, connections)
                    && self.use_free_resend()
                {
                    Action::Resend(Deadline::Kept)
                } else {
                    Action::Retry(Error::Timeout)
                }
            }
        }
    }
}

/// What a query asks for: the name as given, before search domains, and
/// the type.
type Asked = (Name, RecordType);

/// The answers a search has had so far: the first NODATA, the outcome if no
/// later candidate has data, and else the last NXDOMAIN.
#[derive(Debug, Default)]
struct Outcome {
    nodata: Option<Message>,
    last: Option<Message>,
}

impl Outcome {
    /// Take in the NXDOMAIN or NODATA answer `response`.
    fn add(&mut self, response: Message) {
        if response.metadata.response_code == ResponseCode::NoError && self.nodata.is_none() {
            self.nodata = Some(response);
        } else {
            self.last = Some(response);
        }
    }

    /// The answer a search that ran out of candidates ends with, as glibc
    /// reports NO_DATA over HOST_NOT_FOUND.
    fn into_response(self) -> Option<Message> {
        self.nodata.or(self.last)
    }
}

/// Where a search goes after looking its next candidates up in the cache.
#[derive(Debug)]
enum Next {
    /// Send this candidate: the cache holds nothing for it.
    Send(Name),
    /// The cache holds a failure for the next candidate, which ends the
    /// search, as a failure does when it happens.
    Failed(Error),
    /// The cache answered every candidate left with NXDOMAIN or NODATA.
    Done,
}

/// How a query's current attempt went out.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Route {
    /// As a datagram, from the query's own socket.
    Udp,
    /// Written to `connection`, or waiting there for the answer to its
    /// request, which an earlier attempt left as an `Orphan`.
    Stream {
        connection: ConnectionId,
        /// How many responses had arrived on `connection`
        /// (`Connection::responses`) when the attempt was written to it,
        /// or took its request back from an `Orphan`, so that later ones
        /// show the connection still works.
        written_after: u64,
    },
}

/// A DNS transport, as RFC 9520 §3.1 counts sends to a server: UDP, or a
/// stream, which is TCP, or TLS with DNS over TLS. A resolver uses one kind
/// of stream, so the two never mix.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Channel {
    Udp,
    Stream,
}

/// What [`Resolver::emit`] does with the query's deadline.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Deadline {
    /// Start it over from `now`, for the round the attempt is in
    /// (`Config::deadline`).
    Fresh,
    /// Keep it: for the free resend after `Input::Shut`, which must not
    /// stretch how long the server can hold the query.
    Kept,
}

/// What happened to a query's current attempt, for `Pending::decide`.
#[derive(Debug)]
enum Input {
    /// A reply matched to it (`Resolver::handle_reply`).
    Reply(Reply),
    /// No answer from its server, with `error` if it is out of attempts:
    /// its deadline passed, over UDP or on a connection that stays open
    /// (`Resolver::time_out`), its datagram couldn't be sent
    /// (`Resolver::handle_udp_error`), or TLS failed on its connection
    /// (`Resolver::abort`).
    NoAnswer(Error),
    /// Its connection was lost, or ended by the server's close_notify,
    /// after `responses` responses (`Resolver::move_off`); `error` if it
    /// moves on and is out of attempts.
    Lost { responses: u64, error: Error },
    /// The resolver shut its connection because a query on it, this one or
    /// another, timed out with no response since, or it held `MAX_ORPHANS`
    /// orphans (`Resolver::time_out_stream`).
    Shut,
}

/// What a query does next (`Pending::decide`); `Resolver::act_on` carries
/// it out.
#[derive(Debug)]
enum Action {
    /// Send the current attempt again, to the same server, without using
    /// up an attempt (`Resolver::emit`).
    Resend(Deadline),
    /// The same, without EDNS (`Resolver::drop_edns`).
    ResendWithoutEdns,
    /// The server gave no answer: `Resolver::retry`.
    Retry(Error),
    /// The server answered with an error: `Resolver::reject`.
    Reject(Error),
    /// Move on without marking the server: `Resolver::advance`.
    Advance(Error),
    /// `NOERROR` with data, which ends the query (`Resolver::finish`).
    Finish(Message),
    /// `NXDOMAIN` or NODATA, which moves the search on
    /// (`Resolver::search_on`).
    SearchOn(Message),
}

/// A stream connection to one server, shared by its queries.
///
/// It lives from `Resolver::connect` until it leaves
/// `Resolver::connections`, in one of these ways:
///
/// | Input | Ends it | `TcpClose` | Its queries |
/// |---|---|---|---|
/// | `handle_stream_closed`, `handle_stream_error` | `lost` | no | sent again or moved on (`move_off`) |
/// | the server's close_notify, with no TLS error (`Ending::CloseNotify`), in `handle_stream_data` | `retire` | yes | the same, after the answers that came before it |
/// | a TLS error on bytes read from it (`Ending::Failed`), in `handle_stream_data` | `abort` | yes | moved on (`retry`), after the answers decrypted before the error |
/// | a write to it that TLS refuses, in `emit` | `abort` | yes | moved on (`retry`), the query written included |
/// | a query on it times out with no response since `written_after`, or one more `Orphan` would go past `MAX_ORPHANS` | `time_out_stream` | yes | sent again if their deadline hasn't passed, they have room and their free resend is left (`Input::Shut`), else moved on |
/// | its idle deadline passes (`handle_timeout`) | `close_idle_connections` | yes | none: no query is on it |
/// | `shutdown` | `shutdown` | yes | none left |
///
/// Every end but `lost` goes through `shut`, which also queues a TLS
/// session's last bytes before the `TcpClose`: none after an alert from
/// the server that rustls reported as the error (`tls::Session::alerted`).
#[derive(Debug)]
struct Connection {
    /// Between inputs no other connection goes to this server:
    /// `Resolver::emit` connects only when no connection to the server is
    /// open, and one that is `closing` is gone by the end of the input.
    server: SocketAddr,
    /// Decrypted bytes not yet split into messages.
    received: Vec<u8>,
    /// When a query was last written to it or a complete response last
    /// arrived on it (`next_response`); the idle timeout counts from here
    /// once nothing is outstanding on it (RFC 7766 §6.2.3, RFC 7828 §3).
    /// Partial messages and TLS records don't count.
    last_active: Instant,
    /// How many complete responses have arrived on it, matched or not, as
    /// `next_response` counts them.
    responses: u64,
    /// Queries written to it that left it before their answer came. At
    /// most `MAX_ORPHANS`. Their message IDs stay in use
    /// (`Resolver::new_message`), so no two requests outstanding on it
    /// share one unless all 65536 are in use.
    orphans: Vec<Orphan>,
    /// Whether the session ended, by the server's close_notify or a TLS
    /// error, while the answers that came before are still being acted on:
    /// nothing more is sent on it, and it is closed once they are done.
    /// True only within the `handle_stream_data` call that took in the
    /// bytes that ended it, which removes the connection before it returns.
    closing: bool,
    /// The TLS session, when using DNS over TLS.
    #[cfg(feature = "tls")]
    tls: Option<Box<tls::Session>>,
}

/// What [`Connection::receive`] hands back besides the bytes it keeps:
/// nothing without TLS.
#[derive(Debug, Default)]
struct Incoming {
    /// The bytes to send back: the rest of the handshake, and then the
    /// queries that waited for it. Empty if the session failed.
    to_send: Vec<u8>,
    /// How the bytes ended the TLS session, if they did.
    ending: Option<Ending>,
}

/// How bytes read from a connection ended its TLS session: `tls::Ending`
/// with the error as [`Error::Tls`], defined here so that
/// [`Resolver::handle_stream_data`] matches on it without the `tls`
/// feature too. The bytes decrypted before the end are kept either way.
#[derive(Debug)]
#[cfg_attr(
    not(feature = "tls"),
    expect(dead_code, reason = "only a TLS session ends in the bytes it reads")
)]
enum Ending {
    /// The server's close_notify: what followed it is ignored (RFC 8446
    /// §6.1).
    CloseNotify,
    /// The TLS error that ended the session, as [`Error::Tls`]. It wins
    /// over a close_notify in the same bytes.
    Failed(Error),
}

impl Connection {
    /// Whether it takes queries to `server`: it goes to `server`, and its
    /// TLS session, if it has one, hasn't ended (`closing`).
    fn is_open_to(&self, server: SocketAddr) -> bool {
        self.server == server && !self.closing
    }

    /// Take in `data` read from it, through the TLS session if it has one.
    /// If the bytes end the session, it keeps what was decrypted before the
    /// end.
    fn receive(&mut self, data: &[u8]) -> Incoming {
        #[cfg(feature = "tls")]
        if let Some(session) = &mut self.tls {
            let received = session.receive(data);
            self.received.extend_from_slice(&received.plaintext);
            return Incoming {
                to_send: received.reply,
                ending: received.ending.map(|ending| match ending {
                    tls::Ending::CloseNotify => Ending::CloseNotify,
                    tls::Ending::Failed(e) => Ending::Failed(Error::Tls(e)),
                }),
            };
        }
        self.received.extend_from_slice(data);
        Incoming::default()
    }

    /// Take the next response off `received`, or `None` once no complete
    /// length-prefixed message is left. A response is a complete message
    /// whose header and question decode (`Reply::decode`) and that has QR
    /// set; any other complete message is taken off on the way and
    /// dropped. Only a response counts, matched or not: it adds one to
    /// `responses` and sets `last_active`, where the idle timeout counts
    /// from.
    fn next_response(&mut self, now: Instant) -> Option<Reply> {
        loop {
            let (len, rest) = self.received.split_first_chunk::<2>()?;
            let len = usize::from(u16::from_be_bytes(*len));
            let reply = Reply::decode(rest.get(..len)?);
            self.received.drain(..2 + len);
            if let Some(reply) = reply.filter(Reply::is_response) {
                self.responses += 1;
                self.last_active = now;
                return Some(reply);
            }
        }
    }
}

/// A query that left a connection before its answer came: it was
/// cancelled, or timed out and moved on while the connection stayed open.
/// The server may still answer it, so its message ID stays in use on the
/// connection until the answer arrives, which is then dropped, a later
/// attempt of the query takes it back (`Resolver::emit`), or the
/// connection ends (RFC 7766 §6.2.1). It doesn't expire.
#[derive(Debug)]
struct Orphan {
    id: u16,
    question: Vec<Query>,
    /// Until when it counts as outstanding, keeping the connection from
    /// going idle: the deadline the query had, which for one left by a
    /// timeout isn't in the future. Only the idle deadline reads it.
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
/// must use one or a connection is open to `server`
/// (`Connection::is_open_to`), UDP otherwise.
fn channel(
    connections: &BTreeMap<ConnectionId, Connection>,
    pending: &Pending,
    server: SocketAddr,
) -> Channel {
    if pending.stream_only || connections.values().any(|c| c.is_open_to(server)) {
        Channel::Stream
    } else {
        Channel::Udp
    }
}

/// The event that ends `query` with `outcome`.
fn event(query: QueryId, outcome: Result<Message, Error>) -> Event {
    match outcome {
        Ok(response) => Event::Response { query, response },
        Err(error) => Event::Failed { query, error },
    }
}

/// The resolver state machine. See the crate docs for how to drive it.
pub struct Resolver {
    config: Config,
    next_query: u64,
    pending: BTreeMap<QueryId, Pending>,
    next_connection: u64,
    connections: BTreeMap<ConnectionId, Connection>,
    /// Servers whose last attempt failed without an answer, and until when
    /// new queries start after them (`Config::failure_memory`).
    failed: BTreeMap<SocketAddr, Instant>,
    /// Resolution failures and negative answers, by question.
    cache: Cache,
    transmits: VecDeque<Transmit>,
    events: VecDeque<Event>,
    /// How many of `events`, from the front, the lookups were handed
    /// (`run_lookups`): all of them between inputs.
    handed: usize,
    next_lookup: u64,
    /// The address lookups running. Each waits for queries no other one
    /// started.
    lookups: Vec<Lookup>,
    /// Lookups that are done, with their outcomes, in the order they ended.
    looked_up: VecDeque<(LookupId, Result<Vec<IpAddr>, Error>)>,
}

/// Shows the settings and how much is in flight, not the internal state,
/// which is not part of the API.
impl fmt::Debug for Resolver {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Resolver")
            .field("config", &self.config)
            .field("queries", &self.pending.len())
            .field("connections", &self.connections.len())
            .field("transmits", &self.transmits.len())
            .field("events", &self.events.len())
            .finish_non_exhaustive()
    }
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
            cache: Cache::default(),
            transmits: VecDeque::new(),
            events: VecDeque::new(),
            handed: 0,
            next_lookup: 0,
            lookups: Vec::new(),
            looked_up: VecDeque::new(),
        }
    }

    // Inputs. Each one that can end a query ends with `run_lookups`, which
    // hands the lookups the events queued during it.

    /// Start a recursive lookup of `name`/`record_type`.
    ///
    /// A name ending in a dot is used as given. Other names are tried with
    /// the [`Config::search`] domains, ordered by [`Config::ndots`], until
    /// one has data of `record_type` (RFC 1123 §6.1.4.3): the next candidate
    /// is tried after NXDOMAIN and after NODATA, a `NOERROR` answer without
    /// records of that type and class at the end of the CNAME chain (RFC
    /// 2308 §2.2, RFC 1035 §7.4).
    /// glibc's `res_search` moves on after NODATA only when the answer
    /// section is empty, and stops at a CNAME whose target has no data.
    /// When the candidates run out, the event carries the first NODATA
    /// answer if there was one, else the last NXDOMAIN. A query that fails
    /// on a candidate, out of attempts or servers, ends the search with
    /// that error, whatever the error, `SERVFAIL` and `REFUSED` included,
    /// as musl's resolver does: a temporary failure for the name meant must
    /// not turn into an answer for another name. glibc's `res_search` goes
    /// on to the search domains after any failure on the name as given when
    /// that comes first; among the search domains it moves on only after
    /// `SERVFAIL`, and after another failure it stops and still tries the
    /// name as given if that comes last, unless no server could be reached
    /// at all. Without search domains, `example.com` and `example.com.`
    /// send the same question, but only a query for the same name as given
    /// (trailing dot included, case ignored) joins one in flight.
    ///
    /// Each candidate is looked up in the cache first (see the crate docs):
    /// a cached NXDOMAIN or NODATA moves the search on without a transmit,
    /// and a cached failure ends it with the cached error. So a query
    /// answered from the cache alone gets its event at once, as a name
    /// answered locally does.
    ///
    /// Some names are answered at once, without a transmit, in this order:
    ///
    /// - `localhost` names get the loopback address for A and AAAA and
    ///   NODATA for other types (RFC 6761 §6.3), and names under
    ///   `invalid.` and `onion.` get NXDOMAIN (RFC 6761 §6.4, RFC 7686 §2),
    ///   whatever [`Config::hosts`] says, checked for the name as given,
    ///   before any search domain.
    /// - Names listed in [`Config::hosts`] are answered from there for A
    ///   and AAAA queries, with the addresses of that family (possibly
    ///   none), as glibc's `hosts: files dns` does. Only the name as given
    ///   is looked up there.
    /// - Names under `local.` and the link-local reverse zones, which RFC
    ///   6762 reserves for multicast DNS (§3, §4), get NXDOMAIN (§22.1
    ///   items 3 and 4), unless they are under a search domain that is
    ///   itself under one of these zones, such as Kubernetes'
    ///   `cluster.local.`, or under [`Config::unicast_local_zones`]. Those
    ///   go to the name servers. Multicast DNS is up to the caller. RFC
    ///   6762 §3 makes no difference between a `.local.` suffix typed and
    ///   one added from the search list, so this rule applies to each
    ///   search candidate, the name as given among them: a relative name
    ///   gets NXDOMAIN at once only when none of its candidates is left.
    ///   With search domain `cluster.local.`, `db.local` is sent as
    ///   `db.local.cluster.local.`.
    ///
    /// Other names under special-use zones, such as `test.`, `example.`,
    /// `home.arpa.` or `alt.`, are sent like any other (RFC 6761 §6.2,
    /// §6.5, RFC 8375 §4, RFC 9476 §3.2). Search candidates that the first
    /// or the last rule would answer are left out.
    ///
    /// A query for the same name and type as one still in flight (compared
    /// as given, before search domains) joins it, unless the cache answers
    /// it: nothing is sent for it, and it gets the same response or error
    /// as its own event, however late it joined.
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
        let started = self.start(name, record_type, true, now);
        self.run_lookups(now);
        started
    }

    /// Start looking up the addresses of `name`: the A and AAAA queries, as
    /// [`Config::ip_strategy`] picks them, with their addresses merged. The
    /// outcome comes out of [`Resolver::poll_lookup`], at once for a name
    /// answered locally or from the cache. The queries are queries like any
    /// other: their transmits come out of
    /// [`Resolver::poll_transmit`], those of the later search candidates
    /// too, and each ends with its own event, so a driver can close its
    /// socket.
    ///
    /// With [`Config::search`] domains, the lookup walks the candidates
    /// itself, asking each for both families at once, as glibc's
    /// `getaddrinfo` does: it moves on when neither query found an address,
    /// after NXDOMAIN or NODATA (RFC 1123 §6.1.4.3, RFC 2308 §2.2), and
    /// ends on the first candidate where one did, with the addresses of
    /// both families for that name. So they are those of one host (RFC 1123
    /// §6.1.4.3 (b)). A query that fails, or gets an answer whose CNAME
    /// chain loops, ends the search, and when the candidates run out the
    /// outcome is an empty list. Names that [`Resolver::query`] answers
    /// locally are answered that way, before any search domain:
    /// `localhost`, `invalid.` and `onion.` names and [`Config::hosts`]
    /// entries as given, and link-local names not served over unicast when
    /// none of their search candidates is sent. Search candidates that
    /// wouldn't be sent are left out. Each candidate is asked for by its
    /// absolute name, so its queries join, and are joined by, queries for
    /// that name, and each goes through the cache, as any query does: a
    /// candidate whose NXDOMAIN is cached gets it at once and the search
    /// moves on without a transmit, and one whose failure is cached ends
    /// the search with it.
    ///
    /// Sorting the addresses by the host's own ones (RFC 6724 §6) and racing
    /// connections (RFC 8305) is up to the caller. Cancel a lookup with
    /// [`Resolver::cancel_lookup`], not by cancelling its queries.
    ///
    /// # Errors
    ///
    /// If a query for the first search candidate can't be encoded.
    pub fn lookup_ip(&mut self, name: Name, now: Instant) -> Result<LookupId, ProtoError> {
        let started = self.start_lookup(name, now);
        self.run_lookups(now);
        started
    }

    /// The queries `lookup` is still waiting for, those of its current
    /// search candidate. They change when the search moves on, and there
    /// are none once it is done or cancelled.
    pub fn lookup_queries(&self, lookup: LookupId) -> impl Iterator<Item = QueryId> + use<> {
        let lookup = self.lookups.iter().find(|l| l.id == lookup);
        lookup.map(Lookup::queries).into_iter().flatten()
    }

    /// Stop `lookup`: its running queries are cancelled as by
    /// [`Resolver::cancel`], and no outcome comes for it from now on, not
    /// even one already queued for [`Resolver::poll_lookup`]. Returns the
    /// queries it cancelled, so a driver can close their sockets: none for
    /// a lookup that is done.
    pub fn cancel_lookup(
        &mut self,
        lookup: LookupId,
        now: Instant,
    ) -> impl Iterator<Item = QueryId> + use<> {
        self.looked_up.retain(|(id, _)| *id != lookup);
        let index = self.lookups.iter().position(|l| l.id == lookup);
        let lookup = index.map(|index| self.lookups.swap_remove(index));
        for query in lookup.iter().flat_map(Lookup::queries) {
            self.cancel_query(query, now);
        }
        self.run_lookups(now);
        lookup.into_iter().flat_map(|lookup| lookup.queries())
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
            self.run_lookups(now);
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
    /// the session first, which may queue a [`Transport::TcpWrite`]: the
    /// rest of the handshake, and then the queries that waited for it. A
    /// TLS error, such as a record that doesn't decrypt or an alert from
    /// the server that rustls reports as the error
    /// (`rustls::Error::AlertReceived`), ends the session: the answers
    /// decrypted before it in the same bytes count, and then the connection
    /// is closed and its queries move on to their next attempt. Before the
    /// close, the resolver sends what rustls still has to send (the rest of
    /// the handshake, say), ending with the alert it queued for the error
    /// (RFC 8446 §6.2), or with close_notify if it queued none, but nothing
    /// at all after such an alert from the server, as after an error alert
    /// (§6). The server's close_notify ends the session once the handshake
    /// is done; before then, rustls takes it for a TLS error, or ignores it
    /// if it is a warning, one of the session's first four, that arrives
    /// before the server has chosen TLS 1.3. When it ends the session with
    /// no TLS error, the answers before it count and anything after it is
    /// ignored (RFC 8446 §6.1): the resolver sends its own close_notify,
    /// closes the connection and moves its queries on as
    /// [`Resolver::handle_stream_closed`] does. A query that one of those
    /// answers moves on to the same server (the next search candidate, say)
    /// goes to a new connection. A later `handle_stream_closed` or
    /// `handle_stream_error` for the connection is ignored.
    pub fn handle_stream_data(&mut self, connection: ConnectionId, data: &[u8], now: Instant) {
        let Some(conn) = self.connections.get_mut(&connection) else {
            return;
        };
        let Incoming { to_send, ending } = conn.receive(data);
        // Answers that move a query on must not send it here.
        conn.closing = ending.is_some();
        let server = conn.server;
        self.queue_write(connection, server, to_send);
        // One response at a time: acting on an answer may change this
        // connection too.
        while let Some(mut reply) = self
            .connections
            .get_mut(&connection)
            .and_then(|conn| conn.next_response(now))
        {
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
        match ending {
            None => {}
            Some(Ending::CloseNotify) => self.retire(connection, now),
            Some(Ending::Failed(error)) => self.abort(connection, now, &error),
        }
        self.run_lookups(now);
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
        self.run_lookups(now);
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
        self.run_lookups(now);
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
    ///
    /// Not every refused datagram draws an ICMP error: macOS, for one,
    /// rate-limits port unreachable messages, so a datagram refused soon
    /// after another may get none, and the query then waits out its
    /// deadline.
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
            self.act_on(query, Input::NoAnswer(Error::Io(error)), now);
            self.run_lookups(now);
        }
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
            self.time_out(id, now);
        }
        self.close_idle_connections(now);
        self.run_lookups(now);
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
    /// none left, it fails with [`Error::Timeout`] at once, along with the
    /// queries that joined it. That failure isn't cached: no server failed
    /// to answer (RFC 9520 §2), since its answers may have gone to the
    /// sockets of the cancelled queries, so the next query for the name is
    /// sent as usual. Over a stream nothing is sent; the answer
    /// still arrives on the same connection, and the heir keeps the
    /// deadline.
    ///
    /// A query cancelled with no one to take it over after its request was
    /// written to a connection keeps its message ID in use there until the
    /// answer arrives or the connection ends, and keeps the connection from
    /// going idle until the deadline it had (RFC 7766 §6.2.1, §6.2.3). If
    /// the connection already holds 256 such requests, it is closed instead
    /// and its other queries move as when one of them times out with no
    /// response since (see [`Resolver::handle_timeout`]).
    pub fn cancel(&mut self, id: QueryId, now: Instant) {
        self.cancel_query(id, now);
        self.run_lookups(now);
    }

    /// [`Resolver::cancel`], without handing the lookups the events it
    /// queues.
    fn cancel_query(&mut self, id: QueryId, now: Instant) {
        let Some(mut pending) = self.pending.remove(&id) else {
            for p in self.pending.values_mut() {
                p.followers.retain(|&follower| follower != id);
            }
            return;
        };
        if pending.followers.is_empty() {
            // Its request is still outstanding on its connection.
            if let Route::Stream { connection, .. } = pending.route
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
        let heir = pending.followers.remove(0);
        match pending.route {
            // Nothing to send: the answer still arrives on the connection,
            // and the heir keeps the deadline.
            Route::Stream { .. } => {
                self.pending.insert(heir, pending);
            }
            Route::Udp => {
                let room = pending.may_resend(&self.config, &self.connections);
                self.pending.insert(heir, pending);
                if room {
                    self.emit(heir, now, Deadline::Fresh);
                } else if !self.try_advance(heir, now) {
                    // Not a resolution failure (RFC 9520 §2): the server may
                    // well have answered, to the cancelled queries' sockets.
                    self.finish(heir, Err(Error::Timeout));
                }
            }
        }
    }

    /// Forget every cached failure and negative answer (see the crate docs),
    /// and which servers recently failed to answer
    /// ([`Config::failure_memory`]), as a driver should when the host's
    /// network changes: what failed or didn't exist on the old network may
    /// work on the new one, where the servers may be reachable again, and
    /// a failure stays cached for up to five minutes. Queries in flight go
    /// on as they are.
    pub fn flush_cache(&mut self) {
        self.cache.flush();
        self.failed.clear();
    }

    /// Stop: forget every query in flight, as [`Resolver::cancel`] does but
    /// without handing any over, and every lookup, as
    /// [`Resolver::cancel_lookup`] does, and close every open connection,
    /// over TLS after its close_notify alert (RFC 8446 §6.1). For a driver
    /// that is about to drop its connections: carry out the transmits this
    /// queues first. Events and lookup outcomes already queued still come
    /// out of [`Resolver::poll_event`] and [`Resolver::poll_lookup`], and
    /// the resolver takes new queries afterwards.
    pub fn shutdown(&mut self) {
        self.pending.clear();
        self.lookups.clear();
        let connections: Vec<ConnectionId> = self.connections.keys().copied().collect();
        for connection in connections {
            self.shut(connection);
        }
    }

    // Outputs, which the driver polls after each input.

    /// Next transmit to carry out, if any: a datagram, or a stream connect,
    /// write or close.
    pub fn poll_transmit(&mut self) -> Option<Transmit> {
        self.transmits.pop_front()
    }

    /// Next completed query, if any. The queries of the lookups started
    /// with [`Resolver::lookup_ip`] are among them.
    pub fn poll_event(&mut self) -> Option<Event> {
        let event = self.events.pop_front()?;
        self.handed = self.handed.saturating_sub(1);
        Some(event)
    }

    /// Next lookup started with [`Resolver::lookup_ip`] that is done, if
    /// any, with its outcome: the addresses of one family followed by those
    /// of the other, in the order of [`Config::ip_strategy`], each in the
    /// server's order. An error only if no address was found and a query
    /// failed or got an answer whose CNAME chain loops
    /// ([`Error::CnameLoop`]); no address and no failure (NXDOMAIN, or no
    /// records) is an empty list.
    pub fn poll_lookup(&mut self) -> Option<(LookupId, Result<Vec<IpAddr>, Error>)> {
        self.looked_up.pop_front()
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

    // Lookups: starting their queries, and handing them the events of the
    // queries that end.

    /// [`Resolver::lookup_ip`], without handing the lookups the events it
    /// queues. A name answered locally is asked for as given, as
    /// [`Resolver::query`] asks; any other by its first search candidate
    /// (the absolute name if none is left), without [`Config::hosts`],
    /// which applies only to the name as given.
    fn start_lookup(&mut self, name: Name, now: Instant) -> Result<LookupId, ProtoError> {
        let mut absolute = name.clone();
        absolute.set_fqdn(true);
        let local = is_special_use(&absolute)
            || self.config.hosts.lookup(&absolute).is_some()
            || self.config.never_sent_as_given(&name);
        let (first, rest) = if local {
            (name, VecDeque::new())
        } else {
            let mut rest = self.config.candidates(&name);
            (rest.pop_front().unwrap_or(absolute), rest)
        };
        let queries = self.start_lookup_queries(&first, local, now)?;
        let id = LookupId(self.next_lookup);
        self.next_lookup += 1;
        self.lookups.push(Lookup::new(id, queries, rest));
        Ok(id)
    }

    /// Start a lookup's queries for `name`, one per record type of
    /// [`Config::ip_strategy`], in its order, with [`Config::hosts`] if
    /// `hosts`. If the second can't start, the first is cancelled.
    fn start_lookup_queries(
        &mut self,
        name: &Name,
        hosts: bool,
        now: Instant,
    ) -> Result<[Option<QueryId>; 2], ProtoError> {
        let (first, second) = self.config.ip_strategy.record_types();
        let mut queries = [None, None];
        for (slot, record_type) in queries.iter_mut().zip([Some(first), second]) {
            let Some(record_type) = record_type else {
                continue;
            };
            match self.start(name.clone(), record_type, hosts, now) {
                Ok(query) => *slot = Some(query),
                Err(error) => {
                    for query in queries.into_iter().flatten() {
                        self.cancel_query(query, now);
                    }
                    return Err(error);
                }
            }
        }
        Ok(queries)
    }

    /// Hand each event queued since the last call to the lookup waiting for
    /// its query, if any, in the order they were queued. A lookup that is
    /// done goes to `looked_up`. One that moves on starts the queries for
    /// its next search candidate, whose events, if they end at once, are
    /// handed over in turn.
    fn run_lookups(&mut self, now: Instant) {
        while let Some(event) = self.events.get(self.handed) {
            self.handed += 1;
            let (Event::Response { query, .. } | Event::Failed { query, .. }) = event;
            let Some(index) = self.lookups.iter().position(|l| l.waits_for(*query)) else {
                continue;
            };
            let mut lookup = self.lookups.swap_remove(index);
            let outcome = match lookup.handle(event) {
                Step::Wait => None,
                Step::Next(candidate) => match self.start_lookup_queries(&candidate, false, now) {
                    Ok(queries) => {
                        lookup.sent(queries);
                        None
                    }
                    // The outcome so far, an empty list, stands if the next
                    // candidate can't be encoded, as in `Resolver::query`'s
                    // search.
                    Err(_) => Some(Ok(Vec::new())),
                },
                Step::Done(outcome) => Some(outcome),
            };
            match outcome {
                Some(outcome) => self.looked_up.push_back((lookup.id, outcome)),
                None => self.lookups.push(lookup),
            }
        }
    }

    // A query's transitions: starting a search candidate, acting on its
    // replies, moving on, timing out, and sending.

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
        let mut absolute = name.clone();
        absolute.set_fqdn(true);
        let id = QueryId(self.next_query);
        self.next_query += 1;
        let local = if is_special_use(&absolute) {
            Some(local_answer(&absolute, record_type))
        } else {
            hosts
                .then(|| self.config.hosts.answer(&absolute, record_type))
                .flatten()
                .or_else(|| {
                    self.config
                        .never_sent_as_given(&name)
                        .then(|| local_answer(&absolute, record_type))
                })
        };
        if let Some(response) = local {
            self.events.push_back(Event::Response {
                query: id,
                response,
            });
            return Ok(id);
        }
        let mut rest = self.config.candidates(&name);
        if rest.is_empty() {
            rest.push_back(absolute);
        }
        let mut outcome = Outcome::default();
        let candidate = match self.walk(&mut rest, record_type, &mut outcome, now) {
            Next::Send(candidate) => candidate,
            Next::Failed(error) => {
                self.events.push_back(Event::Failed { query: id, error });
                return Ok(id);
            }
            Next::Done => {
                if let Some(response) = outcome.into_response() {
                    self.events.push_back(Event::Response {
                        query: id,
                        response,
                    });
                }
                return Ok(id);
            }
        };
        let asked = (name, record_type);
        if let Some(leader) = self.pending.values_mut().find(|p| p.asked == asked) {
            leader.followers.push(id);
            return Ok(id);
        }
        let mut pending = self.new_pending(candidate, record_type, rest, asked, now)?;
        pending.nodata = outcome.nodata;
        self.pending.insert(id, pending);
        self.emit(id, now, Deadline::Fresh);
        Ok(id)
    }

    /// Look the search candidates in `rest` up in the cache, in order,
    /// taking each one off, until one has to be sent: one the cache holds
    /// nothing for. A cached NXDOMAIN or NODATA goes into `outcome` and the
    /// search moves on without a transmit (RFC 2308 §5, which meets RFC
    /// 1123 §6.1.4.3 (a) here); a cached failure ends the search.
    fn walk(
        &mut self,
        rest: &mut VecDeque<Name>,
        record_type: RecordType,
        outcome: &mut Outcome,
        now: Instant,
    ) -> Next {
        while let Some(name) = rest.pop_front() {
            let question = Query::query(name, record_type);
            match self.cache.get(&question, now) {
                None => return Next::Send(question.name().clone()),
                Some(Hit::Failed(error)) => return Next::Failed(error),
                Some(Hit::Response(response)) => outcome.add(response),
            }
        }
        Next::Done
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
        let first = self.first_server(now);
        #[cfg(feature = "tls")]
        if self.config.uses_tls() {
            protect(&mut request, self.config.server(first))?;
        }
        let payload = request.to_vec()?;
        Ok(Pending {
            asked,
            rest,
            nodata: None,
            followers: Vec::new(),
            request,
            payload,
            first,
            excluded: Vec::new(),
            sends: Vec::new(),
            stream_only: self.config.uses_tls(),
            free_resend_used: false,
            started: now,
            position: first,
            attempt: 0,
            // A placeholder: the caller's `emit` starts the deadline.
            deadline: now,
            route: Route::Udp,
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

    /// Replace `id`'s attempt with one for the search candidate `name`,
    /// with fresh attempts and no servers excluded, `rest` to try after it
    /// and `outcome` so far. If it can't be encoded, the answers so far
    /// stand.
    fn next_candidate(
        &mut self,
        id: QueryId,
        name: Name,
        rest: VecDeque<Name>,
        outcome: Outcome,
        now: Instant,
    ) {
        let Some(asked) = self.pending.get(&id).map(|p| p.asked.clone()) else {
            return;
        };
        let Ok(mut next) = self.new_pending(name, asked.1, rest, asked, now) else {
            // Not expected: the fallible calls in `new_pending` (`to_vec`,
            // and `protect`'s `pad` under `tls`) only encode the message,
            // and only its name has limits to check. hickory's `Name`
            // keeps each label within 63 octets and the name within 255,
            // the limits that encoding a name checks.
            if let Some(response) = outcome.into_response() {
                self.finish(id, Ok(response));
            }
            return;
        };
        if let Some(previous) = self.pending.get_mut(&id) {
            next.followers = std::mem::take(&mut previous.followers);
        }
        next.nodata = outcome.nodata;
        self.pending.insert(id, next);
        self.emit(id, now, Deadline::Fresh);
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

    /// Act on a reply already matched to `id` (`act_on`).
    fn handle_reply(&mut self, id: QueryId, reply: Reply, now: Instant) {
        // Both callers pass a pending query.
        let Some(pending) = self.pending.get(&id) else {
            return;
        };
        // Any answer, even an error code, shows the server is reachable.
        self.failed.remove(&pending.server(&self.config));
        self.act_on(id, Input::Reply(reply), now);
    }

    /// The current search candidate has no data of the type and class asked
    /// for: it doesn't exist (`NXDOMAIN`), or `response` is NODATA. Try the
    /// next candidate, past those the cache answers; when there is none,
    /// the first NODATA answer is the outcome, as glibc reports NO_DATA over
    /// HOST_NOT_FOUND, and otherwise the last NXDOMAIN.
    fn search_on(&mut self, id: QueryId, response: Message, now: Instant) {
        let Some(pending) = self.pending.get_mut(&id) else {
            return;
        };
        let record_type = pending.asked.1;
        let mut rest = std::mem::take(&mut pending.rest);
        let mut outcome = Outcome {
            nodata: pending.nodata.take(),
            last: None,
        };
        outcome.add(response);
        match self.walk(&mut rest, record_type, &mut outcome, now) {
            Next::Send(name) => self.next_candidate(id, name, rest, outcome, now),
            Next::Failed(error) => self.finish(id, Err(error)),
            Next::Done => {
                if let Some(response) = outcome.into_response() {
                    self.finish(id, Ok(response));
                }
            }
        }
    }

    // How a query moves on, row by row of the crate docs' table, and the
    // state that keeps each free step bounded per search candidate. What
    // happens to a query's current attempt goes to `act_on` as an `Input`,
    // `Pending::decide` picks the `Action` in one `match`, and `act_on`
    // carries it out:
    //
    // - no answer by its deadline (`time_out`), datagram not sent
    //   (`handle_udp_error`): `Input::NoAnswer`, then `retry`; on a stream,
    //   `time_out` closes the connection through `time_out_stream` only if
    //   no response arrived on it since the query was written (or since
    //   `emit` took the request back), or it holds `MAX_ORPHANS` orphans,
    //   and otherwise leaves an `Orphan` there, which `emit` takes back if
    //   a later attempt returns to that connection
    // - error code, FORMERR with OPT or a second one without, undecodable
    //   reply, referral: `Action::Reject`, then `reject`, which adds the
    //   server to `excluded`
    // - truncated over UDP: `decide` sets `stream_only`, then
    //   `Action::Resend`, once because `stream_only` keeps every later send
    //   off UDP
    // - FORMERR without OPT: `Action::ResendWithoutEdns`, then `drop_edns`,
    //   once because `request.edns` is taken
    // - connection lost after it answered, or closed by the server's
    //   close_notify (`handle_stream_data`): `move_off`, by way of `lost`
    //   or `retire`, with `Input::Lost`, then `Action::Resend`, for free
    //   every time if it answered after the query was written or took its
    //   request back (`written_after` in `Route::Stream`), else once by way
    //   of `Pending::use_free_resend`
    // - neighbour timed out on the connection, or it was closed for holding
    //   too many orphans: `time_out_stream`, with `Input::Shut`, then
    //   `Action::Resend` by way of `use_free_resend` (the same
    //   `free_resend_used` flag), else `retry`
    // - connection that never answered lost, TLS error on received bytes
    //   (after the answers decrypted before it), TLS write refused
    //   (`emit`): `move_off` with `Input::Lost`, or `abort` with
    //   `Input::NoAnswer`, then `retry`
    // - NXDOMAIN or NODATA, with candidates left: `Action::SearchOn`, then
    //   `search_on` and `next_candidate`, which resets all of the above
    //   with a new `Pending`
    // - joined query cancelled: `cancel`, limited only by the rule below
    //   (each hand-over over UDP sends again; the crate docs' `attempts + 3`
    //   bound leaves it out); an heir without room moves on by
    //   `try_advance`, and with no server left fails through `finish`, not
    //   cached (`give_up`), since the server may have answered the
    //   cancelled queries' sockets
    // - out of attempts, or every server excluded or without room: `advance`
    //   calls `give_up`, which caches the failure for the search candidate
    //   (`Cache::failed`, RFC 9520 §3.2) and fails the query and every
    //   query that joined it (`finish`)
    // - a search candidate with a cached failure: `emit` fails the query
    //   with it instead of sending, whichever path it came by; one with a
    //   cached NXDOMAIN or NODATA: `walk`, from `start` or `search_on`,
    //   moves on past it without sending
    //
    // `emit`'s `Deadline` argument is the table's Deadline column: `Kept`
    // for the free resend after `Input::Shut`, `Fresh` at every other
    // call. A hand-over on a stream (`cancel`) doesn't call `emit` and
    // keeps the deadline.
    //
    // `emit` picks the channel of every send (`channel`: the open
    // connection to the server if there is one, RFC 7766 §5) and counts it
    // in `Pending::sends`, and no search candidate goes to a server over a
    // channel more than three times (RFC 9520 §3.1). `Pending::may_send`
    // checks the room left on the channel `channel` picks for a send:
    // `try_advance` skips servers without room (for `advance`, and for
    // `cancel` when it moves on), and `cancel` and `decide` check it
    // through `Pending::may_resend` before a free send, the switch to TCP
    // included, since earlier attempts may have gone to an open
    // connection. They move on as `retry` (`Input::Lost`, `Input::Shut`),
    // `advance` (truncated, FORMERR without OPT) or `try_advance`
    // (`cancel`) instead. That check is all that bounds the resends after
    // a lost connection that answered since.
    //
    // `act_on`, `retry`, `reject`, `try_advance` and `drop_edns` return
    // early for an `id` that isn't pending, which no caller passes;
    // `try_advance` would report one as sent, so `advance` wouldn't fail it.

    /// `input` happened to `id`'s current attempt: make the move
    /// `Pending::decide` picks.
    fn act_on(&mut self, id: QueryId, input: Input, now: Instant) {
        let (config, connections) = (&self.config, &self.connections);
        let Some(pending) = self.pending.get_mut(&id) else {
            return;
        };
        match pending.decide(input, config, connections, now) {
            Action::Resend(deadline) => self.emit(id, now, deadline),
            Action::ResendWithoutEdns => self.drop_edns(id, now),
            Action::Retry(error) => self.retry(id, now, error),
            Action::Reject(error) => self.reject(id, now, error),
            Action::Advance(error) => self.advance(id, now, error),
            Action::Finish(response) => {
                if let Some(question) = response.queries.first() {
                    self.cache.answered(question);
                }
                self.finish(id, Ok(response));
            }
            Action::SearchOn(response) => {
                self.cache.negative(&response, &self.config, now);
                self.search_on(id, response, now);
            }
        }
    }

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
        if !self.try_advance(id, now) {
            self.give_up(id, error, now);
        }
    }

    /// Send `id`'s next attempt as `advance` does, or return false, leaving
    /// it pending for the caller to fail, if it is out of attempts or no
    /// server is left.
    fn try_advance(&mut self, id: QueryId, now: Instant) -> bool {
        let (config, connections) = (&self.config, &self.connections);
        let Some(pending) = self.pending.get_mut(&id) else {
            return true;
        };
        pending.attempt += 1;
        let servers = config.servers().len();
        let next = (pending.position + 1..=pending.position + servers).find(|&p| {
            let server = config.server(p);
            !pending.excluded.contains(&server) && pending.may_send(server, connections)
        });
        let Some(position) = next.filter(|_| pending.attempt < config.attempts.get()) else {
            return false;
        };
        pending.position = position;
        self.emit(id, now, Deadline::Fresh);
        true
    }

    /// Re-send `id` to the same server without an OPT record (RFC 6891
    /// §6.2.2), without using up an attempt; `Pending::decide` has checked
    /// that it still has EDNS and room to go to the server again.
    fn drop_edns(&mut self, id: QueryId, now: Instant) {
        let Some(pending) = self.pending.get_mut(&id) else {
            return;
        };
        pending.request.edns = None;
        let Ok(payload) = pending.request.to_vec() else {
            self.give_up(id, Error::Server(ResponseCode::FormErr), now);
            return;
        };
        pending.payload = payload;
        self.emit(id, now, Deadline::Fresh);
    }

    /// `id` is out of attempts, every server is excluded, or its TLS
    /// session can't start: its search candidate failed to resolve (RFC
    /// 9520 §2). The failure is cached for the candidate's question, so
    /// nothing is sent for it for a while (§3.2), and `id` and every query
    /// that joined it fail with `error`, however late they joined: a query
    /// issued now would get the cached failure too.
    fn give_up(&mut self, id: QueryId, error: Error, now: Instant) {
        if let Some(pending) = self.pending.get(&id)
            && let Some(question) = pending.request.queries.first()
        {
            self.cache
                .failed(question, error.clone(), pending.started, &self.config, now);
        }
        self.finish(id, Err(error));
    }

    /// End `id`, and the queries that joined it, with `outcome`: `id`'s
    /// event first, then its followers' in the order they joined.
    fn finish(&mut self, id: QueryId, mut outcome: Result<Message, Error>) {
        if let Ok(response) = &mut outcome {
            clamp_ttls(response);
        }
        let followers = self.pending.remove(&id).map(|p| p.followers);
        let copies: Vec<Event> = followers
            .into_iter()
            .flatten()
            .map(|query| event(query, outcome.clone()))
            .collect();
        self.events.push_back(event(id, outcome));
        self.events.extend(copies);
    }

    /// `id`'s deadline has passed: it moves on to its next attempt
    /// (`retry`), leaving its request as an `Orphan` on the connection it
    /// waits on if a response has arrived there since the attempt was
    /// written or took its request back (`written_after`) and the
    /// connection holds fewer than `MAX_ORPHANS` orphans. A connection
    /// with no response since, or with that many orphans, is closed
    /// instead (`time_out_stream`), which moves this query on (see there
    /// for the other queries on it). Does nothing if `id` is no longer pending or its
    /// deadline is after `now`: a close earlier in the same
    /// `handle_timeout` may have moved it on.
    fn time_out(&mut self, id: QueryId, now: Instant) {
        let Some(pending) = self.pending.get(&id) else {
            return;
        };
        if pending.deadline > now {
            return;
        }
        let Route::Stream {
            connection,
            written_after,
        } = pending.route
        else {
            self.act_on(id, Input::NoAnswer(Error::Timeout), now);
            return;
        };
        match self.connections.get_mut(&connection) {
            Some(conn) if conn.responses > written_after && conn.orphans.len() < MAX_ORPHANS => {
                conn.orphans.push(Orphan::of(pending));
                self.act_on(id, Input::NoAnswer(Error::Timeout), now);
            }
            Some(_) => self.time_out_stream(connection, now),
            // Can't happen: every path that removes a connection moves
            // its queries on first. Treated as a plain timeout to be
            // safe.
            None => self.act_on(id, Input::NoAnswer(Error::Timeout), now),
        }
    }

    /// Send `id`'s current attempt and count the send: on the open
    /// connection to its server if there is one (RFC 7766 §5), else over a
    /// new connection if it must use a stream, and as a datagram
    /// otherwise. If the query's own request is still outstanding on that
    /// connection, left there by a timeout, nothing is written: the attempt
    /// waits for that answer, since writing the message ID again would put
    /// it on the connection twice (RFC 7766 §6.2.1). Only responses from
    /// then on show the connection works: the ones before already kept it
    /// open at the last timeout. Over TLS, the query is first prepared for
    /// the server's address family (`protect`). Fails the query if a TLS
    /// session can't be started. If a TLS session refuses the write, the
    /// connection is aborted as after a TLS error on received bytes
    /// (`abort`), and the query moves on with the others on it.
    ///
    /// With `Deadline::Fresh` the query's deadline starts over, also for an
    /// attempt that takes its request back, though nothing is then written
    /// or counted. With `Deadline::Kept` it stays as it was. A query that
    /// a cached failure ends (below) is removed before either.
    ///
    /// Nothing is sent for a question while a failure is cached for it (RFC
    /// 9520 §3.2): the query fails with the cached error instead. That
    /// stops a query that was in flight when another query for the same
    /// question failed, such as one for the name with a trailing dot while
    /// the other was without.
    fn emit(&mut self, id: QueryId, now: Instant, deadline: Deadline) {
        let Some(pending) = self.pending.get_mut(&id) else {
            return;
        };
        if let Some(error) = pending
            .request
            .queries
            .first()
            .and_then(|question| self.cache.failure(question, now))
        {
            self.finish(id, Err(error));
            return;
        }
        if deadline == Deadline::Fresh {
            pending.restart_deadline(&self.config, now);
        }
        let server = pending.server(&self.config);
        // The Client Subnet option names the transport's address family.
        // Encoding can't fail for a message that was encoded once; if it
        // did, the bytes from before go out.
        #[cfg(feature = "tls")]
        if self.config.uses_tls()
            && !is_protected_for(&pending.request, server)
            && let Ok(payload) =
                protect(&mut pending.request, server).and_then(|()| pending.request.to_vec())
        {
            pending.payload = payload;
        }
        let open = self
            .connections
            .iter_mut()
            .find(|(_, c)| c.is_open_to(server));
        let Some((&connection, conn)) = open else {
            if pending.stream_only {
                pending.count_send(server, Channel::Stream);
                let message = frame(&pending.payload);
                match self.connect(server, &message, now) {
                    Ok(connection) => self.written(id, connection),
                    Err(error) => self.give_up(id, error, now),
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
            pending.route = Route::Stream {
                connection,
                written_after: conn.responses,
            };
            return;
        }
        pending.count_send(server, Channel::Stream);
        let message = frame(&pending.payload);
        let written = self.write(connection, &message, now);
        // Even a write TLS refuses puts the query on the connection, so
        // that `abort` moves it on with the others there.
        self.written(id, connection);
        if let Err(error) = written {
            self.abort(connection, now, &error);
        }
    }

    /// `id`'s current attempt was written to `connection`.
    fn written(&mut self, id: QueryId, connection: ConnectionId) {
        let written_after = self.connections.get(&connection).map_or(0, |c| c.responses);
        if let Some(pending) = self.pending.get_mut(&id) {
            pending.route = Route::Stream {
                connection,
                written_after,
            };
        }
    }

    // A connection's transitions: opening, writing, matching what it reads,
    // and closing.

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
                let (mut session, hello) = settings.connect(server).map_err(Error::Tls)?;
                // Waits for the handshake: nothing comes of it yet.
                session.send(message).map_err(Error::Tls)?;
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
            closing: false,
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

    /// Write `message` to an open connection. Over TLS it waits in the
    /// session until the handshake is done. On an error, the session may
    /// have taken part of it, so the connection can't be used any more.
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
            Some(session) => session.send(message).map_err(Error::Tls)?,
            None => message.to_vec(),
        };
        #[cfg(not(feature = "tls"))]
        let payload = message.to_vec();
        let server = conn.server;
        self.queue_write(connection, server, payload);
        Ok(())
    }

    /// Ask the driver to write `payload` to `connection`, whose server is
    /// `server`. Nothing is queued if `payload` is empty.
    fn queue_write(&mut self, connection: ConnectionId, server: SocketAddr, payload: Vec<u8>) {
        if !payload.is_empty() {
            self.transmits.push_back(Transmit {
                transport: Transport::TcpWrite(connection),
                destination: server,
                payload,
            });
        }
    }

    /// What the response `reply`, received on `connection`, answers: a
    /// query whose current attempt was written there, or an orphan of the
    /// connection.
    fn stream_match(&self, connection: ConnectionId, reply: &Reply) -> Option<Matched> {
        let conn = self.connections.get(&connection)?;
        let queries = self.pending.iter().filter(|(_, p)| p.is_on(connection));
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

    /// `connection` went away without being asked to; see
    /// [`Resolver::handle_stream_closed`]. Emits no `TcpClose`: the driver
    /// reported the connection gone.
    fn lost(&mut self, connection: ConnectionId, now: Instant, error: &Error) {
        if let Some(conn) = self.connections.remove(&connection) {
            self.move_off(connection, conn.responses, now, error);
        }
    }

    /// The server's close_notify ended `connection`'s TLS session (RFC 8446
    /// §6.1), and `handle_stream_data` has acted on the answers that came
    /// before it in the same bytes: shut the connection (`shut`, which
    /// queues the session's last bytes, if it has any, and the `TcpClose`),
    /// then move its queries off as `lost` does (`move_off`), with
    /// [`Error::ConnectionClosed`] for those that move on.
    fn retire(&mut self, connection: ConnectionId, now: Instant) {
        if let Some(conn) = self.shut(connection) {
            self.move_off(connection, conn.responses, now, &Error::ConnectionClosed);
        }
    }

    /// Move the queries on `connection`, which was lost (`lost`) or retired
    /// by the server's close_notify (`retire`) after `responses` responses,
    /// as [`Resolver::handle_stream_closed`] says (`Input::Lost`): a query
    /// with room to go to its server again is sent again for free if a
    /// response arrived since it was written or took its request back
    /// (`written_after`), or, if one arrived only before, by using up its
    /// free resend; any other query moves on (`retry`) with `error`.
    fn move_off(&mut self, connection: ConnectionId, responses: u64, now: Instant, error: &Error) {
        for id in self.queries_on(connection) {
            let error = error.clone();
            self.act_on(id, Input::Lost { responses, error }, now);
        }
    }

    /// The queries whose current attempt was written to `connection`.
    fn queries_on(&self, connection: ConnectionId) -> Vec<QueryId> {
        self.pending
            .iter()
            .filter(|(_, p)| p.is_on(connection))
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
    /// it can hold them. The move uses up their free resend
    /// (`Input::Shut`), and one that has used it already, or has no room to
    /// go to its server again (`Pending::may_resend`), moves on instead, so
    /// a server that stops answering costs each query a bounded number of
    /// sends.
    fn time_out_stream(&mut self, connection: ConnectionId, now: Instant) {
        if self.shut(connection).is_none() {
            return;
        }
        for id in self.queries_on(connection) {
            self.act_on(id, Input::Shut, now);
        }
    }

    /// Abort `connection`, whose TLS session failed with `error` while
    /// taking in bytes read from it (`handle_stream_data`, once the answers
    /// decrypted before the error are handled) or on a write (`emit`):
    /// shut it (`shut`), then `retry` every query on it (`Input::NoAnswer`),
    /// which fails one that is out of attempts or servers with `error`. Not
    /// a TCP reset: the driver gets the same [`Transport::TcpClose`] as for
    /// any other close.
    fn abort(&mut self, connection: ConnectionId, now: Instant, error: &Error) {
        if self.shut(connection).is_none() {
            return;
        }
        for id in self.queries_on(connection) {
            self.act_on(id, Input::NoAnswer(error.clone()), now);
        }
    }

    /// Forget `connection` and ask the driver to close it. With TLS, the
    /// session's last bytes, if it has any, go first, as a
    /// [`Transport::TcpWrite`] the driver writes before closing. They end
    /// with the alert rustls queued for a TLS error, which ends the session
    /// (RFC 8446 §6.2), or, if it queued none, with its close_notify alert
    /// (§6.1). There are none after an alert from the server that rustls
    /// reported as the error (`tls::Session::alerted`), as after an error
    /// alert (§6).
    fn shut(&mut self, connection: ConnectionId) -> Option<Connection> {
        #[cfg_attr(
            not(feature = "tls"),
            expect(unused_mut, reason = "only TLS changes it")
        )]
        let mut conn = self.connections.remove(&connection)?;
        #[cfg(feature = "tls")]
        if let Some(session) = &mut conn.tls {
            self.queue_write(connection, conn.server, session.close());
        }
        self.transmits.push_back(Transmit {
            transport: Transport::TcpClose(connection),
            destination: conn.server,
            payload: Vec::new(),
        });
        Some(conn)
    }

    /// Shut every connection whose idle deadline (`idle_deadline`) is at or
    /// before `now`.
    fn close_idle_connections(&mut self, now: Instant) {
        let idle: Vec<ConnectionId> = self
            .connections
            .keys()
            .filter(|c| self.idle_deadline(**c).is_some_and(|d| d <= now))
            .copied()
            .collect();
        for connection in idle {
            self.shut(connection);
        }
    }

    /// When `connection` should close for being idle: `None` while a query
    /// uses it. An orphan keeps it busy until the deadline its query had.
    /// `None` too if that instant would overflow `Instant`: the connection
    /// then doesn't idle out.
    fn idle_deadline(&self, connection: ConnectionId) -> Option<Instant> {
        let conn = self.connections.get(&connection)?;
        if self.pending.values().any(|p| p.is_on(connection)) {
            return None;
        }
        let busy = conn
            .orphans
            .iter()
            .map(|o| o.until)
            .fold(conn.last_active, Instant::max);
        busy.checked_add(self.config.idle_timeout)
    }
}
