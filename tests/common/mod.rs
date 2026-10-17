//! Shared fixtures: two fake name servers, a reply builder, and a trace of
//! a resolver's inputs and outputs for snapshots.

use std::fmt;
use std::io::ErrorKind;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use hickory_proto::op::{Message, MessageType, ResponseCode};
use hickory_proto::rr::rdata::{A, AAAA, NS, SOA};
use hickory_proto::rr::{Name, RData, Record, RecordType};
use rstest::fixture;
use sansio_dns::{Config, ConnectionId, Event, QueryId, Resolver, Transmit, Transport};

pub const S1: SocketAddr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), 53);
pub const S2: SocketAddr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)), 53);
pub const ADDR: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 7);
pub const ADDR6: Ipv6Addr = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 7);

/// Servers `S1` and `S2` with `Config::new`'s settings, except a timeout
/// of two seconds instead of five, which keeps traces short.
#[fixture]
pub fn resolver() -> Resolver {
    Resolver::new(config())
}

/// The settings of [`resolver`].
pub fn config() -> Config {
    let mut config = Config::new(S1, [S2]);
    config.timeout = Duration::from_secs(2);
    config
}

/// Start an `example.com. A` lookup and return the first datagram.
pub fn start(resolver: &mut Resolver, now: Instant) -> Transmit {
    start_name(resolver, "example.com.", now)
}

/// Start an A lookup for a name no earlier call has used, so it doesn't join
/// another query in flight.
pub fn start_distinct(resolver: &mut Resolver, now: Instant) -> Transmit {
    static NEXT: AtomicUsize = AtomicUsize::new(0);
    let n = NEXT.fetch_add(1, Ordering::Relaxed);
    start_name(resolver, &format!("q{n}.example.com."), now)
}

pub fn start_name(resolver: &mut Resolver, name: &str, now: Instant) -> Transmit {
    let name = Name::from_ascii(name).unwrap();
    resolver.query(name, RecordType::A, now).unwrap();
    resolver.poll_transmit().unwrap()
}

/// The DNS message in `transmit`, without the TCP length prefix.
pub fn decode(transmit: &Transmit) -> Message {
    let message = match transmit.transport {
        Transport::Udp(_) => &transmit.payload[..],
        _ => &transmit.payload[2..],
    };
    Message::from_vec(message).unwrap()
}

/// The connection a stream transmit belongs to.
pub fn conn(transmit: &Transmit) -> ConnectionId {
    match transmit.transport {
        Transport::TcpConnect(c) | Transport::TcpWrite(c) | Transport::TcpClose(c) => c,
        Transport::Udp(_) => panic!("not a stream transmit: {transmit:?}"),
    }
}

/// The query a datagram transmit belongs to, i.e. the socket it uses.
pub fn udp(transmit: &Transmit) -> QueryId {
    match transmit.transport {
        Transport::Udp(query) => query,
        _ => panic!("not a datagram transmit: {transmit:?}"),
    }
}

pub fn is_connect(transmit: &Transmit) -> bool {
    matches!(transmit.transport, Transport::TcpConnect(_))
}

/// `message` with the two-byte TCP length prefix.
pub fn frame(message: &[u8]) -> Vec<u8> {
    let len = u16::try_from(message.len()).unwrap().to_be_bytes();
    len.iter().chain(message).copied().collect()
}

/// The answer a well-behaved server would give to `request`. Tests mutate it
/// to model misbehaving or spoofing servers before encoding it.
pub fn reply(request: &Transmit) -> Message {
    reply_to(&decode(request))
}

/// The answer a well-behaved recursive server would give to the query
/// `request`.
pub fn reply_to(request: &Message) -> Message {
    let request = request.clone();
    let mut response = Message::response(request.metadata.id, request.metadata.op_code);
    response.metadata.recursion_available = true;
    response.add_queries(request.queries.clone());
    let question = &request.queries[0];
    let data = match question.query_type() {
        RecordType::AAAA => RData::AAAA(AAAA(ADDR6)),
        _ => RData::A(A(ADDR)),
    };
    response.add_answer(Record::from_rdata(question.name().clone(), 300, data));
    if let Some(edns) = request.edns {
        response.set_edns(edns);
    }
    response
}

/// `response` without its answers: NODATA, if its code is `NOERROR`.
pub fn no_data(mut response: Message) -> Message {
    response.answers.clear();
    response
}

/// `response` as a referral from a server that doesn't recurse: no
/// answers, neither AA nor RA, and the zone's NS record in the authority
/// section (RFC 1034 §4.3.1).
pub fn referral(response: Message) -> Message {
    let mut response = no_data(response);
    response.metadata.authoritative = false;
    response.metadata.recursion_available = false;
    let zone = Name::from_ascii("com.").unwrap();
    let server = Name::from_ascii("a.gtld-servers.net.").unwrap();
    response.add_authority(Record::from_rdata(zone, 172800, RData::NS(NS(server))));
    response
}

/// `response` with the zone's SOA record added to its authority section,
/// as in a negative answer (RFC 2308 §2.2).
pub fn with_soa(mut response: Message) -> Message {
    let zone = Name::from_ascii("example.com.").unwrap();
    let mname = Name::from_ascii("ns1.example.com.").unwrap();
    let rname = Name::from_ascii("hostmaster.example.com.").unwrap();
    let soa = SOA::new(mname, rname, 1, 7200, 3600, 1_209_600, 300);
    response.add_authority(Record::from_rdata(zone, 300, RData::SOA(soa)));
    response
}

pub fn truncated(mut response: Message) -> Message {
    response.metadata.truncation = true;
    response
}

pub fn with_code(mut response: Message, code: ResponseCode) -> Message {
    response.metadata.response_code = code;
    if code != ResponseCode::NoError {
        response.answers.clear();
    }
    response
}

pub fn encode(message: &Message) -> Vec<u8> {
    message.to_vec().unwrap()
}

/// `message` without its last two bytes, so its last record doesn't parse
/// but its header and question still do.
pub fn cut(message: &[u8]) -> Vec<u8> {
    message[..message.len() - 2].to_vec()
}

pub fn is_response(event: Option<Event>) -> bool {
    event.is_some_and(|e| matches!(e, Event::Response { .. }))
}

#[fixture]
pub fn trace(resolver: Resolver) -> Trace {
    Trace::new(resolver)
}

/// A resolver driven by a test, recording what goes in and what comes out
/// as text: queries and connections as `q0` and `c0` in order of first
/// appearance, servers as `S1` and `S2`, times relative to the start. Each
/// input line is followed by the events it caused (`=>`), then the
/// transmits (`->`), then the next deadline (`next`). The resolver keeps
/// events and transmits in separate queues, so that order says nothing
/// about which came first within one input.
#[derive(Debug)]
pub struct Trace {
    resolver: Resolver,
    start: Instant,
    now: Instant,
    queries: Vec<QueryId>,
    connections: Vec<ConnectionId>,
    sent: Vec<Transmit>,
    events: Vec<Event>,
    lines: Vec<String>,
}

impl Trace {
    pub fn new(resolver: Resolver) -> Self {
        let start = Instant::now();
        Self {
            resolver,
            start,
            now: start,
            queries: Vec::new(),
            connections: Vec::new(),
            sent: Vec::new(),
            events: Vec::new(),
            lines: Vec::new(),
        }
    }

    /// Set the clock to `offset` after the start, for the inputs that follow.
    pub fn at(&mut self, offset: Duration) {
        self.now = self.start + offset;
    }

    pub fn query(&mut self, name: &str, record_type: RecordType) -> QueryId {
        let name = Name::from_ascii(name).unwrap();
        let id = self
            .resolver
            .query(name.clone(), record_type, self.now)
            .unwrap();
        let line = format!(
            "query {} {} {record_type}",
            self.query_name(id),
            name.to_ascii()
        );
        self.record(&line);
        id
    }

    /// Answer `to` with `response`: as a datagram from its destination to
    /// its query's socket, or as bytes on its connection.
    pub fn answer(&mut self, to: &Transmit, response: &Message) {
        let bytes = encode(response);
        let via = if let Transport::Udp(query) = to.transport {
            self.resolver
                .handle_datagram(query, to.destination, &bytes, self.now);
            format!("udp {}", self.query_name(query))
        } else {
            self.resolver
                .handle_stream_data(conn(to), &frame(&bytes), self.now);
            self.conn_name(conn(to))
        };
        let line = format!(
            "<- {} {via}: {}",
            server(to.destination),
            describe(response)
        );
        self.record(&line);
    }

    /// Answer `to` with `bytes`, described as `what`, as [`Trace::answer`]
    /// does.
    pub fn answer_bytes(&mut self, to: &Transmit, bytes: &[u8], what: &str) {
        let via = if let Transport::Udp(query) = to.transport {
            self.resolver
                .handle_datagram(query, to.destination, bytes, self.now);
            format!("udp {}", self.query_name(query))
        } else {
            self.resolver
                .handle_stream_data(conn(to), &frame(bytes), self.now);
            self.conn_name(conn(to))
        };
        let line = format!("<- {} {via}: {what}", server(to.destination));
        self.record(&line);
    }

    /// Bytes on the connection `on` was sent over, as they are, without a
    /// length prefix, described as `what`.
    pub fn stream_bytes(&mut self, on: &Transmit, bytes: &[u8], what: &str) {
        self.resolver.handle_stream_data(conn(on), bytes, self.now);
        let line = format!(
            "<- {} {}: {what}",
            server(on.destination),
            self.conn_name(conn(on))
        );
        self.record(&line);
    }

    /// The server closed the connection `on` was sent over.
    pub fn close(&mut self, on: &Transmit) {
        self.resolver.handle_stream_closed(conn(on), self.now);
        let line = format!("{} closed", self.conn_name(conn(on)));
        self.record(&line);
    }

    pub fn error(&mut self, on: &Transmit, error: ErrorKind) {
        self.resolver.handle_stream_error(conn(on), error, self.now);
        let line = format!("{} error {error:?}", self.conn_name(conn(on)));
        self.record(&line);
    }

    /// Binding the socket for `on`, or sending it, failed.
    pub fn udp_error(&mut self, on: &Transmit, error: ErrorKind) {
        self.resolver
            .handle_udp_error(udp(on), on.destination, error, self.now);
        let line = format!(
            "udp {} to {} error {error:?}",
            self.query_name(udp(on)),
            server(on.destination)
        );
        self.record(&line);
    }

    pub fn cancel(&mut self, query: QueryId) {
        self.resolver.cancel(query, self.now);
        let line = format!("cancel {}", self.query_name(query));
        self.record(&line);
    }

    pub fn shutdown(&mut self) {
        self.resolver.shutdown();
        self.record("shutdown");
    }

    /// Move the clock to the next deadline and handle it.
    pub fn timeout(&mut self) {
        let deadline = self.resolver.poll_timeout().unwrap();
        self.timeout_at(deadline.duration_since(self.start));
    }

    pub fn timeout_at(&mut self, offset: Duration) {
        self.at(offset);
        self.resolver.handle_timeout(self.now);
        self.record("timeout");
    }

    /// Handle every deadline in turn until none is left.
    pub fn timeouts(&mut self) {
        for _ in 0..100 {
            if self.resolver.poll_timeout().is_none() {
                return;
            }
            self.timeout();
        }
        panic!("deadlines never ran out:\n{self}");
    }

    /// What the latest input sent.
    pub fn sent(&self) -> &[Transmit] {
        &self.sent
    }

    /// The last DNS message the latest input sent.
    pub fn last(&self) -> Transmit {
        self.sent
            .iter()
            .rfind(|t| !matches!(t.transport, Transport::TcpClose(_)))
            .cloned()
            .unwrap_or_else(|| panic!("nothing sent:\n{self}"))
    }

    /// Every event so far.
    pub fn events(&self) -> &[Event] {
        &self.events
    }

    fn record(&mut self, input: &str) {
        let t = self.now.duration_since(self.start).as_secs_f64();
        self.lines.push(format!("t={t}s {input}"));
        while let Some(event) = self.resolver.poll_event() {
            let line = match &event {
                Event::Response { query, response } => {
                    format!(
                        "  => {} Response {}",
                        self.query_name(*query),
                        describe(response)
                    )
                }
                Event::Failed { query, error } => {
                    format!("  => {} Failed {error:?}", self.query_name(*query))
                }
            };
            self.lines.push(line);
            self.events.push(event);
        }
        self.sent = std::iter::from_fn(|| self.resolver.poll_transmit()).collect();
        for transmit in self.sent.clone() {
            let line = match transmit.transport {
                Transport::Udp(query) => format!("udp {}", self.query_name(query)),
                Transport::TcpConnect(c) => format!("connect {}", self.conn_name(c)),
                Transport::TcpWrite(c) => format!("write {}", self.conn_name(c)),
                Transport::TcpClose(c) => format!("close {}", self.conn_name(c)),
            };
            let to = server(transmit.destination);
            let line = match transmit.transport {
                Transport::TcpClose(_) => format!("  -> {to} {line}"),
                _ => format!("  -> {to} {line}: {}", describe(&decode(&transmit))),
            };
            self.lines.push(line);
        }
        let next = self.resolver.poll_timeout().map_or_else(
            || "none".to_owned(),
            |d| format!("t={}s", d.duration_since(self.start).as_secs_f64()),
        );
        self.lines.push(format!("  next {next}"));
    }

    /// `q0`, `q1`, ... by first appearance.
    fn query_name(&mut self, id: QueryId) -> String {
        format!("q{}", position(&mut self.queries, id))
    }

    fn conn_name(&mut self, id: ConnectionId) -> String {
        format!("c{}", position(&mut self.connections, id))
    }
}

impl fmt::Display for Trace {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.lines.join("\n"))
    }
}

fn position<T: PartialEq>(seen: &mut Vec<T>, item: T) -> usize {
    seen.iter().position(|s| *s == item).unwrap_or_else(|| {
        seen.push(item);
        seen.len() - 1
    })
}

fn server(address: SocketAddr) -> String {
    match address {
        S1 => "S1".to_owned(),
        S2 => "S2".to_owned(),
        other => other.to_string(),
    }
}

/// The question, and for a response its code and answer count, plus the
/// flags a lifecycle depends on.
fn describe(message: &Message) -> String {
    let mut text = message.queries.first().map_or_else(
        || "no question".to_owned(),
        |q| format!("{} {}", q.name().to_ascii(), q.query_type()),
    );
    if message.metadata.message_type == MessageType::Response {
        let n = message.answers.len();
        let code = message.metadata.response_code;
        text += &format!(": {code:?}, {n} answer{}", if n == 1 { "" } else { "s" });
        if message.metadata.authoritative {
            text += ", AA";
        }
        if !message.metadata.recursion_available {
            text += ", no RA";
        }
    }
    if message.metadata.truncation {
        text += ", TC";
    }
    if message.edns.is_none() {
        text += ", no EDNS";
    }
    text
}
