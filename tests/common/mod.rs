//! Shared fixtures: two fake name servers and a reply builder.

#![allow(dead_code, reason = "each test crate uses a different subset")]

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::time::Instant;

use hickory_proto::op::{Message, ResponseCode};
use hickory_proto::rr::rdata::{A, AAAA};
use hickory_proto::rr::{Name, RData, Record, RecordType};
use rstest::fixture;
use sansio_dns::{Config, Event, Resolver, Transmit, Transport};

pub const S1: SocketAddr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), 53);
pub const S2: SocketAddr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)), 53);
pub const ADDR: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 7);
pub const ADDR6: Ipv6Addr = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 7);

#[fixture]
pub fn resolver() -> Resolver {
    Resolver::new(Config::new(S1, [S2]))
}

/// Start an `example.com. A` lookup and return the first datagram.
pub fn start(resolver: &mut Resolver, now: Instant) -> Transmit {
    start_name(resolver, "example.com.", now)
}

pub fn start_name(resolver: &mut Resolver, name: &str, now: Instant) -> Transmit {
    let name = Name::from_ascii(name).unwrap();
    resolver.query(name, RecordType::A, now).unwrap();
    resolver.poll_transmit().unwrap()
}

/// The DNS message in `transmit`, without the TCP length prefix.
pub fn decode(transmit: &Transmit) -> Message {
    let message = match transmit.transport {
        Transport::Udp => &transmit.payload[..],
        Transport::Tcp | Transport::TcpContinue => &transmit.payload[2..],
    };
    Message::from_vec(message).unwrap()
}

/// `message` with the two-byte TCP length prefix.
pub fn frame(message: &[u8]) -> Vec<u8> {
    let len = u16::try_from(message.len()).unwrap().to_be_bytes();
    len.iter().chain(message).copied().collect()
}

/// The answer a well-behaved server would give to `request`. Tests mutate it
/// to model misbehaving or spoofing servers before encoding it.
pub fn reply(request: &Transmit) -> Message {
    let request = decode(request);
    let mut response = Message::response(request.metadata.id, request.metadata.op_code);
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

pub fn is_response(event: Option<Event>) -> bool {
    event.is_some_and(|e| matches!(e, Event::Response { .. }))
}
