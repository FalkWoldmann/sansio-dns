//! Shared fixtures: two fake name servers and a reply builder.

#![allow(dead_code)]

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::Instant;

use hickory_proto::op::{Message, ResponseCode};
use hickory_proto::rr::rdata::A;
use hickory_proto::rr::{Name, RData, Record, RecordType};
use rstest::fixture;
use sansio_dns::{Config, Event, Resolver, Transmit};

pub const S1: SocketAddr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), 53);
pub const S2: SocketAddr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)), 53);
pub const ADDR: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 7);

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

pub fn decode(transmit: &Transmit) -> Message {
    Message::from_vec(&transmit.payload).unwrap()
}

/// The answer a well-behaved server would give to `request`. Tests mutate it
/// to model misbehaving or spoofing servers before encoding it.
pub fn reply(request: &Transmit) -> Message {
    let request = decode(request);
    let mut response = Message::response(request.metadata.id, request.metadata.op_code);
    response.add_queries(request.queries.clone());
    let name = request.queries[0].name().clone();
    response.add_answer(Record::from_rdata(name, 300, RData::A(A(ADDR))));
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
    matches!(event, Some(Event::Response { .. }))
}
