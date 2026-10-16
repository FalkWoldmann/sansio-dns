//! Message helpers: framing, padding, matching replies, and the local
//! answers for special-use names.

use std::net::{Ipv4Addr, Ipv6Addr};

#[cfg(feature = "tls")]
use hickory_proto::ProtoError;
use hickory_proto::op::{Message, MessageType, OpCode, Query, ResponseCode};
use hickory_proto::rr::domain::usage::{INVALID, LOCALHOST, ONION};
#[cfg(feature = "tls")]
use hickory_proto::rr::rdata::opt::EdnsOption;
use hickory_proto::rr::rdata::{A, AAAA};
use hickory_proto::rr::{Name, RData, Record, RecordType};

/// EDNS UDP payload size recommended by DNS Flag Day 2020.
pub(crate) const EDNS_PAYLOAD: u16 = 1232;

/// Prefix `message` with its two-byte length (RFC 7766 §8).
pub(crate) fn frame(message: &[u8]) -> Vec<u8> {
    // A single-question query stays below 500 octets, far from the limit.
    let len = u16::try_from(message.len()).unwrap_or(u16::MAX);
    [&len.to_be_bytes()[..], message].concat()
}

/// Pad `request` with an EDNS padding option so it encodes to a multiple of
/// 128 octets (RFC 8467 §4.1, RFC 7830). The option adds 4 octets of header.
#[cfg(feature = "tls")]
pub(crate) fn pad(request: &mut Message) -> Result<(), ProtoError> {
    let unpadded = request.to_vec()?.len();
    let fill = (128 - (unpadded + 4) % 128) % 128;
    if let Some(edns) = &mut request.edns {
        edns.options_mut()
            .insert(EdnsOption::Unknown(12, vec![0; fill]));
    }
    Ok(())
}

/// Whether `name` is under a zone that must not reach a unicast server.
pub(crate) fn is_special_use(name: &Name) -> bool {
    [&LOCALHOST, &INVALID, &ONION]
        .iter()
        .any(|z| z.name().zone_of(name))
}

/// The local answer for a special-use name, or `None` for any other name.
pub(crate) fn special_use(name: &Name, record_type: RecordType) -> Option<Message> {
    if !is_special_use(name) {
        return None;
    }
    let localhost = LOCALHOST.name().zone_of(name);
    let mut response = Message::response(0, OpCode::Query);
    response.add_query(Query::query(name.clone(), record_type));
    response.metadata.response_code = if localhost {
        ResponseCode::NoError
    } else {
        ResponseCode::NXDomain
    };
    let loopback = match record_type {
        RecordType::A if localhost => Some(RData::A(A(Ipv4Addr::LOCALHOST))),
        RecordType::AAAA if localhost => Some(RData::AAAA(AAAA(Ipv6Addr::LOCALHOST))),
        _ => None,
    };
    response
        .answers
        .extend(loopback.map(|data| Record::from_rdata(name.clone(), 0, data)));
    Some(response)
}

/// Whether `response` answers `request` (RFC 5452 §9.1, RFC 1035 §7.3).
pub(crate) fn is_reply(request: &Message, response: &Message) -> bool {
    response.metadata.message_type == MessageType::Response
        && request.metadata.id == response.metadata.id
        && request.metadata.op_code == response.metadata.op_code
        && request.queries == response.queries
}
