//! Message helpers: framing, padding, matching replies, and the local
//! answers for special-use names.

use std::net::{Ipv4Addr, Ipv6Addr};

#[cfg(feature = "tls")]
use hickory_proto::ProtoError;
use hickory_proto::op::{Header, Message, MessageType, Metadata, OpCode, Query, ResponseCode};
use hickory_proto::rr::domain::usage::{INVALID, LOCALHOST, ONION};
#[cfg(feature = "tls")]
use hickory_proto::rr::rdata::opt::EdnsOption;
use hickory_proto::rr::rdata::{A, AAAA};
use hickory_proto::rr::{Name, RData, Record, RecordType};
use hickory_proto::serialize::binary::{BinDecodable, BinDecoder};

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

/// A message from a server, decoded as far as it goes.
#[derive(Debug)]
pub(crate) enum Reply {
    /// The whole message.
    Whole(Message),
    /// Only the header and question section decode. hickory rejects the
    /// whole message on any record it can't read, such as the last one of a
    /// datagram that a server cut off and set TC on (RFC 2181 §9), or one
    /// with empty RDATA outside an UPDATE (`InvalidEmptyRecord`), which RFC
    /// 3597 §3 requires handling transparently for unknown types.
    Broken {
        metadata: Metadata,
        queries: Vec<Query>,
        error: String,
    },
}

impl Reply {
    /// `data` decoded, or `None` if not even its header and question do.
    pub(crate) fn decode(data: &[u8]) -> Option<Self> {
        let error = match Message::from_vec(data) {
            Ok(message) => return Some(Self::Whole(message)),
            Err(error) => error.to_string(),
        };
        let mut decoder = BinDecoder::new(data);
        let Header { metadata, counts } = Header::read(&mut decoder).ok()?;
        let queries = (0..counts.queries)
            .map(|_| Query::read(&mut decoder))
            .collect::<Result<_, _>>()
            .ok()?;
        Some(Self::Broken {
            metadata,
            queries,
            error,
        })
    }

    /// Whether it answers `request` (RFC 5452 §9.1, RFC 1035 §7.3).
    /// `Query` equality compares name, type and class, and hickory's `Name`
    /// equality ignores case (RFC 1035 §2.3.3) but not the trailing dot.
    pub(crate) fn answers(&self, request: &Message) -> bool {
        let (metadata, queries) = match self {
            Self::Whole(message) => (&message.metadata, &message.queries),
            Self::Broken {
                metadata, queries, ..
            } => (metadata, queries),
        };
        metadata.message_type == MessageType::Response
            && request.metadata.id == metadata.id
            && request.metadata.op_code == metadata.op_code
            && request.queries == *queries
    }
}

/// The names from `response`'s question name along its CNAME chain, in
/// order (RFC 1034 §3.6.2). A chain can't be longer than the answer
/// section; this also ends loops.
pub(crate) fn chain(response: &Message) -> impl Iterator<Item = Name> {
    let target = |name: &Name| {
        response.answers.iter().find_map(|r| match &r.data {
            RData::CNAME(target) if r.name == *name => Some(target.0.clone()),
            _ => None,
        })
    };
    let first = response.queries.first().map(|q| q.name().clone());
    std::iter::successors(first, target).take(response.answers.len() + 1)
}

/// Whether `response` has records of the type asked for, owned by the
/// question name or a name on its CNAME chain; any type for ANY. A
/// `NOERROR` answer without them is NODATA (RFC 2308 §2.2).
pub(crate) fn has_data(response: &Message) -> bool {
    let Some(asked) = response.queries.first().map(Query::query_type) else {
        return false;
    };
    let names: Vec<Name> = chain(response).collect();
    response
        .answers
        .iter()
        .any(|r| (asked == RecordType::ANY || r.record_type() == asked) && names.contains(&r.name))
}

/// Whether `response` is an empty answer from a server that neither
/// recurses nor is authoritative: `NOERROR`, no answer, and neither AA nor
/// RA. Such a server didn't look the name up (RFC 1034 §4.3.1, §5.3.1), so
/// its answer is typically a referral, which a stub resolver can't follow,
/// and can't be trusted as NODATA. glibc's `send_dg` treats it the same.
pub(crate) fn is_referral(response: &Message) -> bool {
    response.metadata.response_code == ResponseCode::NoError
        && response.answers.is_empty()
        && !response.metadata.authoritative
        && !response.metadata.recursion_available
}

/// Treat TTLs with the most significant bit set as zero (RFC 2181 §8).
pub(crate) fn clamp_ttls(response: &mut Message) {
    let records = response
        .answers
        .iter_mut()
        .chain(&mut response.authorities)
        .chain(&mut response.additionals);
    for record in records {
        if record.ttl & (1 << 31) != 0 {
            record.ttl = 0;
        }
    }
}

/// Whether `record_type` can't be asked of a recursive server by a stub:
/// TYPE 0, the meta-types OPT, TKEY and TSIG, and the QTYPEs IXFR, AXFR,
/// MAILB and MAILA (RFC 6895 §3.1), and the meta-type NXNAME, which a
/// resolver must not forward upstream (RFC 9824 §3.5). Zone transfers
/// must go over TCP (RFC 1123 §6.1.3.2) and take more than one message.
/// ANY stays allowed (RFC 8482), and so do the unassigned codes from 129
/// to 248, which future QTYPEs may take.
pub(crate) fn is_meta_type(record_type: RecordType) -> bool {
    matches!(u16::from(record_type), 0 | 41 | 128 | 249..=254)
}
