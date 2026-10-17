//! Message helpers: framing, padding, matching replies, and the local
//! answers for special-use names.

#[cfg(feature = "tls")]
use std::net::{IpAddr, SocketAddr};
use std::net::{Ipv4Addr, Ipv6Addr};
use std::sync::LazyLock;

#[cfg(feature = "tls")]
use hickory_proto::ProtoError;
use hickory_proto::op::{Header, Message, MessageType, Metadata, OpCode, Query, ResponseCode};
use hickory_proto::rr::domain::usage::{INVALID, LOCALHOST, ONION};
#[cfg(feature = "tls")]
use hickory_proto::rr::rdata::opt::{ClientSubnet, EdnsCode, EdnsOption};
use hickory_proto::rr::rdata::{A, AAAA};
use hickory_proto::rr::{DNSClass, Name, RData, Record, RecordType};
use hickory_proto::serialize::binary::{BinDecodable, BinDecoder};

/// EDNS UDP payload size recommended by DNS Flag Day 2020.
pub(crate) const EDNS_PAYLOAD: u16 = 1232;

/// Prefix `message` with its two-byte length (RFC 7766 §8).
pub(crate) fn frame(message: &[u8]) -> Vec<u8> {
    // A single-question query stays below 500 octets, far from the limit.
    let len = u16::try_from(message.len()).unwrap_or(u16::MAX);
    [&len.to_be_bytes()[..], message].concat()
}

/// Prepare `request` for DNS over TLS to `server`: an EDNS Client Subnet
/// option with SOURCE PREFIX-LENGTH 0, the privacy election of RFC 8310
/// §11.1, then the padding, which must be the last option applied (RFC
/// 8467 §3). With no address bits, FAMILY is that of the transport to the
/// server (RFC 7871 §7.1.2). Replaces both options if they are there
/// already, so it can run again for a server of the other family.
#[cfg(feature = "tls")]
pub(crate) fn protect(request: &mut Message, server: SocketAddr) -> Result<(), ProtoError> {
    if let Some(edns) = &mut request.edns {
        let unspecified = if server.ip().to_canonical().is_ipv6() {
            IpAddr::V6(Ipv6Addr::UNSPECIFIED)
        } else {
            IpAddr::V4(Ipv4Addr::UNSPECIFIED)
        };
        let options = edns.options_mut();
        options.remove(EdnsCode::Subnet);
        options.insert(EdnsOption::Subnet(ClientSubnet::new(unspecified, 0, 0)));
    }
    pad(request)
}

/// Whether `request` was prepared by [`protect`] for `server`'s address
/// family.
#[cfg(feature = "tls")]
pub(crate) fn is_protected_for(request: &Message, server: SocketAddr) -> bool {
    request
        .edns
        .as_ref()
        .and_then(|edns| edns.options().get(EdnsCode::Subnet))
        .is_some_and(|option| {
            matches!(option, EdnsOption::Subnet(subnet)
                if subnet.addr().is_ipv6() == server.ip().to_canonical().is_ipv6())
        })
}

/// Pad `request` with an EDNS padding option so it encodes to a multiple of
/// 128 octets (RFC 8467 §4.1, RFC 7830), after the other options. The
/// option adds 4 octets of header. A padding option already there is
/// replaced, so there is never more than one (RFC 7830 §3).
#[cfg(feature = "tls")]
pub(crate) fn pad(request: &mut Message) -> Result<(), ProtoError> {
    if let Some(edns) = &mut request.edns {
        edns.options_mut().remove(EdnsCode::Padding);
    }
    let unpadded = request.to_vec()?.len();
    let fill = (128 - (unpadded + 4) % 128) % 128;
    if let Some(edns) = &mut request.edns {
        edns.options_mut()
            .insert(EdnsOption::Unknown(EdnsCode::Padding.into(), vec![0; fill]));
    }
    Ok(())
}

/// Whether `name` is under `localhost.`, `invalid.` or `onion.`, whose
/// names are answered locally whatever the configuration: loopback for
/// `localhost` names (RFC 6761 §6.3), NXDOMAIN for the others (RFC 6761
/// §6.4, RFC 7686 §2).
pub(crate) fn is_special_use(name: &Name) -> bool {
    [&LOCALHOST, &INVALID, &ONION]
        .iter()
        .any(|z| z.name().zone_of(name))
}

/// The zones that RFC 6762 reserves for multicast DNS: `local.` (§3) and
/// the reverse zones of the IPv4 and IPv6 link-local addresses (§4).
static LINK_LOCAL_ZONES: LazyLock<Vec<Name>> = LazyLock::new(|| {
    [
        "local.",
        "254.169.in-addr.arpa.",
        "8.e.f.ip6.arpa.",
        "9.e.f.ip6.arpa.",
        "a.e.f.ip6.arpa.",
        "b.e.f.ip6.arpa.",
    ]
    .iter()
    .filter_map(|zone| Name::from_ascii(zone).ok())
    .collect()
});

/// Whether `name` is in one of the six zones RFC 6762 reserves for
/// multicast DNS, which a library should not send to its unicast servers
/// (§22.1 item 3).
pub(crate) fn is_link_local(name: &Name) -> bool {
    LINK_LOCAL_ZONES.iter().any(|zone| zone.zone_of(name))
}

/// Whether `name` is strictly under one of the zones of [`is_link_local`],
/// not the zone itself: a domain such as `cluster.local.` that unicast
/// servers serve.
pub(crate) fn is_under_link_local(name: &Name) -> bool {
    LINK_LOCAL_ZONES
        .iter()
        .any(|zone| zone.zone_of(name) && zone.num_labels() < name.num_labels())
}

/// The local answer for a name that isn't sent: for a `localhost` name the
/// loopback address of the type asked for and a negative answer (NODATA)
/// for every other type (RFC 6761 §6.3), and NXDOMAIN for any other name
/// (RFC 6761 §6.4, RFC 7686 §2, RFC 6762 §22.1 item 4).
pub(crate) fn local_answer(name: &Name, record_type: RecordType) -> Message {
    let localhost = is_localhost(name);
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
    response
}

/// Whether `name` is a `localhost` name (RFC 6761 §6.3).
pub(crate) fn is_localhost(name: &Name) -> bool {
    LOCALHOST.name().zone_of(name)
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

    fn header(&self) -> (&Metadata, &[Query]) {
        match self {
            Self::Whole(message) => (&message.metadata, &message.queries),
            Self::Broken {
                metadata, queries, ..
            } => (metadata, queries),
        }
    }

    /// Whether it is a response to a standard query with message ID `id`,
    /// whatever its question section holds.
    pub(crate) fn responds_to(&self, id: u16) -> bool {
        let (metadata, _) = self.header();
        metadata.message_type == MessageType::Response
            && metadata.op_code == OpCode::Query
            && metadata.id == id
    }

    /// Whether it is a response at all (QR set).
    pub(crate) fn is_response(&self) -> bool {
        self.header().0.message_type == MessageType::Response
    }

    /// Whether it has a question section.
    pub(crate) fn has_question(&self) -> bool {
        !self.header().1.is_empty()
    }

    /// Whether it answers the standard query with message ID `id` and
    /// question section `question` (RFC 5452 §9.1, RFC 1035 §7.3, RFC 7766
    /// §7). `Query` equality compares name, type and class, and hickory's
    /// `Name` equality ignores case (RFC 1035 §2.3.3) but not the trailing
    /// dot.
    pub(crate) fn answers(&self, id: u16, question: &[Query]) -> bool {
        self.responds_to(id) && self.header().1 == question
    }

    /// Give a response without a question section the question it was
    /// matched to by message ID, so it reads like any other answer.
    pub(crate) fn fill_question(&mut self, question: &[Query]) {
        if let Self::Whole(message) = self
            && message.queries.is_empty()
        {
            message.queries = question.to_vec();
        }
    }
}

/// The names from `response`'s question name along its CNAME chain, in
/// order (RFC 1034 §3.6.2), following only CNAME records of the question's
/// class (RFC 1035 §7.4). A chain can't be longer than the answer section;
/// this also ends loops.
pub(crate) fn chain(response: &Message) -> impl Iterator<Item = Name> {
    let question = response.queries.first();
    let target = move |name: &Name| {
        response.answers.iter().find_map(|r| match &r.data {
            RData::CNAME(target) if r.name == *name && question.is_some_and(|q| in_class(q, r)) => {
                Some(target.0.clone())
            }
            _ => None,
        })
    };
    let first = question.map(|q| q.name().clone());
    std::iter::successors(first, target).take(response.answers.len() + 1)
}

/// Whether `record` is of the class `question` asks for, any class for
/// ANY.
pub(crate) fn in_class(question: &Query, record: &Record) -> bool {
    question.query_class() == DNSClass::ANY || record.dns_class == question.query_class()
}

/// Whether `response` has records of the type and class asked for, owned
/// by the question name or a name on its CNAME chain; any type for ANY. A
/// `NOERROR` answer without them is NODATA (RFC 2308 §2.2).
pub(crate) fn has_data(response: &Message) -> bool {
    let Some(question) = response.queries.first() else {
        return false;
    };
    let asked = question.query_type();
    let names: Vec<Name> = chain(response).collect();
    response.answers.iter().any(|r| {
        (asked == RecordType::ANY || r.record_type() == asked)
            && in_class(question, r)
            && names.contains(&r.name)
    })
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
