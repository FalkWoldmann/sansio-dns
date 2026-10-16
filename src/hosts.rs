//! Static entries from a hosts file (hosts(5)), checked before DNS.

use std::net::IpAddr;

use hickory_proto::op::{Message, OpCode, Query, ResponseCode};
use hickory_proto::rr::rdata::{A, AAAA};
use hickory_proto::rr::{Name, RData, Record, RecordType};

/// Name-to-address entries from a hosts file such as `/etc/hosts`.
#[derive(Clone, Debug, Default)]
pub struct Hosts {
    entries: Vec<(Name, IpAddr)>,
}

impl Hosts {
    /// Parse the text of a hosts file: an address and one or more names per
    /// line, `#` starting a comment. Lines that don't parse are skipped, as
    /// glibc does, and so are addresses with a zone (`fe80::1%eth0`). A
    /// leading UTF-8 byte order mark, as Windows editors write, is ignored.
    pub fn parse(text: &[u8]) -> Self {
        let text = String::from_utf8_lossy(text.strip_prefix(b"\xef\xbb\xbf").unwrap_or(text));
        let entries = text
            .lines()
            .filter_map(|line| {
                let mut fields = line.split('#').next()?.split_whitespace();
                let address: IpAddr = fields.next()?.parse().ok()?;
                Some(fields.filter_map(move |field| {
                    let mut name = Name::from_ascii(field).ok()?;
                    name.set_fqdn(true);
                    Some((name, address))
                }))
            })
            .flatten()
            .collect();
        Self { entries }
    }

    /// The addresses listed for `name`, in file order, or `None` if the
    /// file doesn't list it. `name` is compared as absolute and without
    /// regard to case.
    pub fn lookup(&self, name: &Name) -> Option<Vec<IpAddr>> {
        let mut name = name.clone();
        name.set_fqdn(true);
        let found: Vec<IpAddr> = self
            .entries
            .iter()
            .filter(|(entry, _)| *entry == name)
            .map(|(_, address)| *address)
            .collect();
        (!found.is_empty()).then_some(found)
    }

    /// The local answer to an A or AAAA query for a listed name: its
    /// addresses of that family, possibly none. `None` for other names and
    /// record types, which go to DNS.
    pub(crate) fn answer(&self, name: &Name, record_type: RecordType) -> Option<Message> {
        if !matches!(record_type, RecordType::A | RecordType::AAAA) {
            return None;
        }
        let addresses = self.lookup(name)?;
        let mut response = Message::response(0, OpCode::Query);
        response.add_query(Query::query(name.clone(), record_type));
        response.metadata.response_code = ResponseCode::NoError;
        let records = addresses.into_iter().filter_map(|address| match address {
            IpAddr::V4(v4) if record_type == RecordType::A => Some(RData::A(A(v4))),
            IpAddr::V6(v6) if record_type == RecordType::AAAA => Some(RData::AAAA(AAAA(v6))),
            _ => None,
        });
        response
            .answers
            .extend(records.map(|data| Record::from_rdata(name.clone(), 0, data)));
        Some(response)
    }
}
