//! Address lookups: A and AAAA for one name, merged.

use std::net::IpAddr;
use std::time::Instant;

use hickory_proto::ProtoError;
use hickory_proto::op::Message;
use hickory_proto::rr::{Name, RData, RecordType};

use crate::{Error, Event, QueryId, Resolver};

/// The addresses `response` gives for its question's name, following the
/// CNAME chain from that name (RFC 1034 §3.6.2). Records owned by any other
/// name are ignored.
pub fn addresses(response: &Message) -> Vec<IpAddr> {
    let Some(question) = response.queries.first() else {
        return Vec::new();
    };
    let cname_target = |name: &Name| {
        response.answers.iter().find_map(|r| match &r.data {
            RData::CNAME(target) if r.name == *name => Some(target.0.clone()),
            _ => None,
        })
    };
    // A chain can't be longer than the answer section; this also ends loops.
    let Some(canonical) = std::iter::successors(Some(question.name().clone()), cname_target)
        .take(response.answers.len() + 1)
        .last()
    else {
        return Vec::new();
    };
    response
        .answers
        .iter()
        .filter(|r| r.name == canonical)
        .filter_map(|r| match r.data {
            RData::A(a) => Some(IpAddr::V4(a.0)),
            RData::AAAA(aaaa) => Some(IpAddr::V6(aaaa.0)),
            _ => None,
        })
        .collect()
}

/// An A and an AAAA query for the same name, with their addresses merged.
///
/// Pass every [`Event`] to [`IpLookup::handle_event`], which hands the
/// lookup back until both queries have finished, and then the outcome
/// instead. Ordering the addresses (RFC 6724) and racing connections
/// (RFC 8305) is up to the caller.
#[derive(Debug, PartialEq, Eq)]
pub struct IpLookup {
    queries: [QueryId; 2],
    /// Only one can be filled: with both, the lookup is over.
    results: [Option<Result<Vec<IpAddr>, Error>>; 2],
}

/// Where an [`IpLookup`] stands after an event.
#[derive(Debug, PartialEq, Eq)]
pub enum Progress {
    /// A query is still running: pass the lookup the next event.
    Waiting(IpLookup),
    /// Both queries have finished. The IPv4 addresses followed by the IPv6
    /// ones, each in the server's order. An error only if no address was
    /// found and a query failed; no address and no failure (NXDOMAIN, or no
    /// records) is an empty list.
    Done(Result<Vec<IpAddr>, Error>),
}

impl IpLookup {
    /// Start the A and AAAA queries for `name` on `resolver`.
    pub fn start(resolver: &mut Resolver, name: Name, now: Instant) -> Result<Self, ProtoError> {
        let a = resolver.query(name.clone(), RecordType::A, now)?;
        let aaaa = resolver.query(name, RecordType::AAAA, now)?;
        Ok(Self {
            queries: [a, aaaa],
            results: [None, None],
        })
    }

    /// Take in `event`; events of other queries leave the lookup as it is.
    pub fn handle_event(mut self, event: &Event) -> Progress {
        let (query, result) = match event {
            Event::Response { query, response } => (query, Ok(addresses(response))),
            Event::Failed { query, error } => (query, Err(error.clone())),
        };
        let slot = self
            .queries
            .iter()
            .zip(&mut self.results)
            .find_map(|(q, slot)| (q == query).then_some(slot));
        if let Some(slot) = slot {
            *slot = Some(result);
        }
        match self.results {
            [Some(a), Some(aaaa)] => Progress::Done(merge(a, aaaa)),
            _ => Progress::Waiting(self),
        }
    }
}

fn merge(
    a: Result<Vec<IpAddr>, Error>,
    aaaa: Result<Vec<IpAddr>, Error>,
) -> Result<Vec<IpAddr>, Error> {
    match (a, aaaa) {
        (Ok(v4), Ok(v6)) => Ok(v4.into_iter().chain(v6).collect()),
        (Ok(found), Err(error)) | (Err(error), Ok(found)) if found.is_empty() => Err(error),
        (Ok(found), Err(_)) | (Err(_), Ok(found)) => Ok(found),
        (Err(error), Err(_)) => Err(error),
    }
}
