//! Address lookups: A and AAAA for one name, merged in the configured order.

use std::net::IpAddr;
use std::time::Instant;

use hickory_proto::ProtoError;
use hickory_proto::op::Message;
use hickory_proto::rr::{Name, RData};

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

/// The A and AAAA queries for the same name, as [`Config::ip_strategy`]
/// picks them, with their addresses merged.
///
/// Pass every [`Event`] to [`IpLookup::handle_event`], which hands the
/// lookup back until all its queries have finished, and then the outcome
/// instead. Sorting the addresses by the host's own ones (RFC 6724 §6) and
/// racing connections (RFC 8305) is up to the caller.
///
/// [`Config::ip_strategy`]: crate::Config::ip_strategy
#[derive(Debug, PartialEq, Eq)]
pub struct IpLookup {
    /// In the order their addresses are listed; the second is `None` when
    /// only one family is asked for.
    queries: [Option<QueryId>; 2],
    /// The outcome of each query, filled as its event arrives.
    results: [Option<Result<Vec<IpAddr>, Error>>; 2],
}

/// Where an [`IpLookup`] stands after an event.
#[derive(Debug, PartialEq, Eq)]
pub enum Progress {
    /// A query is still running: pass the lookup the next event.
    Waiting(IpLookup),
    /// Every query has finished. The addresses of one family followed by
    /// those of the other, in the order of [`Config::ip_strategy`], each in
    /// the server's order. An error only if no address was found and a
    /// query failed; no address and no failure (NXDOMAIN, or no records) is
    /// an empty list.
    ///
    /// [`Config::ip_strategy`]: crate::Config::ip_strategy
    Done(Result<Vec<IpAddr>, Error>),
}

impl IpLookup {
    /// Start the queries for `name` on `resolver`, for the families of its
    /// [`Config::ip_strategy`](crate::Config::ip_strategy).
    pub fn start(resolver: &mut Resolver, name: Name, now: Instant) -> Result<Self, ProtoError> {
        let queries = match resolver.config().ip_strategy.record_types() {
            (first, Some(second)) => [
                Some(resolver.query(name.clone(), first, now)?),
                Some(resolver.query(name, second, now)?),
            ],
            (only, None) => [Some(resolver.query(name, only, now)?), None],
        };
        Ok(Self {
            queries,
            results: [None, None],
        })
    }

    /// Its queries, one or two, to route events to this lookup or to cancel
    /// them.
    pub fn queries(&self) -> impl Iterator<Item = QueryId> + use<> {
        self.queries.into_iter().flatten()
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
            .find_map(|(q, slot)| (*q == Some(*query)).then_some(slot));
        if let Some(slot) = slot {
            *slot = Some(result);
        }
        match (self.queries, self.results) {
            (_, [Some(first), Some(second)]) => Progress::Done(merge(first, second)),
            ([_, None], [Some(only), None]) => Progress::Done(only),
            (_, results) => {
                self.results = results;
                Progress::Waiting(self)
            }
        }
    }
}

fn merge(
    first: Result<Vec<IpAddr>, Error>,
    second: Result<Vec<IpAddr>, Error>,
) -> Result<Vec<IpAddr>, Error> {
    match (first, second) {
        (Ok(first), Ok(second)) => Ok(first.into_iter().chain(second).collect()),
        (Ok(found), Err(error)) | (Err(error), Ok(found)) if found.is_empty() => Err(error),
        (Ok(found), Err(_)) | (Err(_), Ok(found)) => Ok(found),
        (Err(error), Err(_)) => Err(error),
    }
}
