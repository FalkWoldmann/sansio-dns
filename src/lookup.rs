//! Address lookups: A and AAAA for one name, merged in the configured order.

use std::collections::VecDeque;
use std::net::IpAddr;
use std::time::Instant;

use hickory_proto::ProtoError;
use hickory_proto::op::Message;
use hickory_proto::rr::{Name, RData, RecordType};

use crate::wire::chain;
use crate::{Error, Event, QueryId, Resolver};

/// The addresses `response` gives for its question's name, following the
/// CNAME chain from that name (RFC 1034 §3.6.2). Records owned by any other
/// name are ignored.
pub fn addresses(response: &Message) -> Vec<IpAddr> {
    let Some(canonical) = chain(response).last() else {
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
/// With [`Config::search`] domains, the lookup walks the candidates itself,
/// asking each for both families at once, as glibc's `getaddrinfo` does: it
/// moves on when neither query found an address, after NXDOMAIN or NODATA
/// (RFC 1123 §6.1.4.3, RFC 2308 §2.2), and ends on the first candidate
/// where one did, with the addresses of both families for that name. So
/// they are those of one host (RFC 1123 §6.1.4.3 (b)). A query that fails
/// ends the search, and when the candidates run out the outcome is an
/// empty list. Names listed in [`Config::hosts`] and special-use names are
/// answered locally, as given, before any search domain.
///
/// Pass every [`Event`] to [`IpLookup::handle_event`], which hands the
/// lookup back until it is done, and then the outcome instead. Moving on
/// to the next candidate starts new queries on the resolver: send the
/// transmits they queue, and look up [`IpLookup::queries`] again after
/// each event. Sorting the addresses by the host's own ones (RFC 6724 §6)
/// and racing connections (RFC 8305) is up to the caller.
///
/// [`Config::ip_strategy`]: crate::Config::ip_strategy
/// [`Config::search`]: crate::Config::search
/// [`Config::hosts`]: crate::Config::hosts
#[derive(Debug, PartialEq, Eq)]
pub struct IpLookup {
    /// The record types asked for, in the order their addresses are
    /// listed; the second is `None` when only one family is asked for.
    types: [Option<RecordType>; 2],
    /// The queries for the current search candidate, one per type.
    queries: [Option<QueryId>; 2],
    /// The outcome of each query, filled as its event arrives.
    results: [Option<Result<Vec<IpAddr>, Error>>; 2],
    /// The search candidates still to try, as absolute names.
    rest: VecDeque<Name>,
}

/// Where an [`IpLookup`] stands after an event.
#[derive(Debug, PartialEq, Eq)]
pub enum Progress {
    /// A query is still running: pass the lookup the next event.
    Waiting(IpLookup),
    /// The lookup is done. The addresses of one family followed by those of
    /// the other, in the order of [`Config::ip_strategy`], each in the
    /// server's order. An error only if no address was found and a query
    /// failed; no address and no failure (NXDOMAIN, or no records) is an
    /// empty list.
    ///
    /// [`Config::ip_strategy`]: crate::Config::ip_strategy
    Done(Result<Vec<IpAddr>, Error>),
}

impl IpLookup {
    /// Start the queries for `name` on `resolver`, for the families of its
    /// [`Config::ip_strategy`](crate::Config::ip_strategy).
    ///
    /// # Errors
    ///
    /// If a query can't be encoded.
    pub fn start(resolver: &mut Resolver, name: Name, now: Instant) -> Result<Self, ProtoError> {
        let (first, second) = resolver.config().ip_strategy.record_types();
        let types = [Some(first), second];
        if resolver.is_local(&name) {
            let mut queries = [None, None];
            for (query, record_type) in queries.iter_mut().zip(types) {
                if let Some(record_type) = record_type {
                    *query = Some(resolver.query(name.clone(), record_type, now)?);
                }
            }
            return Ok(Self {
                types,
                queries,
                results: [None, None],
                rest: VecDeque::new(),
            });
        }
        let mut rest = resolver.config().candidates(&name);
        let candidate = rest.pop_front().unwrap_or_else(|| {
            let mut absolute = name;
            absolute.set_fqdn(true);
            absolute
        });
        Ok(Self {
            types,
            queries: send(resolver, &candidate, types, now)?,
            results: [None, None],
            rest,
        })
    }

    /// The queries still running for the current search candidate, to
    /// route events to this lookup or to cancel them. They change when the
    /// search moves on.
    pub fn queries(&self) -> impl Iterator<Item = QueryId> + use<> {
        let running = self
            .queries
            .into_iter()
            .zip(self.results.each_ref().map(Option::is_none));
        running.filter_map(|(query, running)| query.filter(|_| running))
    }

    /// Take in `event`; events of other queries leave the lookup as it is.
    /// Once both families have no address for the current search
    /// candidate, the queries for the next one start on `resolver`.
    pub fn handle_event(
        mut self,
        resolver: &mut Resolver,
        event: &Event,
        now: Instant,
    ) -> Progress {
        let (query, result) = match event {
            Event::Response { query, response } => (query, Ok(addresses(response))),
            Event::Failed { query, error } => (query, Err(error.clone())),
        };
        let slot = self
            .queries
            .iter()
            .zip(&mut self.results)
            .find_map(|(q, slot)| (*q == Some(*query) && slot.is_none()).then_some(slot));
        if let Some(slot) = slot {
            *slot = Some(result);
        }
        let outcome = match (self.queries, std::mem::take(&mut self.results)) {
            (_, [Some(first), Some(second)]) => merge(first, second),
            ([_, None], [Some(only), None]) => only,
            (_, results) => {
                self.results = results;
                return Progress::Waiting(self);
            }
        };
        let none_found = outcome.as_ref().is_ok_and(Vec::is_empty);
        let next = self.rest.pop_front().filter(|_| none_found);
        match next.map(|candidate| send(resolver, &candidate, self.types, now)) {
            Some(Ok(queries)) => {
                self.queries = queries;
                Progress::Waiting(self)
            }
            // The current outcome stands if the next candidate can't be
            // encoded, as in `Resolver::query`'s search.
            Some(Err(_)) | None => Progress::Done(outcome),
        }
    }
}

/// Start the queries of `types` for the search candidate `name`. If the
/// second can't start, the first is cancelled.
fn send(
    resolver: &mut Resolver,
    name: &Name,
    types: [Option<RecordType>; 2],
    now: Instant,
) -> Result<[Option<QueryId>; 2], ProtoError> {
    let mut queries = [None, None];
    for (i, record_type) in types.into_iter().enumerate() {
        let Some(record_type) = record_type else {
            continue;
        };
        match resolver.query_candidate(name.clone(), record_type, now) {
            Ok(query) => {
                if let Some(slot) = queries.get_mut(i) {
                    *slot = Some(query);
                }
            }
            Err(error) => {
                for query in queries.into_iter().flatten() {
                    resolver.cancel(query, now);
                }
                return Err(error);
            }
        }
    }
    Ok(queries)
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
