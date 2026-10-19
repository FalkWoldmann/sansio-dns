//! Address lookups: A and AAAA for one name, merged in the configured order.

use std::collections::VecDeque;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use hickory_proto::op::Message;
use hickory_proto::rr::{Name, RData, RecordType};

use crate::wire::{chain, in_class, is_localhost, is_special_use};
use crate::{Error, Event, LookupId, QueryId};

/// The addresses `response` gives for its question, following the CNAME
/// chain from the question name (RFC 1034 §3.6.2): the records at the end
/// of the chain of the type and class asked for, A for A, AAAA for AAAA
/// and both for ANY (RFC 3596 §2.3). Records owned by any other name, or
/// of another type or class, are ignored (RFC 1035 §7.4).
///
/// The chain ends at the first `localhost`, `invalid.` or `onion.` name,
/// which can't be an alias: a `localhost` name gives the loopback address
/// of the type asked for, whatever the server sent with it (RFC 6761
/// §6.3), and the others give none (RFC 6761 §6.4, RFC 7686 §2).
///
/// # Errors
///
/// [`Error::CnameLoop`] if the chain comes back to a name on it (RFC 1034
/// §3.6.2, §5.2.2).
pub fn addresses(response: &Message) -> Result<Vec<IpAddr>, Error> {
    let Some(question) = response.queries.first() else {
        return Ok(Vec::new());
    };
    let mut names: Vec<Name> = Vec::new();
    for name in chain(response) {
        if names.contains(&name) {
            return Err(Error::CnameLoop);
        }
        let special = is_special_use(&name);
        names.push(name);
        if special {
            break;
        }
    }
    let Some(canonical) = names.last() else {
        return Ok(Vec::new());
    };
    let (v4, v6) = match question.query_type() {
        RecordType::A => (true, false),
        RecordType::AAAA => (false, true),
        RecordType::ANY => (true, true),
        _ => (false, false),
    };
    if is_special_use(canonical) {
        let loopback = [
            v4.then_some(IpAddr::V4(Ipv4Addr::LOCALHOST)),
            v6.then_some(IpAddr::V6(Ipv6Addr::LOCALHOST)),
        ];
        let loopback = loopback.into_iter().flatten();
        return Ok(loopback.filter(|_| is_localhost(canonical)).collect());
    }
    let found = response
        .answers
        .iter()
        .filter(|r| r.name == *canonical && in_class(question, r))
        .filter_map(|r| match r.data {
            RData::A(a) if v4 => Some(IpAddr::V4(a.0)),
            RData::AAAA(aaaa) if v6 => Some(IpAddr::V6(aaaa.0)),
            _ => None,
        });
    Ok(found.collect())
}

/// An address lookup the resolver runs for [`Resolver::lookup_ip`]: the A
/// and AAAA queries for one search candidate at a time, as
/// [`Config::ip_strategy`] picks them, with their addresses merged.
///
/// It waits for the outcomes of its queries for the current candidate,
/// which the resolver hands it from their events at the end of the input
/// that queued them (`Resolver::run_lookups`, [`Lookup::handle`]). Once
/// each has its outcome, the lookup moves on to the next candidate if
/// neither found an address and one is left ([`Step::Next`], whose queries
/// the resolver starts and hands it with [`Lookup::sent`]), and is done
/// otherwise ([`Step::Done`]).
///
/// [`Resolver::lookup_ip`]: crate::Resolver::lookup_ip
/// [`Config::ip_strategy`]: crate::Config::ip_strategy
#[derive(Debug)]
pub(crate) struct Lookup {
    pub(crate) id: LookupId,
    /// The queries for the current search candidate, one per record type
    /// of `Config::ip_strategy`, in its order; the second is `None` when
    /// only one family is asked for.
    queries: [Option<QueryId>; 2],
    /// The outcome of each query, filled as its event arrives: `None` while
    /// its query runs, and for a type not asked for, which has no query.
    /// The search candidate is done once each query has its outcome.
    results: [Option<Result<Vec<IpAddr>, Error>>; 2],
    /// The search candidates still to try, as absolute names.
    rest: VecDeque<Name>,
}

/// Where a [`Lookup`] goes after one of its queries ended.
#[derive(Debug)]
pub(crate) enum Step {
    /// Its other query is still running.
    Wait,
    /// Neither query found an address: start the queries for this search
    /// candidate, the next one, and hand them to [`Lookup::sent`]. If they
    /// can't be encoded, the outcome so far, an empty list, stands.
    Next(Name),
    /// The lookup is done. The addresses of one family followed by those of
    /// the other, in the order of `Config::ip_strategy`, each in the
    /// server's order. An error only if no address was found and a query
    /// failed or got an answer whose CNAME chain loops
    /// ([`Error::CnameLoop`]); no address and no failure (NXDOMAIN, or no
    /// records) is an empty list.
    Done(Result<Vec<IpAddr>, Error>),
}

impl Lookup {
    /// A lookup waiting for `queries`, with the search candidates in `rest`
    /// still to try.
    pub(crate) fn new(id: LookupId, queries: [Option<QueryId>; 2], rest: VecDeque<Name>) -> Self {
        Self {
            id,
            queries,
            results: [None, None],
            rest,
        }
    }

    /// The queries still running for the current search candidate. They
    /// change when the search moves on.
    pub(crate) fn queries(&self) -> impl Iterator<Item = QueryId> + use<> {
        let running = self
            .queries
            .into_iter()
            .zip(self.results.each_ref().map(Option::is_none));
        running.filter_map(|(query, running)| query.filter(|_| running))
    }

    /// Whether `query` is one of its running queries.
    pub(crate) fn waits_for(&self, query: QueryId) -> bool {
        self.queries().any(|q| q == query)
    }

    /// Take in `event`, which ends one of its running queries, and say
    /// where the lookup goes next.
    pub(crate) fn handle(&mut self, event: &Event) -> Step {
        let (query, result) = match event {
            Event::Response { query, response } => (query, addresses(response)),
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
                return Step::Wait;
            }
        };
        let none_found = outcome.as_ref().is_ok_and(Vec::is_empty);
        match self.rest.pop_front().filter(|_| none_found) {
            Some(candidate) => Step::Next(candidate),
            None => Step::Done(outcome),
        }
    }

    /// The queries for the search candidate of its last [`Step::Next`]
    /// started.
    pub(crate) fn sent(&mut self, queries: [Option<QueryId>; 2]) {
        self.queries = queries;
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
