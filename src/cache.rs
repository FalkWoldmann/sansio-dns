//! The cache of resolution failures (RFC 9520 §3.2) and negative answers
//! (RFC 2308 §5). It lives inside the resolver and reads time only from the
//! `now` it is given, so it needs no timer: an expired negative answer is
//! dropped when looked up, and an expired failure stays for the backoff of
//! the next one until it is replaced, an answer ends it or the size bound
//! needs room.

use std::collections::BTreeMap;
use std::time::{Duration, Instant};

use hickory_proto::op::{Message, Query, ResponseCode};
use hickory_proto::rr::{DNSClass, Name, RData, RecordType};

use crate::wire::{chain, in_class};
use crate::{Config, Error};

/// What an entry is about: a name in a class, and one record type of it, or
/// every type.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
struct Key {
    /// Absolute and lowercased. hickory's `Name` ordering ignores ASCII case
    /// anyway, and only ASCII case (RFC 4343 §3).
    name: Name,
    class: DNSClass,
    /// `None` for NXDOMAIN, which holds for every type of the name (RFC 2308
    /// §5).
    record_type: Option<RecordType>,
}

impl Key {
    fn new(name: &Name, class: DNSClass, record_type: Option<RecordType>) -> Self {
        Self {
            name: name.to_lowercase(),
            class,
            record_type,
        }
    }

    /// The key for `question` itself, and the one for every type of its
    /// name.
    fn of(question: &Query) -> (Self, Self) {
        let name = question.name();
        let class = question.query_class();
        (
            Self::new(name, class, Some(question.query_type())),
            Self::new(name, class, None),
        )
    }
}

#[derive(Debug)]
struct Slot {
    /// Order of insertion: the oldest entry has the lowest.
    serial: u64,
    entry: Entry,
}

/// A cached outcome. A positive answer would be one more variant, holding a
/// response as `Negative` does.
///
/// A key holds no entry, or a `Negative` or `Failed` one, which is live or
/// expired by `now` (`Entry::is_live`). A question's keys (`Key::of`) are
/// its own and the one of its name without a type, which NXDOMAIN uses.
/// Only these calls change what a key holds:
///
/// | Call | Effect |
/// |---|---|
/// | `Cache::get` | drops an expired `Negative` under either key of the question |
/// | `Cache::answered` | drops whatever either key of the question holds |
/// | `Cache::negative` | first does what `answered` does for the answer's question, then may store a `Negative` under the last name of the answer's CNAME chain, with the question's type after NODATA and none after NXDOMAIN |
/// | `Cache::failed` | stores a `Failed` under the question's own key |
/// | `Cache::flush` | drops every entry |
///
/// A store replaces what the key held. A store under a new key into a full
/// cache first drops every expired entry, and then, if it is still full,
/// the oldest. So an expired `Failed` entry stays, for the backoff of the
/// next failure of its question, until a store replaces it, an answer
/// drops it, the cache needs room or it is flushed.
#[derive(Debug)]
enum Entry {
    /// NXDOMAIN or NODATA, with the authority section it came with (RFC
    /// 2308 §5).
    Negative(Stored),
    /// A resolution failure (RFC 9520 §2, §3.2).
    Failed(Failure),
}

impl Entry {
    /// Whether it still answers queries at `now`.
    fn is_live(&self, now: Instant) -> bool {
        match self {
            Self::Negative(stored) => now < stored.expires,
            Self::Failed(failure) => now < failure.until,
        }
    }
}

#[derive(Debug)]
struct Stored {
    /// The header and authority section to answer with, the TTLs as they
    /// were when stored, none above the entry's lifetime. No OPT record,
    /// which is never cached (RFC 6891 §6.2.1).
    response: Message,
    stored: Instant,
    expires: Instant,
}

impl Stored {
    /// The answer to `question` at `now`: the stored one, asking
    /// `question`, with every TTL less the whole seconds it was stored
    /// (RFC 2308 §5, §6; RFC 1123 §6.1.3.1).
    fn serve(&self, question: &Query, now: Instant) -> Message {
        let elapsed = now.saturating_duration_since(self.stored).as_secs();
        let elapsed = u32::try_from(elapsed).unwrap_or(u32::MAX);
        let mut response = self.response.clone();
        response.queries = vec![question.clone()];
        for record in &mut response.authorities {
            record.ttl = record.ttl.saturating_sub(elapsed);
        }
        response
    }
}

#[derive(Debug)]
struct Failure {
    error: Error,
    /// Until when nothing is sent for the question.
    until: Instant,
    /// How long it was cached for, which the next failure doubles.
    duration: Duration,
    /// Until when a query sent for the question backs off from it if it
    /// fails too: `Config::failure_cache_max` after `until`.
    forget: Instant,
}

/// What the cache holds for a question.
#[derive(Debug)]
pub(crate) enum Hit {
    /// A negative answer, to deliver as the response.
    Response(Message),
    /// A resolution failure, to fail with.
    Failed(Error),
}

/// Resolution failures and negative answers, keyed by the question as sent
/// and bounded by `Config::cache_entries`.
#[derive(Debug, Default)]
pub(crate) struct Cache {
    entries: BTreeMap<Key, Slot>,
    serial: u64,
}

impl Cache {
    /// What the cache holds for `question` at `now`: of a live NODATA or
    /// failure entry for the question and a live NXDOMAIN for its name, the
    /// one stored last.
    pub(crate) fn get(&mut self, question: &Query, now: Instant) -> Option<Hit> {
        let (exact, any) = Key::of(question);
        self.drop_expired(&exact, now);
        self.drop_expired(&any, now);
        let slot = [&exact, &any]
            .into_iter()
            .filter_map(|key| self.entries.get(key))
            .filter(|slot| slot.entry.is_live(now))
            .max_by_key(|slot| slot.serial)?;
        Some(match &slot.entry {
            Entry::Negative(stored) => Hit::Response(stored.serve(question, now)),
            Entry::Failed(failure) => Hit::Failed(failure.error.clone()),
        })
    }

    /// The error of a live failure entry for `question` at `now`, if there
    /// is one: nothing may be sent for it (RFC 9520 §3.2).
    pub(crate) fn failure(&self, question: &Query, now: Instant) -> Option<Error> {
        let (exact, _) = Key::of(question);
        match &self.entries.get(&exact)?.entry {
            Entry::Failed(failure) => (now < failure.until).then(|| failure.error.clone()),
            Entry::Negative(_) => None,
        }
    }

    /// A server gave a useful answer to `question` (RFC 9520 §2): the name
    /// exists, or the answer is new. Ends a failure entry, and so its
    /// backoff, and the negative entries for the question and its name.
    pub(crate) fn answered(&mut self, question: &Query) {
        let (exact, any) = Key::of(question);
        self.entries.remove(&exact);
        self.entries.remove(&any);
    }

    /// Store the NXDOMAIN or NODATA answer `response`, received at `now`
    /// (RFC 2308 §5): for every type of the name after NXDOMAIN, for the
    /// type asked for after NODATA. The name is the last of the answer's
    /// CNAME chain, the QNAME as §1 defines it, so an alias whose target
    /// doesn't exist isn't cached as nonexistent; a chain that loops isn't
    /// cached at all. Its lifetime is the lesser of the SOA record's TTL and
    /// its MINIMUM field, at most `Config::max_negative_ttl`. Not stored:
    /// an answer without an SOA record in the authority section (§5), a
    /// truncated one (RFC 1123 §6.1.3.2, RFC 2181 §9), and one whose
    /// lifetime is zero (RFC 1123 §6.1.2.1). Any answer ends the entries
    /// that `answered` ends.
    pub(crate) fn negative(&mut self, response: &Message, config: &Config, now: Instant) {
        let Some(question) = response.queries.first() else {
            return;
        };
        self.answered(question);
        let record_type = match response.metadata.response_code {
            ResponseCode::NXDomain => None,
            ResponseCode::NoError => Some(question.query_type()),
            _ => return,
        };
        if response.metadata.truncation {
            return;
        }
        let names: Vec<Name> = chain(response).collect();
        let looped = names
            .iter()
            .enumerate()
            .any(|(i, name)| names.iter().take(i).any(|earlier| earlier == name));
        let Some(name) = names.last().filter(|_| !looped) else {
            return;
        };
        let Some(ttl) = negative_ttl(response, question, config) else {
            return;
        };
        let Some(expires) = now.checked_add(Duration::from_secs(ttl.into())) else {
            return;
        };
        let mut stored = Message::response(0, response.metadata.op_code);
        stored.metadata = response.metadata;
        stored.metadata.id = 0;
        stored.metadata.authoritative = false;
        stored.authorities = response
            .authorities
            .iter()
            .map(|record| {
                let mut record = record.clone();
                record.ttl = sane_ttl(record.ttl).min(ttl);
                record
            })
            .collect();
        let key = Key::new(name, question.query_class(), record_type);
        let entry = Entry::Negative(Stored {
            response: stored,
            stored: now,
            expires,
        });
        self.insert(key, entry, config.cache_entries.get(), now);
    }

    /// `question` failed at `now` with `error` (RFC 9520 §2), for a query
    /// first sent at `sent`: nothing is sent for it for a while (§3.2).
    /// That is `Config::failure_cache_min` the first time; twice as long
    /// as the previous entry if the query was first sent within
    /// `Config::failure_cache_max` after that one expired (§3.2's backoff),
    /// up to that maximum, however long its retries took; and as long as
    /// the previous one if the query was sent while it was still live, as
    /// when two queries for the question were in flight at once.
    pub(crate) fn failed(
        &mut self,
        question: &Query,
        error: Error,
        sent: Instant,
        config: &Config,
        now: Instant,
    ) {
        let (shortest, longest) = config.failure_cache();
        let (key, _) = Key::of(question);
        let previous = self.entries.get(&key).and_then(|slot| match &slot.entry {
            Entry::Failed(previous) => Some((previous.until, previous.duration, previous.forget)),
            Entry::Negative(_) => None,
        });
        // Lookups keep failure entries after they expire, so the previous
        // one is still here unless an answer ended it or the size bound
        // needed room.
        let (duration, at_least) = match previous {
            Some((until, duration, _)) if sent < until => (duration, Some(until)),
            Some((_, duration, forget)) if sent < forget => {
                (duration.saturating_mul(2).clamp(shortest, longest), None)
            }
            _ => (shortest, None),
        };
        let until = now
            .checked_add(duration)
            .unwrap_or(now)
            .max(at_least.unwrap_or(now));
        let forget = until.checked_add(longest).unwrap_or(until);
        let entry = Entry::Failed(Failure {
            error,
            until,
            duration,
            forget,
        });
        self.insert(key, entry, config.cache_entries.get(), now);
    }

    /// Drop every entry.
    pub(crate) fn flush(&mut self) {
        self.entries.clear();
    }

    /// Drop the entry for `key` if it is a negative answer that expired at
    /// `now`. A failure entry stays after it expires: the next failure of
    /// its question backs off from it (`Cache::failed`).
    fn drop_expired(&mut self, key: &Key, now: Instant) {
        let expired = self.entries.get(key).is_some_and(|slot| match &slot.entry {
            Entry::Negative(_) => !slot.entry.is_live(now),
            Entry::Failed(_) => false,
        });
        if expired {
            self.entries.remove(key);
        }
    }

    /// Store `entry` under `key`, replacing what was there. A full cache
    /// first drops the entries that have expired, failures kept only for
    /// their backoff among them, and then, if it is still full, the oldest:
    /// RFC 9520 §3.2 asks for a bound on the memory a failure cache uses,
    /// and §5 for one against flooding it with failing names.
    fn insert(&mut self, key: Key, entry: Entry, capacity: usize, now: Instant) {
        if !self.entries.contains_key(&key) && self.entries.len() >= capacity {
            self.entries.retain(|_, slot| slot.entry.is_live(now));
            if self.entries.len() >= capacity
                && let Some(oldest) = self
                    .entries
                    .iter()
                    .min_by_key(|(_, slot)| slot.serial)
                    .map(|(key, _)| key.clone())
            {
                self.entries.remove(&oldest);
            }
        }
        self.serial = self.serial.wrapping_add(1);
        let slot = Slot {
            serial: self.serial,
            entry,
        };
        self.entries.insert(key, slot);
    }
}

/// How long the negative answer `response` to `question` may be cached, in
/// seconds: the lesser of its SOA record's TTL and MINIMUM field (RFC 2308
/// §5), at most `Config::max_negative_ttl`. `None` without an SOA record of
/// the question's class in the authority section, or for zero.
fn negative_ttl(response: &Message, question: &Query, config: &Config) -> Option<u32> {
    let (ttl, minimum) = response
        .authorities
        .iter()
        .find_map(|record| match &record.data {
            RData::SOA(soa) if in_class(question, record) => Some((record.ttl, soa.minimum)),
            _ => None,
        })?;
    let cap = u32::try_from(config.max_negative_ttl.as_secs()).unwrap_or(u32::MAX);
    let ttl = sane_ttl(ttl).min(sane_ttl(minimum)).min(cap);
    (ttl > 0).then_some(ttl)
}

/// `ttl`, or zero if its most significant bit is set (RFC 2181 §8).
fn sane_ttl(ttl: u32) -> u32 {
    if ttl & (1 << 31) == 0 { ttl } else { 0 }
}
