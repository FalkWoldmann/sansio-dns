//! A query for the same name and type as one in flight joins it instead of
//! being sent, and gets its outcome as an event of its own.

use std::assert_matches;
use std::time::{Duration, Instant};

use crate::common::*;
use hickory_proto::op::ResponseCode;
use hickory_proto::rr::{Name, RecordType};
use rstest::rstest;
use sansio_dns::{Config, Error, Event, QueryId, Resolver, Transport};

fn query(resolver: &mut Resolver, name: &str, record_type: RecordType, now: Instant) -> QueryId {
    resolver
        .query(Name::from_ascii(name).unwrap(), record_type, now)
        .unwrap()
}

/// The queries the events are for, in order.
fn finished(resolver: &mut Resolver) -> Vec<QueryId> {
    std::iter::from_fn(|| resolver.poll_event())
        .map(|event| match event {
            Event::Response { query, .. } | Event::Failed { query, .. } => query,
        })
        .collect()
}

#[rstest]
fn same_query_is_sent_once_and_answers_both(mut resolver: Resolver) {
    let now = Instant::now();
    let first = query(&mut resolver, "example.com.", RecordType::A, now);
    let sent = resolver.poll_transmit().unwrap();

    let second = query(&mut resolver, "example.com.", RecordType::A, now);
    assert!(resolver.poll_transmit().is_none());
    resolver.handle_datagram(udp(&sent), S1, &encode(&reply(&sent)), now);

    let events: Vec<Event> = std::iter::from_fn(|| resolver.poll_event()).collect();
    assert_matches!(&events[..], [
        Event::Response { query: a, response: r1 },
        Event::Response { query: b, response: r2 },
    ] if *a == first && *b == second && r1 == r2 && !r1.answers.is_empty());
}

#[rstest]
#[case::other_type("example.com.", RecordType::AAAA)]
#[case::other_name("example.org.", RecordType::A)]
#[case::without_trailing_dot("example.com", RecordType::A)]
fn other_queries_are_sent_separately(
    mut resolver: Resolver,
    #[case] name: &str,
    #[case] record_type: RecordType,
) {
    let now = Instant::now();
    query(&mut resolver, "example.com.", RecordType::A, now);

    query(&mut resolver, name, record_type, now);

    assert_eq!(std::iter::from_fn(|| resolver.poll_transmit()).count(), 2);
}

#[rstest]
fn joined_query_gets_the_failure(mut resolver: Resolver) {
    let now = Instant::now();
    let first = query(&mut resolver, "example.com.", RecordType::A, now);
    let second = query(&mut resolver, "example.com.", RecordType::A, now);

    while let Some(deadline) = resolver.poll_timeout() {
        resolver.handle_timeout(deadline);
        while resolver.poll_transmit().is_some() {}
    }

    let events: Vec<Event> = std::iter::from_fn(|| resolver.poll_event()).collect();
    assert_matches!(&events[..], [
        Event::Failed { query: a, error: Error::Timeout },
        Event::Failed { query: b, error: Error::Timeout },
    ] if *a == first && *b == second);
}

#[rstest]
fn cancelled_follower_leaves_the_query(mut resolver: Resolver) {
    let now = Instant::now();
    let first = query(&mut resolver, "example.com.", RecordType::A, now);
    let sent = resolver.poll_transmit().unwrap();
    let second = query(&mut resolver, "example.com.", RecordType::A, now);

    resolver.cancel(second, now);
    resolver.handle_datagram(udp(&sent), S1, &encode(&reply(&sent)), now);

    assert_eq!(finished(&mut resolver), [first]);
}

/// The follower re-sends the attempt from its own socket: the first query's
/// socket is gone with it.
#[rstest]
fn cancelled_leader_hands_the_query_over(mut resolver: Resolver) {
    let now = Instant::now();
    let first = query(&mut resolver, "example.com.", RecordType::A, now);
    let sent = resolver.poll_transmit().unwrap();
    let second = query(&mut resolver, "example.com.", RecordType::A, now);
    let later = now + Duration::from_millis(1500);

    resolver.cancel(first, later);

    let resent = resolver.poll_transmit().unwrap();
    assert_eq!(resent.transport, Transport::Udp(second));
    assert_eq!(resent.destination, S1);
    assert_eq!(resent.payload, sent.payload);
    assert_eq!(
        resolver.poll_timeout(),
        Some(later + Duration::from_secs(2))
    );
    resolver.handle_datagram(first, S1, &encode(&reply(&sent)), now);
    assert!(resolver.poll_event().is_none());
    resolver.handle_datagram(second, S1, &encode(&reply(&resent)), now);
    assert_eq!(finished(&mut resolver), [second]);
}

#[rstest]
fn cancelled_leader_on_a_stream_hands_over_without_sending(mut resolver: Resolver) {
    let now = Instant::now();
    let first = query(&mut resolver, "example.com.", RecordType::A, now);
    let sent = resolver.poll_transmit().unwrap();
    let mut truncated = reply(&sent);
    truncated.metadata.truncation = true;
    resolver.handle_datagram(udp(&sent), S1, &encode(&truncated), now);
    let tcp = resolver.poll_transmit().unwrap();
    let second = query(&mut resolver, "example.com.", RecordType::A, now);

    resolver.cancel(first, now);

    assert!(resolver.poll_transmit().is_none());
    resolver.handle_stream_data(conn(&tcp), &frame(&encode(&reply(&tcp))), now);
    assert_eq!(finished(&mut resolver), [second]);
}

/// Joining late doesn't mean sharing the first query's spent attempts.
#[test]
fn late_joiner_starts_over_when_the_first_runs_out() {
    let mut resolver = Resolver::new(Config::new(S1, []));
    let start = Instant::now();
    let first = query(&mut resolver, "example.com.", RecordType::A, start);
    resolver.handle_timeout(start + Duration::from_secs(2));
    while resolver.poll_transmit().is_some() {}
    let second = query(
        &mut resolver,
        "example.com.",
        RecordType::A,
        start + Duration::from_millis(3990),
    );
    let end = start + Duration::from_secs(4);

    resolver.handle_timeout(end);

    assert_eq!(finished(&mut resolver), [first]);
    let fresh = resolver.poll_transmit().unwrap();
    assert_eq!(fresh.transport, Transport::Udp(second));
    assert_eq!(resolver.poll_timeout(), Some(end + Duration::from_secs(2)));
}

#[test]
fn joined_query_follows_the_search() {
    let mut config = Config::new(S1, []);
    config.search = vec![Name::from_ascii("corp.example.").unwrap()];
    let mut resolver = Resolver::new(config);
    let now = Instant::now();
    let first = query(&mut resolver, "db", RecordType::A, now);
    let searched = resolver.poll_transmit().unwrap();
    let second = query(&mut resolver, "db", RecordType::A, now);

    let nxdomain = with_code(reply(&searched), ResponseCode::NXDomain);
    resolver.handle_datagram(udp(&searched), S1, &encode(&nxdomain), now);
    let as_given = resolver.poll_transmit().unwrap();
    resolver.handle_datagram(udp(&as_given), S1, &encode(&reply(&as_given)), now);

    assert_eq!(decode(&as_given).queries[0].name().to_ascii(), "db.");
    assert_eq!(finished(&mut resolver), [first, second]);
}
