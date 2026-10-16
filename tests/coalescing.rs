//! A query for the same name and type as one in flight joins it instead of
//! being sent, and gets its outcome as an event of its own.

use std::assert_matches;
use std::time::{Duration, Instant};

use crate::common::*;
use hickory_proto::op::ResponseCode;
use hickory_proto::rr::{Name, RecordType};
use insta::assert_snapshot;
use rstest::rstest;
use sansio_dns::{Config, Event, QueryId, Resolver};

fn query(resolver: &mut Resolver, name: &str, record_type: RecordType, now: Instant) -> QueryId {
    resolver
        .query(Name::from_ascii(name).unwrap(), record_type, now)
        .unwrap()
}

#[rstest]
fn same_query_is_sent_once_and_answers_both(mut trace: Trace) {
    trace.query("example.com.", RecordType::A);
    let sent = trace.last();

    trace.query("example.com.", RecordType::A);
    trace.answer(&sent, &reply(&sent));

    assert_matches!(trace.events(), [
        Event::Response { response: r1, .. },
        Event::Response { response: r2, .. },
    ] if r1 == r2);
    assert_snapshot!(trace, @"
    t=0s query q0 example.com. A
      -> S1 udp q0: example.com. A
      next t=2s
    t=0s query q1 example.com. A
      next t=2s
    t=0s <- S1 udp q0: example.com. A: NoError, 1 answer
      => q0 Response example.com. A: NoError, 1 answer
      => q1 Response example.com. A: NoError, 1 answer
      next none
    ");
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
fn joined_query_gets_the_failure(mut trace: Trace) {
    trace.query("example.com.", RecordType::A);
    trace.query("example.com.", RecordType::A);

    trace.timeouts();

    assert_snapshot!(trace, @"
    t=0s query q0 example.com. A
      -> S1 udp q0: example.com. A
      next t=2s
    t=0s query q1 example.com. A
      next t=2s
    t=2s timeout
      -> S2 udp q0: example.com. A
      next t=4s
    t=4s timeout
      -> S1 udp q0: example.com. A
      next t=6s
    t=6s timeout
      -> S2 udp q0: example.com. A
      next t=8s
    t=8s timeout
      => q0 Failed Timeout
      => q1 Failed Timeout
      next none
    ");
}

#[rstest]
fn cancelled_follower_leaves_the_query(mut trace: Trace) {
    trace.query("example.com.", RecordType::A);
    let sent = trace.last();
    let second = trace.query("example.com.", RecordType::A);

    trace.cancel(second);
    trace.answer(&sent, &reply(&sent));

    assert_snapshot!(trace, @"
    t=0s query q0 example.com. A
      -> S1 udp q0: example.com. A
      next t=2s
    t=0s query q1 example.com. A
      next t=2s
    t=0s cancel q1
      next t=2s
    t=0s <- S1 udp q0: example.com. A: NoError, 1 answer
      => q0 Response example.com. A: NoError, 1 answer
      next none
    ");
}

/// The follower re-sends the attempt from its own socket: the first query's
/// socket is gone with it.
#[rstest]
fn cancelled_leader_hands_the_query_over(mut trace: Trace) {
    let first = trace.query("example.com.", RecordType::A);
    let sent = trace.last();
    trace.query("example.com.", RecordType::A);
    trace.at(Duration::from_millis(1500));

    trace.cancel(first);

    let resent = trace.last();
    assert_eq!(resent.payload, sent.payload);
    trace.answer(&sent, &reply(&sent));
    trace.answer(&resent, &reply(&resent));
    assert_snapshot!(trace, @"
    t=0s query q0 example.com. A
      -> S1 udp q0: example.com. A
      next t=2s
    t=0s query q1 example.com. A
      next t=2s
    t=1.5s cancel q0
      -> S1 udp q1: example.com. A
      next t=3.5s
    t=1.5s <- S1 udp q0: example.com. A: NoError, 1 answer
      next t=3.5s
    t=1.5s <- S1 udp q1: example.com. A: NoError, 1 answer
      => q1 Response example.com. A: NoError, 1 answer
      next none
    ");
}

#[rstest]
fn cancelled_leader_on_a_stream_hands_over_without_sending(mut trace: Trace) {
    let first = trace.query("example.com.", RecordType::A);
    let sent = trace.last();
    trace.answer(&sent, &truncated(reply(&sent)));
    let tcp = trace.last();
    trace.query("example.com.", RecordType::A);

    trace.cancel(first);

    trace.answer(&tcp, &reply(&tcp));
    assert_snapshot!(trace, @"
    t=0s query q0 example.com. A
      -> S1 udp q0: example.com. A
      next t=2s
    t=0s <- S1 udp q0: example.com. A: NoError, 1 answer, TC
      -> S1 connect c0: example.com. A
      next t=2s
    t=0s query q1 example.com. A
      next t=2s
    t=0s cancel q0
      next t=2s
    t=0s <- S1 c0: example.com. A: NoError, 1 answer
      => q1 Response example.com. A: NoError, 1 answer
      next t=10s
    ");
}

/// Joining late doesn't mean sharing the first query's spent attempts.
#[test]
fn late_joiner_starts_over_when_the_first_runs_out() {
    let mut trace = Trace::new(Resolver::new(Config::new(S1, [])));
    trace.query("example.com.", RecordType::A);
    trace.timeout_at(Duration::from_secs(2));
    trace.at(Duration::from_millis(3990));
    trace.query("example.com.", RecordType::A);

    trace.timeout_at(Duration::from_secs(4));

    assert_snapshot!(trace, @"
    t=0s query q0 example.com. A
      -> S1 udp q0: example.com. A
      next t=2s
    t=2s timeout
      -> S1 udp q0: example.com. A
      next t=4s
    t=3.99s query q1 example.com. A
      next t=4s
    t=4s timeout
      => q0 Failed Timeout
      -> S1 udp q1: example.com. A
      next t=6s
    ");
}

#[test]
fn joined_query_follows_the_search() {
    let mut config = Config::new(S1, []);
    config.search = vec![Name::from_ascii("corp.example.").unwrap()];
    let mut trace = Trace::new(Resolver::new(config));
    trace.query("db", RecordType::A);
    let searched = trace.last();
    trace.query("db", RecordType::A);

    trace.answer(
        &searched,
        &with_code(reply(&searched), ResponseCode::NXDomain),
    );
    let as_given = trace.last();
    trace.answer(&as_given, &reply(&as_given));

    assert_snapshot!(trace, @"
    t=0s query q0 db A
      -> S1 udp q0: db.corp.example. A
      next t=2s
    t=0s query q1 db A
      next t=2s
    t=0s <- S1 udp q0: db.corp.example. A: NXDomain, 0 answers
      -> S1 udp q0: db. A
      next t=2s
    t=0s <- S1 udp q0: db. A: NoError, 1 answer
      => q0 Response db. A: NoError, 1 answer
      => q1 Response db. A: NoError, 1 answer
      next none
    ");
}
