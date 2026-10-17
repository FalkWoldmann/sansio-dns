//! RFC 9520, Negative Caching of DNS Resolution Failures.
//! <https://rfc-annotations.research.icann.org/rfc9520.html>

use std::net::SocketAddr;
use std::num::NonZeroUsize;
use std::time::Duration;

use crate::common::*;
use hickory_proto::op::{Message, ResponseCode};
use hickory_proto::rr::RecordType;
use insta::assert_snapshot;
use rstest::rstest;
use sansio_dns::{Config, Resolver};

/// §3.1: "A resolver MUST NOT retry a given query to a server address over
/// a given DNS transport more than twice (i.e., three queries in total)".
/// Every send of a search candidate counts, free ones included; a send that
/// would be the fourth goes to the next server with room as a new attempt,
/// and the query fails when no server has room. TCP is a transport of its
/// own.
mod section_3_1 {
    use super::*;

    /// `S1` alone, with `attempts` and the fixture's two-second timeout.
    fn one_server(attempts: usize) -> Trace {
        let mut config = Config::new(S1, []);
        config.timeout = Duration::from_secs(2);
        config.attempts = NonZeroUsize::new(attempts).unwrap();
        Trace::new(Resolver::new(config))
    }

    #[test]
    fn three_datagrams_to_one_server_however_many_attempts() {
        let mut trace = one_server(5);
        trace.query("example.com.", RecordType::A);

        trace.timeouts();

        assert_snapshot!(trace, @"
        t=0s query q0 example.com. A
          -> S1 udp q0: example.com. A
          next t=2s
        t=2s timeout
          -> S1 udp q0: example.com. A
          next t=6s
        t=6s timeout
          -> S1 udp q0: example.com. A
          next t=14s
        t=14s timeout
          => q0 Failed Timeout
          next none
        ");
    }

    #[test]
    fn a_server_with_three_sends_is_skipped() {
        let mut config = config();
        config.attempts = NonZeroUsize::new(6).unwrap();
        let mut trace = Trace::new(Resolver::new(config));
        trace.query("example.com.", RecordType::A);
        trace.timeout();
        trace.timeout();
        let sent = trace.last();
        let mut response = with_code(reply(&sent), ResponseCode::FormErr);
        response.edns = None;
        trace.answer(&sent, &response);

        trace.timeouts();

        assert_snapshot!(trace, @"
        t=0s query q0 example.com. A
          -> S1 udp q0: example.com. A
          next t=2s
        t=2s timeout
          -> S2 udp q0: example.com. A
          next t=4s
        t=4s timeout
          -> S1 udp q0: example.com. A
          next t=8s
        t=4s <- S1 udp q0: example.com. A: FormErr, 0 answers, no EDNS
          -> S1 udp q0: example.com. A, no EDNS
          next t=8s
        t=8s timeout
          -> S2 udp q0: example.com. A, no EDNS
          next t=12s
        t=12s timeout
          -> S2 udp q0: example.com. A, no EDNS
          next t=20s
        t=20s timeout
          => q0 Failed Timeout
          next none
        ");
    }

    /// The EDNS drop would be a fourth datagram: the query keeps EDNS and
    /// moves on, here to no server at all.
    #[test]
    fn edns_drop_counts() {
        let mut trace = one_server(4);
        trace.query("example.com.", RecordType::A);
        trace.timeout();
        trace.timeout();
        let sent = trace.last();
        let mut response = with_code(reply(&sent), ResponseCode::FormErr);
        response.edns = None;
        trace.answer(&sent, &response);

        assert_snapshot!(trace, @"
        t=0s query q0 example.com. A
          -> S1 udp q0: example.com. A
          next t=2s
        t=2s timeout
          -> S1 udp q0: example.com. A
          next t=6s
        t=6s timeout
          -> S1 udp q0: example.com. A
          next t=14s
        t=6s <- S1 udp q0: example.com. A: FormErr, 0 answers, no EDNS
          => q0 Failed Server(FormErr)
          next none
        ");
    }

    #[test]
    fn tcp_counts_on_its_own() {
        let mut trace = one_server(6);
        trace.query("example.com.", RecordType::A);
        trace.timeout();
        trace.timeout();
        let sent = trace.last();
        trace.answer(&sent, &truncated(reply(&sent)));

        trace.timeouts();

        assert_snapshot!(trace, @"
        t=0s query q0 example.com. A
          -> S1 udp q0: example.com. A
          next t=2s
        t=2s timeout
          -> S1 udp q0: example.com. A
          next t=6s
        t=6s timeout
          -> S1 udp q0: example.com. A
          next t=14s
        t=6s <- S1 udp q0: example.com. A: NoError, 1 answer, TC
          -> S1 connect c0: example.com. A
          next t=14s
        t=14s timeout
          -> S1 close c0
          -> S1 connect c1: example.com. A
          next t=30s
        t=30s timeout
          -> S1 close c1
          -> S1 connect c2: example.com. A
          next t=62s
        t=62s timeout
          => q0 Failed Timeout
          -> S1 close c2
          next none
        ");
    }

    /// The free resend after a working connection was lost is a stream send
    /// too: after it, a timeout finds the server out of sends while the
    /// query still has attempts.
    #[test]
    fn resend_after_a_lost_connection_counts() {
        let mut trace = one_server(5);
        trace.query("a.example.", RecordType::A);
        let sent = trace.last();
        trace.answer(&sent, &truncated(reply(&sent)));
        trace.timeout();
        let q0_tcp = trace.last();
        trace.query("b.example.", RecordType::A);
        let q1_tcp = trace.last();
        trace.answer(&q1_tcp, &reply(&q1_tcp));
        trace.close(&q0_tcp);

        trace.timeouts();

        assert_snapshot!(trace, @"
        t=0s query q0 a.example. A
          -> S1 udp q0: a.example. A
          next t=2s
        t=0s <- S1 udp q0: a.example. A: NoError, 1 answer, TC
          -> S1 connect c0: a.example. A
          next t=2s
        t=2s timeout
          -> S1 close c0
          -> S1 connect c1: a.example. A
          next t=6s
        t=2s query q1 b.example. A
          -> S1 write c1: b.example. A
          next t=4s
        t=2s <- S1 c1: b.example. A: NoError, 1 answer
          => q1 Response b.example. A: NoError, 1 answer
          next t=6s
        t=2s c1 closed
          -> S1 connect c2: a.example. A
          next t=6s
        t=6s timeout
          => q0 Failed Timeout
          -> S1 close c2
          next none
        ");
    }

    /// A hand-over's datagram counts: the second heir can't send to `S1`
    /// again and sends its next attempt to `S2`.
    #[rstest]
    fn hand_over_counts(mut trace: Trace) {
        let q0 = trace.query("example.com.", RecordType::A);
        let q1 = trace.query("example.com.", RecordType::A);
        trace.query("example.com.", RecordType::A);
        trace.timeout();
        trace.timeout();
        trace.cancel(q0);
        trace.cancel(q1);

        assert_snapshot!(trace, @"
        t=0s query q0 example.com. A
          -> S1 udp q0: example.com. A
          next t=2s
        t=0s query q1 example.com. A
          next t=2s
        t=0s query q2 example.com. A
          next t=2s
        t=2s timeout
          -> S2 udp q0: example.com. A
          next t=4s
        t=4s timeout
          -> S1 udp q0: example.com. A
          next t=8s
        t=4s cancel q0
          -> S1 udp q1: example.com. A
          next t=8s
        t=4s cancel q1
          -> S2 udp q2: example.com. A
          next t=8s
        ");
    }

    /// With no room left for the hand-over's datagram and no other server,
    /// an heir that joined when the search candidate started shares the
    /// failure, and so does the query that joined with it.
    #[test]
    fn early_heir_without_room_fails() {
        let mut trace = one_server(4);
        let q0 = trace.query("example.com.", RecordType::A);
        trace.query("example.com.", RecordType::A);
        trace.query("example.com.", RecordType::A);
        trace.timeout();
        trace.timeout();
        trace.cancel(q0);

        assert_snapshot!(trace, @"
        t=0s query q0 example.com. A
          -> S1 udp q0: example.com. A
          next t=2s
        t=0s query q1 example.com. A
          next t=2s
        t=0s query q2 example.com. A
          next t=2s
        t=2s timeout
          -> S1 udp q0: example.com. A
          next t=6s
        t=6s timeout
          -> S1 udp q0: example.com. A
          next t=14s
        t=6s cancel q0
          => q1 Failed Timeout
          => q2 Failed Timeout
          next none
        ");
    }

    /// So does an heir that joined after the search candidate started. The
    /// failure isn't cached, since no server failed to answer (§2): the
    /// answers may have gone to the cancelled queries' sockets. So the next
    /// query is sent.
    #[test]
    fn late_heir_without_room_fails() {
        let mut trace = one_server(2);
        let q0 = trace.query("example.com.", RecordType::A);
        trace.timeout();
        trace.at(Duration::from_secs(3));
        let q1 = trace.query("example.com.", RecordType::A);
        trace.cancel(q0);
        trace.at(Duration::from_secs(4));
        trace.query("example.com.", RecordType::A);
        trace.cancel(q1);
        trace.query("example.com.", RecordType::A);

        assert_snapshot!(trace, @"
        t=0s query q0 example.com. A
          -> S1 udp q0: example.com. A
          next t=2s
        t=2s timeout
          -> S1 udp q0: example.com. A
          next t=6s
        t=3s query q1 example.com. A
          next t=6s
        t=3s cancel q0
          -> S1 udp q1: example.com. A
          next t=7s
        t=4s query q2 example.com. A
          next t=7s
        t=4s cancel q1
          => q2 Failed Timeout
          next none
        t=4s query q3 example.com. A
          -> S1 udp q3: example.com. A
          next t=6s
        ");
    }

    /// Lookups of one name that keep being dropped before their answer, as
    /// callers with short timeouts do, use up the server's three sends by
    /// hand-overs; the heir that finds no room fails, but nothing is cached,
    /// and the next query is sent and answered.
    #[test]
    fn repeated_hand_overs_cache_nothing() {
        let mut config = Config::new(S1, []);
        config.timeout = Duration::from_secs(2);
        let mut trace = Trace::new(Resolver::new(config));
        let mut previous = trace.query("example.com.", RecordType::A);
        for at in [300, 600, 900] {
            trace.at(Duration::from_millis(at));
            let next = trace.query("example.com.", RecordType::A);
            trace.cancel(previous);
            previous = next;
        }
        trace.at(Duration::from_millis(1200));
        trace.query("example.com.", RecordType::A);
        let sent = trace.last();
        trace.answer(&sent, &reply(&sent));

        assert_snapshot!(trace, @"
        t=0s query q0 example.com. A
          -> S1 udp q0: example.com. A
          next t=2s
        t=0.3s query q1 example.com. A
          next t=2s
        t=0.3s cancel q0
          -> S1 udp q1: example.com. A
          next t=2.3s
        t=0.6s query q2 example.com. A
          next t=2.3s
        t=0.6s cancel q1
          -> S1 udp q2: example.com. A
          next t=2.6s
        t=0.9s query q3 example.com. A
          next t=2.6s
        t=0.9s cancel q2
          => q3 Failed Timeout
          next none
        t=1.2s query q4 example.com. A
          -> S1 udp q4: example.com. A
          next t=3.2s
        t=1.2s <- S1 udp q4: example.com. A: NoError, 1 answer
          => q4 Response example.com. A: NoError, 1 answer
          next none
        ");
    }
}

/// §3.2: "Resolvers MUST implement a cache for resolution failures. [...]
/// When an incoming query matches a cached resolution failure, the
/// resolver MUST NOT send any corresponding outgoing queries until after
/// the cache entries expire." Failures are cached by question for at least
/// a second, backing off on repeated failures up to a configurable maximum
/// of at most five minutes. NXDOMAIN and NODATA are no failures (§2).
/// Separately, a server that failed to answer goes after the others for at
/// most five minutes, whatever `Config::failure_memory` says, as RFC 2308
/// §7.2 caps a dead server indication.
mod section_3_2 {
    use super::*;

    /// `S1` alone, with the fixture's two-second timeout and `config`'s
    /// changes: a `SERVFAIL` from it fails a query at once.
    fn one_server(change: impl FnOnce(&mut Config)) -> Trace {
        let mut config = Config::new(S1, []);
        config.timeout = Duration::from_secs(2);
        change(&mut config);
        Trace::new(Resolver::new(config))
    }

    /// Query `name` and fail it with `SERVFAIL` from `S1`.
    fn fail(trace: &mut Trace, name: &str) {
        trace.query(name, RecordType::A);
        let sent = trace.last();
        trace.answer(&sent, &with_code(reply(&sent), ResponseCode::ServFail));
    }

    #[test]
    fn failure_is_cached_for_a_second() {
        let mut trace = one_server(|_| {});
        fail(&mut trace, "example.com.");
        trace.at(Duration::from_millis(999));
        trace.query("example.com.", RecordType::A);
        trace.query("example.com.", RecordType::AAAA);
        trace.at(Duration::from_secs(1));
        trace.query("example.com.", RecordType::A);

        assert_snapshot!(trace, @"
        t=0s query q0 example.com. A
          -> S1 udp q0: example.com. A
          next t=2s
        t=0s <- S1 udp q0: example.com. A: ServFail, 0 answers
          => q0 Failed Server(ServFail)
          next none
        t=0.999s query q1 example.com. A
          => q1 Failed Server(ServFail)
          next none
        t=0.999s query q2 example.com. AAAA
          -> S1 udp q2: example.com. AAAA
          next t=2.999s
        t=1s query q3 example.com. A
          -> S1 udp q3: example.com. A
          next t=2.999s
        ");
    }

    /// Each failure soon after the cached one expired is cached twice as
    /// long, up to `failure_cache_max`.
    #[test]
    fn repeated_failures_back_off() {
        let mut trace = one_server(|c| c.failure_cache_max = Duration::from_secs(4));
        let mut at = 0;
        for wait in [1, 2, 4, 4] {
            trace.at(Duration::from_secs(at));
            fail(&mut trace, "example.com.");
            at += wait;
            trace.at(Duration::from_millis(at * 1000 - 1));
            trace.query("example.com.", RecordType::A);
        }
        trace.at(Duration::from_secs(at));
        trace.query("example.com.", RecordType::A);

        assert_snapshot!(trace, @"
        t=0s query q0 example.com. A
          -> S1 udp q0: example.com. A
          next t=2s
        t=0s <- S1 udp q0: example.com. A: ServFail, 0 answers
          => q0 Failed Server(ServFail)
          next none
        t=0.999s query q1 example.com. A
          => q1 Failed Server(ServFail)
          next none
        t=1s query q2 example.com. A
          -> S1 udp q2: example.com. A
          next t=3s
        t=1s <- S1 udp q2: example.com. A: ServFail, 0 answers
          => q2 Failed Server(ServFail)
          next none
        t=2.999s query q3 example.com. A
          => q3 Failed Server(ServFail)
          next none
        t=3s query q4 example.com. A
          -> S1 udp q4: example.com. A
          next t=5s
        t=3s <- S1 udp q4: example.com. A: ServFail, 0 answers
          => q4 Failed Server(ServFail)
          next none
        t=6.999s query q5 example.com. A
          => q5 Failed Server(ServFail)
          next none
        t=7s query q6 example.com. A
          -> S1 udp q6: example.com. A
          next t=9s
        t=7s <- S1 udp q6: example.com. A: ServFail, 0 answers
          => q6 Failed Server(ServFail)
          next none
        t=10.999s query q7 example.com. A
          => q7 Failed Server(ServFail)
          next none
        t=11s query q8 example.com. A
          -> S1 udp q8: example.com. A
          next t=13s
        ");
    }

    /// The first failure is cached for `failure_cache_min`: never less than
    /// a second, and never more than five minutes, as `failure_cache_max`.
    #[rstest]
    #[case::default(None, None, 1)]
    #[case::configured(Some(5), None, 5)]
    #[case::below_one_second(Some(0), None, 1)]
    #[case::above_the_maximum(Some(60), Some(10), 60)]
    #[case::above_five_minutes(Some(u64::MAX), Some(u64::MAX), 300)]
    fn first_failure_lasts_the_minimum(
        #[case] min: Option<u64>,
        #[case] max: Option<u64>,
        #[case] secs: u64,
    ) {
        let mut trace = one_server(|c| {
            if let Some(min) = min {
                c.failure_cache_min = Duration::from_secs(min);
            }
            if let Some(max) = max {
                c.failure_cache_max = Duration::from_secs(max);
            }
        });
        fail(&mut trace, "example.com.");
        let end = Duration::from_secs(secs);

        trace.at(Duration::from_millis(secs * 1000 - 1));
        trace.query("example.com.", RecordType::A);
        assert!(trace.sent().is_empty(), "sent while cached:\n{trace}");
        trace.at(end);
        trace.query("example.com.", RecordType::A);
        assert_eq!(trace.sent().len(), 1, "not sent after {secs} s:\n{trace}");
    }

    /// With the maximum at its own limit too, repeated failures are cached
    /// for five minutes at most.
    #[test]
    fn backoff_stops_at_five_minutes() {
        let mut trace = one_server(|c| {
            c.failure_cache_min = Duration::from_secs(200);
            c.failure_cache_max = Duration::MAX;
        });
        fail(&mut trace, "example.com.");
        trace.at(Duration::from_secs(200));
        fail(&mut trace, "example.com.");
        trace.at(Duration::from_secs(499));
        trace.query("example.com.", RecordType::A);
        trace.at(Duration::from_secs(500));
        trace.query("example.com.", RecordType::A);

        assert_snapshot!(trace, @"
        t=0s query q0 example.com. A
          -> S1 udp q0: example.com. A
          next t=2s
        t=0s <- S1 udp q0: example.com. A: ServFail, 0 answers
          => q0 Failed Server(ServFail)
          next none
        t=200s query q1 example.com. A
          -> S1 udp q1: example.com. A
          next t=202s
        t=200s <- S1 udp q1: example.com. A: ServFail, 0 answers
          => q1 Failed Server(ServFail)
          next none
        t=499s query q2 example.com. A
          => q2 Failed Server(ServFail)
          next none
        t=500s query q3 example.com. A
          -> S1 udp q3: example.com. A
          next t=502s
        ");
    }

    /// A useful answer, data, NXDOMAIN or NODATA, ends the backoff: the next
    /// failure is cached for the minimum again. The negative answers with
    /// an SOA record are cached for a second.
    #[rstest]
    #[case::data(|r| r)]
    #[case::nxdomain(|r| with_code(r, ResponseCode::NXDomain))]
    #[case::nxdomain_with_soa(|r| with_soa_ttls(with_code(r, ResponseCode::NXDomain), 1, 1))]
    #[case::nodata(|r| no_data(r))]
    #[case::nodata_with_soa(|r| with_soa_ttls(no_data(r), 1, 1))]
    fn answer_resets_the_backoff(#[case] answer: fn(Message) -> Message) {
        let mut trace = one_server(|_| {});
        fail(&mut trace, "example.com.");
        trace.at(Duration::from_secs(1));
        trace.query("example.com.", RecordType::A);
        let sent = trace.last();
        trace.answer(&sent, &answer(reply(&sent)));
        trace.at(Duration::from_secs(2));
        fail(&mut trace, "example.com.");

        trace.at(Duration::from_secs(3));
        trace.query("example.com.", RecordType::A);

        assert_eq!(trace.sent().len(), 1, "backed off:\n{trace}");
    }

    /// The backoff counts from when the query was first sent, however long
    /// its retries take. With three servers and `Config::new`'s timeouts, a
    /// query sent when the cached failure expires fails 45 seconds later,
    /// past the 30 seconds after expiry that the backoff looks back, and is
    /// still cached twice as long.
    #[test]
    fn backoff_outlasts_slow_retries() {
        let s3 = SocketAddr::from(([10, 0, 0, 3], 53));
        let mut trace = Trace::new(Resolver::new(Config::new(S1, [S2, s3])));
        let mut at = 0;
        for secs in [1, 2, 4, 8, 16, 30, 30] {
            trace.at(Duration::from_secs(at));
            trace.query("example.com.", RecordType::A);
            assert_eq!(trace.sent().len(), 1, "not sent:\n{trace}");
            trace.timeouts();
            at += 45 + secs;
            trace.at(Duration::from_millis(at * 1000 - 1));
            trace.query("example.com.", RecordType::A);
            assert!(trace.sent().is_empty(), "not cached for {secs} s:\n{trace}");
        }
    }

    /// A failure that comes long after the cached one expired starts at the
    /// minimum again.
    #[test]
    fn late_failure_starts_over_at_the_minimum() {
        let mut trace = one_server(|_| {});
        fail(&mut trace, "example.com.");
        trace.at(Duration::from_secs(31));
        fail(&mut trace, "example.com.");
        trace.at(Duration::from_secs(32));
        trace.query("example.com.", RecordType::A);

        assert_snapshot!(trace, @"
        t=0s query q0 example.com. A
          -> S1 udp q0: example.com. A
          next t=2s
        t=0s <- S1 udp q0: example.com. A: ServFail, 0 answers
          => q0 Failed Server(ServFail)
          next none
        t=31s query q1 example.com. A
          -> S1 udp q1: example.com. A
          next t=33s
        t=31s <- S1 udp q1: example.com. A: ServFail, 0 answers
          => q1 Failed Server(ServFail)
          next none
        t=32s query q2 example.com. A
          -> S1 udp q2: example.com. A
          next t=34s
        ");
    }

    /// §2: "NXDOMAIN and NOERROR/NODATA responses are not conditions for
    /// resolution failure." Without an SOA record they aren't cached as
    /// negative answers either (RFC 2308 §5), so the question is sent again.
    #[rstest]
    #[case::nxdomain(|r| with_code(r, ResponseCode::NXDomain))]
    #[case::nodata(|r| no_data(r))]
    fn negative_answer_is_no_failure(#[case] negative: fn(Message) -> Message) {
        let mut trace = one_server(|_| {});
        trace.query("example.com.", RecordType::A);
        let sent = trace.last();
        trace.answer(&sent, &negative(reply(&sent)));

        trace.query("example.com.", RecordType::A);

        assert_eq!(trace.sent().len(), 1, "not sent again:\n{trace}");
    }

    /// Every query that joined the failed one fails with it, however late
    /// it joined, and so does every query for the question while the
    /// failure is cached; nothing is sent for any of them.
    #[test]
    fn joined_and_later_queries_get_the_failure() {
        let mut trace = one_server(|_| {});
        trace.query("example.com.", RecordType::A);
        let sent = trace.last();
        trace.query("example.com.", RecordType::A);
        trace.at(Duration::from_millis(500));
        trace.query("example.com.", RecordType::A);
        trace.answer(&sent, &with_code(reply(&sent), ResponseCode::ServFail));
        trace.query("example.com.", RecordType::A);

        assert_snapshot!(trace, @"
        t=0s query q0 example.com. A
          -> S1 udp q0: example.com. A
          next t=2s
        t=0s query q1 example.com. A
          next t=2s
        t=0.5s query q2 example.com. A
          next t=2s
        t=0.5s <- S1 udp q0: example.com. A: ServFail, 0 answers
          => q0 Failed Server(ServFail)
          => q1 Failed Server(ServFail)
          => q2 Failed Server(ServFail)
          next none
        t=0.5s query q3 example.com. A
          => q3 Failed Server(ServFail)
          next none
        ");
    }

    /// A query in flight for the same question, here asked without the
    /// trailing dot so it doesn't join, sends nothing more once the other
    /// one's failure is cached: its retry fails with the cached error. A new
    /// query asked like it fails at once rather than join it.
    #[test]
    fn query_in_flight_sends_nothing_more() {
        let mut config = config();
        config.failure_cache_min = Duration::from_secs(5);
        let mut trace = Trace::new(Resolver::new(config));
        trace.query("example.com.", RecordType::A);
        let first = trace.last();
        trace.query("example.com", RecordType::A);
        trace.answer(&first, &with_code(reply(&first), ResponseCode::ServFail));
        let second = trace.last();
        trace.answer(&second, &with_code(reply(&second), ResponseCode::ServFail));
        trace.query("example.com", RecordType::A);

        trace.timeouts();

        assert_snapshot!(trace, @"
        t=0s query q0 example.com. A
          -> S1 udp q0: example.com. A
          next t=2s
        t=0s query q1 example.com A
          -> S1 udp q1: example.com. A
          next t=2s
        t=0s <- S1 udp q0: example.com. A: ServFail, 0 answers
          -> S2 udp q0: example.com. A
          next t=2s
        t=0s <- S2 udp q0: example.com. A: ServFail, 0 answers
          => q0 Failed Server(ServFail)
          next t=2s
        t=0s query q2 example.com A
          => q2 Failed Server(ServFail)
          next t=2s
        t=2s timeout
          => q1 Failed Server(ServFail)
          next none
        ");
    }

    /// Two queries for the same question that fail together, one asked
    /// with the trailing dot and one without, are one failure: the second
    /// doesn't back off from the first.
    #[test]
    fn failures_in_flight_together_count_once() {
        let mut trace = one_server(|_| {});
        trace.query("example.com.", RecordType::A);
        let first = trace.last();
        trace.query("example.com", RecordType::A);
        let second = trace.last();
        trace.answer(&first, &with_code(reply(&first), ResponseCode::ServFail));
        trace.answer(&second, &with_code(reply(&second), ResponseCode::ServFail));
        trace.at(Duration::from_secs(1));
        trace.query("example.com.", RecordType::A);

        assert_snapshot!(trace, @"
        t=0s query q0 example.com. A
          -> S1 udp q0: example.com. A
          next t=2s
        t=0s query q1 example.com A
          -> S1 udp q1: example.com. A
          next t=2s
        t=0s <- S1 udp q0: example.com. A: ServFail, 0 answers
          => q0 Failed Server(ServFail)
          next t=2s
        t=0s <- S1 udp q1: example.com. A: ServFail, 0 answers
          => q1 Failed Server(ServFail)
          next none
        t=1s query q2 example.com. A
          -> S1 udp q2: example.com. A
          next t=3s
        ");
    }

    /// The question's name is compared without regard to ASCII case (RFC
    /// 4343 §3).
    #[test]
    fn name_case_is_ignored() {
        let mut trace = one_server(|_| {});
        fail(&mut trace, "Example.COM.");

        trace.query("example.com.", RecordType::A);

        assert_snapshot!(trace, @"
        t=0s query q0 Example.COM. A
          -> S1 udp q0: Example.COM. A
          next t=2s
        t=0s <- S1 udp q0: Example.COM. A: ServFail, 0 answers
          => q0 Failed Server(ServFail)
          next none
        t=0s query q1 example.com. A
          => q1 Failed Server(ServFail)
          next none
        ");
    }

    /// §3.2: "resolvers SHOULD implement measures to mitigate resource
    /// exhaustion attacks on the failed resolution cache". A full cache
    /// drops its expired entries first, here the failure of `b.`, and only
    /// then the oldest, here the negative answer for `a.`.
    #[test]
    fn full_cache_drops_expired_entries_then_the_oldest() {
        let mut trace = one_server(|c| c.cache_entries = NonZeroUsize::new(2).unwrap());
        trace.query("a.example.com.", RecordType::A);
        let sent = trace.last();
        trace.answer(
            &sent,
            &with_soa(with_code(reply(&sent), ResponseCode::NXDomain)),
        );
        fail(&mut trace, "b.example.com.");
        trace.at(Duration::from_secs(2));
        fail(&mut trace, "c.example.com.");
        trace.query("a.example.com.", RecordType::A);
        fail(&mut trace, "d.example.com.");
        trace.query("a.example.com.", RecordType::A);
        trace.query("c.example.com.", RecordType::A);
        trace.query("d.example.com.", RecordType::A);

        assert_snapshot!(trace, @"
        t=0s query q0 a.example.com. A
          -> S1 udp q0: a.example.com. A
          next t=2s
        t=0s <- S1 udp q0: a.example.com. A: NXDomain, 0 answers, SOA 300
          => q0 Response a.example.com. A: NXDomain, 0 answers, SOA 300
          next none
        t=0s query q1 b.example.com. A
          -> S1 udp q1: b.example.com. A
          next t=2s
        t=0s <- S1 udp q1: b.example.com. A: ServFail, 0 answers
          => q1 Failed Server(ServFail)
          next none
        t=2s query q2 c.example.com. A
          -> S1 udp q2: c.example.com. A
          next t=4s
        t=2s <- S1 udp q2: c.example.com. A: ServFail, 0 answers
          => q2 Failed Server(ServFail)
          next none
        t=2s query q3 a.example.com. A
          => q3 Response a.example.com. A: NXDomain, 0 answers, SOA 298, no EDNS
          next none
        t=2s query q4 d.example.com. A
          -> S1 udp q4: d.example.com. A
          next t=4s
        t=2s <- S1 udp q4: d.example.com. A: ServFail, 0 answers
          => q4 Failed Server(ServFail)
          next none
        t=2s query q5 a.example.com. A
          -> S1 udp q5: a.example.com. A
          next t=4s
        t=2s query q6 c.example.com. A
          => q6 Failed Server(ServFail)
          next t=4s
        t=2s query q7 d.example.com. A
          => q7 Failed Server(ServFail)
          next t=4s
        ");
    }

    /// `flush_cache`, for a network change, forgets the cached failures and
    /// negative answers, and which servers failed to answer: after it, new
    /// queries start at `S1` again.
    #[test]
    fn flush_forgets_everything() {
        let mut config = config();
        config.failure_cache_min = Duration::from_secs(10);
        let mut trace = Trace::new(Resolver::new(config));
        trace.query("b.example.com.", RecordType::A);
        for _ in 0..2 {
            let sent = trace.last();
            trace.answer(&sent, &with_code(reply(&sent), ResponseCode::ServFail));
        }
        trace.query("a.example.com.", RecordType::A);
        trace.timeout();
        let sent = trace.last();
        let nxdomain = with_soa(with_code(reply(&sent), ResponseCode::NXDomain));
        trace.answer(&sent, &nxdomain);
        trace.query("a.example.com.", RecordType::A);
        trace.query("b.example.com.", RecordType::A);

        trace.flush();
        trace.query("a.example.com.", RecordType::A);
        trace.query("b.example.com.", RecordType::A);

        assert_snapshot!(trace, @"
        t=0s query q0 b.example.com. A
          -> S1 udp q0: b.example.com. A
          next t=2s
        t=0s <- S1 udp q0: b.example.com. A: ServFail, 0 answers
          -> S2 udp q0: b.example.com. A
          next t=2s
        t=0s <- S2 udp q0: b.example.com. A: ServFail, 0 answers
          => q0 Failed Server(ServFail)
          next none
        t=0s query q1 a.example.com. A
          -> S1 udp q1: a.example.com. A
          next t=2s
        t=2s timeout
          -> S2 udp q1: a.example.com. A
          next t=4s
        t=2s <- S2 udp q1: a.example.com. A: NXDomain, 0 answers, SOA 300
          => q1 Response a.example.com. A: NXDomain, 0 answers, SOA 300
          next none
        t=2s query q2 a.example.com. A
          => q2 Response a.example.com. A: NXDomain, 0 answers, SOA 300, no EDNS
          next none
        t=2s query q3 b.example.com. A
          => q3 Failed Server(ServFail)
          next none
        t=2s flush
          next none
        t=2s query q4 a.example.com. A
          -> S1 udp q4: a.example.com. A
          next t=4s
        t=2s query q5 b.example.com. A
          -> S1 udp q5: b.example.com. A
          next t=4s
        ");
    }

    #[test]
    fn failure_memory_is_capped_at_five_minutes() {
        let mut config = config();
        config.failure_memory = Duration::MAX;
        let mut trace = Trace::new(Resolver::new(config));
        trace.query("a.example.", RecordType::A);
        trace.timeout();
        let sent = trace.last();
        trace.answer(&sent, &reply(&sent));
        trace.at(Duration::from_secs(301));
        trace.query("b.example.", RecordType::A);
        trace.at(Duration::from_secs(302));
        trace.query("c.example.", RecordType::A);

        assert_snapshot!(trace, @"
        t=0s query q0 a.example. A
          -> S1 udp q0: a.example. A
          next t=2s
        t=2s timeout
          -> S2 udp q0: a.example. A
          next t=4s
        t=2s <- S2 udp q0: a.example. A: NoError, 1 answer
          => q0 Response a.example. A: NoError, 1 answer
          next none
        t=301s query q1 b.example. A
          -> S2 udp q1: b.example. A
          next t=303s
        t=302s query q2 c.example. A
          -> S1 udp q2: c.example. A
          next t=303s
        ");
    }
}
