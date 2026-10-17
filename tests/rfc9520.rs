//! RFC 9520, Negative Caching of DNS Resolution Failures.
//! <https://rfc-annotations.research.icann.org/rfc9520.html>

use std::num::NonZeroUsize;
use std::time::Duration;

use crate::common::*;
use hickory_proto::op::ResponseCode;
use hickory_proto::rr::RecordType;
use insta::assert_snapshot;
use rstest::rstest;
use sansio_dns::{Config, Resolver};

/// §3.1: "A resolver MUST NOT retry a given query to a server address over
/// a given DNS transport more than twice (i.e., three queries in total)".
/// Every send of a search candidate counts, free ones included; a send that
/// would be the fourth goes to the next server with room as a new attempt,
/// and the query fails when no server has room, or starts over if it took
/// over from a cancelled query after joining late. TCP is a transport of
/// its own.
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

    /// An heir that joined after the search candidate started hasn't had
    /// attempts of its own: with no room left, it starts over rather than
    /// fail at once, as a late joiner does when the first query runs out
    /// (`Resolver::query`). Three successive hand-overs with one server.
    #[test]
    fn late_heir_without_room_starts_over() {
        let mut trace = one_server(2);
        let q0 = trace.query("example.com.", RecordType::A);
        trace.timeout();
        trace.at(Duration::from_secs(3));
        let q1 = trace.query("example.com.", RecordType::A);
        trace.cancel(q0);
        trace.at(Duration::from_secs(4));
        trace.query("example.com.", RecordType::A);
        trace.cancel(q1);

        trace.timeouts();

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
          -> S1 udp q2: example.com. A
          next t=6s
        t=6s timeout
          -> S1 udp q2: example.com. A
          next t=10s
        t=10s timeout
          => q2 Failed Timeout
          next none
        ");
    }
}

/// §3.2: "resolution failures MUST NOT be cached for longer than 5
/// minutes" (as RFC 2308 §7.2 caps a dead server indication). A server that
/// failed to answer goes after the others for at most that long, whatever
/// `Config::failure_memory` says.
mod section_3_2 {
    use super::*;

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
