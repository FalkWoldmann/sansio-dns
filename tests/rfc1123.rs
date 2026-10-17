//! RFC 1123, Requirements for Internet Hosts -- Application and Support.
//! <https://rfc-annotations.research.icann.org/rfc1123.html>

use std::num::NonZeroUsize;

use crate::common::*;
use hickory_proto::rr::RecordType;
use insta::assert_snapshot;
use sansio_dns::{Config, Resolver};

/// §6.1.3.3 (5): retries back off exponentially, and without measured round
/// trip times the first wait is no less than five seconds.
mod section_6_1_3_3 {
    use super::*;

    /// `Config::new`'s defaults: five seconds on each server, then ten.
    #[test]
    fn default_waits_five_seconds_then_backs_off() {
        let mut trace = Trace::new(Resolver::new(Config::new(S1, [S2])));
        trace.query("example.com.", RecordType::A);

        trace.timeouts();

        assert_snapshot!(trace, @"
        t=0s query q0 example.com. A
          -> S1 udp q0: example.com. A
          next t=5s
        t=5s timeout
          -> S2 udp q0: example.com. A
          next t=10s
        t=10s timeout
          -> S1 udp q0: example.com. A
          next t=20s
        t=20s timeout
          -> S2 udp q0: example.com. A
          next t=30s
        t=30s timeout
          => q0 Failed Timeout
          next none
        ");
    }

    /// With one server, every attempt is a new round: each waits twice as
    /// long as the one before.
    #[test]
    fn one_server_doubles_every_attempt() {
        let mut config = Config::new(S1, []);
        config.attempts = NonZeroUsize::new(3).unwrap();
        let mut trace = Trace::new(Resolver::new(config));
        trace.query("example.com.", RecordType::A);

        trace.timeouts();

        assert_snapshot!(trace, @"
        t=0s query q0 example.com. A
          -> S1 udp q0: example.com. A
          next t=5s
        t=5s timeout
          -> S1 udp q0: example.com. A
          next t=15s
        t=15s timeout
          -> S1 udp q0: example.com. A
          next t=35s
        t=35s timeout
          => q0 Failed Timeout
          next none
        ");
    }
}
