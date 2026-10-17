//! RFC 2181, Clarifications to the DNS Specification.
//! <https://rfc-annotations.research.icann.org/rfc2181.html>

use std::time::Instant;

use crate::common::*;
use hickory_proto::rr::rdata::A;
use hickory_proto::rr::{RData, Record, RecordType};
use insta::assert_snapshot;
use rstest::rstest;
use sansio_dns::{Event, Resolver};

/// §8: a TTL is at most 2^31 - 1, and one received with the most
/// significant bit set is treated as zero.
mod section_8 {
    use super::*;

    #[rstest]
    fn ttl_with_the_top_bit_set_is_zero(mut resolver: Resolver) {
        let now = Instant::now();
        let sent = start(&mut resolver, now);
        let mut response = reply(&sent);
        let name = response.queries[0].name().clone();
        let record = |ttl| Record::from_rdata(name.clone(), ttl, RData::A(A(ADDR)));
        response.answers = vec![record(0x8000_0000), record(0x7fff_ffff)];
        response.authorities = vec![record(0x8000_0001)];
        response.additionals = vec![record(u32::MAX)];

        resolver.handle_datagram(udp(&sent), S1, &encode(&response), now);

        let Some(Event::Response { response, .. }) = resolver.poll_event() else {
            panic!("expected a response");
        };
        let ttls = |records: &[Record]| records.iter().map(|r| r.ttl).collect::<Vec<_>>();
        assert_eq!(ttls(&response.answers), [0, 0x7fff_ffff]);
        assert_eq!(ttls(&response.authorities), [0]);
        assert_eq!(ttls(&response.additionals), [0]);
    }
}

/// §9: a reply with TC set is ignored and the query sent again over TCP,
/// even when the server cut the datagram off mid-record, so it doesn't
/// parse.
mod section_9 {
    use super::*;

    #[rstest]
    fn cut_off_truncated_reply_switches_to_tcp(mut trace: Trace) {
        trace.query("example.com.", RecordType::A);
        let sent = trace.last();
        let mut response = truncated(reply(&sent));
        response.edns = None;

        trace.answer_bytes(&sent, &cut(&encode(&response)), "cut short, TC");

        assert_eq!(decode(&trace.last()).metadata.id, decode(&sent).metadata.id);
        assert_snapshot!(trace, @"
        t=0s query q0 example.com. A
          -> S1 udp q0: example.com. A
          next t=2s
        t=0s <- S1 udp q0: cut short, TC
          -> S1 connect c0: example.com. A
          next t=2s
        ");
    }
}
