//! RFC 6891, Extension Mechanisms for DNS (EDNS(0)).
//! <https://rfc-annotations.research.icann.org/rfc6891.html>

use std::time::Instant;

use crate::common::*;
use hickory_proto::op::ResponseCode;
use hickory_proto::rr::RecordType;
use insta::assert_snapshot;
use rstest::rstest;
use sansio_dns::Resolver;

/// §6.1.1 / §6.2.3: the query carries exactly one OPT record advertising a
/// payload size of at least 512 octets that avoids fragmentation.
mod section_6_2_3 {
    use super::*;

    #[rstest]
    fn query_advertises_a_safe_payload_size(mut resolver: Resolver) {
        let sent = decode(&start(&mut resolver, Instant::now()));
        let edns = sent.edns.expect("query carries OPT");
        assert_eq!(edns.max_payload(), 1232);
        assert_eq!(edns.version(), 0);
    }
}

/// §7 / §6.2.2: a server that doesn't implement EDNS answers FORMERR without
/// an OPT record; the requestor may retry without EDNS. FORMERR *with* OPT
/// means the server does speak EDNS, so it's an ordinary server error.
mod section_7 {
    use super::*;

    #[rstest]
    fn formerr_without_opt_retries_same_server_without_edns(mut trace: Trace) {
        trace.query("example.com.", RecordType::A);
        let sent = trace.last();
        let mut response = with_code(reply(&sent), ResponseCode::FormErr);
        response.edns = None;

        trace.answer(&sent, &response);
        let retry = trace.last();
        trace.answer(&retry, &reply(&retry));

        assert_eq!(decode(&retry).metadata.id, decode(&sent).metadata.id);
        assert_snapshot!(trace, @"
        t=0s query q0 example.com. A
          -> S1 udp q0: example.com. A
          next t=2s
        t=0s <- S1 udp q0: example.com. A: FormErr, 0 answers, no EDNS
          -> S1 udp q0: example.com. A, no EDNS
          next t=2s
        t=0s <- S1 udp q0: example.com. A: NoError, 1 answer, no EDNS
          => q0 Response example.com. A: NoError, 1 answer, no EDNS
          next none
        ");
    }

    #[rstest]
    fn formerr_with_opt_fails_over(mut trace: Trace) {
        trace.query("example.com.", RecordType::A);
        let sent = trace.last();

        trace.answer(&sent, &with_code(reply(&sent), ResponseCode::FormErr));

        assert_snapshot!(trace, @"
        t=0s query q0 example.com. A
          -> S1 udp q0: example.com. A
          next t=2s
        t=0s <- S1 udp q0: example.com. A: FormErr, 0 answers
          -> S2 udp q0: example.com. A
          next t=2s
        ");
    }

    /// The downgrade happens once; FORMERR to the plain query is final for
    /// that server, so a broken server can't keep the query alive forever.
    #[rstest]
    fn edns_is_dropped_only_once(mut trace: Trace) {
        trace.query("example.com.", RecordType::A);

        for _ in 0..3 {
            let sent = trace.last();
            let mut response = with_code(reply(&sent), ResponseCode::FormErr);
            response.edns = None;
            trace.answer(&sent, &response);
        }

        assert_snapshot!(trace, @"
        t=0s query q0 example.com. A
          -> S1 udp q0: example.com. A
          next t=2s
        t=0s <- S1 udp q0: example.com. A: FormErr, 0 answers, no EDNS
          -> S1 udp q0: example.com. A, no EDNS
          next t=2s
        t=0s <- S1 udp q0: example.com. A: FormErr, 0 answers, no EDNS
          -> S2 udp q0: example.com. A, no EDNS
          next t=2s
        t=0s <- S2 udp q0: example.com. A: FormErr, 0 answers, no EDNS
          => q0 Failed Server(FormErr)
          next none
        ");
    }
}
