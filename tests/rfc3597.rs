//! RFC 3597, Handling of Unknown DNS Resource Record (RR) Types.
//! <https://rfc-annotations.research.icann.org/rfc3597.html>

use std::time::Instant;

use crate::common::*;
use hickory_proto::rr::rdata::NULL;
use hickory_proto::rr::{Name, RData, Record, RecordType};
use insta::assert_snapshot;
use rstest::rstest;
use sansio_dns::{Event, Resolver};

const PRIVATE: RecordType = RecordType::Unknown(65280);

/// §3: RRs of unknown type are handled transparently, as opaque RDATA.
mod section_3 {
    use super::*;

    #[rstest]
    fn unknown_type_is_answered_as_opaque_data(mut resolver: Resolver) {
        let now = Instant::now();
        let name = Name::from_ascii("example.com.").unwrap();
        resolver.query(name.clone(), PRIVATE, now).unwrap();
        let sent = resolver.poll_transmit().unwrap();
        let mut response = reply(&sent);
        let data = RData::Unknown {
            code: PRIVATE,
            rdata: NULL::with(vec![1, 2, 3]),
        };
        response.answers = vec![Record::from_rdata(name, 300, data.clone())];

        resolver.handle_datagram(udp(&sent), S1, &encode(&response), now);

        let Some(Event::Response { response, .. }) = resolver.poll_event() else {
            panic!("expected a response");
        };
        assert_eq!(response.answers[0].data, data);
    }

    /// hickory rejects a whole message that has a record with empty RDATA
    /// outside an UPDATE, although `\# 0` is valid for an unknown type
    /// (§5). The query can't use the answer, but it moves on to the next
    /// server at once instead of waiting out its deadlines.
    #[rstest]
    fn empty_rdata_moves_on_at_once(mut trace: Trace) {
        trace.query("example.com.", RecordType::A);

        for _ in 0..2 {
            let sent = trace.last();
            let bytes = with_empty_record(&encode(&reply(&sent)));
            trace.answer_bytes(
                &sent,
                &bytes,
                "NoError, 1 answer, TYPE65280 with empty RDATA",
            );
        }

        assert_snapshot!(trace, @r#"
        t=0s query q0 example.com. A
          -> S1 udp q0: example.com. A
          next t=2s
        t=0s <- S1 udp q0: NoError, 1 answer, TYPE65280 with empty RDATA
          -> S2 udp q0: example.com. A
          next t=2s
        t=0s <- S2 udp q0: NoError, 1 answer, TYPE65280 with empty RDATA
          => q0 Failed Malformed("unexpected record with length 0 in non-update message")
          next none
        "#);
    }

    /// `message` with one more additional record: TYPE65280, owned by the
    /// question name, with no RDATA.
    fn with_empty_record(message: &[u8]) -> Vec<u8> {
        let mut bytes = message.to_vec();
        let count = u16::from_be_bytes([bytes[10], bytes[11]]) + 1;
        bytes[10..12].copy_from_slice(&count.to_be_bytes());
        // A pointer to the question name, then type, class IN, TTL and an
        // RDLENGTH of zero.
        bytes.extend([0xc0, 0x0c, 0xff, 0x00, 0, 1, 0, 0, 1, 0x2c, 0, 0]);
        bytes
    }
}
