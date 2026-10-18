//! `Config::from_resolv_conf`: settings as glibc reads them from resolv.conf,
//! and `Config::from_resolv_conf_with_env`: what glibc also takes from the
//! environment and the host name.

use std::net::SocketAddr;
use std::time::{Duration, Instant};

use crate::common::*;
use hickory_proto::rr::Name;
use rstest::rstest;
use sansio_dns::{Config, IpStrategy, ResolvEnv, Resolver};
use std::assert_matches;

/// Let one query time out on every attempt; return where each attempt went
/// and how long the first one waited.
fn attempts(conf: impl AsRef<[u8]>) -> (Vec<SocketAddr>, Duration) {
    let mut resolver = Resolver::new(Config::from_resolv_conf(conf.as_ref()));
    let start_time = Instant::now();
    let first = start(&mut resolver, start_time);
    let wait = resolver.poll_timeout().unwrap() - start_time;
    let mut destinations = vec![first.destination];
    while let Some(deadline) = resolver.poll_timeout() {
        resolver.handle_timeout(deadline);
        destinations.extend(resolver.poll_transmit().map(|t| t.destination));
    }
    (destinations, wait)
}

fn addr(s: &str) -> SocketAddr {
    s.parse().unwrap()
}

#[test]
fn nameservers_in_order_two_attempts_each_by_default() {
    let (sent, wait) = attempts(
        "nameserver 192.0.2.53\n\
         nameserver 2001:db8::53\n\
         nameserver fe80::1%eth0\n\
         nameserver fe80::2%3\n",
    );
    let servers = [
        addr("192.0.2.53:53"),
        addr("[2001:db8::53]:53"),
        addr("[fe80::2%3]:53"),
    ];
    assert_eq!(sent, [servers, servers].concat(), "named scope skipped");
    assert_eq!(wait, Duration::from_secs(5));
}

/// glibc takes up to 5 attempts per server, but RFC 9520 §3.1 allows no
/// more than three sends of a query to one server over one transport. The
/// sends alone don't show the clamp, since the resolver stops at three
/// datagrams per server anyway; the attempts it leaves would go over TCP.
#[rstest]
#[case::as_given("options timeout:7 attempts:2", 7, 2)]
#[case::three("options timeout:7 attempts:3", 7, 3)]
#[case::at_most_three_attempts("options timeout:7 attempts:5", 7, 3)]
#[case::capped("options timeout:99 attempts:9", 30, 3)]
fn timeout_and_attempts(#[case] options: &str, #[case] secs: u64, #[case] tries: usize) {
    let conf = format!("nameserver 192.0.2.53\nnameserver 192.0.2.54\n{options}\n");
    assert_eq!(
        Config::from_resolv_conf(conf.as_bytes()).attempts.get(),
        2 * tries,
        "attempts per server times servers"
    );
    let (sent, wait) = attempts(conf);
    assert_eq!(sent.len(), 2 * tries);
    assert_eq!(wait, Duration::from_secs(secs));
}

/// glibc's MAXNS: a fourth server is never asked.
#[test]
fn at_most_three_nameservers() {
    let (sent, _) = attempts(
        "nameserver 192.0.2.1\n\
         nameserver 192.0.2.2\n\
         nameserver 192.0.2.3\n\
         nameserver 192.0.2.4\n",
    );
    let servers = [
        addr("192.0.2.1:53"),
        addr("192.0.2.2:53"),
        addr("192.0.2.3:53"),
    ];
    assert_eq!(sent, [servers, servers].concat());
}

/// Lines and options it can't use are skipped, as glibc skips them, and
/// the rest still applies.
#[test]
fn unusable_lines_are_skipped() {
    let (sent, wait) = attempts(
        b"nameserver not-an-address\n\
         nameserver\n\
         nameserver 192.0.2.53 extra words\n\
         unknown-directive value\n\
         options unknown-option timeout:7 ndots\n\
         \xff\xfe not UTF-8\n\
         nameserver 192.0.2.54\n",
    );
    assert_eq!(
        sent,
        [
            addr("192.0.2.53:53"),
            addr("192.0.2.54:53"),
            addr("192.0.2.53:53"),
            addr("192.0.2.54:53"),
        ]
    );
    assert_eq!(wait, Duration::from_secs(7));
}

#[rstest]
#[case::default("", IpStrategy::Ipv6First)]
#[case::no_aaaa("options no-aaaa\n", IpStrategy::Ipv4Only)]
fn no_aaaa_asks_only_for_ipv4(#[case] options: &str, #[case] expected: IpStrategy) {
    let config = Config::from_resolv_conf(format!("nameserver 192.0.2.53\n{options}").as_bytes());
    assert_eq!(config.ip_strategy, expected);
}

#[test]
fn no_nameserver_asks_the_local_host() {
    let (sent, _) = attempts("# empty\n");
    assert_eq!(sent, [addr("127.0.0.1:53"), addr("127.0.0.1:53")]);
}

/// The unspecified address is the local host, as for glibc, whose queries
/// to it Linux sends to the loopback address. The replies come from there
/// and pass the source check (RFC 5452 §9.1).
#[rstest]
#[case::v4("0.0.0.0", "127.0.0.1:53")]
#[case::v4_one_number("0", "127.0.0.1:53")]
#[case::v6("::", "[::1]:53")]
#[case::v6_long("0:0:0:0:0:0:0:0", "[::1]:53")]
fn unspecified_nameserver_is_the_local_host(#[case] address: &str, #[case] expected: &str) {
    let conf = format!("nameserver {address}\n");
    let mut resolver = Resolver::new(Config::from_resolv_conf(conf.as_bytes()));
    let now = Instant::now();

    let sent = start(&mut resolver, now);
    resolver.handle_datagram(udp(&sent), addr(expected), &encode(&reply(&sent)), now);

    assert_eq!(sent.destination, addr(expected));
    assert!(is_response(resolver.poll_event()));
}

/// `Config::new` does the same, keeping the port.
#[rstest]
#[case::v4("0.0.0.0:5353", "127.0.0.1:5353")]
#[case::v6("[::]:5353", "[::1]:5353")]
#[case::not_unspecified("192.0.2.1:5353", "192.0.2.1:5353")]
fn unspecified_server_is_the_local_host(#[case] server: &str, #[case] expected: &str) {
    let mut resolver = Resolver::new(Config::new(addr(server), []));
    assert_eq!(
        start(&mut resolver, Instant::now()).destination,
        addr(expected)
    );
}

/// glibc takes a keyword only at the start of a line, followed by a space
/// or a tab: an indented line is ignored, whatever it says.
#[test]
fn indented_lines_are_ignored() {
    let conf = concat!(
        "  nameserver 192.0.2.9\n",
        "\tnameserver 192.0.2.8\n",
        "nameserver\t192.0.2.53\n",
        "  search lead.example\n",
        "\tdomain lead.example\n",
        " options ndots:4 no-aaaa\n",
    );

    let config = Config::from_resolv_conf(conf.as_bytes());
    let (sent, _) = attempts(conf);

    assert_eq!(sent, [addr("192.0.2.53:53"), addr("192.0.2.53:53")]);
    assert!(config.search.is_empty());
    assert_eq!(config.ndots, 1);
    assert_eq!(config.ip_strategy, IpStrategy::Ipv6First);
}

/// A keyword needs a space or a tab after it.
#[test]
fn keyword_without_a_blank_is_ignored() {
    let (sent, _) = attempts("nameserver:192.0.2.9\nnameserver 192.0.2.53\n");
    assert_eq!(sent, [addr("192.0.2.53:53"), addr("192.0.2.53:53")]);
}

/// glibc reads each line as a C string, so a NUL byte ends it.
#[test]
fn nul_byte_ends_a_line() {
    let conf = concat!(
        "nameserver 192.0.2.9\0junk\n",
        "search a.example\0b.example c.example\n",
        "options ndots:3\0x no-aaaa\n",
        "\0nameserver 192.0.2.8\n",
    );

    let config = Config::from_resolv_conf(conf.as_bytes());
    let (sent, _) = attempts(conf);

    assert_eq!(sent, [addr("192.0.2.9:53"), addr("192.0.2.9:53")]);
    let search: Vec<String> = config.search.iter().map(Name::to_ascii).collect();
    assert_eq!(search, ["a.example."]);
    assert_eq!(config.ndots, 3);
    assert_eq!(config.ip_strategy, IpStrategy::Ipv6First);
}

/// glibc reads a `nameserver` address with `inet_aton` first, which takes
/// one to four numbers, each decimal, octal or hexadecimal, the last one
/// filling the bytes the others leave; then as IPv6, strictly.
#[rstest]
#[case::two_numbers("127.1", "127.0.0.1:53")]
#[case::three_numbers("1.2.3", "1.2.0.3:53")]
#[case::one_number("16843009", "1.1.1.1:53")]
#[case::last_number_of_three_bytes("1.65793", "1.1.1.1:53")]
#[case::hexadecimal("0x7f.1", "127.0.0.1:53")]
#[case::hexadecimal_upper_case("0X7F.0.0.0Xa", "127.0.0.10:53")]
#[case::octal("0177.0.0.010", "127.0.0.8:53")]
#[case::ipv4_mapped("::ffff:192.0.2.1", "[::ffff:192.0.2.1]:53")]
#[case::numeric_scope("fe80::1%2", "[fe80::1%2]:53")]
fn nameserver_in_any_form_inet_aton_reads(#[case] address: &str, #[case] expected: &str) {
    let (sent, _) = attempts(format!("nameserver {address}\nnameserver 192.0.2.54\n"));
    let servers = [addr(expected), addr("192.0.2.54:53")];
    assert_eq!(sent, [servers, servers].concat());
}

/// Anything else is skipped, and the next line is used.
#[rstest]
#[case::not_octal("08.0.0.1")]
#[case::number_above_255("256.1")]
#[case::last_number_too_large("1.2.65536")]
#[case::more_than_32_bits("4294967296")]
#[case::five_numbers("1.2.3.4.5")]
#[case::trailing_dot("1.2.3.4.")]
#[case::empty_number("1..2")]
#[case::hexadecimal_without_digits("0x")]
#[case::trailing_garbage("1.2.3.4x")]
#[case::sign("+1.2.3.4")]
#[case::host_name("dns.example")]
#[case::short_ipv6_tail("::1.2")]
#[case::scope_on_ipv4("192.0.2.1%2")]
fn garbage_nameserver_is_skipped(#[case] address: &str) {
    let (sent, _) = attempts(format!("nameserver {address}\nnameserver 192.0.2.54\n"));
    assert_eq!(sent, [addr("192.0.2.54:53"), addr("192.0.2.54:53")]);
}

/// Unlike glibc, which maps an interface name to its index with a system
/// call and keeps a server whose scope it can't read with scope 0, the
/// resolver skips a server whose scope isn't a number.
#[rstest]
#[case::named_scope("fe80::1%eth0")]
#[case::empty_scope("fe80::1%")]
#[case::scope_with_a_sign("fe80::1%+2")]
fn scope_that_isnt_a_number_is_skipped(#[case] address: &str) {
    let (sent, _) = attempts(format!("nameserver {address}\nnameserver 192.0.2.54\n"));
    assert_eq!(sent, [addr("192.0.2.54:53"), addr("192.0.2.54:53")]);
}

/// glibc's `res_setoptions` knows an option by how it starts, spells
/// `no-tld-query` with dashes or underscores, turns a flag off again with
/// `-` in front, and reads a number with `strtol`.
mod options {
    use super::*;

    fn config(options: &str) -> Config {
        Config::from_resolv_conf(format!("nameserver 192.0.2.53\n{options}\n").as_bytes())
    }

    #[rstest]
    #[case::default("", true)]
    #[case::dashes("options no-tld-query", false)]
    #[case::underscores("options no_tld_query", false)]
    #[case::longer("options no-tld-query-please", false)]
    #[case::turned_off_again("options no_tld_query -no-tld-query", true)]
    #[case::later_line("options no-tld-query\noptions -no_tld_query", true)]
    #[case::shorter("options no-tld", true)]
    fn no_tld_query(#[case] options: &str, #[case] tld_query: bool) {
        assert_eq!(config(options).tld_query, tld_query);
    }

    #[rstest]
    #[case::dashes("options no-aaaa", IpStrategy::Ipv4Only)]
    #[case::longer("options no-aaaa-please", IpStrategy::Ipv4Only)]
    #[case::turned_off_again("options no-aaaa -no-aaaa", IpStrategy::Ipv6First)]
    #[case::underscores_unknown("options no_aaaa", IpStrategy::Ipv6First)]
    fn no_aaaa(#[case] options: &str, #[case] strategy: IpStrategy) {
        assert_eq!(config(options).ip_strategy, strategy);
    }

    #[rstest]
    #[case::plain("options ndots:3", 3)]
    #[case::space_after_the_colon("options ndots: 3", 3)]
    #[case::trailing_garbage("options ndots:3x", 3)]
    #[case::no_number("options ndots:x", 0)]
    #[case::empty("options ndots:", 0)]
    // glibc stores it in four bits, so -2 becomes 14 there.
    #[case::negative("options ndots:-2", 0)]
    #[case::at_most_15("options ndots:99", 15)]
    #[case::huge("options ndots:99999999999999999999999", 15)]
    #[case::no_colon("options ndots", 1)]
    #[case::last_wins("options ndots:2 ndots:4", 4)]
    #[case::crlf("options ndots:3\r", 3)]
    fn ndots(#[case] options: &str, #[case] expected: u8) {
        assert_eq!(config(options).ndots, expected);
    }

    #[rstest]
    #[case::trailing_garbage("options timeout:7s attempts:3x", 7, 3)]
    #[case::zero("options timeout:0 attempts:0", 1, 1)]
    #[case::negative("options timeout:-1 attempts:-1", 1, 1)]
    fn timeout_and_attempts(#[case] options: &str, #[case] secs: u64, #[case] per_server: usize) {
        let config = config(options);
        assert_eq!(config.timeout, Duration::from_secs(secs));
        assert_eq!(config.attempts.get(), per_server);
    }
}

/// `LOCALDOMAIN`, `RES_OPTIONS` and the host name, which glibc's `res_init`
/// reads besides the file.
mod environment {
    use super::*;

    fn env(
        localdomain: Option<&str>,
        res_options: Option<&str>,
        hostname: Option<&str>,
    ) -> ResolvEnv {
        let mut env = ResolvEnv::default();
        env.localdomain = localdomain.map(|value| value.as_bytes().to_vec());
        env.res_options = res_options.map(|value| value.as_bytes().to_vec());
        env.hostname = hostname.map(|value| value.as_bytes().to_vec());
        env
    }

    fn search(conf: &str, env: &ResolvEnv) -> Vec<String> {
        Config::from_resolv_conf_with_env(conf.as_bytes(), env)
            .search
            .iter()
            .map(Name::to_ascii)
            .collect()
    }

    /// `LOCALDOMAIN` replaces `search` and `domain`, even when empty;
    /// without it and them, the host name's domain is the search domain.
    #[rstest]
    #[case::localdomain_over_search(
        "search a.example\n",
        Some("b.example c.example"),
        Some("host.d.example"),
        &["b.example.", "c.example."]
    )]
    #[case::localdomain_over_domain("domain a.example\n", Some("b.example"), None, &["b.example."])]
    #[case::localdomain_blanks_and_newline(
        "",
        Some("\tb.example \t c.example\nd.example"),
        None,
        &["b.example.", "c.example."]
    )]
    #[case::empty_localdomain("search a.example\n", Some(""), Some("host.d.example"), &[])]
    #[case::hostname("nameserver 192.0.2.53\n", None, Some("host.d.example"), &["d.example."])]
    #[case::hostname_without_a_dot("", None, Some("host"), &[])]
    #[case::hostname_ending_in_a_dot("", None, Some("host."), &[])]
    #[case::search_over_hostname("search a.example\n", None, Some("host.d.example"), &["a.example."])]
    #[case::domain_over_hostname("domain a.example\n", None, Some("host.d.example"), &["a.example."])]
    #[case::empty_search_line_ignored(
        "search a.example\nsearch \n",
        None,
        Some("host.d.example"),
        &["a.example."]
    )]
    #[case::only_an_empty_search_line("search\t\n", None, Some("host.d.example"), &["d.example."])]
    #[case::localdomain_ends_at_nul("", Some("b.example\0c.example"), None, &["b.example."])]
    #[case::hostname_ends_at_nul("", None, Some("host.d.example\0.e"), &["d.example."])]
    fn search_domains(
        #[case] conf: &str,
        #[case] localdomain: Option<&str>,
        #[case] hostname: Option<&str>,
        #[case] expected: &[&str],
    ) {
        assert_eq!(search(conf, &env(localdomain, None, hostname)), expected);
    }

    /// `RES_OPTIONS` reads as an `options` line, after the file's.
    #[test]
    fn res_options_override_the_file() {
        let conf = "nameserver 192.0.2.53\noptions ndots:2 no-aaaa timeout:3\n";
        let env = env(None, Some("ndots:4 -no-aaaa no_tld_query"), None);

        let config = Config::from_resolv_conf_with_env(conf.as_bytes(), &env);

        assert_eq!(config.ndots, 4);
        assert_eq!(config.ip_strategy, IpStrategy::Ipv6First);
        assert!(!config.tld_query);
        assert_eq!(config.timeout, Duration::from_secs(3));
    }

    /// `RES_OPTIONS` ends at its first NUL byte, as a C string does.
    #[test]
    fn res_options_end_at_nul() {
        let env = env(None, Some("ndots:3\0 no-aaaa"), None);

        let config = Config::from_resolv_conf_with_env(b"nameserver 192.0.2.53\n", &env);

        assert_eq!(config.ndots, 3);
        assert_eq!(config.ip_strategy, IpStrategy::Ipv6First);
    }

    /// Without a file, the environment still applies.
    #[test]
    fn environment_without_a_file() {
        let env = env(
            Some("corp.example"),
            Some("ndots:3"),
            Some("host.d.example"),
        );

        let config = Config::from_resolv_conf_with_env(b"", &env);

        assert_eq!(search("", &env), ["corp.example."]);
        assert_eq!(config.ndots, 3);
    }

    /// `from_resolv_conf` is the file alone.
    #[test]
    fn from_resolv_conf_takes_no_host_name() {
        assert!(
            Config::from_resolv_conf(b"nameserver 192.0.2.53\n")
                .search
                .is_empty()
        );
        assert_eq!(
            search("", &env(None, None, Some("host.d.example"))),
            ["d.example."]
        );
    }
}

/// `search` and `ndots`, following glibc's `res_search` order and stopping
/// as soon as a candidate has data of the type asked for.
mod search {
    use super::*;
    use hickory_proto::op::ResponseCode;
    use hickory_proto::rr::{Name, RecordType};
    use sansio_dns::Event;

    const CONF: &str = "nameserver 192.0.2.53\n\
                        search corp.example lab.example\n\
                        options ndots:2\n";

    /// Query `name`, answer every candidate with `code`, and return the
    /// names asked for, in order, plus the final event.
    fn tried(conf: &str, name: &str, code: ResponseCode) -> (Vec<String>, Option<Event>) {
        let mut resolver = Resolver::new(Config::from_resolv_conf(conf.as_bytes()));
        let now = Instant::now();
        resolver
            .query(Name::from_ascii(name).unwrap(), RecordType::A, now)
            .unwrap();
        let mut asked = Vec::new();
        while let Some(t) = resolver.poll_transmit() {
            let request = decode(&t);
            asked.push(request.queries[0].name().to_ascii());
            resolver.handle_datagram(
                udp(&t),
                t.destination,
                &encode(&with_code(reply(&t), code)),
                now,
            );
        }
        (asked, resolver.poll_event())
    }

    #[rstest]
    #[case::fewer_dots_search_first(
        "a.b",
        &["a.b.corp.example.", "a.b.lab.example.", "a.b."]
    )]
    #[case::enough_dots_as_given_first(
        "a.b.c",
        &["a.b.c.", "a.b.c.corp.example.", "a.b.c.lab.example."]
    )]
    #[case::trailing_dot_only_as_given("db.", &["db."])]
    fn candidates_in_order(#[case] name: &str, #[case] expected: &[&str]) {
        let (asked, event) = tried(CONF, name, ResponseCode::NXDomain);
        assert_eq!(asked, expected);
        let Some(Event::Response { response, .. }) = event else {
            panic!("expected the last NXDOMAIN");
        };
        assert_eq!(response.metadata.response_code, ResponseCode::NXDomain);
    }

    /// The default `ndots` is 1, as glibc's.
    #[rstest]
    #[case::no_dots("db", &["db.a.example.", "db.b.example.", "db."])]
    #[case::one_dot("db.x", &["db.x.", "db.x.a.example.", "db.x.b.example."])]
    fn default_ndots_is_one(#[case] name: &str, #[case] expected: &[&str]) {
        let conf = "nameserver 192.0.2.53\nsearch a.example b.example\n";
        assert_eq!(Config::from_resolv_conf(conf.as_bytes()).ndots, 1);

        let (asked, _) = tried(conf, name, ResponseCode::NXDomain);

        assert_eq!(asked, expected);
    }

    /// `options no-tld-query`, as in glibc: with search domains, a name of
    /// one label isn't tried as given, which would ask for a top-level
    /// domain (a weaker form of RFC 1123 §6.1.4.3 (b)). Names with a dot
    /// still are, and without search domains every name is.
    #[rstest]
    #[case::one_label("search a.example b.example\n", "db", &["db.a.example.", "db.b.example."])]
    #[case::one_dot("search a.example\n", "db.x", &["db.x.", "db.x.a.example."])]
    #[case::absolute("search a.example\n", "db.", &["db."])]
    #[case::no_search_domains("", "db", &["db."])]
    fn no_tld_query_keeps_single_labels_from_the_name_servers(
        #[case] search: &str,
        #[case] name: &str,
        #[case] expected: &[&str],
    ) {
        let conf = format!("nameserver 192.0.2.53\n{search}options no-tld-query\n");
        assert!(!Config::from_resolv_conf(conf.as_bytes()).tld_query);

        let (asked, _) = tried(&conf, name, ResponseCode::NXDomain);

        assert_eq!(asked, expected);
    }

    /// Unless every candidate is left out: then the name gets NXDOMAIN at
    /// once.
    #[test]
    fn no_tld_query_without_a_candidate_left() {
        let conf = "nameserver 192.0.2.53\nsearch local\noptions no-tld-query\n";
        let (asked, event) = tried(conf, "printer", ResponseCode::NoError);
        assert!(asked.is_empty());
        let Some(Event::Response { response, .. }) = event else {
            panic!("expected a local answer");
        };
        assert_eq!(response.metadata.response_code, ResponseCode::NXDomain);
    }

    #[test]
    fn tld_query_is_on_by_default() {
        let conf = "nameserver 192.0.2.53\nsearch a.example\n";
        assert!(Config::from_resolv_conf(conf.as_bytes()).tld_query);
        assert!(Config::new(addr("192.0.2.53:53"), []).tld_query);
    }

    /// A record of the type asked for ends the search. NODATA doesn't; see
    /// `rfc1123::section_6_1_4_3`.
    #[test]
    fn existing_name_ends_the_search() {
        let (asked, event) = tried(CONF, "db", ResponseCode::NoError);
        assert_eq!(asked, ["db.corp.example."]);
        assert_matches!(event, Some(Event::Response { .. }));
    }

    #[test]
    fn special_use_search_domain_is_skipped() {
        let conf = "nameserver 192.0.2.53\nsearch invalid corp.example\n";
        let (asked, _) = tried(conf, "printer", ResponseCode::NXDomain);
        assert_eq!(asked, ["printer.corp.example.", "printer."]);
    }

    /// A Kubernetes pod's resolv.conf: short service names resolve through
    /// the `cluster.local` search domains.
    #[test]
    fn kubernetes_service_name_is_found() {
        let conf = "nameserver 10.96.0.10\n\
                    search ns.svc.cluster.local svc.cluster.local cluster.local\n\
                    options ndots:5\n";
        let (asked, event) = tried(conf, "myservice", ResponseCode::NoError);
        assert_eq!(asked, ["myservice.ns.svc.cluster.local."]);
        assert_matches!(event, Some(Event::Response { .. }));
    }

    /// Service `db` in a namespace named `local`: every candidate under
    /// `cluster.local` is tried, and only `db.local.` itself, link-local
    /// (RFC 6762 §22.1), is left out.
    #[test]
    fn kubernetes_namespace_named_local_is_searched() {
        let conf = "nameserver 10.96.0.10\n\
                    search ns.svc.cluster.local svc.cluster.local cluster.local\n\
                    options ndots:5\n";
        let (asked, event) = tried(conf, "db.local", ResponseCode::NXDomain);
        assert_eq!(
            asked,
            [
                "db.local.ns.svc.cluster.local.",
                "db.local.svc.cluster.local.",
                "db.local.cluster.local.",
            ]
        );
        assert_matches!(event, Some(Event::Response { .. }));
    }

    #[test]
    fn localhost_is_not_searched() {
        let (asked, event) = tried(CONF, "localhost", ResponseCode::NXDomain);
        assert!(asked.is_empty());
        assert_matches!(event, Some(Event::Response { .. }));
    }
}
