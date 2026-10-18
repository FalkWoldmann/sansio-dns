//! `Resolver`'s `Debug` output: the settings and counts, not internal state.

use std::time::Instant;

use crate::common::*;

#[test]
fn resolver_shows_counts_not_internals() {
    let mut resolver = resolver();
    start(&mut resolver, Instant::now());
    let debug = format!("{resolver:?}");
    assert!(debug.starts_with("Resolver { config: Config {"), "{debug}");
    assert!(
        debug.ends_with("queries: 1, connections: 0, transmits: 0, events: 0, .. }"),
        "{debug}"
    );
    assert!(!debug.contains("Pending"), "{debug}");
}

/// With TLS, `Config` and `Resolver` show each server's authentication name
/// and the ALPN protocols, not the rustls configuration.
#[cfg(feature = "tls")]
#[test]
fn tls_settings_show_names_and_alpn() {
    use std::net::SocketAddr;
    use std::sync::Arc;

    use rustls::pki_types::ServerName;
    use rustls::{ClientConfig, RootCertStore};
    use sansio_dns::{Config, Resolver};

    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let mut client = ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_root_certificates(RootCertStore::empty())
        .with_no_client_auth();
    client.alpn_protocols = vec![b"dot".to_vec()];
    let t1: SocketAddr = "192.0.2.1:853".parse().unwrap();
    let t2: SocketAddr = "192.0.2.2:853".parse().unwrap();
    let names = [
        (t1, ServerName::try_from("dns.example").unwrap()),
        (t2, ServerName::try_from("other.example").unwrap()),
        (t2, ServerName::try_from("192.0.2.2").unwrap()),
    ];
    let config = Config::new(t1, [t2])
        .with_tls_names(Arc::new(client), names)
        .unwrap();

    let debug = format!("{config:?}");
    let settings = r#"tls: Some(Settings { names: {192.0.2.1:853: "dns.example", 192.0.2.2:853: "192.0.2.2"}, alpn: ["dot"], .. }) }"#;
    assert!(debug.ends_with(settings), "{debug}");
    let debug = format!("{:?}", Resolver::new(config));
    assert!(debug.len() < 600, "{} characters: {debug}", debug.len());
    for internal in [
        "ClientConfig",
        "provider",
        "verifier",
        "Resumption",
        "cipher",
    ] {
        assert!(!debug.contains(internal), "{internal} in {debug}");
    }
}
