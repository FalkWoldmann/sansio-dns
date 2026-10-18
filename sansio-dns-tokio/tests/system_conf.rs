//! `Resolver::from_system_conf`: what it takes from the environment besides
//! `/etc/resolv.conf`, as glibc's `res_init` does. The environment is set
//! for a child process, which runs `print_system_conf`.

use std::process::Command;

use sansio_dns_tokio::Resolver;

/// Run by `environment_applies` in a child process with the environment
/// set: prints the resolver, settings included.
#[test]
#[ignore = "run by environment_applies, in a child process with the environment set"]
fn print_system_conf() {
    println!("{:?}", Resolver::from_system_conf().unwrap());
}

/// `LOCALDOMAIN` replaces whatever search list the host has, and
/// `RES_OPTIONS` comes after the file's options, so the outcome doesn't
/// depend on the host's `/etc/resolv.conf`.
#[test]
fn environment_applies() {
    let output = Command::new(std::env::current_exe().unwrap())
        .args(["system_conf::print_system_conf", "--exact", "--ignored"])
        .args(["--nocapture", "--test-threads=1"])
        .env("LOCALDOMAIN", "corp.example\tlab.example")
        .env("RES_OPTIONS", "ndots:4 no_tld_query")
        .output()
        .unwrap();

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(output.status.success(), "{stdout}");
    let search = r#"search: [Name("corp.example."), Name("lab.example.")]"#;
    assert!(stdout.contains(search), "{stdout}");
    assert!(stdout.contains("ndots: 4,"), "{stdout}");
    assert!(stdout.contains("tld_query: false,"), "{stdout}");
}
