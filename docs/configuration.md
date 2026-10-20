# System configuration and name handling

How `Config::from_resolv_conf`, the hosts file, search domains and the locally answered
names behave, in detail, and where that differs from glibc and musl. The README's
[Configuration](../README.md#configuration) section has the short version.

## Name servers

`Config::new(first, more)` takes the servers in the order they are asked. A server at the
unspecified address, `0.0.0.0` or `::`, stands for the local host, as it does for glibc on
Linux: no datagram may be sent to the unspecified address (RFC 1122 §3.2.1.3, RFC 4291
§2.5.2), and the replies would come from the loopback address and fail the source check
(RFC 5452 §9.1), so it is replaced by `127.0.0.1` or `::1`, keeping the port.

## resolv.conf

`Config::from_resolv_conf(&bytes)` reads the text of a `resolv.conf` (you read the file)
the way glibc's `res_init` does, skipping lines it can't use instead of failing. A keyword
counts only at the start of a line, so indented lines are ignored. It takes:

- the first three `nameserver` lines, IPv4 ones in any form `inet_aton` reads (`127.1` is
  127.0.0.1), with `0.0.0.0` and `::` asking the local host;
- `search` or `domain`, whichever comes last;
- the options `ndots`, `timeout`, `attempts`, `no-aaaa` and `no-tld-query` (also spelled
  `no_tld_query`), each known by how it starts, with its number read as `strtol` reads it.

Unlike glibc, it takes at most 3 attempts per server instead of 5, since RFC 9520 §3.1
allows no more than three sends of a query to one server over one transport, reads `#` and
`;` as starting a comment anywhere on a line, and takes CRLF line ends. Other options
(`rotate`, `use-vc`, `sortlist`, …) are ignored.

`Config::from_resolv_conf_with_env(&bytes, &env)` also applies what glibc reads from the
environment and the host: `LOCALDOMAIN` replaces the search domains, `RES_OPTIONS` adds
options after the file's, and without a search list or `LOCALDOMAIN`, the host name's domain
(the part after its first dot) is the search domain. `sansio-dns-tokio`'s
`from_system_conf` fills these in from `/etc/resolv.conf`, the environment and `uname`.
Without `/etc/resolv.conf`, the local host is asked, as glibc does.

## Hosts file

`Config::hosts = Hosts::parse(&bytes)` adds static entries from a hosts file (you read the
file). Listed names are answered locally for A and AAAA, with the addresses of that family,
before any DNS query, as glibc's `hosts: files dns` does. A name listed with only an IPv4
address gets an empty AAAA answer, not a DNS query, as glibc does. Only the name as given is
looked up in the hosts file, never a search candidate.

## Search domains

With search domains, a name without a trailing dot is tried with each of them: before the
name as given if it has fewer than `ndots` dots, after it otherwise. `options no-tld-query`
(`Config::tld_query = false`) leaves out a name of one label as given, so with search
domains `db` never asks for a top-level domain. Without search domains every name is used
as given.

For `Resolver::query` the search moves on after NXDOMAIN and after NODATA (the name exists
without records of the type and class asked for at the end of its CNAME chain), until a
candidate has data (RFC 1123 §6.1.4.3, RFC 2308 §2.2). When it runs out, the outcome is
the first NODATA, else the last NXDOMAIN. A failure on a candidate, such as SERVFAIL or
REFUSED, ends the search with that error, as musl does, so that a temporary failure for
the name meant doesn't turn into an answer for another name.

`Resolver::lookup_ip` asks each candidate for both families and moves on when neither has
an address, as glibc's `getaddrinfo` does, so its addresses are always those of one name.

Where glibc differs:

- glibc moves on after NODATA only when the answer section is empty, so it stops at a
  CNAME whose target has no data.
- glibc goes on to the search domains after any failure on the name as given when that
  comes first; among the search domains it moves on only after SERVFAIL, and after another
  failure it stops and still tries the name as given if that comes last, unless no server
  could be reached at all.

A candidate with a cached NXDOMAIN or NODATA is passed over without a query, and one with
a cached failure ends the search; see the crate docs on the cache.

## Names answered without a query

Some names never reach the network. They are checked in this order:

1. Names under `localhost.` get the loopback addresses for A and AAAA and an empty answer
   for other types; names under `invalid.` and `onion.` get NXDOMAIN (RFC 6761 §6.3, §6.4,
   RFC 7686 §2). This holds whatever the hosts file says, and relative ones aren't searched.
2. Names listed in `Config::hosts`, for A and AAAA.
3. Names under `local.` and the link-local reverse zones (`254.169.in-addr.arpa.`, and
   `8.e.f` to `b.e.f.ip6.arpa.`) belong to multicast DNS (RFC 6762 §3, §4), so they get
   NXDOMAIN without a query (§22.1), unless the name servers serve them: names under a
   search domain that is itself under one of these zones, such as Kubernetes'
   `cluster.local` or an Active Directory `corp.local`, or under a zone in
   `Config::unicast_local_zones`, go to the servers. The rule applies to each search
   candidate (RFC 6762 §3), so with search domain `cluster.local` the relative `db.local`
   is sent as `db.local.cluster.local`, and a relative name gets NXDOMAIN at once only when
   none of its candidates is sent. Multicast DNS itself is up to the caller.

Other special-use names, such as `test.`, `example.`, `home.arpa.` and `alt.`, are sent
like any other (RFC 6761 §6.2, §6.5, RFC 8375 §4, RFC 9476 §3.2).

## Address families

`Config::ip_strategy` picks which families `Resolver::lookup_ip` asks for and which come
first: `Ipv6First` (the default), `Ipv4First`, `Ipv4Only` or `Ipv6Only`. `options no-aaaa`
in a `resolv.conf` sets `Ipv4Only`.

IPv6 comes first even on a host without a global IPv6 address, such as a container with
only a ULA, where `getaddrinfo` puts IPv4 first (RFC 6724 §6). A client there that tries
the addresses one at a time waits on each IPv6 one. Race the connections instead (Happy
Eyeballs, RFC 8305), as hyper does, or use `IpStrategy::Ipv4First` on such hosts. Within a
family, addresses keep the server's order; they aren't sorted by the host's own addresses
(RFC 6724 §6).

## Host names in the Tokio driver

`sansio_dns_tokio::Resolver::lookup_ip` takes a host string and turns it into a name:

- An IP address is returned as it is.
- A non-ASCII name is converted as a whole by UTS 46 non-transitional processing, as
  browsers do: `bücher。example` asks for `xn--bcher-kva.example`. A U-label with `--` in
  its third and fourth positions is rejected (RFC 5891 §5.4). UTS 46 accepts some code
  points that IDNA2008 marks DISALLOWED, such as `☃`, which are looked up as browsers look
  them up.
- An ASCII name is used as given, in its case (RFC 4343 §4), so `my_host.example` and
  `r3---sn-abc.example` work. Each `xn--` label must be a valid A-label.
- Rejected with `Error::InvalidName` (RFC 1123 §2.1): an empty name, one to four dotted
  numbers that aren't an IP address (`127.1`, `01.2.3.4`, `0x7f.0.0.1`, `1.2.3.256`), an
  absolute name whose last label is all digits, a name with a `\`, and IPv6 addresses with
  a zone (`fe80::1%eth0`). Relative names like `host.123` are looked up, since a search
  domain may complete them.
