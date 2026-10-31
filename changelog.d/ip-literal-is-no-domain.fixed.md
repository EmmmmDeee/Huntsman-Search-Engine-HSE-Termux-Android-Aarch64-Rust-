- `scan` no longer sends an address that is not public to the domain sources. Routing judged an
  address by the public-only rule the `ip` lookup refuses by, so `scan 10.0.0.5` (or
  `192.168.1.20`, `127.0.0.1`) fell through to the domain rule, which took a dotted quad for a
  domain name: the keyless domain lookup then sent 46 requests to 22 hosts (crt.sh, Cert Spotter,
  the DNS and filtering resolvers, RDAP, the Wayback Machine and Common Crawl indexes, OTX,
  urlscan.io and the rest), 38 of them naming the private address. An address or address block is
  now routed to `ip` or `netblock` whether or not it is public, so a non-public one is refused
  before any request (exit 65, and a `400` from the web UI's scan), as `ip 10.0.0.5` always was. A
  name whose last label is all digits is no domain anywhere, as no top-level domain is, so `domain
  10.0.0.5` is refused too, and a crawl does not look up as a domain an address a source recorded
  as a host name.
