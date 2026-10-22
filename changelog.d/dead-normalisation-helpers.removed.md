- The `signals` module, `spf::Member`, `spf::members`, `SpfRecord::lists_ip`,
  `DmarcRecord::report_addresses` and `tlsrpt::report_hosts`, none of which had a caller outside
  its own file and tests. `signals::fingerprint` printed a key's first and last characters, and the
  module's surname and SIM-anonymity carrier scoring was a weak-correlation inference nothing
  used. The tag reader SPF and DMARC share now lives in `value_syntax`, and TLS-RPT reads its
  `mailto:` report addresses with DMARC's list reader, so the two records agree on what a mailbox
  is; neither parser's output changes.
- `validation`'s six IP classifiers (`is_non_routable_ip`, `is_bogus_ip`, `is_cdn_edge_ip`,
  `untrusted_ip_geo_reason` and two private helpers) and `recon`'s `ReconFinding`, `host_key`, sort
  helpers and `build_host_lookup_request`, which nothing called. The classifiers' IPv6 rules
  disagreed with `egress`, the check a fetch is held to, and the ipinfo and Netlas anycast flags
  are what mark an anycast edge; `egress`'s tests now also refuse the reserved addresses the
  deleted classifier test asserted. `recon` keeps `ReconTargetKind`.
- `hibp::key::ApiKey::redact_in`, `textnorm::mask_secret`, which showed a secret's first and last
  four characters, and `hibp::key::REDACTED`.
