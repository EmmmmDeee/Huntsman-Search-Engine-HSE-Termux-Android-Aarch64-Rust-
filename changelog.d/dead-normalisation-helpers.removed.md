- The `signals` module, `spf::Member`, `spf::members`, `SpfRecord::lists_ip`,
  `DmarcRecord::report_addresses` and `tlsrpt::report_hosts`, none of which had a caller outside
  its own file and tests. `signals::fingerprint` printed a key's first and last characters, and the
  module's surname and SIM-anonymity carrier scoring was a weak-correlation inference nothing
  used. The tag reader SPF and DMARC share now lives in `value_syntax`, and TLS-RPT reads its
  `mailto:` report addresses with DMARC's list reader, so the two records agree on what a mailbox
  is; neither parser's output changes.
