- `domain` and `recon dns` ask for the zone's SOA record. The domain lookup keeps its primary name
  server (as a host, like an NS record), its serial and its responsible mailbox (RFC 1035's RNAME
  read as an address). The mailbox becomes an e-mail entity only when it sits in the looked-up
  domain or below it; a DNS host's `hostmaster@` mailbox, which is on every zone the
  host serves, stays recorded on the domain and never links those zones.
