- AU-109 `shared_registrant` no longer names two domains as one registrant's when all they share
  is a privacy service. Two domains under registries that publish registrant contacts, such as
  `alpha-shop.org` and `beta-shop.info` both registered through "Domains By Proxy, LLC", each got
  a `RegisteredBy` relation from their RDAP record to the proxy's organisation, so
  `scan --recurse`, web UI scans and stored-scan correlation reported them as sharing one
  registrant/operator. A registrant or admin organisation, name or mailbox that names a privacy
  service or redaction notice, or a mailbox at a registrar's or host's own mail domain (such as
  `alpha-shop-org@domainsbyproxy.com`), no longer gives a `RegisteredBy` relation; the value
  stays in the domain's evidence and the proxy stays an entity. Whoxy lookups already worked
  this way.
