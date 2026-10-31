- A link's host is the entity it is. GitHub, crates.io, Docker Hub, npm and Hacker News typed every
  dotted link host as a domain, so a blog or homepage on an address (`http://45.131.135.227/`) left
  a "domain" `45.131.135.227` that a crawl could neither look up nor route, and Wikidata, SEC EDGAR,
  ACNC and PeeringDB dropped an official website on an address altogether. One rule now types a
  link's host for all nine: an address (IPv4 or IPv6, public or not) is an `IpAddress` in its one
  written form, which a crawl follows to the `ip` lookup when it is public, and a name the domain
  rule accepts is a `Domain`; the link itself is kept as its URL either way. A URL on an address is
  hosted on that address in the relation graph, as one on a name is on the name, and an address is
  read before a phone number when a selector is canonicalised.
