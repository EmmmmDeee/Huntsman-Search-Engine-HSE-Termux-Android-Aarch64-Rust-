- The `netblock` and `asn` lookups (and their `scan` arms) now decide how they end from their
  source rows through `source_outcome::SourceReach`, like `ip`, instead of a `network` side
  channel that only captured a transport failure. When no source answered:
  - A RIPEstat call (or, for netblock, RDAP or the reverse-DNS sweep) refused before sending now
    makes the lookup a refusal — exit 77 with that row's reason — where before only a transport
    failure stopped it and a refusal fell through to exit 69 with no reason.
  - A RIPEstat call that reached the service and gave no response is now "no usable response" —
    exit 69, `no source answered for netblock …` / `no source answered for AS… : …` naming the
    first row — where before an unanswered RIPEstat call exited 77.
- `asn_cli::routing_entities` no longer returns the transport failure, and `netblock_cli` drops
  its `network` local: the one RIPEstat row carries the reason, read like any other row.
