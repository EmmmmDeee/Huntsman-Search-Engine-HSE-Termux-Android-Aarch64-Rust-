- An `asn AS-NUMBER` lookup (and `scan -k asn`, the Web UI AS scan and saved AS scans) now also
  queries the keyless **PeeringDB** registry beside the AS's RDAP registration and RIPEstat routing,
  so an AS scan is no longer limited to registry and BGP data. PeeringDB adds the operator's
  self-published profile — its organisation name (a `Organisation` candidate, never a confirmed
  identity), official website (a `Domain` pivot), peering policy, traffic level, IRR AS-SET and
  prefix counts — and its public Internet-exchange presence, each peering address an `IpAddress`
  pivot that carries the exchange name and port speed and flows straight into an IP lookup. The AS
  profile folds onto the same `Asn` entity the RDAP and RIPEstat legs emit, corroborating the holder
  across registries. Evidence integrity is fail-closed: a network is accepted only when the `net`
  record's `asn` is exactly the requested number (a mismatch is schema drift, never a fabricated
  entity), a 404 or empty result is a clean zero, a malformed peering address is skipped rather than
  minted, and every published field is kept verbatim. This adds the new keyless `peeringdb` source
  client, wired into the AS module list, run by `asn_cli` beside the existing legs, with its
  saved-ledger provenance attributed to `src/peeringdb.rs`. The network's facilities (`netfac`) and
  public contacts (`poc`) over the same record are a planned compounding follow-up.
