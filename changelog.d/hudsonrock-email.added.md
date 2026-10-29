- The keyless `hudsonrock` (Hudson Rock Cavalier) indicator source now answers for an email
  selector as well as a domain, so `email ADDRESS`, email scans and `/api/lookup` run it through
  the shared indicator registry — the single worst keyless breach-coverage gap. One GET to the
  public `search-by-email` endpoint: an address with no infection answers `200` with an empty
  `stealers` list (a clean zero), a `404` is a failed lookup never a zero, and an empty selector
  asks nothing. Only non-credential breach metadata is kept — the number of infostealer records
  naming the address, the distinct stealer families, the first and last compromise dates, and the
  corporate/user service counts — tagged into the existing `breach` correlator family. The stolen
  credentials, logins, machine name and host address in each record are never deserialized and
  never stored, so no secret leaves the boundary.
