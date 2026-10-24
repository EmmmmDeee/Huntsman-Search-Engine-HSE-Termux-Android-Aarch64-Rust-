- The `ip` lookup (and the ip arm of `scan`) now decides how it ends from its source rows through
  `source_outcome::SourceReach`, not from a side channel that only Mnemonic and the keyed legs
  wrote. The exit codes are unchanged in principle — a request refused before sending is 77, no
  usable response is 69 — but two things change for a lookup no source answered:
  - A module-selected ip lookup whose one chosen leg was refused before sending
    (`scans run ADDR -m MODULE`, `sf -s ADDR -m MODULE`) now exits 77 with that leg's reason,
    where before a refused keyed or indicator leg exited 69 with no reason.
  - The reason now names the first row in the order the legs ran (reverse DNS, then RDAP, then
    Mnemonic, then the rest), not Mnemonic's. For a fully refused lookup the reason is the PTR
    row, e.g. `dnsresolve: no resolver answered the PTR query: refused: …`; for one that only got
    no response it is the first transport-failure row, e.g. `rdap: no route`.
- `mnemonic::Leg` drops its `error` field: a failed Mnemonic leg's row already carries the kind
  and reason, which the lookup reads like any other row. No output changes from this.
