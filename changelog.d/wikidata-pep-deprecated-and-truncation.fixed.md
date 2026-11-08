- The Wikidata politically-exposed-person check no longer treats a deprecated classification as
  current: `claim_targets` skips deprecated-rank P31/P279 claims, so a position typed a public
  office only on a deprecated claim does not flag the person. When more than 20 positions (P39) are
  held, every message reports "only 20 of N positions held were checked, incomplete" and keeps the
  total, so a "none" or a count is never read as exhaustive.
