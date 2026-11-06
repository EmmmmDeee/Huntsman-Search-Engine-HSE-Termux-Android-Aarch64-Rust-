- `credential-status --probe` no longer spends a DeHashed search credit. It used to run a real
  search, which costs one credit, and it read an account out of credits as a rejected key.
  - **The new probe.** It asks `/v2/search-password` about the SHA-256 of a fixed probe string,
    never a password. DeHashed documents that endpoint as needing neither credits nor a
    subscription.
  - **What proves the key.** Only that endpoint's own answer, `results_found`.
