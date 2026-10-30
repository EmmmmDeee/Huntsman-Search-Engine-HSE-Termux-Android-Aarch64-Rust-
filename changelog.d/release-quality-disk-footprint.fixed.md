- Bound ephemeral Rust test debug artifacts and disable incremental compilation in
  release acceptance jobs, preserving the full MSRV and stable verification gates.
  Record free disk before and after host acceptance so runner-capacity failures
  remain distinguishable from application regressions.
