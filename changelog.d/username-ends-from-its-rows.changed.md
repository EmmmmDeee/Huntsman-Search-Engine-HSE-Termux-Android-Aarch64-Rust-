- The `username` lookup (and the username arm of `scan`) now decides how it ends from its profile
  source rows through `source_outcome::SourceReach`, like `ip`. When no profile source answered:
  - A profile request refused before sending (the guarded egress dropped it) now makes the lookup
    a refusal — exit 77 with that row's reason, naming the first refused source — where before the
    lookup printed an empty report and exited 0.
  - Every profile source reaching the service and giving no response is now "no usable response" —
    exit 69, `no source answered for …` — where before it printed and exited 0.
  A source that answered, even with an error, still prints, as the lookup always has. The handle's
  own derived variants are not a finding, so they no longer keep a lookup no source answered from
  failing.
- `username_cli::UsernameRun` is now `source_outcome::SourceRun<Report>`, gaining the `Network`
  (refusal) variant the other single-source front-ends already have; `scan`'s username composition
  routes that refusal beside its other legs like any other lookup's.
