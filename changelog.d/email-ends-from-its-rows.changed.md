- The `email` lookup (and the email arm of `scan`) now decides how it ends from its source rows
  through `source_outcome::SourceReach`, like `ip` and `username`, instead of `Gathered`'s
  `refused`/`unanswered` side channels. A lookup no source answered is still not printed — the
  address's own derivations are not a finding — and it still exits 77 for a source refused before
  sending or 69 for no usable response; the reason is now read from whichever row stopped it rather
  than from a side channel, so an indicator leg (`StopForumSpam`, Kickbox, `XposedOrNot`,
  `IPQualityScore`, Hunter, Whoxy) refused before sending now surfaces its own row as the refusal.
  A lookup with no row at all now says `no source answered for {email}` rather than
  `… : no source ran`.
- `email_cli::EmailRun` is now `source_outcome::SourceRun<Report>`; `Gathered` drops its
  `refused`/`unanswered` fields, and `run_keyed` stops reading `indicator_legs`' `network` side
  channel. Each leg's row carries its own reason, read like any other through `SourceReach::of`.
