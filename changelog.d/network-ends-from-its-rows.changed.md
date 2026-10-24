- The `network` lookup (and the network arm of `scan`) now decides how it ends from its source
  rows through `source_outcome::SourceReach`, instead of a side channel only the WiGLE searches
  wrote. The WiGLE behaviour is unchanged — a refused search is still a refusal (exit 77) and one
  that got no response is still "no source answered the network lookup: …" (exit 69) — but a
  `cell:` or `LAT,LON` lookup whose only source is OpenCelliD now ends from OpenCelliD's row too:
  OpenCelliD refused before sending is exit 77, OpenCelliD no response is exit 69, where before
  the lookup printed its rows and exited 0 because only WiGLE could stop it. A source that
  answered with an error still prints, as the network lookup always has.
- `network_cli` drops its private `Unanswered` struct and `wigle_leg`'s `unanswered` parameter
  (and the `#[allow(clippy::too_many_arguments)]` it needed): the WiGLE row carries the reason,
  read like any other row.
