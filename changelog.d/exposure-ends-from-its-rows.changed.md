- The `exposure` lookup (and the exposure arm of `scan`) now decides how it ends from its breach
  source rows through `source_outcome::SourceReach`, like the other lookups, instead of a private
  `network` side channel that only captured transport failures. When no breach source answered:
  - a source refused before sending (the guarded egress dropped the request) is a refusal (exit
    77) — where before a refused stolen.tax or `OathNet` path printed an empty report and exited 0,
    because only HIBP, `OathNet` or `DeHashed` could write the side channel;
  - a source reached but silent is now "no usable response" (exit 69), `no source answered for …`
    — where before it was a refusal (exit 77).
  A source that answered, even with an error, still prints, as does the seed alone.
- `exposure_cli::ExposureRun` is now `source_outcome::SourceRun<Report>`; `LegRun` drops its
  `network` field and `run_leg`/`hibp_leg`/`oathnet_leg`/`dehashed_leg` drop the `network`
  parameter. Each leg's row carries its own reason, read like any other through `SourceReach::of`.
- HIBP and `DeHashed` gain a `Refused` error for a request the guarded egress dropped before
  sending (previously folded into their transport-error variant), mapping to
  `RefusedBeforeSending` so the lookup refuses (exit 77) rather than reading as a no-response, and
  to `EX_UNAVAILABLE` on the standalone `hibp`/`dehashed` CLIs.
- `fetch` no longer turns a received 3xx whose `Location` cannot be parsed into an http(s) URL into
  an error: like a same-site redirect it could not follow, the 3xx is kept as the answer
  (`RedirectChanged`, with the refused redirect recorded) under every redirect policy. A caller can
  no longer read a request that was sent and answered as "refused before sending / nothing reached
  the network"; `fetch` returns an error only for a request refused before it was sent.
