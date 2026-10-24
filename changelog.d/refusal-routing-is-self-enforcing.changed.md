- The refusal-routing contract is now self-enforcing. Two architecture-boundary tests
  (`tests/architecture_boundaries.rs`) hold every lookup that ends from its rows — `ip`, `netblock`,
  `asn`, `domain`, `email`, `username`, `exposure`, `network` and the indicator legs below them — to
  reading how far its sources got from the rows they recorded: none may name a typed refusal
  (`LegError::Refused`/`Transport`) or read `is_transport_failure` at the call site, and none may
  keep a `refused`/`unanswered`/`no_response`/`network` reason side channel of type `Option<String>`
  beside those rows. The one authority is each row's kind, read by `source_outcome::SourceReach`.
- `indicator_legs::Legs` drops its `network` side channel (the last front-end stopped reading it):
  each failed leg's row carries its own cause, read like any other.
- The README exit-code sentence and the eight front-end module docs name the lookups that end from
  their rows (exit 77 refused before sending, exit 69 no usable response), and no longer list a
  redirect target among the refusal causes — a received redirect that cannot be followed is the
  3xx answer, not a request refused before sending.
