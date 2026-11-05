- A scan's intelligence report now lists `temporal_conflicts`: dates one source gave the same
  entity in an impossible order, such as a first sighting after the last, a registration after
  its expiry, or an incorporation after its dissolution. It appears in the analysis that `plan`,
  `serve`, `correlate` and the web UI's scan API return. Each conflict is a lead to check, not a
  finding, and the field is left out when there are none.
