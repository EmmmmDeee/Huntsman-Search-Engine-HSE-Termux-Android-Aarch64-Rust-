- An email or username lookup (and a saved scan of one) now reports a keyed breach leg that was
  refused or got no response as that leg's own row, and saves it to the ledger. When every
  configured breach leg failed that way, the lookup dropped all their rows and printed one
  `exposure=unavailable` line instead, so the report and its ledger did not show which configured
  source had been asked and failed. The `exposure` lookup itself still ends with exit 77 or 69
  when no breach source answered.
