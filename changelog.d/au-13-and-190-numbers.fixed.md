- Australian six-digit `13` numbers (such as Telstra's 13 22 00) and `190x` premium numbers are
  now phone numbers everywhere a phone is read: `phone`, `scans run -k phone`, `investigate` and
  the classifier. The AU numbering plan already typed them as local-rate and premium-rate, but
  the canonicaliser refused them first, so they could never be looked up. An E.164 number may now
  hold 8 to 15 digits (`+61132200` has 8); free-text extraction of `+` numbers keeps its own
  10-to-15-digit window. A test now holds the canonicaliser and the plan to the same ranges.
