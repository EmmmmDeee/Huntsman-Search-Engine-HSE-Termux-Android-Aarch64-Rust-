- The ICIJ Offshore Leaks and FBI-notice collectors no longer read a capped or partly unreadable
  answer as a clean negative. An ICIJ result with nodes beyond the cap or nodes that could not be
  read, and an FBI search whose reported `total` exceeds the notices this one page fetched, now
  make an unmatched result `inconclusive` rather than a `valid_zero`, and a match reports the
  shortfall (how many results named other people and how many were never fetched) in its outcome
  detail. Before, a subject could sit in the results a cap or an unreadable row hid while the
  collector reported a clean zero or a success that read as the whole corpus.
