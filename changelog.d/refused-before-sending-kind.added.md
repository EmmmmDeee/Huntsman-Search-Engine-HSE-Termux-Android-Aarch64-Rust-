- Add the source outcome kind `refused_before_sending`: Huntsman's egress policy or request
  guard refused a request, so the source was never asked. It is never counted as an answer or as
  a transport failure, its recommended action is `investigate`, a scan's uncertainty register
  lists it under its own category, and the web UI shows it as a warning. Today no row carries
  this label, so no output changes; it appears in lookup reports, saved scans and JSON once the
  sources record it. A build that reads unknown kinds as `inconclusive` but predates
  this kind reads this label as `inconclusive`; a build without that fallback cannot read a saved
  scan that holds it.
