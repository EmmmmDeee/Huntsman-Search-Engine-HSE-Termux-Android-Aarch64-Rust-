- One rule now says when a provider's 404 is an error rather than "nothing known":
  `api_leg::Answer::body_or_unexpected` turns `Answer::NotFound` into
  `LegError::Unexpected(404)` and hands back the 2xx body otherwise. The thirty hand-written
  `match` arms that each spelled that rule out — in AbuseIPDB, Cert Spotter, Exa, HackerTarget,
  Hudson Rock, Hunter, IPinfo, IPQS, ISC, Kickbox, Maltiverse, Netlas, Numverify, OpenCelliD, OTX,
  PhishStats, RIPEstat, Robtex, StopForumSpam, ThreatFox, URLhaus, urlscan and Whoxy — now call
  it, so a provider cannot drift into treating an endpoint failure as a clean zero. Behaviour and
  the `unexpected` outcome kind are unchanged; the shared rule has its own unit test.
