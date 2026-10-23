- The keyed indicator legs `ip`, `domain`, `email`, `phone` and `network cell:` run (Shodan,
  Pulsedive, Netlas, OTX, urlscan.io and the rest) are asked at once instead of one after another,
  so a lookup with many keys set takes as long as its slowest provider: fifteen legs that each
  take 200 ms answer in about 200 ms rather than three seconds. Each provider has its own host
  and its own pacing, the scan's chosen modules still decide which legs run, and the report is
  unchanged: answers are folded in the legs' fixed order.
