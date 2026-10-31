- The Passive use case (`scans run -u passive`, `sf -u passive`, New Scan's Passive, and the
  continuous collection, which always runs Passive) now asks no keyed breach source: HIBP,
  DeHashed, OathNet, stolen.tax or SeekNow. It is a module set like Footprint and Investigate, so
  every lookup's legs honour it. Before, Passive skipped only the separate breach pass of an email,
  while the email lookup itself, and the username and people lookups, still sent the address,
  handle or name to every keyed breach source with a key set. A continuous collection repeated
  those paid queries on every cycle. A breach (`exposure`) scan under Passive asks nothing, so it
  is refused by name before it is saved, as is running one saved under Passive again: run it under
  another use case. OpenCelliD's access is spelled `operator_key` like every other keyed module's,
  not `keyed`.
