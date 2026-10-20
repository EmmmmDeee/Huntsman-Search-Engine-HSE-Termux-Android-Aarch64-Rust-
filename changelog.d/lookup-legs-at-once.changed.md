- An email, username or name lookup no longer waits for each of its sources in turn. The four
  keyed breach legs (HIBP, stolen.tax, OathNet and DeHashed) run at the same time, and an email
  or username lookup's own sources, `SeekNow` and those breach legs run at the same time too, as
  do a name's people sources and `SeekNow`. A lookup now takes as long as its slowest source:
  with every request taking 400 ms, the four breach legs answer in 1.2 s, the time stolen.tax's
  three requests take, where they took 2.4 s. The report is the same as before, its entities and
  outcomes in the same order. This is the same for `email`, `username`, `people`, `exposure`,
  `scan`, `scans run`, New Scan and `/api/lookup`, which all run the one lookup path. Each source
  runs on a thread of its own with the 4 MiB stack a lookup gets in `serve`; a source whose
  thread cannot be started runs after the others instead.
