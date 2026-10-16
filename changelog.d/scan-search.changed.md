- A scan's own search runs on the server's matcher, the same one `scans search` uses, instead of
  the page's: a `/regex/` is read as Python's `re` reads it, as Spiderfoot's search does, and runs
  in time linear in each value whatever the pattern.
