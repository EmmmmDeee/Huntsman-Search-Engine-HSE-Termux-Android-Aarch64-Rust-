- The Radar tab reads the cells Android reports (**Read cells**, `GET /api/radar/cells`, as
  `radar cells` reads them, each cell with its codes offering **Investigate** into a prefilled
  `cell:` network scan) and logs a track sweep (**Log a sweep**, `POST /api/radar/track`, the
  cached Wi-Fi scan placed at the registered cell, into the same log `radar track` keeps) and
  shows the followers and recurring devices the log holds. Both routes take exactly the Wi-Fi
  radar route's guards (same origin, the lookup header, one method, no parameters, no body, one
  request at a time) and refuse where no adapter is installed. `radar track` and the page record
  through one library path, so the log is one history however a sweep was taken.
