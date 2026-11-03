- The ASIC Connect director leg of a `people` scan now records what Connect actually answers:
  its JavaScript search landing page (an Oracle ADF form whose register search runs only in a
  browser session), as an `interaction_drift` outcome naming the cause, instead of an
  `inconclusive` "neither records nor an empty marker" that read as a transient retry on every
  scan. No evidence changes — the leg never produced a record through a `GET` — but the Sources
  panel, the coverage line and `scans show` now say why, and the stale "403 WAF since
  2026-08-04" note in the module is replaced by the observed behaviour.
