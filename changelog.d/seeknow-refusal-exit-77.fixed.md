- `seeknow search` now exits 77 (a request refused before it was sent) instead of 69 (no usable
  response) when the egress policy or request guard refuses the SeekNow request before anything
  leaves the host, matching the exit code the README already documents for a refusal. A SeekNow
  request that reaches the service and then fails still exits 69, and the `dehashed` command's exit
  codes are unchanged.
