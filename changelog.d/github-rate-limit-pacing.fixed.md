- An exhausted GitHub rate limit is now read as one wherever it arrives: `fetch` classifies a
  403 or 429 carrying `retry-after`, or `x-ratelimit-remaining: 0`, as `rate_limited` and keeps
  the pause GitHub asks for (`retry-after` seconds, else until `x-ratelimit-reset`). The GitHub
  profile and repository lookups (`username`, scans and `/api/lookup`) are now paced by the
  shared per-host breaker, so after one exhausted quota no further request goes to
  `api.github.com` until the reset, as GitHub's guidelines require; a held lookup says it was
  not sent and is never a "no such user". Before, the 403 was a refusal to `fetch`, the breaker
  counted it as a success, the reset time was dropped and every later lookup was still sent.
