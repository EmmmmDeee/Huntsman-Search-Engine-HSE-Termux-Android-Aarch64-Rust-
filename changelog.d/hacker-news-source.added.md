- `username HANDLE` now runs a keyless `hacker_news` leg (also in username scans and the module
  catalogue), restoring a dropped legacy source and wiring the previously dangling `hacker_news`
  reference in the correlator's `forum` family. It reads a Hacker News account from the official
  public Firebase API (`GET /v0/user/{id}.json`). The account is confirmed only when the returned
  `id` is exactly the queried handle. Because Hacker News ids are case-sensitive, CLI, scan and
  HTTP routing preserve the operator's original case for this source; the other username sources
  continue to use canonical selectors. The exact-echo check rejects any mismatched `id` as
  semantic drift, and a payload with no id is schema
  drift, and the API's literal `null` (a 200, not a 404) is a clean zero. It keeps the confirmed `Username`, its public `news.ycombinator.com`
  profile `Url`, and its karma, creation time and verbatim decoded `about` bio as evidence; each
  `http(s)` link self-published in the bio becomes a candidate `Url` with its non-platform host a
  `Domain` pivot. A self-declared bio link is a lead to review, never proof of who controls the
  account.
