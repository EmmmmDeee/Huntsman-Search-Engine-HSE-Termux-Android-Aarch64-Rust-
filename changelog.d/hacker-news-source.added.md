- `username HANDLE` now runs a keyless `hacker_news` leg (also in username scans and the module
  catalogue), restoring a dropped legacy source and wiring the previously dangling `hacker_news`
  reference in the correlator's `forum` family. It reads a Hacker News account from the official
  public Firebase API (`GET /v0/user/{id}.json`). The account is confirmed only when the returned
  `id` is exactly the queried handle. Username selectors reach this leg in the engine's canonical
  lower-case form (as for every username source), so the handle is looked up and confirmed in that
  form; because Hacker News ids are themselves case-sensitive, the exact-echo check rejects any `id`
  the API returns that is not the one queried (semantic drift), a payload with no id is schema
  drift, and the API's literal `null` (a 200, not a 404) is a clean zero. It keeps the confirmed `Username`, its public `news.ycombinator.com`
  profile `Url`, and its karma, creation time and verbatim decoded `about` bio as evidence; each
  `http(s)` link self-published in the bio becomes a candidate `Url` with its non-platform host a
  `Domain` pivot. A self-declared bio link is a lead to review, never proof of who controls the
  account.
