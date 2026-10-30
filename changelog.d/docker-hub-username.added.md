- A `username HANDLE` lookup (and `scan -k username`, the Web UI username scan and saved username
  scans) now also queries the keyless **Docker Hub** registry, beside the GitHub, GitLab, Bluesky,
  Keybase, Wikipedia, Mastodon, TikTok, npm, crates.io, Hacker News and Lobsters legs, so a username
  scan reaches a major developer-identity platform. A handle resolves to a public Docker Hub account
  — confirmed only when the returned `username` (a user) or `orgname` (an organisation) is exactly
  the queried handle, never a near-match — surfacing the account as a candidate `Username`, its
  self-declared display name as a `Person` (a user with a person-shaped name) or the account as an
  `Organisation` (`type` is `Organization`), its self-declared website as a `Url` and its non-forge
  host as a `Domain` pivot, with its location, company, join date, verified-publisher badge and
  published image repository count kept verbatim as evidence. A published name or website is a lead
  to review, never proof of who controls the account.
- Keyless and fail-closed, reusing the shared `fetch` boundary and mirroring `crates_io`: the account
  is the single confirming gate — a 404 is a clean zero, a returned handle that is not the queried one
  is semantic drift, and a response carrying neither a `username` nor an `orgname` is schema drift.
  Docker Hub serves an organisation on `/v2/orgs/`; the `/v2/users/` path may redirect there, so a
  3xx is followed to the organisation endpoint this client builds (same host), never by chasing an
  arbitrary `Location`. `gravatar_email` is published blank, so no email is ever minted; the
  repository listing is enrichment, so an unreadable one loses only the count, never the account.
- This adds the new keyless `docker_hub_user` source client, wired into the Username scan module
  list and run by `username_cli` beside the existing public-profile legs.
