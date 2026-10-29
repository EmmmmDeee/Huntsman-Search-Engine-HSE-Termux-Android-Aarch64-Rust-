- `username HANDLE` now runs a keyless `lobsters` leg (also in username scans and the module
  catalogue), restoring a dropped legacy source and wiring a new `lobsters` producer into the
  correlator's `forum` family beside `hacker_news` and `reddit_user`. It reads a Lobsters account
  from the site's public per-user JSON (`GET /~{username}.json`). The account is confirmed only
  when the returned `username` is the queried handle (Lobsters usernames are case-insensitive, so
  the match ignores case); a `404` read as a plain upstream 4xx is a clean zero, a challenge page
  at that status is a wall not a zero, a payload with no username is schema drift, and a different
  username is semantic drift. It keeps the confirmed `Username`, its public `lobste.rs/~` profile
  `Url`, and its karma, join date, any admin/moderator role and the decoded `about` bio as verbatim
  evidence. The GitHub handle the account self-declares is surfaced as a cross-platform `Username`
  lead the relation layer ties to the `github_user` cohort — a candidate to review, never a
  confirmed link.
