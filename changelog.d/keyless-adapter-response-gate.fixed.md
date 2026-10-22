- With `HUNTSMAN_GITHUB_TOKEN` set, a `401` from GitHub's profile lookup is recorded as a rejected
  token (`auth_rejected`), not a missing one (`auth_required`): the lookup classified the response
  a second time and lost what `fetch` knew about the token it had sent.
- A keyless source's answer that is not the JSON document it expects is still `parser_drift`, but
  its diagnostic names only the decode error's category and position. It kept serde's message,
  which quotes the body, so a saved ledger could hold text from the provider's answer. This
  applies to GitHub, Bluesky, Gravatar, Keybase, Duolingo, the App Store search and Wikipedia.
- A rate limit or other refusal from a keyless source keeps the pause the provider asked for in
  the outcome's `retry_after_secs`. This applies to GitHub, Bluesky, Gravatar, Keybase, Duolingo,
  the App Store search, Wikipedia and the keys.openpgp.org key index.
