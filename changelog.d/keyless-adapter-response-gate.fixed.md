- With `HUNTSMAN_GITHUB_TOKEN` set, a `401` from GitHub's profile lookup is recorded as a rejected
  token (`auth_rejected`), not a missing one (`auth_required`): the lookup classified the response
  a second time and lost what `fetch` knew about the token it had sent.
- `crypto BITCOIN-ADDRESS` records only a plain `400` or `404` from blockchain.info as a clean
  negative (`valid_zero`). Every `4xx` was one, so a rate limit (`429`), a refusal and a challenge
  page were each saved as evidence the address has no account; they are now `rate_limited`,
  `auth_rejected`, `bot_waf` or `upstream4xx`.
- A challenge page at `400` or `404` from Keybase, or at `404` from Gravatar, GitHub's profile
  lookup or the keys.openpgp.org key index, was recorded as a clean negative (`valid_zero`): the
  status alone decided it. Each is now `bot_waf`; a plain `4xx` at those statuses is still
  `valid_zero`.
- A keyless source's answer that is not the JSON document it expects is still `parser_drift`, but
  its diagnostic names only the decode error's category and position. It kept serde's message,
  which quotes the body, so a saved ledger could hold text from the provider's answer. This
  applies to GitHub, Bluesky, Gravatar, Keybase, Duolingo, the App Store search, Wikipedia,
  blockchain.info and Nominatim.
- A `429` or `503` from a keyless source keeps the pause the provider asked for, in the outcome's
  `retry_after_secs`, when the response carries `Retry-After`; no other status carries one. This
  applies to GitHub, Bluesky, Gravatar, Keybase, Duolingo, the App Store search, Wikipedia,
  blockchain.info and the keys.openpgp.org key index.
