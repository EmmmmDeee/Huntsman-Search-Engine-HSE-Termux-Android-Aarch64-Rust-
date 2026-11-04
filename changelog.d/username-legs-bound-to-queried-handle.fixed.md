- The GitHub, Mastodon, Bluesky and Keybase username legs now report an account only when the
  answer names the queried handle, as the GitLab, Chess.com, Lichess and the other username legs
  already did. An answer for another login, username or handle (including a Mastodon remote
  account for a local handle, and a Bluesky profile whose handle could not be verified,
  `handle.invalid`) is `semantic_drift` with no entities, instead of that account's profile,
  links and names being listed as the result for the handle that was asked about. Case is
  ignored, as each service ignores it.
