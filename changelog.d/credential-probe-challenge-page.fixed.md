- `credential-status --probe` and `doctor --probe` no longer call a key rejected or valid when
  the provider's edge answers with a challenge page instead of the provider. HIBP behind
  Cloudflare serving its "Just a moment..." interstitial with a 403 printed `probe=rejected`
  for HIBP, and `doctor --probe` failed with the advice to replace a key that was never
  checked; the same page served with a 200 printed `probe=valid`. A challenge page at any
  status now prints `probe=indeterminate`, so `doctor --probe` neither lists the provider as
  rejected nor counts it as answering valid. A 429 is still `probe=rate_limited`.
