- Rules around the credential-origin boundary that were written out more than once now have one
  home each. Output is unchanged.
  - `AuthenticationAuthority::configured_slot` builds the `operator configured <slot>` approval
    that the keyed API lookups, the GitHub, OathNet and stolen.tax lookups and the live key
    checks of `credential-status --probe` and `doctor --probe` each wrote out.
  - `CredentialFingerprint::short` is the 12-hex-digit prefix that `keys FILE`,
    `recon stolen-tax`, `fetch --bearer`/`--header` and the fingerprint's debug form print in
    place of the digest, which each sliced out by hand.
  - `KeyPlace::auth_style` gives the request style for a provider key, so a live key check
    places the key as the lookup does.
