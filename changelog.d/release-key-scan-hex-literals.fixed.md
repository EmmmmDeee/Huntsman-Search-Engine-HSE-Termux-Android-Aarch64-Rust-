- The aarch64 release binary passes its key scan again. `credential-status --probe` sent
  DeHashed a fixed SHA-256 written into the source. The pre-release key scan refused the
  binary, since 32 hex characters in a row look like an HIBP key.
  - **The probe.** It now works the digest out when it is sent (`ProbeBody::Sha256Hex`), so the
    request is unchanged.
  - **`doctor`.** It derives the `CACHEDIR.TAG` signature from its definition, the MD5 of
    `.IsCacheDirectory`, instead of holding it as a literal. The literal had passed only because
    the compiler folded the comparison into instructions.
  - **A new guard.** `no_production_literal_holds_a_key_shaped_hex_run` now refuses, at `cargo
    test`, any production literal the scan would refuse. That covers raw and byte strings, and
    the scanner itself is unchanged.
