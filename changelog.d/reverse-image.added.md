- Add `reverse-image IMAGE-FILE [--live] [--json]`: an offline exact-file SHA-256
  evidence fingerprint and explicitly opted-in public reverse-image indexes:
  Google Cloud Vision WEB_DETECTION, Lenso duplicate search, and SauceNAO.
  Use Huntsman's guarded Rust HTTP transport, credential store, bounded inputs,
  typed per-provider outcomes and fail-closed response parsing. No new Cargo
  dependencies or runtime LLM. External calls require --live and provider keys;
  no-credential and failed requests are never presented as negative matches.
