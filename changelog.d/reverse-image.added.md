- Add `reverse-image IMAGE-FILE [--live] [--json]`: an offline exact-file SHA-256
  evidence fingerprint and explicitly opted-in public reverse-image indexes:
  Google Cloud Vision WEB_DETECTION, Lenso duplicate search, and SauceNAO.
  Use Huntsman's guarded Rust HTTP transport, credential store, bounded inputs,
  typed per-provider outcomes and fail-closed response parsing. No new Cargo
  dependencies or runtime LLM. External calls require --live and provider keys;
  no-credential and failed requests are never presented as negative matches.

- Connect the protected binary upload pipeline to `POST /api/reverse-image`
  and the **Inspect** Web UI, with an offline default and explicit selection
  of one paid provider per browser search; retain the existing CSP and checks.
  Add bounded symlink-refusing file reads, named-provider CLI selection,
  challenge-page and parser-error rejection, and timestamped/truncation-aware
  provider evidence with cross-provider image-URL agreement. Fix a module-level
  MAX_IMAGE_BYTES name collision detected by the existing byte-bound test.
