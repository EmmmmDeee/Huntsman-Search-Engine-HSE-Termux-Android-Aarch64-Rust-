# legacy/

Read-only reconstruction oracles extracted from the two historical repository archives.
The extracted trees, rather than opaque ZIP containers, are the canonical references in
HEAD. Do not edit or move them casually: `tests/legacy_reference.rs` pins their file counts,
and Git records every content change.

- `hse-monolith-v1.41.0/` — extracted HSE monolith (1314 files); historical Git tree `58adb561ddad030092838234c69ed63e2c1a0314`.
- `refactor-overlay-feef60a/` — extracted end-to-end refactor overlay (40 files); historical Git tree `39d9f765f0b58c70b2e30ae6b49538a74042ff1c`.

The original archive filenames, SHA-256 digests, Git blob identities, and a commit from
which the exact bytes remain recoverable are recorded in `docs/ARCHIVE_PROVENANCE.md`.
Nothing under `legacy/` is part of the build. Per-file dispositions: `docs/DISPOSITIONS.md`.
