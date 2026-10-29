- `username HANDLE` now runs a keyless `npm_author` leg (also in username scans and the module
  catalogue), restoring a dropped legacy source and wiring the previously dangling `npm_author`
  reference in the correlator's `code` family. It reads the packages a handle maintains from npm's
  official public registry search API and keeps the confirmed-on-npm handle (with package coverage
  as evidence), the maintainer/publisher/author email and profile URL **only** from records whose
  own username is the subject -- so a co-maintainer's or a stale `author` block's address is never
  mis-attributed to the person being scanned -- every other npm username as its own co-maintainer
  lead, and each package's homepage/repository as a `Url` with its non-forge host a `Domain` pivot.
  A published maintainer email is a high-value handle->identity lead to review, not proof of who
  operates the account; nothing is fetched without a valid handle.
