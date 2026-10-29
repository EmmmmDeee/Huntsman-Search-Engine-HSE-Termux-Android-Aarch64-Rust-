- `username HANDLE` now runs a keyless `crates_io` leg (also in username scans and the module
  catalogue), restoring a dropped legacy source and wiring the previously dangling `crates_io`
  reference in the correlator's `code` family. It reads a crates.io account from the official public
  API (`/api/v1/users/{login}`, then `/api/v1/crates?user_id={id}`). The account is confirmed only
  when the returned `login` is exactly the queried handle (a mismatch is semantic drift, a malformed
  envelope schema drift, an unknown account a clean zero); because crates.io authenticates through
  GitHub, the account's `url` ties the handle to the owner's GitHub profile. It keeps the confirmed
  `Username`, the owner's display name as a `Person` only when it reads as a person's, the GitHub
  profile `Url`, and each published crate's repository/homepage/documentation as a `Url` with its
  non-forge host a `Domain` and a `github.com` repository owner a cross-platform `Username` lead. The
  user endpoint is exact and the crate listing is filtered by the resolved numeric `user_id`, so the
  account is the single fail-closed gate and a refused crate listing loses only crate pivots. A
  published name or repository link is a lead to review, never confirmed identity.
