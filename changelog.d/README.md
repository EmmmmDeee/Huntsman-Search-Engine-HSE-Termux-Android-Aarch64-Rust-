# Changelog fragments

A change adds one file here instead of a line in `CHANGELOG.md`, so two pull requests never
edit the same lines of the changelog and a merge never conflicts on it.

- Name: `<slug>.<section>.md`. The slug is the topic or branch in lowercase letters, digits and
  hyphens. The section is one of Keep a Changelog's: `added`, `changed`, `deprecated`,
  `removed`, `fixed`, `security`.
- Body: one or more Markdown bullets, `- text`, each continued by lines indented two spaces,
  ending in a newline. Write the entry as it will read in `CHANGELOG.md`.
- Every gate mode runs `cargo run --locked -p xtask -- changelog check`, so a malformed
  fragment never reaches `main`.
- `cargo run --locked -p xtask -- changelog render` prints `CHANGELOG.md` with the fragments
  assembled at the top of their sections under `## [Unreleased]`, without writing.
- `cargo run --locked -p xtask -- changelog assemble` writes that and deletes the fragments. It
  is run when a version heading is cut, in the release's own pull request.
