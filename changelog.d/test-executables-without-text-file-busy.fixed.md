- Tests no longer fail intermittently with "Text file busy" (os error 26) when they run a fake
  program (`gh`, `cargo`, `docker`, a sensor shim, a git hook) they have just written. Writing
  the file from the multi-threaded test process let a sibling test's forked child hold its write
  descriptor until it exec'd; reproduced as 1 failure in 400 runs of
  `xtask/tests/issue_fix_report.rs` (#1590). Every test now writes such a program through
  `tests/support/executable.rs`, which has a short-lived `sh` child write it from a pipe, and
  `tests/executable_policy.rs` refuses any other way of setting an execute bit in a test. The
  file-local lock that `tests/release_ci.rs` used for the same race is removed.
