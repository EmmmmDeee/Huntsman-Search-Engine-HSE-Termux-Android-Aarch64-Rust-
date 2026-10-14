//! Process exit statuses for every binary in this package.
//!
//! The README's `Exit codes:` line is the external contract for `huntsman-recon`. The tests in
//! `tests/readme.rs` check that line against the statuses the CLI sources use, and check that
//! every status below is used by some binary. This module is the only place these numbers are
//! written: call sites import the names, and the same tests reject a literal status.
//!
//! The values follow the `sysexits(3)` convention, except [`EX_PIPE`], which is the status a
//! shell reports for SIGPIPE. The gate codes 2 to 11 that `check` returns for its individual
//! gates are not statuses in this list; the README documents them separately.

/// Usage error: unknown command, missing or extra argument, or a malformed option.
pub const EX_USAGE: u8 = 64;
/// Bad data: input that was read but is malformed or refused, or a ledger that is malformed or
/// whose chain is broken.
pub const EX_DATAERR: u8 = 65;
/// Unreadable input, or failed credential setup such as an unconfigured slot or unreadable keys.
pub const EX_NOINPUT: u8 = 66;
/// No usable response from a service, or a register that could not be used.
pub const EX_UNAVAILABLE: u8 = 69;
/// Artifact or output write failure.
pub const EX_IOERR: u8 = 74;
/// Refused by policy (egress, or a malformed URL or redirect target), or no permission for it.
pub const EX_NOPERM: u8 = 77;
/// Configuration error: `doctor` found a check that fails.
pub const EX_CONFIG: u8 = 78;
/// The reader of standard output or standard error went away before the command finished, as
/// when the output is piped into `head`. 141 is 128 plus SIGPIPE, the status a shell reports
/// for a process that signal ended. Rust ignores SIGPIPE, so each binary's panic hook exits with
/// it when `stdio_failure` names a failed print as a closed reader.
pub const EX_PIPE: u8 = 141;
