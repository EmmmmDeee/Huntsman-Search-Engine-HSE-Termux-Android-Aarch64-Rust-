//! Process exit statuses for every binary in this package.
//!
//! The README's `Exit codes:` line is the external contract for `huntsman-recon`. The tests in
//! `tests/readme.rs` check that line against the statuses the CLI sources use, and check that
//! every status below is used by some binary. This module is the only place these numbers are
//! written: call sites import the names, and the same tests reject a literal status.
//!
//! The values follow the `sysexits(3)` convention. The gate codes 2 to 11 that `check` returns
//! for its individual gates are not statuses in this list; the README documents them separately.

/// Usage error: unknown command, missing or extra argument, or a malformed option.
pub const EX_USAGE: u8 = 64;
/// Bad data: input that was read but is malformed or refused, or a ledger that is malformed or
/// whose chain is broken.
pub const EX_DATAERR: u8 = 65;
/// Unreadable input, or failed credential setup such as an unconfigured slot or unreadable keys.
pub const EX_NOINPUT: u8 = 66;
/// No usable response from a service, or a register that could not be used.
pub const EX_UNAVAILABLE: u8 = 69;
/// Internal failure of the program. Only the `investigate` binary uses this status.
pub const EX_SOFTWARE: u8 = 70;
/// Artifact or output write failure.
pub const EX_IOERR: u8 = 74;
/// Refused by policy (egress, or a malformed URL or redirect target), or no permission for it.
pub const EX_NOPERM: u8 = 77;
