//! The error type shared by the xtask commands. A message is for a person: it says what
//! failed, and where it helps, what to look at.

use std::fmt;
use std::io;
use std::path::PathBuf;
use std::process::ExitCode;

/// Exit status for a refused input or a failed check, as the shell scripts used.
pub const EX_REFUSED: u8 = 1;
/// Exit status for a usage error or malformed input (EX_USAGE).
pub const EX_USAGE: u8 = 64;
/// Exit status for a command that is not implemented yet. Only a placeholder while the
/// migration is in progress; a finished command never returns it.
pub const EX_UNIMPLEMENTED: u8 = 70;

#[derive(Debug)]
pub enum Error {
    /// Reading, writing, or inspecting a path failed.
    Io { path: PathBuf, source: io::Error },
    /// A command could not be started, or ran and did not succeed.
    Command { shown: String, reason: String },
    /// A check refused its input. The message says why.
    Refused(String),
    /// The input is malformed, so the command cannot run on it.
    Invalid(String),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io { path, source } => write!(f, "{}: {source}", path.display()),
            Self::Command { shown, reason } => write!(f, "`{shown}` {reason}"),
            Self::Refused(message) | Self::Invalid(message) => f.write_str(message),
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io { source, .. } => Some(source),
            _ => None,
        }
    }
}

pub type Result<T> = std::result::Result<T, Error>;

/// Prints `prefix: error` and returns the exit status for it: 64 for malformed input, 1 for
/// everything else.
#[must_use]
pub fn report(prefix: &str, error: &Error) -> ExitCode {
    eprintln!("{prefix}: {error}");
    match error {
        Error::Invalid(_) => ExitCode::from(EX_USAGE),
        _ => ExitCode::from(EX_REFUSED),
    }
}

/// Prints a usage message and returns the usage status.
#[must_use]
pub fn usage(text: &str) -> ExitCode {
    eprintln!("{text}");
    ExitCode::from(EX_USAGE)
}

/// The placeholder for a command whose port has not landed yet.
#[must_use]
pub fn unimplemented(name: &str) -> ExitCode {
    eprintln!("xtask: `{name}` is not implemented yet");
    ExitCode::from(EX_UNIMPLEMENTED)
}
