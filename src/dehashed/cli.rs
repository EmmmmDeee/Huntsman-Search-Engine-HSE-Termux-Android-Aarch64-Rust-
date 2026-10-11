//! `huntsman-recon dehashed …`: the command-line surface over [`DehashedClient`].
//!
//! ```text
//! dehashed search (--email ADDR | --username NAME | --domain DOMAIN)
//!                 --purpose PURPOSE [--size N] [--page N]
//! ```
//!
//! Exactly one identifier flag is required. `--purpose` is required and must
//! be one of [`Purpose::NAMES`]. Arguments are validated before the key is
//! loaded, and the key is loaded before any request, so a usage or key error
//! never touches the network.
//!
//! Output is `key=value` lines: `source=DeHashed`, the purpose and query as
//! sent, `results=N`, `total=` when the API reports it, then one block per
//! entry with the database name, emails, usernames, and whether a password or
//! hash exists. Passwords and hashes are never printed.

use std::io::Write;
use std::sync::Arc;

use super::client::{
    DehashedClient, DehashedError, MAX_PAGE, MAX_PAGE_SIZE, SearchOutcome, SearchRequest,
};
use super::query::{Field, Purpose, Selector};
use crate::http::Transport;
use crate::keys::Secret;
use crate::textnorm::escape_controls;

pub const DEHASHED_USAGE: &str = "usage: huntsman-recon dehashed search (--email ADDR | --username NAME | --domain DOMAIN) --purpose PURPOSE [--size N] [--page N] | help";

const EX_USAGE: u8 = 64;
const EX_DATAERR: u8 = 65;
const EX_NOINPUT: u8 = 66;
const EX_UNAVAILABLE: u8 = 69;
const EX_NOPERM: u8 = 77;

/// Why a command stopped: an exit code and the stderr text.
#[derive(Debug, PartialEq, Eq)]
pub struct Failure {
    pub code: u8,
    pub message: String,
}

impl Failure {
    fn usage(detail: &str) -> Self {
        Self {
            code: EX_USAGE,
            message: format!("{detail}\n{DEHASHED_USAGE}"),
        }
    }
}

impl From<DehashedError> for Failure {
    fn from(error: DehashedError) -> Self {
        let code = match &error {
            DehashedError::Query(_)
            | DehashedError::InvalidSize(_)
            | DehashedError::InvalidPage(_) => EX_DATAERR,
            DehashedError::MissingKey | DehashedError::KeyFilePermissions => EX_NOINPUT,
            DehashedError::Unauthorized | DehashedError::Forbidden => EX_NOPERM,
            DehashedError::BadRequest
            | DehashedError::RateLimited { .. }
            | DehashedError::Server(_)
            | DehashedError::Unexpected(_)
            | DehashedError::Transport
            | DehashedError::Decode(_) => EX_UNAVAILABLE,
        };
        Self {
            code,
            message: error.to_string(),
        }
    }
}

/// Parse `search …` arguments into a request. Pure: no I/O, no key.
///
/// # Errors
/// A [`Failure`] with exit code 64 (usage) or 65 (invalid identifier, purpose,
/// size or page).
pub fn parse_search(args: &[String]) -> Result<SearchRequest, Failure> {
    let mut selector: Option<Selector> = None;
    let mut purpose: Option<Purpose> = None;
    let mut size: Option<u32> = None;
    let mut page: Option<u32> = None;

    let mut iter = args.iter();
    while let Some(flag) = iter.next() {
        let mut value = || {
            iter.next()
                .map(String::as_str)
                .ok_or_else(|| Failure::usage(&format!("{flag} needs a value")))
        };
        match flag.as_str() {
            "--email" | "--username" | "--domain" => {
                if selector.is_some() {
                    return Err(Failure::usage(
                        "give exactly one of --email, --username, --domain",
                    ));
                }
                let field = match flag.as_str() {
                    "--email" => Field::Email,
                    "--username" => Field::Username,
                    _ => Field::Domain,
                };
                let raw = value()?;
                selector = Some(Selector::new(field, raw).map_err(|e| Failure {
                    code: EX_DATAERR,
                    message: format!("dehashed: {e}"),
                })?);
            }
            "--purpose" => {
                let raw = value()?;
                purpose = Some(Purpose::parse(raw).ok_or_else(|| Failure {
                    code: EX_DATAERR,
                    message: format!(
                        "dehashed: unknown purpose {raw:?}; expected one of {}",
                        Purpose::NAMES.join(", ")
                    ),
                })?);
            }
            "--size" => size = Some(parse_number(value()?, "--size", MAX_PAGE_SIZE)?),
            "--page" => page = Some(parse_number(value()?, "--page", MAX_PAGE)?),
            other => return Err(Failure::usage(&format!("unknown argument {other:?}"))),
        }
    }

    let selector =
        selector.ok_or_else(|| Failure::usage("a search needs --email, --username or --domain"))?;
    let purpose = purpose.ok_or_else(|| Failure::usage("a search needs --purpose"))?;
    let mut request = SearchRequest::new(selector, purpose);
    if let Some(size) = size {
        request.size = size;
    }
    if let Some(page) = page {
        request.page = page;
    }
    Ok(request)
}

fn parse_number(raw: &str, flag: &str, max: u32) -> Result<u32, Failure> {
    raw.parse::<u32>()
        .ok()
        .filter(|n| (1..=max).contains(n))
        .ok_or_else(|| Failure {
            code: EX_DATAERR,
            message: format!("dehashed: {flag} must be between 1 and {max}, got {raw:?}"),
        })
}

/// Render one search result as `key=value` lines.
#[must_use]
pub fn render(outcome: &SearchOutcome) -> String {
    use std::fmt::Write as _;
    let mut out = String::new();
    let _ = writeln!(out, "source=DeHashed");
    let _ = writeln!(out, "purpose={}", outcome.purpose);
    let _ = writeln!(out, "query={}", escape_controls(&outcome.query));
    let _ = writeln!(out, "page={}", outcome.page);
    let _ = writeln!(out, "results={}", outcome.entries.len());
    match outcome.total {
        Some(total) => {
            let _ = writeln!(out, "total={total}");
        }
        None => {
            let _ = writeln!(out, "total=<none>");
        }
    }
    for (index, entry) in outcome.entries.iter().enumerate() {
        let _ = writeln!(out, "entry={}", index + 1);
        let database = entry.database_name.as_deref().unwrap_or("<none>");
        let _ = writeln!(out, "database={}", escape_controls(database));
        for email in &entry.email {
            let _ = writeln!(out, "email={}", escape_controls(email));
        }
        for username in &entry.username {
            let _ = writeln!(out, "username={}", escape_controls(username));
        }
        let _ = writeln!(out, "has_password={}", entry.has_password());
        let _ = writeln!(out, "has_hashed_password={}", entry.has_hashed_password());
    }
    out
}

/// Run the `dehashed` command.
///
/// `key` is called only after arguments validate, and `http` is only used
/// after the key loads. Returns the process exit code.
pub fn run(
    args: &[String],
    key: impl FnOnce() -> Result<Secret, DehashedError>,
    http: Arc<dyn Transport + Send + Sync>,
    out: &mut dyn Write,
    err: &mut dyn Write,
) -> u8 {
    match execute(args, key, http) {
        Ok(text) => {
            let _ = out.write_all(text.as_bytes());
            0
        }
        Err(failure) => {
            let _ = writeln!(err, "{}", failure.message);
            failure.code
        }
    }
}

fn execute(
    args: &[String],
    key: impl FnOnce() -> Result<Secret, DehashedError>,
    http: Arc<dyn Transport + Send + Sync>,
) -> Result<String, Failure> {
    match args.first().map(String::as_str) {
        Some("help") => Ok(format!("{DEHASHED_USAGE}\n")),
        Some("search") => {
            let request = parse_search(&args[1..])?;
            let key = key()?;
            let client = DehashedClient::new(http, key);
            let outcome = client.search(&request)?;
            Ok(render(&outcome))
        }
        _ => Err(Failure::usage("expected a subcommand: search or help")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn argv(parts: &[&str]) -> Vec<String> {
        parts.iter().map(|s| (*s).to_string()).collect()
    }

    #[test]
    fn parses_one_identifier_with_purpose_and_bounds() {
        let request = parse_search(&argv(&[
            "--email",
            "a@example.com",
            "--purpose",
            "own-account",
            "--size",
            "25",
            "--page",
            "2",
        ]))
        .unwrap();
        assert_eq!(request.selector.query(), "email:\"a@example.com\"");
        assert_eq!(request.purpose, Purpose::OwnAccount);
        assert_eq!((request.size, request.page), (25, 2));
    }

    #[test]
    fn usage_errors_name_the_missing_piece() {
        let no_purpose = parse_search(&argv(&["--email", "a@example.com"])).unwrap_err();
        assert_eq!(no_purpose.code, EX_USAGE);
        assert!(no_purpose.message.contains("--purpose"));

        let no_selector = parse_search(&argv(&["--purpose", "own-account"])).unwrap_err();
        assert_eq!(no_selector.code, EX_USAGE);

        let two = parse_search(&argv(&[
            "--email",
            "a@example.com",
            "--domain",
            "example.com",
            "--purpose",
            "own-account",
        ]))
        .unwrap_err();
        assert_eq!(two.code, EX_USAGE);

        let dangling = parse_search(&argv(&["--email"])).unwrap_err();
        assert_eq!(dangling.code, EX_USAGE);
    }

    #[test]
    fn invalid_identifier_purpose_and_bounds_are_data_errors() {
        let wildcard = parse_search(&argv(&[
            "--email",
            "*@example.com",
            "--purpose",
            "own-account",
        ]))
        .unwrap_err();
        assert_eq!(wildcard.code, EX_DATAERR);
        assert!(
            wildcard.message.contains("wildcards"),
            "{}",
            wildcard.message
        );

        let purpose =
            parse_search(&argv(&["--email", "a@example.com", "--purpose", "fun"])).unwrap_err();
        assert_eq!(purpose.code, EX_DATAERR);

        let size = parse_search(&argv(&[
            "--email",
            "a@example.com",
            "--purpose",
            "own-account",
            "--size",
            "101",
        ]))
        .unwrap_err();
        assert_eq!(size.code, EX_DATAERR);

        let page = parse_search(&argv(&[
            "--email",
            "a@example.com",
            "--purpose",
            "own-account",
            "--page",
            "0",
        ]))
        .unwrap_err();
        assert_eq!(page.code, EX_DATAERR);
    }

    #[test]
    fn render_reports_presence_not_passwords() {
        let entry = super::super::types::Entry {
            database_name: Some("Example\nBreach".into()),
            email: vec!["a@example.com".into()],
            username: vec!["ada".into()],
            password: Some("hunter2-secret".into()),
            hashed_password: None,
        };
        let outcome = SearchOutcome {
            query: "email:\"a@example.com\"".into(),
            purpose: Purpose::OwnAccount,
            page: 1,
            size: 10,
            total: Some(1),
            response_sha256: String::new(),
            entries: vec![entry],
        };
        let text = render(&outcome);
        assert!(text.contains("source=DeHashed\n"), "{text}");
        assert!(text.contains("results=1\n"), "{text}");
        assert!(text.contains("email=a@example.com\n"), "{text}");
        assert!(text.contains("database=Example\\nBreach\n"), "{text}");
        assert!(text.contains("has_password=true\n"), "{text}");
        assert!(!text.contains("hunter2"), "{text}");
    }
}
