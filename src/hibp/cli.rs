//! `huntsman-recon hibp …`: the command-line surface over [`HibpClient`].
//!
//! Each subcommand maps to one client call:
//!
//! | Subcommand | Client call | Key |
//! | --- | --- | --- |
//! | `breach NAME` | [`HibpClient::breach`] | no |
//! | `breaches [--domain DOMAIN]` | [`HibpClient::breaches`] | no |
//! | `account EMAIL` | [`HibpClient::breached_account`] (`truncateResponse=false`) | yes |
//! | `pastes EMAIL` | [`HibpClient::paste_account`] | yes |
//! | `password-range PREFIX` | [`HibpClient::pwned_passwords_range`] (SHA-1, padded) | no |
//! | `password` | [`HibpClient::check_password`] (SHA-1) | no |
//! | `subscription` | [`HibpClient::subscription_status`] | yes |
//!
//! Requests go through the client, so through the guarded fetch boundary
//! (`hibp::send`) with redirects off. Keys come from [`KeyLoader::default_chain`]
//! and are loaded only for keyed subcommands; output names where a key came
//! from, never its value. `password` reads one line from stdin, hashes it
//! locally and prints only the count: the password, its hash and its suffix are
//! never written anywhere.
//!
//! Output is `key=value` lines: a `source=HIBP` header with the attribution
//! HIBP's licence requires, `results=N`, `query=` (the address as sent, for
//! `account` and `pastes`), then one block per record with every model field.
//! A field HIBP sent as null or omitted prints as `<none>`; an empty string
//! prints as `key=`; a literal `<none>` value prints as `\<none>`. Values are
//! escaped (`\\`, `\n`, `\r`, `\t`) so each field stays on one line. For
//! `breach`, `breaches`, `account` and `pastes` a 404 is `results=0`, not an
//! error; `subscription` and `password-range` treat a 404 as an error (exit 69).

use std::fmt::{self, Display, Write as _};
use std::io::{BufRead, Read as _, Write};

use super::client::{Auth, HibpClient, HibpConfig};
use super::error::HibpError;
use super::key::{ApiKey, KeyLoader, KeyOrigin};
use super::passwords::{PasswordHashMode, wipe};
use super::types::{
    BreachModel, BreachedAccountOptions, BreachesFilter, PasteModel, SubscriptionStatus,
};

/// Usage for `huntsman-recon hibp`.
pub const HIBP_USAGE: &str = "usage: huntsman-recon hibp [breach NAME | breaches [--domain DOMAIN] | account EMAIL | pastes EMAIL | password-range PREFIX | password | subscription | help]";

const SUBCOMMANDS: [&str; 8] = [
    "breach",
    "breaches",
    "account",
    "pastes",
    "password-range",
    "password",
    "subscription",
    "help",
];

const EX_USAGE: u8 = 64;
const EX_DATAERR: u8 = 65;
const EX_NOINPUT: u8 = 66;
const EX_UNAVAILABLE: u8 = 69;
const EX_IOERR: u8 = 74;
const EX_NOPERM: u8 = 77;

/// Longest password line read from stdin, in bytes.
const MAX_PASSWORD_BYTES: u64 = 4096;

const HIBP_ATTRIBUTION: &str =
    "Have I Been Pwned (https://haveibeenpwned.com), CC BY 4.0 International";
const PASSWORDS_ATTRIBUTION: &str =
    "Pwned Passwords by Have I Been Pwned (https://haveibeenpwned.com/Passwords)";

/// The `hibp` command: a key chain plus a way to build a client for an [`Auth`].
pub struct HibpCommand {
    keys: KeyLoader,
    connect: Box<dyn Fn(Auth) -> HibpClient>,
}

impl fmt::Debug for HibpCommand {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("HibpCommand")
            .field("keys", &self.keys)
            .finish_non_exhaustive()
    }
}

/// Why a subcommand stopped: an exit code and the stderr text.
struct Failure {
    code: u8,
    message: String,
}

impl Failure {
    fn usage(detail: &str) -> Self {
        Self {
            code: EX_USAGE,
            message: format!("{detail}\n{HIBP_USAGE}"),
        }
    }
}

impl From<HibpError> for Failure {
    fn from(e: HibpError) -> Self {
        let code = match &e {
            HibpError::MissingKey => EX_NOINPUT,
            HibpError::InvalidInput(_) | HibpError::BadRequest(_) => EX_DATAERR,
            HibpError::Unauthorized(_)
            | HibpError::Forbidden(_)
            | HibpError::PlanNotEntitled { .. } => EX_NOPERM,
            HibpError::RateLimited { .. }
            | HibpError::Server { .. }
            | HibpError::UnexpectedStatus { .. }
            | HibpError::Transport(_)
            | HibpError::Decode(_)
            | HibpError::OAuth(_) => EX_UNAVAILABLE,
        };
        let message = match &e {
            HibpError::RateLimited { retry_after } => format!(
                "hibp: rate limited (HTTP 429)\nretry_after={}",
                retry_after.map_or_else(|| "unknown".into(), |d| format!("{}s", d.as_secs()))
            ),
            other => other.to_string(),
        };
        Self { code, message }
    }
}

type Outcome = Result<String, Failure>;

impl HibpCommand {
    /// A command over `keys` that builds clients with `connect`.
    #[must_use]
    pub fn new(keys: KeyLoader, connect: impl Fn(Auth) -> HibpClient + 'static) -> Self {
        Self {
            keys,
            connect: Box::new(connect),
        }
    }

    /// The binary's command: [`KeyLoader::default_chain`] and
    /// [`HibpClient::production`] with the default config.
    #[must_use]
    pub fn production() -> Self {
        Self::new(KeyLoader::default_chain(None), |auth| {
            HibpClient::production(auth, HibpConfig::default())
        })
    }

    /// Run `hibp ARGS…`. Results go to `stdout`, errors to `stderr`; the
    /// return value is the process exit code (0 on success, including a 404
    /// "no results").
    pub fn run(
        &self,
        args: &[String],
        stdin: &mut dyn BufRead,
        stdout: &mut dyn Write,
        stderr: &mut dyn Write,
    ) -> u8 {
        match self.dispatch(args, stdin) {
            Ok(text) => match stdout
                .write_all(text.as_bytes())
                .and_then(|()| stdout.flush())
            {
                Ok(()) => 0,
                Err(_) => EX_IOERR,
            },
            Err(failure) => {
                // Nothing useful can be done if stderr itself is gone.
                let _ = writeln!(stderr, "{}", failure.message);
                failure.code
            }
        }
    }

    fn dispatch(&self, args: &[String], stdin: &mut dyn BufRead) -> Outcome {
        let words: Vec<&str> = args.iter().map(String::as_str).collect();
        match words.as_slice() {
            ["help" | "-h" | "--help"] => Ok(format!("{HIBP_USAGE}\n")),
            ["breach", name] => self.breach(name),
            ["breaches"] => self.breaches(None),
            ["breaches", "--domain", domain] => self.breaches(Some(domain)),
            ["account", email] => self.account(email),
            ["pastes", email] => self.pastes(email),
            ["password-range", prefix] => self.password_range(prefix),
            ["password"] => self.password(stdin),
            ["subscription"] => self.subscription(),
            [] => Err(Failure::usage("hibp: missing subcommand")),
            [sub, ..] if SUBCOMMANDS.contains(sub) => {
                Err(Failure::usage(&format!("hibp: bad arguments for `{sub}`")))
            }
            [sub, ..] => Err(Failure::usage(&format!("hibp: unknown subcommand `{sub}`"))),
        }
    }

    fn public(&self) -> HibpClient {
        (self.connect)(Auth::None)
    }

    fn keyed(&self) -> Result<(HibpClient, KeyOrigin), Failure> {
        let (key, origin): (ApiKey, KeyOrigin) = self.keys.load().ok_or(HibpError::MissingKey)?;
        Ok(((self.connect)(Auth::ApiKey(key)), origin))
    }

    fn breach(&self, name: &str) -> Outcome {
        let found = self.public().breach(name)?;
        let mut out = header("api-v3", HIBP_ATTRIBUTION, usize::from(found.is_some()));
        if let Some(model) = &found {
            write_breach(&mut out, model);
        }
        Ok(out)
    }

    fn breaches(&self, domain: Option<&str>) -> Outcome {
        let domain = match domain.map(str::trim) {
            Some("") => return Err(HibpError::InvalidInput("domain is empty".into()).into()),
            other => other,
        };
        let filter = BreachesFilter {
            domain: domain.map(str::to_owned),
            is_spam_list: None,
        };
        let models = self.public().breaches(&filter)?;
        Ok(breach_list(&models))
    }

    fn account(&self, email: &str) -> Outcome {
        let (client, _) = self.keyed()?;
        let options = BreachedAccountOptions {
            truncate_response: Some(false),
            ..BreachedAccountOptions::default()
        };
        let models = client.breached_account(email, &options)?;
        let mut out = header("api-v3", HIBP_ATTRIBUTION, models.len());
        line(&mut out, "query", email.trim());
        for model in &models {
            write_breach(&mut out, model);
        }
        Ok(out)
    }

    fn pastes(&self, email: &str) -> Outcome {
        let (client, _) = self.keyed()?;
        let pastes = client.paste_account(email)?;
        let mut out = header("api-v3", HIBP_ATTRIBUTION, pastes.len());
        line(&mut out, "query", email.trim());
        for paste in &pastes {
            write_paste(&mut out, paste);
        }
        Ok(out)
    }

    fn password_range(&self, prefix: &str) -> Outcome {
        let entries = self
            .public()
            .pwned_passwords_range(prefix, PasswordHashMode::Sha1, true)?;
        let mut out = header("pwned-passwords", PASSWORDS_ATTRIBUTION, entries.len());
        line(&mut out, "mode", "sha1");
        line(&mut out, "prefix", prefix.trim().to_ascii_uppercase());
        for entry in &entries {
            let _ = writeln!(out, "{}:{}", entry.suffix, entry.count);
        }
        Ok(out)
    }

    fn password(&self, stdin: &mut dyn BufRead) -> Outcome {
        let password = read_password(stdin)?;
        let counted = self
            .public()
            .check_password(&password, PasswordHashMode::Sha1);
        wipe(password.into_bytes());
        let count = counted?;
        let mut out = header("pwned-passwords", PASSWORDS_ATTRIBUTION, 1);
        line(&mut out, "mode", "sha1");
        line(&mut out, "count", count);
        Ok(out)
    }

    fn subscription(&self) -> Outcome {
        let (client, origin) = self.keyed()?;
        let status = client.subscription_status()?;
        let mut out = header("api-v3", HIBP_ATTRIBUTION, 1);
        line(&mut out, "key_source", origin_label(&origin));
        write_subscription(&mut out, &status);
        Ok(out)
    }
}

/// One line of stdin without its terminator. The error text never includes
/// what was read, and every rejected buffer is wiped.
fn read_password(stdin: &mut dyn BufRead) -> Result<String, Failure> {
    // Room for the limit plus a two-byte `\r\n` terminator, allocated once so
    // growth never leaves an unwiped copy behind. The limit applies to the
    // content after the terminator is stripped.
    let cap = usize::try_from(MAX_PASSWORD_BYTES + 2).unwrap_or(usize::MAX);
    let mut bytes = Vec::with_capacity(cap);
    if stdin
        .take(MAX_PASSWORD_BYTES + 2)
        .read_until(b'\n', &mut bytes)
        .is_err()
    {
        wipe(bytes);
        return Err(
            HibpError::InvalidInput("could not read the password from stdin".into()).into(),
        );
    }
    if bytes.last() == Some(&b'\n') {
        bytes.pop();
        if bytes.last() == Some(&b'\r') {
            bytes.pop();
        }
    }
    let rejected = if bytes.is_empty() {
        Some("no password on stdin".to_owned())
    } else if bytes.len() as u64 > MAX_PASSWORD_BYTES {
        Some(format!(
            "password on stdin is longer than {MAX_PASSWORD_BYTES} bytes"
        ))
    } else {
        None
    };
    if let Some(reason) = rejected {
        wipe(bytes);
        return Err(HibpError::InvalidInput(reason).into());
    }
    String::from_utf8(bytes).map_err(|e| {
        wipe(e.into_bytes());
        HibpError::InvalidInput("password on stdin is not UTF-8".into()).into()
    })
}

fn origin_label(origin: &KeyOrigin) -> String {
    match origin {
        KeyOrigin::Env(name) => format!("env:{name}"),
        KeyOrigin::HuntsmanSlot => "slot:HUNTSMAN_HIBP_KEY".into(),
        KeyOrigin::File(path) => format!("file:{}", path.display()),
        KeyOrigin::Embedded => "embedded".into(),
        KeyOrigin::Provided => "provided".into(),
    }
}

fn header(service: &str, attribution: &str, results: usize) -> String {
    let mut out = String::new();
    line(&mut out, "source", "HIBP");
    line(&mut out, "service", service);
    line(&mut out, "source_attribution", attribution);
    line(&mut out, "results", results);
    out
}

fn breach_list(models: &[BreachModel]) -> String {
    let mut out = header("api-v3", HIBP_ATTRIBUTION, models.len());
    for model in models {
        write_breach(&mut out, model);
    }
    out
}

/// Every [`BreachModel`] field. The destructuring has no `..`, so a field
/// added to the model is a compile error here until it is printed.
fn write_breach(out: &mut String, b: &BreachModel) {
    let BreachModel {
        name,
        title,
        domain,
        breach_date,
        added_date,
        modified_date,
        pwn_count,
        description,
        logo_path,
        attribution,
        data_classes,
        is_verified,
        is_fabricated,
        is_sensitive,
        is_retired,
        is_spam_list,
        is_malware,
        is_stealer_log,
        is_subscription_free,
    } = b;
    out.push('\n');
    line(out, "breach", name);
    line_opt(out, "title", title.as_ref());
    line_opt(out, "domain", domain.as_ref());
    line_opt(out, "breach_date", breach_date.as_ref());
    line_opt(out, "added_date", added_date.as_ref());
    line_opt(out, "modified_date", modified_date.as_ref());
    line_opt(out, "pwn_count", pwn_count.as_ref());
    line(out, "data_classes", data_classes.len());
    for class in data_classes {
        line(out, "data_class", class);
    }
    for (key, value) in [
        ("is_verified", is_verified),
        ("is_fabricated", is_fabricated),
        ("is_sensitive", is_sensitive),
        ("is_retired", is_retired),
        ("is_spam_list", is_spam_list),
        ("is_malware", is_malware),
        ("is_stealer_log", is_stealer_log),
        ("is_subscription_free", is_subscription_free),
    ] {
        line_opt(out, key, value.as_ref());
    }
    line_opt(out, "attribution", attribution.as_ref());
    line_opt(out, "logo_path", logo_path.as_ref());
    line_opt(out, "description", description.as_ref());
}

/// Every [`PasteModel`] field (exhaustive destructuring, as above).
fn write_paste(out: &mut String, p: &PasteModel) {
    let PasteModel {
        source,
        id,
        title,
        date,
        email_count,
    } = p;
    out.push('\n');
    line_opt(out, "paste_source", source.as_ref());
    line_opt(out, "paste_id", id.as_ref());
    line_opt(out, "title", title.as_ref());
    line_opt(out, "date", date.as_ref());
    line_opt(out, "email_count", email_count.as_ref());
}

/// Every [`SubscriptionStatus`] field (exhaustive destructuring, as above).
fn write_subscription(out: &mut String, s: &SubscriptionStatus) {
    let SubscriptionStatus {
        subscription_name,
        description,
        subscribed_until,
        rpm,
        domain_search_max_breached_accounts,
        max_breached_domains,
        includes_stealer_logs,
        includes_bulk_domain_add,
        includes_auto_subdomain_verification,
        includes_customer_domains,
        includes_k_anon,
    } = s;
    line(out, "subscription_name", subscription_name);
    line_opt(out, "description", description.as_ref());
    line_opt(out, "subscribed_until", subscribed_until.as_ref());
    line_opt(out, "rpm", rpm.as_ref());
    line_opt(
        out,
        "domain_search_max_breached_accounts",
        domain_search_max_breached_accounts.as_ref(),
    );
    line_opt(out, "max_breached_domains", max_breached_domains.as_ref());
    for (key, value) in [
        ("includes_stealer_logs", includes_stealer_logs),
        ("includes_bulk_domain_add", includes_bulk_domain_add),
        (
            "includes_auto_subdomain_verification",
            includes_auto_subdomain_verification,
        ),
        ("includes_customer_domains", includes_customer_domains),
        ("includes_k_anon", includes_k_anon),
    ] {
        line_opt(out, key, value.as_ref());
    }
}

/// Printed for a field HIBP sent as null or omitted. A string value that is
/// literally `<none>` is printed as `\<none>`, so the two never collide.
const ABSENT: &str = "<none>";

/// `key=value\n` for an optional field: [`ABSENT`] when there is no value.
fn line_opt<T: Display>(out: &mut String, key: &str, value: Option<&T>) {
    if let Some(v) = value {
        line(out, key, v);
    } else {
        out.push_str(key);
        out.push('=');
        out.push_str(ABSENT);
        out.push('\n');
    }
}

/// `key=value\n`, with `\`, newline, carriage return and tab escaped, and a
/// literal `<none>` written as `\<none>`.
fn line(out: &mut String, key: &str, value: impl Display) {
    let value = value.to_string();
    out.push_str(key);
    out.push('=');
    if value == ABSENT {
        out.push('\\');
    }
    for c in value.chars() {
        match c {
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c => out.push(c),
        }
    }
    out.push('\n');
}
