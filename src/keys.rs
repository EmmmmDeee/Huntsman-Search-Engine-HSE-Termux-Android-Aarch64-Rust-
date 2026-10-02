//! Operator credentials: loading, presence checks, and hygiene.
//!
//! Credentials are welcome here; leaking them is not. A `Secret` cannot be printed,
//! serialised or compared by value: it exposes its text only through `expose`, and
//! its `Debug` shows the credential fingerprint, which is what ledgers and logs
//! record. Values come from a keys file (`NAME=value` lines, mode 0600) or the
//! process environment; the file wins so a project can pin its own keys.

use std::collections::BTreeMap;
use std::env;
use std::fmt;
use std::path::Path;

use crate::credential_origin::CredentialFingerprint;
use crate::error::Error;
use crate::fsio::read_bounded;

const MAX_KEYS_FILE_BYTES: u64 = 64 * 1024;

/// Is this a real credential rather than a blank or a template placeholder?
///
/// Rejects empty/whitespace values and the placeholders operators leave in
/// `.env.example` files (`insert_key_here`, `<your-key>`, `changeme`, `xxxx`).
#[must_use]
pub fn is_configured_value(value: &str) -> bool {
    let v = value.trim();
    if v.is_empty() || v.chars().any(char::is_control) {
        return false;
    }
    let lower = v.to_ascii_lowercase();
    let placeholder_words = [
        "changeme",
        "change_me",
        "your_key",
        "your-key",
        "todo",
        "null",
        "none",
    ];
    if placeholder_words.contains(&lower.as_str()) {
        return false;
    }
    if (lower.starts_with("insert_") || lower.starts_with("your_") || lower.starts_with("your-"))
        && (lower.ends_with("_here") || lower.ends_with("-here"))
    {
        return false;
    }
    if (lower.starts_with('<') && lower.ends_with('>'))
        || (lower.starts_with("${") && lower.ends_with('}'))
    {
        return false;
    }
    // "xxxx", "****", "....": one repeated filler character, four or more times.
    let mut chars = lower.chars();
    if let Some(first) = chars.next() {
        if matches!(first, 'x' | '*' | '.' | '-' | '_' | '0')
            && v.len() >= 4
            && chars.all(|c| c == first)
        {
            return false;
        }
    }
    true
}

/// A credential value. No `Display`, no `Serialize`, no `PartialEq`.
#[derive(Clone)]
pub struct Secret(String);

impl Secret {
    /// # Errors
    /// `Error::Invalid` for blank/placeholder values and for control characters,
    /// which would allow header injection.
    pub fn new(value: impl Into<String>) -> Result<Self, Error> {
        let value = value.into();
        if !is_configured_value(&value) {
            return Err(Error::Invalid(
                "credential is blank or a placeholder".into(),
            ));
        }
        Ok(Self(value.trim().to_owned()))
    }

    /// The only way to read the value; call it where it is sent, nowhere else.
    #[must_use]
    pub fn expose(&self) -> &str {
        &self.0
    }

    #[must_use]
    pub fn fingerprint(&self) -> CredentialFingerprint {
        CredentialFingerprint::of_secret(&self.0)
    }
}

impl fmt::Debug for Secret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Secret({:?})", self.fingerprint())
    }
}

/// Slot names are environment-variable shaped so they cannot smuggle separators.
#[must_use]
pub fn valid_slot(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 64
        && name.starts_with(|c: char| c.is_ascii_uppercase())
        && name
            .chars()
            .all(|c| c.is_ascii_uppercase() || c.is_ascii_digit() || c == '_')
}

/// Parsed keys file plus an environment fallback.
#[derive(Default)]
pub struct Keys {
    entries: BTreeMap<String, Secret>,
    use_env: bool,
}

impl Keys {
    /// Environment only.
    #[must_use]
    pub fn from_env() -> Self {
        Self {
            entries: BTreeMap::new(),
            use_env: true,
        }
    }

    /// Parse `NAME=value` lines. Accepts `export NAME=value`, single or double
    /// quotes, blank lines and `#` comments. A later line overrides an earlier one.
    /// Placeholder values are skipped, not stored.
    ///
    /// # Errors
    /// `Error::Invalid` (line number only, never the value) for a line that is not
    /// `NAME=value` or whose name is not a valid slot.
    pub fn parse(text: &str) -> Result<Self, Error> {
        let mut entries = BTreeMap::new();
        for (idx, raw) in text.lines().enumerate() {
            let line = raw.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let line = line.strip_prefix("export ").map_or(line, str::trim_start);
            let Some((name, value)) = line.split_once('=') else {
                return Err(Error::Invalid(format!(
                    "keys line {}: expected NAME=value",
                    idx + 1
                )));
            };
            let name = name.trim();
            if !valid_slot(name) {
                return Err(Error::Invalid(format!(
                    "keys line {}: bad slot name",
                    idx + 1
                )));
            }
            let value = unquote(value.trim());
            if let Ok(secret) = Secret::new(value) {
                entries.insert(name.to_owned(), secret);
            } else {
                entries.remove(name);
            }
        }
        Ok(Self {
            entries,
            use_env: false,
        })
    }

    /// Load a keys file, falling back to the environment for slots it lacks.
    /// On Unix a file readable by group or others is refused: fix with `chmod 600`.
    ///
    /// # Errors
    /// `Error::Store` for I/O problems or loose permissions; `Error::Invalid` for
    /// malformed content.
    pub fn load(path: &Path) -> Result<Self, Error> {
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(path)
                .map_err(|e| Error::Store(format!("{}: {e}", path.display())))?
                .permissions()
                .mode();
            if mode & 0o077 != 0 {
                return Err(Error::Store(format!(
                    "{} is accessible by group/others (mode {:o}); run chmod 600",
                    path.display(),
                    mode & 0o777
                )));
            }
        }
        let bytes = read_bounded(path, MAX_KEYS_FILE_BYTES)?;
        let text = String::from_utf8(bytes)
            .map_err(|_| Error::Invalid("keys file is not utf-8".into()))?;
        let mut keys = Self::parse(&text)?;
        keys.use_env = true;
        Ok(keys)
    }

    /// File entry first, then the environment. Blank or placeholder values read as
    /// absent, so "not configured" is a single state.
    #[must_use]
    pub fn get(&self, slot: &str) -> Option<Secret> {
        if !valid_slot(slot) {
            return None;
        }
        if let Some(s) = self.entries.get(slot) {
            return Some(s.clone());
        }
        if self.use_env {
            return env::var(slot).ok().and_then(|v| Secret::new(v).ok());
        }
        None
    }

    /// Slot names present in the file (never values), for `doctor`-style listings.
    #[must_use]
    pub fn slots(&self) -> Vec<&str> {
        self.entries.keys().map(String::as_str).collect()
    }
}

impl fmt::Debug for Keys {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Keys")
            .field("slots", &self.slots())
            .finish_non_exhaustive()
    }
}

fn unquote(v: &str) -> &str {
    for q in ['"', '\''] {
        if v.len() >= 2 && v.starts_with(q) && v.ends_with(q) {
            return &v[1..v.len() - 1];
        }
    }
    // An unquoted trailing " # comment" is a comment.
    v.split_once(" #").map_or(v, |(a, _)| a.trim_end())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn blanks_and_placeholders_are_not_configured() {
        for v in [
            "",
            "   ",
            "\t\n",
            "insert_api_key_here",
            "INSERT_TOKEN_HERE",
            "your_key_here",
            "your-api-key-here",
            "<your key>",
            "${SHODAN_KEY}",
            "changeme",
            "xxxxxxxx",
            "********",
            "0000",
            "null",
            "with\ncontrol",
        ] {
            assert!(!is_configured_value(v), "{v:?}");
        }
        for v in ["k3y-8f2a91", "abcd1234", "xoxb-1234", "0123", "a"] {
            assert!(is_configured_value(v), "{v:?}");
        }
    }

    #[test]
    fn secret_never_prints_its_value() {
        let s = Secret::new("super-secret-value-1").expect("secret");
        let shown = format!("{s:?}");
        assert!(!shown.contains("super-secret"));
        assert!(shown.starts_with("Secret(CredentialFingerprint("));
        assert_eq!(s.expose(), "super-secret-value-1");
        assert_eq!(
            s.fingerprint(),
            Secret::new("super-secret-value-1")
                .expect("s")
                .fingerprint()
        );
        assert!(Secret::new("insert_key_here").is_err());
        assert!(Secret::new("a\r\nX-Evil: 1").is_err(), "header injection");
    }

    #[test]
    fn keys_file_syntax() {
        let k = Keys::parse(
            "# comment\n\nexport A_KEY=\"quoted value\"\nB_KEY = 'single'\nC_KEY=plain # trailing\n\
             D_KEY=insert_key_here\nA_KEY=\"override\"\n",
        )
        .expect("parse");
        assert_eq!(k.get("A_KEY").expect("a").expose(), "override");
        assert_eq!(k.get("B_KEY").expect("b").expose(), "single");
        assert_eq!(k.get("C_KEY").expect("c").expose(), "plain");
        assert!(k.get("D_KEY").is_none(), "placeholder reads as absent");
        assert_eq!(k.slots(), ["A_KEY", "B_KEY", "C_KEY"]);
        let shown = format!("{k:?}");
        assert!(!shown.contains("override") && shown.contains("A_KEY"));
    }

    #[test]
    fn a_placeholder_line_unsets_an_earlier_real_value() {
        let k = Keys::parse("A_KEY=real-value-1\nA_KEY=insert_here\n").expect("parse");
        assert!(k.get("A_KEY").is_none());
    }

    #[test]
    fn malformed_lines_report_line_numbers_not_values() {
        let err = Keys::parse("OK_KEY=value1\nthis is not a pair secretword\n").expect_err("bad");
        let msg = err.to_string();
        assert!(msg.contains("line 2") && !msg.contains("secretword"));
        assert!(Keys::parse("lowercase=value1\n").is_err());
        assert!(Keys::parse("BAD NAME=value1\n").is_err());
        assert!(Keys::parse("A=b\n").is_ok());
    }

    #[test]
    fn slot_names_are_constrained() {
        assert!(valid_slot("SHODAN_API_KEY"));
        for s in ["", "lower", "1ABC", "A-B", "A B", "A=B", &"A".repeat(65)] {
            assert!(!valid_slot(s), "{s:?}");
        }
        assert!(Keys::default().get("bad slot").is_none());
    }

    #[test]
    fn environment_is_a_fallback_only_when_enabled() {
        // PATH is set in every test environment and is a valid-looking slot name.
        assert!(Keys::default().get("PATH").is_none());
        assert!(Keys::from_env().get("PATH").is_some());
        assert!(
            Keys::from_env()
                .get("HUNTSMAN_SURELY_UNSET_SLOT_9")
                .is_none()
        );
    }

    #[cfg(unix)]
    #[test]
    fn loose_permissions_are_refused_and_tight_ones_load() {
        use std::os::unix::fs::PermissionsExt;
        let dir = std::env::temp_dir().join(format!("huntsman-keys-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("dir");
        let path = dir.join("keys.env");
        std::fs::write(&path, "T_KEY=value-12345\n").expect("write");
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).expect("chmod");
        let err = Keys::load(&path).expect_err("loose");
        assert!(err.to_string().contains("chmod 600"));
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).expect("chmod");
        let k = Keys::load(&path).expect("tight");
        assert_eq!(k.get("T_KEY").expect("t").expose(), "value-12345");
        std::fs::remove_dir_all(&dir).expect("cleanup");
    }
}
