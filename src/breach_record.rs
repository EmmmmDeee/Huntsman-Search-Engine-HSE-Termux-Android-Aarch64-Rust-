//! What a breach record exposes, one rule for every keyed breach source (`OathNet`, `DeHashed`).
//!
//! A record is a JSON object whose keys name fields. Each field the record holds a value in is an
//! exposed field, kept by name. The value is kept too, so a report shows what the record said,
//! with one exception: a cleartext credential. A key that holds one of the
//! [`CREDENTIAL_MARKERS`] (a [`NOT_A_CREDENTIAL`] aside) is reduced to its name and the fact that
//! it was exposed, and so is a list or object holding such a key at any depth: a password, a hash
//! or a salt is the value an attacker needs for account takeover, so no report, entity or saved
//! ledger ever carries one. Whether a password was exposed is read more narrowly, from a key's
//! words ([`PASSWORD_WORDS`]). Field names, values per field and value lengths are bounded, so
//! one record cannot flood a report. **Pure.**

use std::collections::{BTreeMap, BTreeSet};

use serde_json::Value;

/// Most field names kept for one breach database.
pub const MAX_FIELDS: usize = 64;
/// Longest field name kept, in bytes. A longer or unusual name is dropped, never shortened.
pub const MAX_FIELD_BYTES: usize = 48;
/// Most distinct values kept for one exposed field of one breach database.
pub const MAX_VALUES_PER_FIELD: usize = 64;
/// Longest record value kept, in bytes. A longer value is dropped whole, never truncated, so a
/// surfaced value is always exactly what the record held.
pub const MAX_VALUE_BYTES: usize = 1024;

/// What a record key holds, in any case, when it may carry a password or something derived from
/// one: `password`, `password_hash`, `hashed_password`, `passwd`, `passphrase`, `pwd`, `salt` and
/// the like, read in the key as written and in its letters and digits run together (`pa_ssword`).
/// The value of such a key is held back, and the match fails closed, so a key that only looks like
/// one (`passenger_name`, `file_hash`) is held back too, with one exception: a `pass` that begins
/// [`NOT_A_CREDENTIAL`] does not count. Whether a password was exposed is read more narrowly, from
/// the key's words (see [`PASSWORD_WORDS`]).
pub const CREDENTIAL_MARKERS: [&str; 4] = ["pass", "pwd", "hash", "salt"];
/// A word that holds a marker but names no credential, in any case and anywhere in a key: a
/// passport number is not a password. Any other marker in the key still counts.
pub const NOT_A_CREDENTIAL: &str = "passport";
/// A key it holds back names a password, and so sets a breach's `password_exposed` when it holds a
/// value, when one of its words, read with trailing digits dropped (`pass1`, `salt2`), begins with
/// one of these (`Passwd`, `user_password`, `passwordhash`) or is one of [`PASSWORD_NAMES`], or is
/// one of [`AMBIGUOUS_PASSWORD_WORDS`] standing alone or beside another credential word or one of
/// [`PASSWORD_COMPANIONS`]. A key with one of [`PASSWORD_METADATA`] describes a password rather
/// than holding one. Words split at anything but a letter or digit, where a lower-case letter
/// meets an upper-case one and before the last capital of a run (`PASSHash`). So `passenger_name`,
/// `boarding_pass`, `compass`, `hashtags`, `file_hash` and `pwdLastSet` are held back but expose no
/// password.
pub const PASSWORD_WORDS: [&str; 5] = ["password", "passwd", "passwort", "passphrase", "passcode"];
/// Words that name a password or its hash or salt whole.
pub const PASSWORD_NAMES: [&str; 5] = ["pwd", "pwdhash", "passhash", "userpass", "salt"];
/// Words too common to name a password alone (`boarding_pass`, `file_hash`): they count as the
/// whole key or beside another credential word or a companion.
pub const AMBIGUOUS_PASSWORD_WORDS: [&str; 3] = ["pass", "hash", "hashed"];
/// Words beside which an ambiguous word names a password: whose it is, its age or how it is kept.
pub const PASSWORD_COMPANIONS: [&str; 17] = [
    "user",
    "login",
    "account",
    "admin",
    "old",
    "new",
    "plain",
    "clear",
    "md5",
    "sha1",
    "sha256",
    "sha512",
    "bcrypt",
    "crypt",
    "enc",
    "encrypted",
    "salted",
];
/// Words that make a key describe a password, not hold one (`pwdLastSet`, `password_changed_at`).
pub const PASSWORD_METADATA: [&str; 21] = [
    "at", "date", "time", "sent", "changed", "updated", "created", "set", "last", "count", "age",
    "max", "min", "length", "len", "less", "reset", "expires", "expiry", "hint", "policy",
];

/// Adds what one record exposes to one breach database's account of it: each named field that
/// holds a value goes into `fields`, and the value of each non-credential one into `values`,
/// within [`MAX_FIELDS`], [`MAX_VALUES_PER_FIELD`] and [`MAX_VALUE_BYTES`]. A cleartext credential
/// (a field [`is_credential`] names) is never kept, nor is a list or object that
/// [`holds_credential`], and either one sets `password_exposed` when a key inside it that
/// [`names_a_password`] holds a value. `named` is the record's keys and values, less the record's
/// own metadata, which each source names. **Pure.**
pub(crate) fn expose<'a>(
    named: impl Iterator<Item = (&'a String, &'a Value)>,
    fields: &mut BTreeSet<String>,
    values: &mut BTreeMap<String, BTreeSet<String>>,
    password_exposed: &mut bool,
) {
    for (key, value) in named {
        if !present(value) {
            continue;
        }
        // The raw key is judged, so a credential whose name `field_name` drops is still exposed.
        let credential = is_credential(key);
        if names_a_password(key) || holds_credential(value, names_a_password, present) {
            *password_exposed = true;
        }
        let Some(field) = field_name(key) else {
            continue;
        };
        if fields.len() < MAX_FIELDS || fields.contains(&field) {
            // The report is unredacted for the record's own data, but a third party's cleartext
            // credential (password, hash or salt) is never emitted: that is the value an attacker
            // needs for account takeover. The fact that such a field was exposed, its type and the
            // breach it came from are kept (the field name and `password_exposed`); only the secret
            // value is held back, and so is a list or object with a credential inside it. Every
            // other field's value is surfaced as the record held it.
            if !credential && !holds_credential(value, is_credential, |_| true) {
                if let Some(text) = record_value(value) {
                    let seen = values.entry(field.clone()).or_default();
                    if seen.len() < MAX_VALUES_PER_FIELD {
                        seen.insert(text);
                    }
                }
            }
            fields.insert(field);
        }
    }
}

/// One record value as text for the report: a string as written, a number or boolean as shown, a
/// list or object as compact JSON. `None` when it is blank or longer than [`MAX_VALUE_BYTES`], so
/// an oversized value is dropped whole rather than cut and a surfaced value is exactly what the
/// record held. [`present`] has already ruled out null, `false` and empty containers. **Pure.**
pub(crate) fn record_value(value: &Value) -> Option<String> {
    let text = match value {
        Value::Null | Value::Bool(false) => return None,
        Value::Bool(true) => "true".to_owned(),
        Value::Number(number) => number.to_string(),
        Value::String(string) => string.trim().to_owned(),
        Value::Array(_) | Value::Object(_) => serde_json::to_string(value).ok()?,
    };
    (!text.is_empty() && text.len() <= MAX_VALUE_BYTES).then_some(text)
}

/// `key` names a password or something derived from one: it holds one of the
/// [`CREDENTIAL_MARKERS`], in any case, other than a `pass` that begins [`NOT_A_CREDENTIAL`].
/// **Pure.**
pub(crate) fn is_credential(key: &str) -> bool {
    let written = key.to_ascii_lowercase();
    let joined: String = written
        .chars()
        .filter(char::is_ascii_alphanumeric)
        .collect();
    [written, joined].iter().any(|form| {
        CREDENTIAL_MARKERS.iter().any(|marker| {
            form.match_indices(marker)
                .any(|(at, _)| !form[at..].starts_with(NOT_A_CREDENTIAL))
        })
    })
}

/// `key` names a password by its words, as [`PASSWORD_WORDS`] says. It is always a key
/// [`is_credential`] holds back, so a named password's value is never kept. **Pure.**
pub(crate) fn names_a_password(key: &str) -> bool {
    let words: Vec<String> = key_words(key)
        .into_iter()
        .filter(|word| !word.bytes().all(|byte| byte.is_ascii_digit()))
        .collect();
    let base = |word: &str| {
        word.trim_end_matches(|c: char| c.is_ascii_digit())
            .to_owned()
    };
    let names = |word: &str| {
        let word = base(word);
        PASSWORD_WORDS.iter().any(|stem| word.starts_with(stem))
            || PASSWORD_NAMES.contains(&word.as_str())
    };
    let ambiguous = |word: &str| AMBIGUOUS_PASSWORD_WORDS.contains(&base(word).as_str());
    let counts = |at: usize, word: &String| {
        names(word)
            || (ambiguous(word)
                && (words.len() == 1
                    || words.iter().enumerate().any(|(other, beside)| {
                        other != at
                            && (PASSWORD_COMPANIONS.contains(&beside.as_str())
                                || ambiguous(beside)
                                || names(beside))
                    })))
    };
    is_credential(key)
        && !words
            .iter()
            .any(|word| PASSWORD_METADATA.contains(&word.as_str()))
        && words.iter().enumerate().any(|(at, word)| counts(at, word))
}

/// The words of a key, in lower case: split at anything but an ASCII letter or digit, where a
/// lower-case letter meets an upper-case one, and before the last capital of a run that a
/// lower-case letter follows, so `userPass`, `user_pass`, `User Pass` and `USERPass` read alike.
/// **Pure.**
pub(crate) fn key_words(key: &str) -> Vec<String> {
    let chars: Vec<char> = key.chars().collect();
    let mut words = Vec::new();
    let mut word = String::new();
    for (at, &c) in chars.iter().enumerate() {
        if !c.is_ascii_alphanumeric() {
            if !word.is_empty() {
                words.push(std::mem::take(&mut word));
            }
            continue;
        }
        let previous = at.checked_sub(1).map(|before| chars[before]);
        let next = chars.get(at + 1);
        let starts_word = c.is_ascii_uppercase()
            && previous.is_some_and(|previous| {
                previous.is_ascii_lowercase()
                    || (previous.is_ascii_uppercase() && next.is_some_and(char::is_ascii_lowercase))
            });
        if starts_word && !word.is_empty() {
            words.push(std::mem::take(&mut word));
        }
        word.push(c.to_ascii_lowercase());
    }
    if !word.is_empty() {
        words.push(word);
    }
    words
}

/// `value` is a list or object with a key `names` (a credential, [`is_credential`], or a named
/// password, [`names_a_password`]) at some depth whose value `counts`. With every value counted
/// and every credential named, its compact JSON would carry a credential out; with only a
/// [`present`] value under a named password counted, it exposes one. `serde_json`'s nesting limit
/// on the body bounds the walk. **Pure.**
pub(crate) fn holds_credential(
    value: &Value,
    names: fn(&str) -> bool,
    counts: fn(&Value) -> bool,
) -> bool {
    match value {
        Value::Array(items) => items
            .iter()
            .any(|item| holds_credential(item, names, counts)),
        Value::Object(map) => map.iter().any(|(key, value)| {
            (names(key) && counts(value)) || holds_credential(value, names, counts)
        }),
        Value::Null | Value::Bool(_) | Value::Number(_) | Value::String(_) => false,
    }
}

/// `key` as a field name: lower-case ASCII letters, digits and `_`, at most [`MAX_FIELD_BYTES`].
/// Anything else is dropped, so a key cannot smuggle a value into the report. **Pure.**
pub(crate) fn field_name(key: &str) -> Option<String> {
    let name = key.trim().to_ascii_lowercase();
    let ok = !name.is_empty()
        && name.len() <= MAX_FIELD_BYTES
        && name
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_');
    ok.then_some(name)
}

/// The value holds something: a non-blank string, a number, `true`, or a non-empty list or
/// object. **Pure.**
pub(crate) fn present(value: &Value) -> bool {
    match value {
        Value::Null | Value::Bool(false) => false,
        Value::Bool(true) | Value::Number(_) => true,
        Value::String(s) => !s.trim().is_empty(),
        Value::Array(a) => !a.is_empty(),
        Value::Object(o) => !o.is_empty(),
    }
}
