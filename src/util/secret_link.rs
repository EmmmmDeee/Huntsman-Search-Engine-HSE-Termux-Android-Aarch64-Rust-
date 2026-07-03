//! Small, stable identity-linking predicates shared between the correlator
//! (which reasons about a *finding*) and the relation graph (which reasons
//! about an *edge*) — the same "single canonical predicate" pattern already
//! used for `util::domains::is_proxy_registrant`/`registrable_domain`
//! (shared by `core::relation::builders::derive_co_ownership` and
//! `core::correlator::rules::org`'s AU-109/AU-110).
//!
//! Deliberately narrow: this module holds only the leaf shape-classification
//! that is safe to share (no entropy scoring, no denylists — see
//! `core::correlator::rules::breach` for the precision-critical logic around
//! a *reused plaintext password*, which stays single-sourced there rather
//! than being split across two call sites).

/// True if `s` is a **salted** password-hash digest — bcrypt / sha-crypt /
/// argon2 / scrypt / yescrypt, all of which embed their salt. This is the
/// precision gate that makes credential-based identity linking sound: a salted
/// digest is globally unique by construction, so two identities carrying the
/// *identical* value share the exact stored credential (the same person reused or
/// copied it) — not a weak-password coincidence. A bare unsalted hex digest is
/// deliberately EXCLUDED: `md5("123456")` is shared by millions, and linking
/// people on it would manufacture false identities, which is the opposite of
/// finding the real one.
#[must_use]
pub fn is_salted_hash(s: &str) -> bool {
    let s = s.trim();
    s.starts_with("$2") // bcrypt $2a/$2b/$2y
        || s.starts_with("$argon2")
        || s.starts_with("$scrypt")
        || s.starts_with("$y$") // yescrypt
        || s.starts_with("$7$") // scrypt (crypt format)
        || s.starts_with("$6$") // sha512crypt
        || s.starts_with("$5$") // sha256crypt
}

/// Canonical comparison form of a handle: ASCII-lowercased with the handle
/// separators (`.`, `_`, `-`) removed, so the same handle written with
/// inconsistent punctuation collapses to one token (`jordan.meyers`,
/// `jordan_meyers`, `jordanmeyers` → `jordanmeyers`). People reuse a single
/// handle across services with different separators; this is the comparison
/// the match needs.
#[must_use]
pub fn canonical_handle(s: &str) -> String {
    s.chars()
        .filter(|c| !matches!(c, '.' | '_' | '-'))
        .map(|c| c.to_ascii_lowercase())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn is_salted_hash_accepts_every_salted_scheme() {
        for h in [
            "$2a$10$abcdefghijklmnopqrstuv",
            "$2b$12$....",
            "$2y$10$....",
            "$argon2id$v=19$m=65536",
            "$scrypt$ln=16",
            "$y$j9T$salt",
            "$7$DU..../....",
            "$6$rounds=5000$salt",
            "$5$rounds=5000$salt",
        ] {
            assert!(is_salted_hash(h), "should be salted: {h}");
        }
    }

    #[test]
    fn is_salted_hash_rejects_bare_hex_and_trims() {
        assert!(!is_salted_hash("5f4dcc3b5aa765d61d8327deb882cf99")); // md5 hex
        assert!(!is_salted_hash("not a hash"));
        // Leading/trailing whitespace is trimmed before the prefix test.
        assert!(is_salted_hash("  $2a$10$x  "));
    }

    #[test]
    fn canonical_handle_collapses_separators_and_case() {
        assert_eq!(canonical_handle("Jordan.Meyers"), "jordanmeyers");
        assert_eq!(canonical_handle("jordan_meyers"), "jordanmeyers");
        assert_eq!(canonical_handle("jordan-meyers"), "jordanmeyers");
    }

    #[test]
    fn canonical_handle_is_idempotent_on_an_already_canonical_value() {
        assert_eq!(canonical_handle("jordanmeyers"), "jordanmeyers");
        assert_eq!(canonical_handle(""), "");
    }
}
