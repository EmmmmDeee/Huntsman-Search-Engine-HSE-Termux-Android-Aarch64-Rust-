// `Digest` (and the md5/sha1/sha2 hash types) are already in scope via the
// parent module's imports, which `use super::*` re-exposes to this child.
use super::*;

#[test]
fn identify_hash_classifies_common_formats() {
    assert_eq!(identify_hash(&"a".repeat(32)), Some(("md5", true)));
    assert_eq!(identify_hash(&"a".repeat(40)), Some(("sha1", true)));
    assert_eq!(identify_hash(&"a".repeat(64)), Some(("sha256", true)));
    assert_eq!(identify_hash(&"a".repeat(128)), Some(("sha512", true)));
    assert_eq!(
        identify_hash(&format!("*{}", "A".repeat(40))),
        Some(("mysql", true))
    );
    assert_eq!(
        identify_hash("$2b$12$R9h/cIPz0gi.URNNX3kh2OPST9PgBkqquzi.Ss7KIUgO2t0jWMUW"),
        Some(("bcrypt", false))
    );
    assert_eq!(
        identify_hash("$argon2id$v=19$m=65536,t=3,p=4$c2FsdHNhbHQ$aGFzaGhhc2g"),
        Some(("argon2", false))
    );
    assert_eq!(
        identify_hash("$6$rounds=5000$salt$hashhash"),
        Some(("sha512crypt", false))
    );
    assert_eq!(identify_hash("not-a-hash"), None);
}

#[test]
fn identify_hash_reads_digest_with_appended_salt() {
    // A bare md5 followed by a salt token still classifies by the leading hex run.
    assert_eq!(
        identify_hash(&format!("{} :=salt", "a".repeat(32))),
        Some(("md5", true))
    );
}

#[test]
fn is_salted_flags_appended_salt_only() {
    assert!(is_salted(&format!("{}:somesalt", "a".repeat(32))));
    assert!(is_salted(&format!("{} appended", "b".repeat(40))));
    // A bare digest with no salt is not salted.
    assert!(!is_salted(&"a".repeat(32)));
    // A prefixed KDF carries its own salt and is classified slow, not "salted" here.
    assert!(!is_salted("$2b$12$abcdefghijklmnopqrstuv"));
}

#[test]
fn crack_common_round_trips_every_listed_password() {
    // Every common password resolves from its own MD5 / SHA-1 / SHA-256 / SHA-512
    // digest — the table is built from exactly these functions, so this also
    // proves the four algorithms are wired correctly.
    for &pw in COMMON_PASSWORDS {
        let md5 = hex::encode(md5::Md5::digest(pw.as_bytes()));
        let sha1 = hex::encode(sha1::Sha1::digest(pw.as_bytes()));
        let sha256 = hex::encode(sha2::Sha256::digest(pw.as_bytes()));
        let sha512 = hex::encode(sha2::Sha512::digest(pw.as_bytes()));
        assert_eq!(crack_common(&md5), Some(pw), "md5({pw})");
        assert_eq!(crack_common(&sha1), Some(pw), "sha1({pw})");
        assert_eq!(crack_common(&sha256), Some(pw), "sha256({pw})");
        assert_eq!(crack_common(&sha512), Some(pw), "sha512({pw})");
        // Upper-cased and salt-appended forms resolve too.
        assert_eq!(crack_common(&md5.to_uppercase()), Some(pw));
        assert_eq!(crack_common(&format!("{md5}:salt")), Some(pw));
    }
}

#[test]
fn crack_common_resolves_famous_weak_hashes_and_none_for_strong() {
    // The canonical md5("password") and sha1("password").
    assert_eq!(
        crack_common("5f4dcc3b5aa765d61d8327deb882cf99"),
        Some("password")
    );
    assert_eq!(
        crack_common("5baa61e4c9b93f3f0682250b6cf8331b7ee68fd8"),
        Some("password")
    );
    // A random 32-hex digest of nothing common.
    assert_eq!(crack_common("00112233445566778899aabbccddeeff"), None);
    // A slow adaptive KDF is never reverse-looked-up.
    assert_eq!(
        crack_common("$2b$12$R9h/cIPz0gi.URNNX3kh2OPST9PgBkqquzi.Ss7KIUgO2t0jWMUW"),
        None
    );
    // A genuinely salted digest (digest != md5(plaintext)) does not resolve.
    assert_eq!(crack_common("deadbeefdeadbeefdeadbeefdeadbeef:salt"), None);

    assert!(is_common_collision("5f4dcc3b5aa765d61d8327deb882cf99"));
    assert!(!is_common_collision("00112233445566778899aabbccddeeff"));
}

#[test]
fn digests_of_produces_the_four_resolvable_digests() {
    // The four digests a plaintext would take if stored hashed — exactly what
    // `crack_common` resolves, proving the bridge and the table agree.
    let d = digests_of("password");
    assert_eq!(d.len(), 4);
    assert_eq!(crack_common(&d[0]), Some("password")); // md5
    assert_eq!(crack_common(&d[1]), Some("password")); // sha1
    assert_eq!(crack_common(&d[2]), Some("password")); // sha256
    assert_eq!(crack_common(&d[3]), Some("password")); // sha512
}

#[test]
fn is_common_password_flags_membership_case_insensitively() {
    assert!(is_common_password("password"));
    assert!(is_common_password("PASSWORD"));
    assert!(is_common_password("  qwerty "));
    assert!(!is_common_password("Tr0ub4dor&3xY-uncommon"));
}
