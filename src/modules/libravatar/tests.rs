use super::{Libravatar, SRC, build_avatar_result};
use crate::core::{
    entity::EntityKind,
    module::Module,
    scan::{Target, TargetKind},
};
use crate::util::gravatar::hash as avatar_hash;

#[test]
fn accepts_email_only() {
    let m = Libravatar;
    assert!(m.accepts(&Target::new(TargetKind::Email, "x@y.com")));
    assert!(!m.accepts(&Target::new(TargetKind::Domain, "y.com")));
    assert!(!m.accepts(&Target::new(TargetKind::Username, "bob")));
}

#[test]
fn module_name_is_stable() {
    assert_eq!(Libravatar.name(), "libravatar");
    assert_eq!(Libravatar.name(), SRC);
}

#[test]
fn present_avatar_yields_image_url_entity() {
    let hash = avatar_hash("Person@Example.com");
    let r = build_avatar_result(&hash, "scan-1");
    assert_eq!(r.entities.len(), 1);
    let e = &r.entities[0];
    assert_eq!(e.kind, EntityKind::Url);
    // The emitted URL serves the image (no d=404), and carries the hash.
    assert_eq!(
        e.value,
        format!("https://seccdn.libravatar.org/avatar/{hash}")
    );
    assert!(!e.value.contains("d=404"));
    assert!(e.has_tag(SRC));
    assert!(e.has_tag("avatar"));
    assert!(e.has_tag("public-profile"));
    assert_eq!(
        e.evidence[0]
            .attributes
            .get("avatar_hash")
            .map(String::as_str),
        Some(hash.as_str())
    );
}

#[test]
fn hash_matches_gravatar_compatible_md5_of_normalised_email() {
    // Libravatar reuses Gravatar's identifier: MD5 of the trimmed, lowercased
    // address — so surrounding whitespace and case do not change the hash.
    assert_eq!(
        avatar_hash("  Person@Example.com "),
        avatar_hash("person@example.com")
    );
    // A 32-char lowercase hex digest, as an MD5 hex encoding must be.
    let h = avatar_hash("person@example.com");
    assert_eq!(h.len(), 32);
    assert!(
        h.chars()
            .all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase())
    );
}
