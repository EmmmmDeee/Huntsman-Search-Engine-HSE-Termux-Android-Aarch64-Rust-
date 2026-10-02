use super::{Libravatar, SRC, build_avatar_result, is_image_content_type};
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

/// REQ-LIBRAVATAR-001. Presence was decided by the status line alone — the
/// module's own comment said so: *"The body is never read — presence is decided
/// by the status line alone."* With `d=404` a genuine miss is a 404, but a 200
/// is not necessarily an avatar: an anti-bot interstitial, a CDN error page or
/// a consent wall is served 200 with an HTML body, and each minted a
/// `public-profile` `Url` claiming the address has a public web presence.
///
/// Every non-image type is checked and survivors are collected, so a partial
/// gate is named rather than masked by whichever case runs first.
#[test]
fn a_200_that_is_not_an_image_is_not_an_avatar() {
    let mut admitted: Vec<&str> = Vec::new();
    for wall in [
        "text/html",
        "text/html; charset=utf-8",
        "TEXT/HTML",
        "application/json",
        "text/plain",
        "application/xhtml+xml",
        // A missing or unreadable header — `process` substitutes "" — must fail
        // closed: a real CDN image response always declares its type.
        "",
        // Near-misses that must not satisfy a `contains("image")` shortcut.
        "text/html; x-note=image/png",
        "application/imagemagick",
        "multipart/form-data; boundary=image/png",
    ] {
        if is_image_content_type(wall) {
            admitted.push(wall);
        }
    }
    assert!(
        admitted.is_empty(),
        "non-image 200 content types accepted as an avatar: {admitted:?}"
    );
}

/// The control, and what makes the gate safe to assert: every shape a real
/// avatar response actually declares still passes. Passes on the baseline and
/// on the fix, so it proves the gate keys on the media type rather than having
/// simply disabled the emitter.
#[test]
fn real_avatar_content_types_still_count_as_a_presence() {
    let mut refused: Vec<&str> = Vec::new();
    for ok in [
        "image/png",
        "image/jpeg",
        "image/gif",
        "image/webp",
        "image/avif",
        "image/svg+xml",
        // Parameters and casing are carried by real responses and must not
        // change the answer (RFC 9110: the media type is case-insensitive and
        // parameters are not part of it).
        "image/png; charset=binary",
        "IMAGE/PNG",
        "  image/jpeg  ",
        "image/jpeg ;q=1",
    ] {
        if !is_image_content_type(ok) {
            refused.push(ok);
        }
    }
    assert!(
        refused.is_empty(),
        "real avatar content types refused: {refused:?}"
    );
}
