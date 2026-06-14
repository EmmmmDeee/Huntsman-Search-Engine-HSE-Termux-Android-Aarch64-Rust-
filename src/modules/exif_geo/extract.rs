//! High-level extraction helpers: URL classification, camera device
//! fingerprinting, and owner-name sanitisation.

use super::IMAGE_EXTS;

/// True if the URL ends (case-insensitive) with one of the
/// image extensions we extract EXIF from. Query strings and
/// fragments are stripped before the check so
/// `https://x.com/a.jpg?w=1024` still matches.
pub(super) fn looks_like_image_url(url: &str) -> bool {
    let trimmed = url.trim();
    // Strip query string and fragment in one pass. `split(['?', '#'])`
    // splits at either delimiter; the first segment is the URL path,
    // which is what we want to extension-check.
    let path = trimmed.split(['?', '#']).next().unwrap_or(trimmed);
    let lower = path.to_lowercase();
    IMAGE_EXTS.iter().any(|ext| lower.ends_with(ext))
}

/// Build a stable cross-image correlation anchor for a physical camera — used
/// **only** when a serial number is present. A serial uniquely identifies one
/// device, so the same serial recovered from two images links them to the same
/// camera. Make+model alone is deliberately *not* an anchor: millions of devices
/// share `Apple iPhone 13`, so clustering on it would fuse unrelated people.
/// Returns `None` without a (non-blank) serial.
pub(super) fn device_fingerprint(
    make: Option<&str>,
    model: Option<&str>,
    serial: Option<&str>,
) -> Option<String> {
    let serial = serial.map(str::trim).filter(|s| !s.is_empty())?;
    let mut label = String::new();
    for part in [make, model]
        .into_iter()
        .flatten()
        .map(str::trim)
        .filter(|s| !s.is_empty())
    {
        if !label.is_empty() {
            label.push(' ');
        }
        label.push_str(part);
    }
    Some(if label.is_empty() {
        format!("camera s/n {serial}")
    } else {
        format!("{label} s/n {serial}")
    })
}

/// Sanitise an EXIF owner/artist string into a usable Person name, or `None` if
/// it is empty or obvious non-identity boilerplate (a copyright notice, a stock
/// agency, a software string). Conservative — a metadata name is a real lead, so
/// only clear junk is rejected.
pub(super) fn clean_owner(raw: Option<&str>) -> Option<String> {
    let s = raw?.trim();
    if s.len() < 2 || s.chars().count() > 80 || !s.chars().any(char::is_alphabetic) {
        return None;
    }
    let lower = s.to_ascii_lowercase();
    const NOISE: &[&str] = &[
        "copyright",
        "all rights",
        "getty",
        "shutterstock",
        "istock",
        "adobe",
        "unknown",
        "n/a",
        "camera owner",
    ];
    if lower.starts_with('©') || lower.starts_with("(c)") || NOISE.iter().any(|n| lower.contains(n))
    {
        return None;
    }
    Some(s.to_string())
}
