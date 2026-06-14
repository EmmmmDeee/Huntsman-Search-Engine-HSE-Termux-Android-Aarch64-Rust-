/// Stable fingerprint of an SSH public key for cross-account correlation:
/// `ssh:<first-16-hex of SHA-256(algo + " " + base64)>`. The trailing comment
/// (`user@host`) is dropped — it varies between machines while the key material
/// is the identity, so the same key on two accounts yields the same fingerprint.
/// Returns `None` for a malformed key (missing algo/base64).
pub(super) fn ssh_fingerprint(raw: &str) -> Option<String> {
    use sha2::{Digest, Sha256};
    let mut parts = raw.split_whitespace();
    let algo = parts.next()?;
    let blob = parts.next()?;
    if blob.len() < 16 {
        return None; // not a plausible key body
    }
    let mut hasher = Sha256::new();
    hasher.update(algo.as_bytes());
    hasher.update(b" ");
    hasher.update(blob.as_bytes());
    let digest = hasher.finalize();
    Some(format!("ssh:{}", hex::encode(&digest[..8])))
}

/// Normalise and vet a commit-author email for emission: trimmed + lowercased,
/// must be a plausible address, and must NOT be one of GitHub's privacy
/// placeholders (`…@users.noreply.github.com`, any `noreply`/`*.github.com`
/// address) which carry no real identity. Returns the clean address, or `None`
/// to drop it.
pub(super) fn usable_commit_email(raw: &str) -> Option<String> {
    let email = raw.trim().to_lowercase();
    if email.len() < 5
        || !email.contains('@')
        || email.contains("noreply")
        || email.ends_with("@github.com")
        || email.ends_with(".github.com")
    {
        return None;
    }
    Some(email)
}

/// Top-`n` event types formatted as `type=count`, ranked by count descending
/// then type-name ascending. The name tiebreak makes the ranking deterministic
/// even though `event_types` comes from a `HashMap` (randomised iteration
/// order) — so the `top_event_types` finding is byte-reproducible.
pub(super) fn top_event_types(
    event_types: std::collections::HashMap<String, u32>,
    n: usize,
) -> Vec<String> {
    let mut sorted: Vec<(String, u32)> = Vec::with_capacity(event_types.len());
    sorted.extend(event_types);
    sorted.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
    sorted
        .into_iter()
        .take(n)
        .map(|(t, c)| format!("{t}={c}"))
        .collect()
}
