//! HaveIBeenPwned Pwned Passwords — k-Anonymity password hash check.
//!
//! Endpoint: `GET https://api.pwnedpasswords.com/range/{first_5_chars_of_sha1}`
//! Auth:     None (100% free, no rate limit).
//!
//! Securely verifies if a credential's password hash exists in known
//! breach datasets using k-Anonymity (only the first 5 chars of the
//! SHA-1 hash are sent).

use async_trait::async_trait;
use sha1::{Digest, Sha1};

use crate::core::{
    entity::{Entity, Evidence},
    error::{Error, Result},
    module::{Module, ModuleCategory, ModuleContext, ModuleResult},
    scan::{Target, TargetKind},
};
use crate::util::http::RequestBuilderExt;

const SRC: &str = "pwned_passwords";

pub struct PwnedPasswords;

/// Parse the breach count for `suffix` out of a k-Anonymity range body.
/// **Pure** (no network). The body is the plain-text `SUFFIX:count` listing
/// returned for one 5-char SHA-1 prefix; the (unique) line whose suffix matches
/// `suffix` (case-insensitively) yields its count. `None` when the suffix is
/// absent or its count is unparseable — `find` stops at the first match,
/// mirroring the original break.
fn parse_breach_count(body: &str, suffix: &str) -> Option<u64> {
    body.lines()
        .filter_map(|line| line.trim().split_once(':'))
        .find(|(hash_suffix, _)| hash_suffix.eq_ignore_ascii_case(suffix))
        .and_then(|(_, count_str)| count_str.trim().parse().ok())
}

/// Confidence band for a pwned-password hit: more breach occurrences ⇒ higher
/// confidence the credential is genuinely compromised. **Pure.**
fn confidence_for(count: u64) -> f64 {
    if count >= 100 {
        0.90
    } else if count >= 10 {
        0.80
    } else {
        0.70
    }
}

/// Map a k-Anonymity breach `count` for `target` to its entities. **Pure** (no
/// network), so the count→confidence→tag→evidence mapping is unit-testable.
///
/// Emits a single subject entity (the queried Email/Username) tagged
/// `pwned-password` + `breach`, carrying the breach count and the SHA-1 prefix
/// as evidence. Returns an empty `Vec` when `count == 0` (the API's "not found"
/// signal — padding rows report a zero count), so a non-hit produces nothing.
fn build_entities(target: &Target, count: u64, prefix: &str, scan_id: &str) -> Vec<Entity> {
    if count == 0 {
        return Vec::new();
    }
    let mut entity = Entity::new(
        target.kind.to_entity_kind(),
        &target.value,
        confidence_for(count),
        scan_id,
    );
    entity.tag("pwned-password");
    entity.tag("breach");
    entity.add_evidence(
        Evidence::new(
            SRC,
            format!("HIBP Pwned Passwords: value seen in {count} breach(es) (k-Anonymity check)"),
        )
        .with_attr("breach_count", count.to_string())
        .with_attr("sha1_prefix", prefix),
    );
    vec![entity]
}

#[async_trait]
impl Module for PwnedPasswords {
    fn name(&self) -> &'static str {
        "pwned_passwords"
    }
    fn description(&self) -> &'static str {
        "HIBP Pwned Passwords k-Anonymity check for credential breach exposure"
    }
    fn priority(&self) -> u8 {
        115
    }
    fn category(&self) -> ModuleCategory {
        ModuleCategory::Breach
    }
    fn accepts(&self, t: &Target) -> bool {
        matches!(t.kind, TargetKind::Email | TargetKind::Username)
    }
    fn max_timeout_ms(&self) -> u64 {
        // Single k-anonymity range GET with no per-request timeout; the 3s
        // default would kill a slow-but-connected response as a spurious
        // engine "timeout".
        10_000
    }

    fn is_passive(&self) -> bool {
        // NOT passive: this module makes an outbound request to
        // api.pwnedpasswords.com. `--passive-only` is documented as "skip
        // network-reaching modules", and the trait defines passive as
        // local-sensor / no-network — so a module that queries a remote API
        // must report false or it would silently egress under passive-only.
        false
    }

    fn produces(&self) -> &'static [crate::core::entity::EntityKind] {
        use crate::core::entity::EntityKind;
        const KINDS: &[EntityKind] = &[EntityKind::Email, EntityKind::Username];
        KINDS
    }

    async fn process(&self, target: &Target, ctx: &ModuleContext) -> Result<ModuleResult> {
        let value = target.value.trim();
        if value.is_empty() {
            return Ok(ModuleResult::new());
        }

        let mut hasher = Sha1::new();
        hasher.update(value.as_bytes());
        let hash = hex::encode(hasher.finalize()).to_uppercase();

        if hash.len() < 5 {
            return Ok(ModuleResult::new());
        }

        let prefix = &hash[..5];
        let suffix = &hash[5..];

        let url = format!("https://api.pwnedpasswords.com/range/{prefix}");

        let resp = ctx
            .http
            .get(&url)
            .header("Add-Padding", "true")
            .send_tagged(SRC)
            .await?;

        if !resp.status().is_success() {
            return Ok(ModuleResult::new());
        }

        let body = resp
            .text()
            .await
            .map_err(|e| Error::module(SRC, e.to_string()))?;

        let Some(count) = parse_breach_count(&body, suffix) else {
            return Ok(ModuleResult::new());
        };

        let mut result = ModuleResult::new();
        result.entities = build_entities(target, count, prefix, &ctx.scan_id);
        Ok(result)
    }
}

#[cfg(test)]
mod tests {
    include!("tests.rs");
}
