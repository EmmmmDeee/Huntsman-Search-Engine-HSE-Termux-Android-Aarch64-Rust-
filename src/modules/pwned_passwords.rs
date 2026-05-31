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
    module::{Module, ModuleContext, ModuleResult},
    scan::{Target, TargetKind},
};

const SRC: &str = "pwned_passwords";

pub struct PwnedPasswords;

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
            .send()
            .await
            .map_err(|e| Error::module(SRC, e.to_string()))?;

        if !resp.status().is_success() {
            return Ok(ModuleResult::new());
        }

        let body = resp
            .text()
            .await
            .map_err(|e| Error::module(SRC, e.to_string()))?;

        let mut breach_count: Option<u64> = None;
        for line in body.lines() {
            let line = line.trim();
            if let Some((hash_suffix, count_str)) = line.split_once(':')
                && hash_suffix.eq_ignore_ascii_case(suffix)
            {
                breach_count = count_str.trim().parse().ok();
                break;
            }
        }

        let Some(count) = breach_count else {
            return Ok(ModuleResult::new());
        };
        if count == 0 {
            return Ok(ModuleResult::new());
        }

        let mut result = ModuleResult::new();
        let confidence = if count >= 100 {
            0.90
        } else if count >= 10 {
            0.80
        } else {
            0.70
        };
        let mut entity = Entity::new(
            target.kind.to_entity_kind(),
            &target.value,
            confidence,
            &ctx.scan_id,
        );
        entity.tag("pwned-password");
        entity.tag("breach");

        entity.add_evidence(
            Evidence::new(
                SRC,
                format!(
                    "HIBP Pwned Passwords: value seen in {count} breach(es) (k-Anonymity check)"
                ),
            )
            .with_attr("breach_count", count.to_string())
            .with_attr("sha1_prefix", prefix),
        );

        result.push(entity);
        Ok(result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_email_and_username() {
        let m = PwnedPasswords;
        assert!(m.accepts(&Target::new(TargetKind::Email, "x@y.com")));
        assert!(m.accepts(&Target::new(TargetKind::Username, "test")));
        assert!(!m.accepts(&Target::new(TargetKind::Domain, "x.com")));
    }

    #[test]
    fn module_metadata() {
        assert_eq!(PwnedPasswords.name(), "pwned_passwords");
        assert_eq!(PwnedPasswords.priority(), 115);
        assert_eq!(PwnedPasswords.max_timeout_ms(), 10_000);
        // Network-reaching (api.pwnedpasswords.com) → not passive.
        assert!(!PwnedPasswords.is_passive());
    }

    #[test]
    fn sha1_hash_format() {
        use sha1::{Digest, Sha1};
        let mut h = Sha1::new();
        h.update(b"password");
        let hash = hex::encode(h.finalize()).to_uppercase();
        assert_eq!(hash.len(), 40);
        assert_eq!(&hash[..5], "5BAA6");
    }
}
