//! PGP keyserver lookup — free, no-credential email → identity enrichment.
//!
//! Queries the HKP **machine-readable index** (`op=index&options=mr`) on a
//! public SKS-style keyserver. The index returns colon-delimited `pub:`/`uid:`
//! records — no OpenPGP packet parsing required, no key download — and each
//! User ID is a `Name <email>` string. From one email that resolves to a key we
//! recover the owner's **real name** and **every other email** bound to the same
//! key: a pure, free identity-graph edge that strongly corroborates breach /
//! social / gravatar findings (cross-correlation), with zero credentials.
//!
//! Endpoint: `https://keyserver.ubuntu.com/pks/lookup?op=index&options=mr&search=<email>`
//! (SKS-style `op=index` is used over keys.openpgp.org, which hides UIDs by
//! default for privacy and so returns nothing useful for this purpose).

use async_trait::async_trait;

use crate::core::{
    entity::{Entity, EntityKind, Evidence},
    error::Result,
    module::{Module, ModuleCategory, ModuleContext, ModuleResult},
    scan::{Target, TargetKind},
};
use crate::util::http::{read_body_capped, urldecode, urlencode};

const SRC: &str = "pgp";

/// HKP index responses are small (a handful of keys); 256 KiB is generous and
/// bounds a hostile/oversized reply on a low-memory device.
const BODY_CAP: usize = 256 * 1024;

pub struct Pgp;

#[async_trait]
impl Module for Pgp {
    fn name(&self) -> &'static str {
        "pgp"
    }

    fn description(&self) -> &'static str {
        "PGP keyserver lookup (email → owner name + alternate emails via HKP index)"
    }

    fn priority(&self) -> u8 {
        91
    }

    fn accepts(&self, t: &Target) -> bool {
        matches!(t.kind, TargetKind::Email)
    }

    fn category(&self) -> ModuleCategory {
        ModuleCategory::People
    }

    fn attack_techniques(&self) -> &'static [&'static str] {
        // People default (T1589.003 Employee Names + T1591.004 Identify Roles).
        // PGP key lookup surfaces the key owner's real name (T1589.003) and
        // email address (T1589.002) — but carries no role/organisational
        // information, so T1591.004 is over-claimed. Replacing with the precise
        // pair that matches the produced entity kinds.
        &["T1589.002", "T1589.003"]
    }

    fn max_timeout_ms(&self) -> u64 {
        12_000
    }

    fn produces(&self) -> &'static [EntityKind] {
        const KINDS: &[EntityKind] = &[EntityKind::Person, EntityKind::Email];
        KINDS
    }

    async fn process(&self, target: &Target, ctx: &ModuleContext) -> Result<ModuleResult> {
        let mut result = ModuleResult::new();
        let email = target.value.trim();
        if !email.contains('@') {
            return Ok(result);
        }
        let url = format!(
            "https://keyserver.ubuntu.com/pks/lookup?op=index&options=mr&exact=on&search={}",
            urlencode(email)
        );
        let resp = match ctx.http.get(&url).send().await {
            Ok(r) => r,
            Err(_) => return Ok(result), // network hiccup → quiet, not fatal
        };
        // 404 / no-keys is the clean "no PGP key for this email" signal.
        if !resp.status().is_success() {
            return Ok(result);
        }
        let Some(body) = read_body_capped(resp, BODY_CAP).await else {
            return Ok(result);
        };

        extract(&body, email, &ctx.scan_id, &mut result);
        Ok(result)
    }
}

/// Parse an HKP machine-readable index body into entities. Pure of I/O so it is
/// unit-tested against a fixture. Format (per the HKP draft):
///   `pub:<fingerprint>:<algo>:<len>:<created>:<expires>:<flags>`
///   `uid:<URL-encoded "Name <email>">:<created>:<expires>:<flags>`
fn extract(body: &str, query_email: &str, scan_id: &str, result: &mut ModuleResult) {
    let query_lower = query_email.to_lowercase();
    let mut fingerprint = String::new();
    // Collect a few fingerprints for evidence; the most recent `pub:` applies to
    // the `uid:` lines that follow it.
    let mut seen_person = std::collections::HashSet::new();
    let mut seen_email = std::collections::HashSet::new();

    for line in body.lines() {
        if let Some(rest) = line.strip_prefix("pub:") {
            fingerprint = rest.split(':').next().unwrap_or("").to_string();
            continue;
        }
        let Some(rest) = line.strip_prefix("uid:") else {
            continue;
        };
        let raw_uid = rest.split(':').next().unwrap_or("");
        let uid = urldecode(raw_uid);
        let (name, email) = split_uid(&uid);

        let ev = || {
            let mut e = Evidence::new(SRC, "PGP keyserver User ID");
            if !fingerprint.is_empty() {
                e = e.with_attr("key_fingerprint", &fingerprint);
            }
            e.with_attr("uid", &uid)
        };

        if let Some(name) = name
            && name.trim().contains(' ')
            && seen_person.insert(name.to_lowercase())
        {
            let mut e = Entity::new(EntityKind::Person, name.trim(), 0.65, scan_id);
            e.tag(SRC);
            e.add_evidence(ev());
            result.push(e);
        }
        if let Some(email) = email {
            let lower = email.to_lowercase();
            // Alternate emails bound to the same key are the high-value pivot;
            // the queried email itself adds nothing new.
            if lower.contains('@') && lower != query_lower && seen_email.insert(lower) {
                let mut e = Entity::new(EntityKind::Email, email, 0.70, scan_id);
                e.tag(SRC);
                e.tag("pgp-linked");
                e.add_evidence(ev());
                result.push(e);
            }
        }
    }
}

/// Split a `Name <email>` User ID into `(name, email)`, either of which may be
/// absent. Tolerant of `Name` only, `<email>` only, or a bare email.
fn split_uid(uid: &str) -> (Option<&str>, Option<&str>) {
    if let (Some(lt), Some(gt)) = (uid.find('<'), uid.rfind('>'))
        && lt < gt
    {
        let name = uid[..lt].trim();
        let email = uid[lt + 1..gt].trim();
        return (
            (!name.is_empty()).then_some(name),
            (!email.is_empty()).then_some(email),
        );
    }
    // No angle brackets: a bare email, or a name with no address.
    let t = uid.trim();
    if t.contains('@') && !t.contains(' ') {
        (None, Some(t))
    } else {
        ((!t.is_empty()).then_some(t), None)
    }
}

#[cfg(test)]
mod tests {
    include!("tests.rs");
}
