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
    confidence,
    entity::{Entity, EntityKind, Evidence},
    error::Result,
    module::{Module, ModuleCategory, ModuleContext, ModuleResult},
    scan::{Target, TargetKind},
};
use crate::util::http::{RequestBuilderExt, read_body_capped, urldecode, urlencode};

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
        "PGP keyserver recon — pivots an email to owner name and alternate emails via the HKP index"
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
        // Credential: the key fingerprint as a correlatable artifact (the PGP
        // analogue of github_user's ssh-key) that AU-048 links across accounts.
        const KINDS: &[EntityKind] = &[
            EntityKind::Person,
            EntityKind::Email,
            EntityKind::Credential,
        ];
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
        let resp = ctx.http.get(&url).send_tagged(SRC).await?;
        // 404 is the keyserver's clean "no PGP key for this email" signal — keep
        // it as an empty result. But a transport error (propagated above) or any
        // OTHER non-2xx (5xx outage, 429 throttle, proxy error page) is a real
        // keyserver failure, not an absence of keys: surfacing it instead of a
        // silent empty stops a keyserver outage from masquerading as "this email
        // has no PGP key."
        if resp.status().as_u16() == 404 {
            return Ok(result);
        }
        if !resp.status().is_success() {
            return Err(crate::util::http::http_status_error(SRC, resp).await);
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
    let mut seen_person = std::collections::HashSet::new();
    let mut seen_email = std::collections::HashSet::new();
    // fingerprint → every email bound to that key (the queried one plus each UID
    // email). Becomes a correlatable Credential below, the PGP analogue of
    // github_user's ssh-key: a key bound to two distinct controllers is the
    // AU-048 "shared public key links accounts" signal.
    let mut key_emails: std::collections::BTreeMap<String, std::collections::BTreeSet<String>> =
        std::collections::BTreeMap::new();

    // Group the flat line stream into per-key blocks: each `pub:` line starts a
    // new key, and every `uid:` line up to the next `pub:` belongs to it. A
    // `uid:` line with no preceding `pub:` is malformed input and dropped.
    let mut blocks: Vec<(String, Vec<&str>)> = Vec::new();
    for line in body.lines() {
        if let Some(rest) = line.strip_prefix("pub:") {
            blocks.push((rest.split(':').next().unwrap_or("").to_string(), Vec::new()));
        } else if line.starts_with("uid:")
            && let Some((_, uids)) = blocks.last_mut()
        {
            uids.push(line);
        }
    }

    for (fingerprint, uid_lines) in &blocks {
        let decoded: Vec<(Option<String>, Option<String>, String)> = uid_lines
            .iter()
            .map(|line| {
                let rest = line.strip_prefix("uid:").unwrap_or(line);
                let raw_uid = rest.split(':').next().unwrap_or("");
                let uid = urldecode(raw_uid);
                let (name, email) = split_uid(&uid);
                (name.map(str::to_string), email.map(str::to_string), uid)
            })
            .collect();

        // `exact=on` is a per-KEY match guarantee from the keyserver, not a
        // per-UID one: a key can legitimately carry several UIDs (that's the
        // whole point — "every other email bound to the same key"), but if the
        // server ever returns an unrelated key (fuzzy fallback, keyserver bug),
        // NONE of its UIDs name the queried address. Trusting that key's other
        // UIDs would misattribute a stranger's name and emails to this query,
        // so gate the whole key on actually containing the queried email.
        let key_matches_query = decoded.iter().any(|(_, email, _)| {
            email
                .as_deref()
                .is_some_and(|e| e.to_lowercase() == query_lower)
        });
        if !key_matches_query {
            continue;
        }

        for (name, email, uid) in &decoded {
            let ev = || {
                let mut e = Evidence::new(SRC, "PGP keyserver User ID");
                if !fingerprint.is_empty() {
                    e = e.with_attr("key_fingerprint", fingerprint);
                }
                e.with_attr("uid", uid)
            };

            if let Some(name) = name
                && name.trim().contains(' ')
                && seen_person.insert(name.to_lowercase())
            {
                let mut e = Entity::new(EntityKind::Person, name.trim(), confidence::HIGH, scan_id);
                e.tag(SRC);
                e.add_evidence(ev());
                result.push(e);
            }
            if let Some(email) = email {
                let lower = email.to_lowercase();
                if lower.contains('@') && !fingerprint.is_empty() {
                    // Bind EVERY UID email (including the queried one) to the
                    // key, so the Credential carries the full controller set.
                    key_emails
                        .entry(fingerprint.clone())
                        .or_default()
                        .insert(lower.clone());
                }
                // Alternate emails bound to the same key are the high-value
                // pivot; the queried email itself adds nothing new standalone.
                if lower.contains('@') && lower != query_lower && seen_email.insert(lower) {
                    let mut e =
                        Entity::new(EntityKind::Email, email, confidence::HIGH_PLUS, scan_id);
                    e.tag(SRC);
                    e.tag("pgp-linked");
                    e.add_evidence(ev());
                    result.push(e);
                }
            }
        }
    }

    // Mint each key as a fingerprinted, CORRELATABLE Credential — value
    // `pgp:<fp>` so the SAME key recovered for two different seeds dedups to one
    // artifact carrying both controllers' emails, which AU-048 then links (the
    // exact mechanism github_user's `ssh:<fp>` artifact uses). The queried email
    // is always bound (the key matched it), so a key whose UIDs name a second,
    // distinct identity fires the link even within a single scan.
    for (fp, emails) in key_emails {
        if fp.is_empty() {
            continue;
        }
        let value = format!("pgp:{}", fp.to_lowercase());
        let mut cred = Entity::new(
            EntityKind::Credential,
            &value,
            confidence::HIGH_PLUSPLUS_PLUS,
            scan_id,
        );
        cred.tag("pgp-key");
        cred.tag("public-key");
        cred.tag(SRC);
        for email in &emails {
            cred.add_evidence(
                Evidence::new(SRC, format!("PGP public key {fp} bound to {email}"))
                    .with_attr("email", email)
                    .with_attr("key_fingerprint", &fp),
            );
        }
        result.push(cred);
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
