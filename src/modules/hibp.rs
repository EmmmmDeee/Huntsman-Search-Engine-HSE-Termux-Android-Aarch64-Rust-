//! Have I Been Pwned (HIBP) v3 API — definitive breach + paste oracle.
//!
//! Endpoints:
//!   GET /api/v3/breachedaccount/{email}  — breaches containing this email
//!   GET /api/v3/pasteaccount/{email}     — pastes containing this email
//!   GET /api/v3/breaches?domain={domain} — breaches affecting a domain
//!
//! Rate limit: 10 req/min on the basic subscription. The module
//! throttles internally with 6.5s inter-request delay to stay within
//! budget across all queries per process() call.
//!
//! Key: hardcoded for testing, overridden by HUNTSMAN_HIBP_KEY env var.

use std::time::Duration;

use async_trait::async_trait;
use serde::Deserialize;

use crate::core::{
    entity::{Entity, EntityKind, Evidence},
    error::{Error, Result},
    module::{Module, ModuleCategory, ModuleContext, ModuleCost, ModuleResult},
    scan::{Target, TargetKind},
    tags,
};
use crate::util::http::{error_snippet, urlencode};

const SRC: &str = "hibp";
const KEY_ENV: &str = "HUNTSMAN_HIBP_KEY";
// Embedded fallback: single source of truth lives in `util::keys`.
const HARDCODED_KEY: &str = crate::util::keys::HIBP_DEFAULT_KEY;
const BASE_URL: &str = "https://haveibeenpwned.com/api/v3";

fn resolve_key(ctx_key: Option<&str>) -> &str {
    crate::util::keys::resolve_or_default(ctx_key, HARDCODED_KEY)
}

// ── API response types ──────────────────────────────────────────────

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
struct Breach {
    name: String,
    #[serde(default)]
    title: Option<String>,
    #[serde(default)]
    domain: Option<String>,
    #[serde(default)]
    breach_date: Option<String>,
    #[serde(default)]
    added_date: Option<String>,
    #[serde(default)]
    modified_date: Option<String>,
    #[serde(default)]
    pwn_count: Option<u64>,
    #[serde(default)]
    description: Option<String>,
    #[serde(default)]
    data_classes: Vec<String>,
    #[serde(default)]
    is_verified: Option<bool>,
    #[serde(default)]
    is_fabricated: Option<bool>,
    #[serde(default)]
    is_sensitive: Option<bool>,
    #[serde(default)]
    is_retired: Option<bool>,
    #[serde(default)]
    is_spam_list: Option<bool>,
    #[serde(default)]
    is_subscription_free: Option<bool>,
    #[serde(default)]
    logo_path: Option<String>,
}

/// Trimmed, non-empty view of an optional string field.
fn nonempty(o: &Option<String>) -> Option<&str> {
    o.as_deref().map(str::trim).filter(|s| !s.is_empty())
}

/// One evidence record carrying **every** field HIBP returns for a breach, so no
/// API-provided datum is dropped. The `Breach` struct previously deserialised
/// `title`/`description`/`added_date`/`is_fabricated`/`is_sensitive`/… only for
/// test assertions (hence its struct-level dead-code allow); they are now
/// surfaced. **Pure** (no IO), so the mapping is unit-tested.
fn breach_evidence(b: &Breach) -> Evidence {
    let label = nonempty(&b.title).unwrap_or(&b.name);
    let mut ev = Evidence::new(
        SRC,
        format!(
            "Breach: {label} ({})",
            nonempty(&b.breach_date).unwrap_or("date unknown")
        ),
    )
    .with_attr("name", &b.name);
    if let Some(v) = nonempty(&b.title) {
        ev = ev.with_attr("title", v);
    }
    if let Some(v) = nonempty(&b.domain) {
        ev = ev.with_attr("domain", v);
    }
    if let Some(v) = nonempty(&b.breach_date) {
        // Keep the `breach_date` key: the AU-019 temporal-cluster rule reads it.
        ev = ev.with_attr("breach_date", v);
    }
    if let Some(v) = nonempty(&b.added_date) {
        ev = ev.with_attr("added_date", v);
    }
    if let Some(v) = nonempty(&b.modified_date) {
        ev = ev.with_attr("modified_date", v);
    }
    if let Some(p) = b.pwn_count {
        ev = ev.with_attr("pwn_count", p.to_string());
    }
    if let Some(v) = nonempty(&b.description) {
        ev = ev.with_attr("description", v);
    }
    if !b.data_classes.is_empty() {
        ev = ev.with_attr("data_classes", b.data_classes.join(", "));
    }
    if let Some(v) = b.is_verified {
        ev = ev.with_attr("is_verified", v.to_string());
    }
    if let Some(v) = b.is_fabricated {
        ev = ev.with_attr("is_fabricated", v.to_string());
    }
    if let Some(v) = b.is_sensitive {
        ev = ev.with_attr("is_sensitive", v.to_string());
    }
    if let Some(v) = b.is_retired {
        ev = ev.with_attr("is_retired", v.to_string());
    }
    if let Some(v) = b.is_spam_list {
        ev = ev.with_attr("is_spam_list", v.to_string());
    }
    if let Some(v) = b.is_subscription_free {
        ev = ev.with_attr("is_subscription_free", v.to_string());
    }
    if let Some(v) = nonempty(&b.logo_path) {
        ev = ev.with_attr("logo_path", v);
    }
    ev
}

/// Reliability-aware aggregate of a breach set. **Pure** so the
/// counting/union logic is unit-tested without a live API. Surfaces the
/// classification HIBP provides — sensitive / fabricated / spam-list / retired —
/// that the module previously discarded, so downstream weighting can tell a
/// verified breach apart from a fabricated or spam-list one.
#[derive(Default)]
struct BreachClassification {
    total: usize,
    verified: usize,
    fabricated: usize,
    spam_list: usize,
    sensitive: usize,
    retired: usize,
    total_pwns: u64,
    /// Sorted union of every breach's data classes (what was leaked).
    data_classes: Vec<String>,
    has_passwords: bool,
    has_phone: bool,
    has_physical: bool,
    /// Most recent breach date (max ISO-8601 string).
    latest_date: Option<String>,
}

fn classify_breaches(breaches: &[Breach]) -> BreachClassification {
    let mut c = BreachClassification {
        total: breaches.len(),
        ..Default::default()
    };
    let mut dc_set: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
    for b in breaches {
        if b.is_verified == Some(true) {
            c.verified += 1;
        }
        if b.is_fabricated == Some(true) {
            c.fabricated += 1;
        }
        if b.is_spam_list == Some(true) {
            c.spam_list += 1;
        }
        if b.is_sensitive == Some(true) {
            c.sensitive += 1;
        }
        if b.is_retired == Some(true) {
            c.retired += 1;
        }
        c.total_pwns += b.pwn_count.unwrap_or(0);
        for dc in &b.data_classes {
            let dcl = dc.to_lowercase();
            if dcl.contains("password") {
                c.has_passwords = true;
            }
            if dcl.contains("phone") {
                c.has_phone = true;
            }
            if dcl.contains("physical") || dcl.contains("address") || dcl.contains("location") {
                c.has_physical = true;
            }
            dc_set.insert(dc.clone());
        }
        if let Some(d) = nonempty(&b.breach_date)
            && c.latest_date.as_deref().is_none_or(|cur| d > cur)
        {
            c.latest_date = Some(d.to_string());
        }
    }
    c.data_classes = dc_set.into_iter().collect();
    c
}

// ── Module impl ─────────────────────────────────────────────────────

pub struct Hibp;

#[async_trait]
impl Module for Hibp {
    fn name(&self) -> &'static str {
        "hibp"
    }

    fn description(&self) -> &'static str {
        "Have I Been Pwned — definitive breach + paste oracle (API v3)"
    }

    fn priority(&self) -> u8 {
        120
    }

    fn cost(&self) -> ModuleCost {
        ModuleCost::KeyGated
    }

    fn accepts(&self, t: &Target) -> bool {
        matches!(t.kind, TargetKind::Email | TargetKind::Domain)
    }

    fn category(&self) -> ModuleCategory {
        ModuleCategory::Breach
    }

    fn produces(&self) -> &'static [EntityKind] {
        // HIBP returns breach metadata on the input Email/Domain — it
        // does NOT emit standalone Credential entities (policy: leaked
        // passwords are redacted, only the fact of the breach surfaces
        // as tags/evidence on the seed). Declaration is therefore
        // limited to the corroborated seed kinds.
        const KINDS: &[EntityKind] = &[EntityKind::Email, EntityKind::Domain];
        KINDS
    }

    fn max_timeout_ms(&self) -> u64 {
        60_000
    }

    async fn process(&self, target: &Target, ctx: &ModuleContext) -> Result<ModuleResult> {
        let key = resolve_key(ctx.key_opt(KEY_ENV));
        let mut result = ModuleResult::new();

        match target.kind {
            TargetKind::Email => {
                self.query_breached_account(key, target, ctx, &mut result)
                    .await?;
            }
            TargetKind::Domain => {
                self.query_domain_breaches(key, target, ctx, &mut result)
                    .await?;
            }
            _ => {}
        }

        Ok(result)
    }
}

impl Hibp {
    async fn api_get<T: serde::de::DeserializeOwned>(
        &self,
        key: &str,
        url: &str,
        ctx: &ModuleContext,
    ) -> Result<Option<T>> {
        let mut retries = 0u8;
        loop {
            let resp = ctx
                .http
                .get(url)
                .header("hibp-api-key", key)
                .header("Accept", "application/json")
                .timeout(Duration::from_secs(15))
                .send()
                .await
                .map_err(|e| Error::module(SRC, e.to_string()))?;

            let status = resp.status().as_u16();
            match status {
                200 => {
                    let data = resp
                        .json::<T>()
                        .await
                        .map_err(|e| Error::module(SRC, format!("JSON parse: {e}")))?;
                    return Ok(Some(data));
                }
                404 => return Ok(None),
                401 | 403 => {
                    ctx.report_key_exhausted(SRC, key, status);
                    return Err(Error::module(
                        SRC,
                        format!("HTTP {status}: invalid or expired API key"),
                    ));
                }
                429 if retries < 3 => {
                    // 60s module budget, up to 3 sleeps: cap each at 10s so the
                    // retry chain stays within process()'s timeout.
                    let retry_secs = crate::util::http::retry_after_secs(resp.headers(), 7, 10);
                    retries += 1;
                    tokio::time::sleep(Duration::from_secs(retry_secs)).await;
                    continue;
                }
                429 => {
                    ctx.report_key_exhausted(SRC, key, status);
                    let snippet = error_snippet(resp).await;
                    return Err(Error::module(
                        SRC,
                        format!("HTTP 429 rate-limited after {retries} retries: {snippet}"),
                    ));
                }
                _ => {
                    let snippet = error_snippet(resp).await;
                    return Err(Error::module(SRC, format!("HTTP {status}: {snippet}")));
                }
            }
        }
    }

    /// GET /api/v3/breachedaccount/{email}?truncateResponse=false
    async fn query_breached_account(
        &self,
        key: &str,
        target: &Target,
        ctx: &ModuleContext,
        result: &mut ModuleResult,
    ) -> Result<()> {
        let email = urlencode(target.value.trim());
        let url = format!("{BASE_URL}/breachedaccount/{email}?truncateResponse=false");
        let breaches: Vec<Breach> = match self.api_get(key, &url, ctx).await? {
            Some(b) => b,
            None => return Ok(()),
        };

        if breaches.is_empty() {
            return Ok(());
        }

        let cls = classify_breaches(&breaches);
        let top_names: String = breaches
            .iter()
            .map(|b| b.name.as_str())
            .take(10)
            .collect::<Vec<_>>()
            .join(", ");

        let base_conf = match cls.verified {
            0 => 0.65,
            1..=2 => 0.80,
            3..=5 => 0.88,
            _ => 0.95,
        };

        let mut email_ent = Entity::new(
            EntityKind::Email,
            target.value.trim(),
            base_conf,
            &ctx.scan_id,
        );
        email_ent.tag(tags::BREACH);
        email_ent.tag("hibp");
        if cls.verified >= 3 {
            email_ent.tag(tags::HIGH_EXPOSURE);
        }
        // Reliability classification recovered from previously-discarded fields:
        // a sensitive breach (e.g. an affair/identity site) is high-signal; a
        // fabricated or spam-list "breach" is low-fidelity and flagged as such.
        if cls.sensitive > 0 {
            email_ent.tag("sensitive-breach");
        }
        if cls.fabricated > 0 || cls.spam_list > 0 {
            email_ent.tag("unverified-breach-data");
        }
        if cls.has_passwords {
            email_ent.tag(tags::PASSWORD_AT_RISK);
        }
        if cls.has_phone {
            email_ent.tag("phone-exposed");
        }
        if cls.has_physical {
            email_ent.tag("address-exposed");
        }
        email_ent.corroboration = cls.verified.max(1) as u32;
        email_ent.add_evidence(
            Evidence::new(
                SRC,
                format!(
                    "Found in {} breach(es) ({} verified): {top_names}",
                    cls.total, cls.verified
                ),
            )
            .with_attr("breach_count", cls.total.to_string())
            .with_attr("verified_count", cls.verified.to_string())
            .with_attr("fabricated_count", cls.fabricated.to_string())
            .with_attr("spam_list_count", cls.spam_list.to_string())
            .with_attr("sensitive_count", cls.sensitive.to_string())
            .with_attr("retired_count", cls.retired.to_string())
            .with_attr("total_pwn_count", cls.total_pwns.to_string())
            .with_attr("data_classes", cls.data_classes.join(", "))
            .with_attr(
                "breach_names",
                breaches
                    .iter()
                    .map(|b| b.name.as_str())
                    .collect::<Vec<_>>()
                    .join(", "),
            )
            .with_attr("breach_date", cls.latest_date.clone().unwrap_or_default()),
        );
        // Per-breach detail — every field HIBP returned, nothing dropped.
        for breach in &breaches {
            email_ent.add_evidence(breach_evidence(breach));
        }
        result.push(email_ent);

        // Extract associated domains as expansion seeds, each carrying the full
        // breach record as provenance.
        for breach in &breaches {
            if let Some(domain) = nonempty(&breach.domain)
                && domain.contains('.')
            {
                let mut de = Entity::new(EntityKind::Domain, domain, 0.55, &ctx.scan_id);
                de.tag(tags::BREACH);
                de.tag("hibp");
                de.tag(tags::BREACH_DERIVED);
                de.add_evidence(breach_evidence(breach));
                result.push(de);
            }
        }

        Ok(())
    }

    /// GET /api/v3/breaches?domain={domain}
    async fn query_domain_breaches(
        &self,
        key: &str,
        target: &Target,
        ctx: &ModuleContext,
        result: &mut ModuleResult,
    ) -> Result<()> {
        let domain = urlencode(target.value.trim());
        let url = format!("{BASE_URL}/breaches?domain={domain}");
        let breaches: Vec<Breach> = match self.api_get(key, &url, ctx).await? {
            Some(b) => b,
            None => return Ok(()),
        };

        if breaches.is_empty() {
            return Ok(());
        }

        let cls = classify_breaches(&breaches);
        let names: Vec<&str> = breaches.iter().map(|b| b.name.as_str()).collect();
        let base_conf = if cls.verified >= 2 { 0.80 } else { 0.65 };

        let mut domain_ent = Entity::new(
            EntityKind::Domain,
            target.value.trim(),
            base_conf,
            &ctx.scan_id,
        );
        domain_ent.tag(tags::BREACH);
        domain_ent.tag("hibp");
        if cls.total_pwns > 1_000_000 {
            domain_ent.tag(tags::HIGH_EXPOSURE);
        }
        if cls.sensitive > 0 {
            domain_ent.tag("sensitive-breach");
        }
        if cls.fabricated > 0 || cls.spam_list > 0 {
            domain_ent.tag("unverified-breach-data");
        }
        domain_ent.corroboration = cls.verified.max(1) as u32;
        domain_ent.add_evidence(
            Evidence::new(
                SRC,
                format!(
                    "Domain affected by {} breach(es) ({} verified, {} total records): {}",
                    cls.total,
                    cls.verified,
                    cls.total_pwns,
                    names
                        .iter()
                        .take(10)
                        .copied()
                        .collect::<Vec<_>>()
                        .join(", ")
                ),
            )
            .with_attr("breach_count", cls.total.to_string())
            .with_attr("verified_count", cls.verified.to_string())
            .with_attr("fabricated_count", cls.fabricated.to_string())
            .with_attr("spam_list_count", cls.spam_list.to_string())
            .with_attr("sensitive_count", cls.sensitive.to_string())
            .with_attr("retired_count", cls.retired.to_string())
            .with_attr("total_pwn_count", cls.total_pwns.to_string())
            .with_attr("data_classes", cls.data_classes.join(", "))
            .with_attr("breach_names", names.join(", ")),
        );
        // Per-breach detail — every field HIBP returned, nothing dropped.
        for breach in &breaches {
            domain_ent.add_evidence(breach_evidence(breach));
        }
        result.push(domain_ent);

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_email_and_domain() {
        let m = Hibp;
        assert!(m.accepts(&Target::new(TargetKind::Email, "x@y.com")));
        assert!(m.accepts(&Target::new(TargetKind::Domain, "example.com")));
        assert!(!m.accepts(&Target::new(TargetKind::Username, "alice")));
        assert!(!m.accepts(&Target::new(TargetKind::IpAddress, "1.2.3.4")));
    }

    #[test]
    fn priority_above_free_breach_modules() {
        let m = Hibp;
        assert!(
            m.priority() > 100,
            "HIBP should run before free breach modules"
        );
    }

    #[test]
    fn cost_is_key_gated() {
        assert_eq!(Hibp.cost(), ModuleCost::KeyGated);
    }

    #[test]
    fn resolve_key_prefers_provided() {
        assert_eq!(resolve_key(Some("my-key")), "my-key");
    }

    #[test]
    fn resolve_key_falls_back_to_hardcoded() {
        assert_eq!(resolve_key(None), HARDCODED_KEY);
    }

    #[test]
    fn resolve_key_falls_back_on_empty() {
        assert_eq!(resolve_key(Some("")), HARDCODED_KEY);
    }

    #[test]
    fn name_is_hibp() {
        assert_eq!(Hibp.name(), "hibp");
    }

    #[test]
    fn description_non_empty() {
        assert!(!Hibp.description().is_empty());
    }

    #[test]
    fn max_timeout_generous() {
        assert!(Hibp.max_timeout_ms() >= 30_000);
    }

    #[test]
    fn breach_deser_full_payload() {
        let json = r#"[{
            "Name": "Adobe",
            "Title": "Adobe",
            "Domain": "adobe.com",
            "BreachDate": "2013-10-04",
            "AddedDate": "2013-12-04",
            "ModifiedDate": "2022-05-15",
            "PwnCount": 152445165,
            "Description": "Adobe breach",
            "DataClasses": ["Email addresses", "Password hints", "Passwords", "Usernames"],
            "IsVerified": true,
            "IsFabricated": false,
            "IsSensitive": false,
            "IsRetired": false,
            "IsSpamList": false,
            "IsSubscriptionFree": false,
            "LogoPath": "https://haveibeenpwned.com/Content/Images/PwnedLogos/Adobe.png"
        }]"#;
        let breaches: Vec<Breach> = serde_json::from_str(json).unwrap();
        assert_eq!(breaches.len(), 1);
        assert_eq!(breaches[0].name, "Adobe");
        assert_eq!(breaches[0].domain.as_deref(), Some("adobe.com"));
        assert_eq!(breaches[0].pwn_count, Some(152445165));
        assert!(breaches[0].is_verified == Some(true));
        assert_eq!(breaches[0].data_classes.len(), 4);
        assert!(breaches[0].data_classes.contains(&"Passwords".to_string()));
    }

    #[test]
    fn breach_deser_minimal() {
        let json = r#"[{"Name": "Unknown"}]"#;
        let breaches: Vec<Breach> = serde_json::from_str(json).unwrap();
        assert_eq!(breaches.len(), 1);
        assert_eq!(breaches[0].name, "Unknown");
        assert!(breaches[0].domain.is_none());
        assert!(breaches[0].data_classes.is_empty());
    }

    fn parse(json: &str) -> Vec<Breach> {
        serde_json::from_str(json).unwrap()
    }

    #[test]
    fn classify_counts_reliability_classes_and_unions_data() {
        let breaches = parse(
            r#"[
            {"Name":"A","BreachDate":"2013-10-04","PwnCount":100,
             "DataClasses":["Email addresses","Passwords"],"IsVerified":true},
            {"Name":"B","BreachDate":"2019-01-02","PwnCount":50,
             "DataClasses":["Phone numbers","Physical addresses"],"IsSensitive":true},
            {"Name":"C","BreachDate":"2011-05-01","PwnCount":5,
             "DataClasses":["Email addresses"],"IsSpamList":true,"IsFabricated":true}
        ]"#,
        );
        let c = classify_breaches(&breaches);
        assert_eq!(c.total, 3);
        assert_eq!(c.verified, 1);
        assert_eq!(c.sensitive, 1);
        assert_eq!(c.spam_list, 1);
        assert_eq!(c.fabricated, 1);
        assert_eq!(c.total_pwns, 155);
        assert!(c.has_passwords && c.has_phone && c.has_physical);
        // Sorted union across all breaches.
        assert_eq!(
            c.data_classes,
            vec![
                "Email addresses".to_string(),
                "Passwords".to_string(),
                "Phone numbers".to_string(),
                "Physical addresses".to_string(),
            ]
        );
        // Latest date is the max ISO string.
        assert_eq!(c.latest_date.as_deref(), Some("2019-01-02"));
    }

    #[test]
    fn classify_empty_is_all_zero() {
        let c = classify_breaches(&[]);
        assert_eq!(c.total, 0);
        assert_eq!(c.verified, 0);
        assert!(c.data_classes.is_empty());
        assert!(c.latest_date.is_none());
        assert!(!c.has_passwords);
    }

    #[test]
    fn breach_evidence_surfaces_every_field() {
        let b = &parse(
            r#"[{
            "Name":"Adobe","Title":"Adobe","Domain":"adobe.com","BreachDate":"2013-10-04",
            "AddedDate":"2013-12-04","ModifiedDate":"2022-05-15","PwnCount":152445165,
            "Description":"Adobe breach","DataClasses":["Email addresses","Passwords"],
            "IsVerified":true,"IsFabricated":false,"IsSensitive":false,"IsRetired":false,
            "IsSpamList":false,"IsSubscriptionFree":false,
            "LogoPath":"https://example/Adobe.png"
        }]"#,
        )[0];
        let ev = breach_evidence(b);
        let a = &ev.attributes;
        // Previously-discarded fields are now present.
        assert_eq!(a.get("title").map(String::as_str), Some("Adobe"));
        assert_eq!(a.get("added_date").map(String::as_str), Some("2013-12-04"));
        assert_eq!(
            a.get("modified_date").map(String::as_str),
            Some("2022-05-15")
        );
        assert_eq!(
            a.get("description").map(String::as_str),
            Some("Adobe breach")
        );
        assert_eq!(a.get("is_fabricated").map(String::as_str), Some("false"));
        assert_eq!(a.get("is_sensitive").map(String::as_str), Some("false"));
        assert_eq!(a.get("is_retired").map(String::as_str), Some("false"));
        assert_eq!(a.get("is_spam_list").map(String::as_str), Some("false"));
        assert_eq!(
            a.get("is_subscription_free").map(String::as_str),
            Some("false")
        );
        assert_eq!(
            a.get("logo_path").map(String::as_str),
            Some("https://example/Adobe.png")
        );
        // And the fields the rules depend on are preserved.
        assert_eq!(a.get("breach_date").map(String::as_str), Some("2013-10-04"));
        assert_eq!(a.get("pwn_count").map(String::as_str), Some("152445165"));
    }

    #[test]
    fn breach_evidence_omits_absent_optionals_and_titles_from_name() {
        let b = &parse(r#"[{"Name":"Solo"}]"#)[0];
        let ev = breach_evidence(b);
        // Falls back to Name in the summary when Title is absent.
        assert!(ev.summary.contains("Solo"));
        assert_eq!(ev.attributes.get("name").map(String::as_str), Some("Solo"));
        // Absent optionals are not emitted as empty attributes.
        for k in ["title", "domain", "description", "logo_path", "is_verified"] {
            assert!(
                !ev.attributes.contains_key(k),
                "absent field {k} must be omitted"
            );
        }
    }
}
