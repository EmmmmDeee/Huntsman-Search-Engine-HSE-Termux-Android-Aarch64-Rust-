//! IPQualityScore (IPQS) reputation lookup. Key-gated; free tier available.
//!
//! Three endpoints sharing the same URL shape and key dispatch:
//!   * IP:    `GET /api/json/ip/{key}/{ip}`
//!   * Email: `GET /api/json/email/{key}/{email}`
//!   * Phone: `GET /api/json/phone/{key}/{phone}`
//!
//! Each returns a `fraud_score` (0–100) plus type-specific signals.
//! We tag risky outputs (`high-risk`, `proxy`, `vpn`, `tor`, `disposable`,
//! `recent_abuse`) and embed the raw score in evidence for triage.

use async_trait::async_trait;
use serde::Deserialize;

use crate::core::{
    confidence,
    entity::{Entity, EntityKind, Evidence},
    error::{Error, Result},
    module::{Module, ModuleCategory, ModuleContext, ModuleCost, ModuleResult},
    scan::{Target, TargetKind},
};
use crate::util::http::urlencode;

const KEY_ENV: &str = "HUNTSMAN_IPQS_KEY";

#[derive(Deserialize)]
struct Common {
    #[serde(default)]
    success: Option<bool>,
    /// The human message IPQS returns alongside `success:false` — distinguishes a
    /// dead/exhausted key ("You have insufficient credits…", "Invalid API key")
    /// from a genuinely invalid target ("Please enter a valid IP address").
    #[serde(default)]
    message: Option<String>,
    #[serde(default)]
    fraud_score: Option<i32>,
    #[serde(default)]
    recent_abuse: Option<bool>,
    // IP-specific
    #[serde(default)]
    proxy: Option<bool>,
    #[serde(default)]
    vpn: Option<bool>,
    #[serde(default)]
    tor: Option<bool>,
    #[serde(default)]
    is_crawler: Option<bool>,
    #[serde(default)]
    isp: Option<String>,
    #[serde(default)]
    organization: Option<String>,
    #[serde(default)]
    country_code: Option<String>,
    #[serde(default)]
    asn: Option<i64>,
    // Email-specific
    #[serde(default)]
    valid: Option<bool>,
    #[serde(default)]
    disposable: Option<bool>,
    #[serde(default)]
    deliverability: Option<String>,
    #[serde(default)]
    smtp_score: Option<i32>,
    #[serde(default)]
    leaked: Option<bool>,
    #[serde(default)]
    first_seen: Option<FirstSeen>,
    // Phone-specific
    #[serde(default)]
    line_type: Option<String>,
    #[serde(default)]
    carrier: Option<String>,
    #[serde(default)]
    active: Option<bool>,
}

#[derive(Deserialize)]
struct FirstSeen {
    #[serde(default)]
    human: Option<String>,
}

const SRC: &str = "ipqs";

/// `fraud_score` at/above this is treated as actively malicious (`high-risk`).
const HIGH_RISK_SCORE: i32 = 85;
/// `fraud_score` at/above this (but below [`HIGH_RISK_SCORE`]) is `elevated-risk`.
const ELEVATED_RISK_SCORE: i32 = 50;

/// Map an IPQS reputation response onto the target's entity. **Pure** (no
/// network/IO): translates the `fraud_score` into a single risk tag
/// (`high-risk` ≥ [`HIGH_RISK_SCORE`], else `elevated-risk` ≥
/// [`ELEVATED_RISK_SCORE`]), raises the boolean signal tags
/// (proxy/vpn/tor/crawler/disposable/leaked/recent-abuse) only when the API said
/// `true`, and emits a `country:<CC>` tag, then records every present
/// type-specific field as evidence. `endpoint` is the IPQS sub-API (`ip` /
/// `email` / `phone`) the response came from.
fn build_reputation_entity(
    kind: EntityKind,
    endpoint: &str,
    value: &str,
    body: &Common,
    scan_id: &str,
) -> Entity {
    let mut entity = Entity::new(kind, value, confidence::HIGH_PLUSPLUS_PLUS, scan_id);
    entity.tag("ipqs");

    let score = body.fraud_score.unwrap_or(0);
    if score >= HIGH_RISK_SCORE {
        entity.tag("high-risk");
    } else if score >= ELEVATED_RISK_SCORE {
        entity.tag("elevated-risk");
    }
    // Boolean signal tags — raised only on an explicit `true`.
    crate::util::geo::tag_flags(
        &mut entity,
        &[
            (body.proxy, "proxy"),
            (body.vpn, "vpn"),
            (body.tor, "tor"),
            (body.is_crawler, "crawler"),
            (body.disposable, "disposable"),
            (body.leaked, "leaked"),
            (body.recent_abuse, "recent-abuse"),
        ],
    );
    if let Some(c) = body.country_code.as_deref() {
        entity.tag(format!("country:{}", c.to_uppercase()));
    }

    let mut ev = Evidence::new(
        SRC,
        format!("IPQS {endpoint} reputation for {value} (fraud_score={score})"),
    )
    .with_attr("endpoint", endpoint)
    .with_attr("fraud_score", score.to_string());
    if let Some(v) = body.isp.as_deref() {
        ev = ev.with_attr("isp", v);
    }
    if let Some(v) = body.organization.as_deref() {
        ev = ev.with_attr("organization", v);
    }
    if let Some(v) = body.asn {
        ev = ev.with_attr("asn", v.to_string());
    }
    if let Some(v) = body.country_code.as_deref() {
        ev = ev.with_attr("country", v);
    }
    if let Some(v) = body.deliverability.as_deref() {
        ev = ev.with_attr("deliverability", v);
    }
    if let Some(v) = body.smtp_score {
        ev = ev.with_attr("smtp_score", v.to_string());
    }
    if let Some(v) = body.line_type.as_deref() {
        ev = ev.with_attr("line_type", v);
    }
    if let Some(v) = body.carrier.as_deref() {
        ev = ev.with_attr("carrier", v);
    }
    if let Some(v) = body.valid {
        ev = ev.with_attr("valid", v.to_string());
    }
    if let Some(v) = body.active {
        ev = ev.with_attr("active", v.to_string());
    }
    if let Some(fs) = body.first_seen.as_ref()
        && let Some(h) = fs.human.as_deref()
    {
        ev = ev.with_attr("first_seen", h);
    }
    entity.add_evidence(ev);
    entity
}

/// What a 200 body means to the key cascade: `success:false` with a key/quota
/// message burns the key and rotates; ANY other `success:false` — whatever its
/// text, or none — is accepted and then failed by [`accepted`], so a backend
/// fault, a suspended account or a plan restriction is never read as "IPQS
/// holds nothing" (the stolen_tax backlog #40 shape, REQ-SUCCESSFLAG-001).
/// It used to be a clean miss, every time (REQ-IPQS-001). **Pure.**
///
/// No refusal text is treated as a clean miss. IPQS's response-parameter docs
/// describe `message` only as "generally success, but may contain … some form
/// of an error notice", and name no invalid-target wording to trust; an
/// invalid email or phone is answered `success:true` with `valid:false`.
fn body_verdict(parsed: &Common) -> crate::util::http::BodyVerdict {
    if parsed.success != Some(false) {
        return crate::util::http::BodyVerdict::Accept;
    }
    let msg = parsed.message.as_deref().unwrap_or_default();
    if crate::util::http::is_key_or_quota_message(msg) {
        // Carry IPQS's own message through: it is the only thing that
        // distinguishes quota exhaustion from a bad key from a plan limit,
        // and the operator needs that to act.
        return crate::util::http::BodyVerdict::KeyFailure {
            code: 401,
            detail: Some(msg.to_string()),
        };
    }
    crate::util::http::BodyVerdict::Accept
}

/// A `success:false` body that reached this far is not key-shaped: the
/// provider failed the query. Fail closed with its own words. **Pure.**
fn accepted(body: Common) -> Result<Common> {
    if body.success != Some(false) {
        return Ok(body);
    }
    Err(Error::module(
        SRC,
        format!(
            "IPQS answered success=false: {}",
            body.message.as_deref().unwrap_or("no message")
        ),
    ))
}

/// IPQS's JSON API root; `{endpoint}/{key}/{value}` follows.
const API_BASE: &str = "https://www.ipqualityscore.com/api/json";

/// One IPQS lookup against `api_base`: the key cascade and the body verdict,
/// then [`accepted`]. `Ok(None)` is a genuine miss (`404`); a dead or exhausted
/// key rotates to the next pooled key (IPQS reports one in-body, on an HTTP
/// 200, as `success:false` with a key/quota message); any other
/// `success:false` is an error in IPQS's own words, never "holds nothing"
/// (REQ-IPQS-001). The key rides in the URL path, so the builder re-renders
/// the URL per key.
async fn query(
    ctx: &ModuleContext,
    client: &reqwest::Client,
    api_base: &str,
    endpoint: &str,
    value: &str,
    initial_key: &str,
) -> Result<Option<Common>> {
    let Some(body): Option<Common> = crate::util::http::keyed_cascade_json(
        ctx,
        SRC,
        initial_key,
        // 404 = unknown selector, a clean miss rather than a failure.
        &[404],
        |key| {
            client.get(format!(
                "{api_base}/{endpoint}/{}/{}",
                urlencode(key),
                urlencode(value)
            ))
        },
        body_verdict,
    )
    .await?
    else {
        return Ok(None);
    };
    accepted(body).map(Some)
}

pub struct IpQs;

#[async_trait]
impl Module for IpQs {
    fn name(&self) -> &'static str {
        "ipqs"
    }
    fn description(&self) -> &'static str {
        "IPQS quality scoring — probes an IP, email, and phone for fraud and risk signals"
    }
    fn priority(&self) -> u8 {
        100
    }

    fn cost(&self) -> ModuleCost {
        ModuleCost::KeyGated
    }
    fn accepts(&self, t: &Target) -> bool {
        matches!(
            t.kind,
            TargetKind::IpAddress | TargetKind::Email | TargetKind::Phone
        )
    }
    fn max_timeout_ms(&self) -> u64 {
        8_000
    }

    fn category(&self) -> ModuleCategory {
        ModuleCategory::Infrastructure
    }

    fn attack_techniques(&self) -> &'static [&'static str] {
        // IPQualityScore is a paid fraud/reputation vendor scoring IP / email /
        // phone, so beyond the Infrastructure default (T1590.005 IP Addresses +
        // T1596.005 Scan Databases) it is Search Closed Sources: Threat Intel
        // Vendors (T1597.001). Scoring also surfaces Email entities (T1589.002)
        // and Phone entities (T1589 Gather Victim Identity Info), and identifies
        // the ISP/organization/carrier as an Organisation entity (T1591.002
        // Business Relationships) — the same pivot abuseipdb/greynoise/ipquery/
        // ip_registry/ip2location/criminal_ip/censys/shodan/onyphe/zoomeye/
        // ripestat all declare for their own ISP/ASN-operator Organisation.
        // Superset.
        &[
            "T1589",
            "T1589.002",
            "T1590.005",
            "T1591.002",
            "T1596.005",
            "T1597.001",
        ]
    }

    fn produces(&self) -> &'static [crate::core::entity::EntityKind] {
        use crate::core::entity::EntityKind;
        const KINDS: &[EntityKind] = &[
            EntityKind::IpAddress,
            EntityKind::Email,
            EntityKind::Phone,
            EntityKind::Organisation,
            EntityKind::Asn,
        ];
        KINDS
    }

    async fn process(&self, target: &Target, ctx: &ModuleContext) -> Result<ModuleResult> {
        let initial_key = match ctx.key_opt(KEY_ENV) {
            Some(k) => k,
            // PROVIDER FAILURE != ZERO EVIDENCE: returning Ok(empty) here made
            // dispatch record ModuleDone { found: 0 }, which coverage reads as a
            // CleanNegative -- "queried, holds nothing on this subject" -- for a
            // provider that was never asked. Error::MissingKey is the contract
            // (REQ-KEYSKIP-001).
            None => return Err(crate::core::error::Error::MissingKey(KEY_ENV.into())),
        };
        let endpoint = match target.kind {
            TargetKind::IpAddress => "ip",
            TargetKind::Email => "email",
            TargetKind::Phone => "phone",
            _ => return Ok(ModuleResult::new()),
        };
        let value = target.value.trim();
        if value.is_empty() {
            return Ok(ModuleResult::new());
        }
        // The whole request path — key cascade, body verdict, fail-closed
        // acceptance — is `query`, so a loopback test runs it for real.
        let Some(body) = query(ctx, &ctx.http, API_BASE, endpoint, value, initial_key).await?
        else {
            return Ok(ModuleResult::new());
        };

        let mut result = ModuleResult::new();
        result.push(build_reputation_entity(
            target.kind.to_entity_kind(),
            endpoint,
            value,
            &body,
            &ctx.scan_id,
        ));

        // For IP targets, emit Organisation and Asn as pivot entities — consistent
        // with shodan/abuseipdb/greynoise which extract the same provider context.
        if target.kind == TargetKind::IpAddress {
            let org_lc = body
                .organization
                .as_deref()
                .map(|s| s.trim().to_ascii_lowercase())
                .filter(|s| s.len() >= 2);
            if let Some(org) = body.organization.as_deref().filter(|o| o.len() >= 2) {
                let mut oe = Entity::new(
                    EntityKind::Organisation,
                    org,
                    confidence::HIGH,
                    &ctx.scan_id,
                );
                oe.tag("ipqs");
                oe.add_evidence(
                    Evidence::new(SRC, format!("IP operator for {value} via IPQS"))
                        .with_attr("ip", value),
                );
                result.push(oe);
            }
            // ISP is a distinct pivot when it differs from org (e.g. the network
            // provider vs the organisation that leases the block).
            if let Some(isp) = body.isp.as_deref().filter(|i| i.len() >= 2) {
                let isp_lc = isp.trim().to_ascii_lowercase();
                if org_lc.as_deref() != Some(&isp_lc) {
                    let mut ie = Entity::new(
                        EntityKind::Organisation,
                        isp,
                        confidence::MEDIUM_PLUS,
                        &ctx.scan_id,
                    );
                    ie.tag("ipqs");
                    ie.tag("isp");
                    ie.add_evidence(
                        Evidence::new(SRC, format!("ISP for {value} via IPQS"))
                            .with_attr("ip", value),
                    );
                    result.push(ie);
                }
            }
            if let Some(asn_n) = body.asn.filter(|n| *n > 0) {
                let asn_str = format!("AS{asn_n}");
                let mut ae = Entity::new(
                    EntityKind::Asn,
                    &asn_str,
                    confidence::HIGH_PLUSPLUS,
                    &ctx.scan_id,
                );
                ae.tag("ipqs");
                ae.add_evidence(
                    Evidence::new(SRC, format!("ASN for {value} via IPQS")).with_attr("ip", value),
                );
                result.push(ae);
            }
        }

        // For phone targets, emit the carrier as an Organisation entity — the
        // mobile network operator is a durable identity signal for burner-risk
        // analysis (cross-referenced with sim_anonymity).
        if target.kind == TargetKind::Phone
            && let Some(carrier) = body.carrier.as_deref().filter(|c| c.len() >= 2)
        {
            {
                let mut ce = Entity::new(
                    EntityKind::Organisation,
                    carrier,
                    confidence::MEDIUM_PLUS,
                    &ctx.scan_id,
                );
                ce.tag("ipqs");
                ce.tag("carrier");
                ce.add_evidence(
                    Evidence::new(SRC, format!("Phone carrier for {value} via IPQS"))
                        .with_attr("phone", value),
                );
                result.push(ce);
            }
        }

        Ok(result)
    }
}

#[cfg(test)]
mod tests {
    include!("tests.rs");
}
