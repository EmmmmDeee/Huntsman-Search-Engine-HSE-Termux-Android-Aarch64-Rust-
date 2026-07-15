//! Deserialisation types for SEON API responses.

use serde::Deserialize;

#[derive(Deserialize)]
pub(super) struct SeonEmailResp {
    #[serde(default)]
    pub(super) success: Option<bool>,
    #[serde(default)]
    pub(super) data: Option<SeonEmailData>,
}

/// Matches SEON's `email-api/v3` response shape exactly (verified against
/// SEON's own current API reference, 2026-07). The `v3` migration removed
/// the per-platform `account_details` object entirely (individual platform
/// registration/name/url are no longer returned by any plan) and replaced it
/// with `account_aggregates` (category-level registration COUNTS, not names
/// or profile links) plus three genuinely new sections this module never
/// modelled at all: `breach_details` (haveibeenpwned-sourced breach list),
/// `associated_domain_registrations` (WHOIS-style registrant PII for domains
/// linked to this email), and `seon_fraud_history` (consortium fraud hits).
#[derive(Deserialize)]
pub(super) struct SeonEmailData {
    #[serde(default)]
    pub(super) risk_scores: Option<RiskScores>,
    #[serde(default)]
    pub(super) email_details: Option<EmailDetails>,
    #[serde(default)]
    pub(super) email_domain_details: Option<EmailDomainDetails>,
    #[serde(default)]
    pub(super) account_aggregates: Option<AccountAggregates>,
    #[serde(default)]
    pub(super) seon_fraud_history: Option<SeonFraudHistory>,
    #[serde(default)]
    pub(super) breach_details: Option<BreachDetails>,
    #[serde(default)]
    pub(super) associated_domain_registrations: Option<AssociatedDomainRegistrations>,
}

#[derive(Deserialize)]
pub(super) struct RiskScores {
    #[serde(default)]
    pub(super) global_network_score: Option<f64>,
}

#[derive(Deserialize)]
pub(super) struct EmailDetails {
    #[serde(default)]
    pub(super) deliverable: Option<bool>,
    #[serde(default)]
    pub(super) full_inbox: Option<bool>,
    #[serde(default)]
    pub(super) valid_format: Option<bool>,
    #[serde(default)]
    pub(super) minimum_age_months: Option<i64>,
    #[serde(default)]
    pub(super) earliest_profile_date: Option<String>,
}

#[derive(Deserialize)]
pub(super) struct EmailDomainDetails {
    #[serde(default)]
    pub(super) domain: Option<String>,
    #[serde(default)]
    pub(super) registered: Option<bool>,
    #[serde(default)]
    pub(super) disposable: Option<bool>,
    #[serde(default)]
    pub(super) free: Option<bool>,
    #[serde(default)]
    pub(super) custom: Option<bool>,
    #[serde(default)]
    pub(super) suspicious_tld: Option<bool>,
    #[serde(default)]
    pub(super) valid_mx: Option<bool>,
    #[serde(default)]
    pub(super) website_exists: Option<bool>,
    #[serde(default)]
    pub(super) registered_to: Option<String>,
    #[serde(default)]
    pub(super) registrar_name: Option<String>,
    #[serde(default)]
    pub(super) created: Option<String>,
}

/// Category-level registration counts (e.g. `social_media: {registered: 8,
/// checked: 21}`) — SEON's v3 replacement for the old per-platform booleans.
/// `#[serde(flatten)]` captures every category key (`technology`,
/// `social_media`, `dating`, …) into a `BTreeMap` rather than enumerating a
/// category list SEON can add to at any time, and keeps iteration
/// deterministic (this codebase's determinism-by-construction convention —
/// a `HashMap` here would leak process-random category order into evidence
/// text).
#[derive(Deserialize)]
pub(super) struct AccountCategoryGroup {
    #[serde(default)]
    pub(super) total_registration: Option<u32>,
    #[serde(flatten)]
    pub(super) categories: std::collections::BTreeMap<String, CategoryCount>,
}

#[derive(Deserialize)]
pub(super) struct CategoryCount {
    #[serde(default)]
    pub(super) registered: Option<u32>,
    #[serde(default)]
    pub(super) checked: Option<u32>,
}

#[derive(Deserialize)]
pub(super) struct AccountAggregates {
    #[serde(default)]
    pub(super) total_registration: Option<u32>,
    #[serde(default)]
    pub(super) business: Option<AccountCategoryGroup>,
    #[serde(default)]
    pub(super) personal: Option<AccountCategoryGroup>,
}

#[derive(Deserialize)]
pub(super) struct SeonFraudHistory {
    #[serde(default)]
    pub(super) hits: Option<u32>,
    #[serde(default)]
    pub(super) customer_hits: Option<u32>,
    #[serde(default)]
    pub(super) fraudulent_decline_hits: Option<u32>,
    #[serde(default)]
    pub(super) first_seen: Option<i64>,
    #[serde(default)]
    pub(super) last_seen: Option<i64>,
}

#[derive(Deserialize)]
pub(super) struct BreachDetails {
    #[serde(default)]
    pub(super) breaches: Vec<Breach>,
    #[serde(default)]
    pub(super) number_of_breaches: Option<u32>,
    #[serde(default)]
    pub(super) haveibeenpwned_listed: Option<bool>,
}

#[derive(Deserialize)]
pub(super) struct Breach {
    #[serde(default)]
    pub(super) date: Option<String>,
    #[serde(default)]
    pub(super) domain: Option<String>,
    #[serde(default)]
    pub(super) name: Option<String>,
}

#[derive(Deserialize)]
pub(super) struct AssociatedDomainRegistrations {
    // `exists` deliberately not modelled: it is fully redundant with whether
    // `domains` is non-empty (SEON's own example shows `exists: true` iff
    // `domains` carries entries), and the extractor already branches on the
    // latter.
    #[serde(default)]
    pub(super) domains: Vec<DomainRegistration>,
}

/// WHOIS-style registrant PII for a domain SEON associates with this email
/// (a domain historically registered using it). Mirrors `whois`/`rdap_domain`'s
/// registrant extraction, not a new concept.
#[derive(Deserialize)]
pub(super) struct DomainRegistration {
    #[serde(default)]
    pub(super) domain_name: Option<String>,
    #[serde(default)]
    pub(super) full_name: Option<String>,
    #[serde(default)]
    pub(super) company_name: Option<String>,
    #[serde(default)]
    pub(super) mailing_address: Option<String>,
    #[serde(default)]
    pub(super) city_name: Option<String>,
    #[serde(default)]
    pub(super) state_name: Option<String>,
    #[serde(default)]
    pub(super) zip_code: Option<String>,
    #[serde(default)]
    pub(super) country_code: Option<String>,
    #[serde(default)]
    pub(super) phone_number: Option<String>,
}

#[derive(Deserialize)]
pub(super) struct SeonPhoneResp {
    #[serde(default)]
    pub(super) success: Option<bool>,
    #[serde(default)]
    pub(super) data: Option<SeonPhoneData>,
}

#[derive(Deserialize)]
pub(super) struct SeonPhoneData {
    #[serde(default)]
    pub(super) score: Option<f64>,
    #[serde(default)]
    pub(super) valid: Option<bool>,
    #[serde(default)]
    pub(super) carrier: Option<String>,
    #[serde(default)]
    pub(super) country: Option<String>,
    #[serde(default)]
    pub(super) country_code: Option<String>,
    #[serde(default, rename = "type")]
    pub(super) line_type: Option<String>,
    #[serde(default)]
    pub(super) account_details: Option<PhoneAccountDetails>,
}

#[derive(Deserialize)]
pub(super) struct PhoneAccountDetails {
    #[serde(default)]
    pub(super) whatsapp: Option<AccountPresence>,
    #[serde(default)]
    pub(super) viber: Option<AccountPresence>,
    #[serde(default)]
    pub(super) telegram: Option<AccountPresence>,
}

// NOTE: `PhoneAccountDetails`/`AccountPresence` model the SAME obsolete
// `account_details` shape the email side used before this fix — SEON's
// `phone-api/v2` response no longer carries per-platform presence either
// (verified against SEON's current API reference alongside the email fix,
// 2026-07). The phone-side rewrite is deliberately NOT part of this change
// (kept to one API surface per cycle); `PhoneAccountDetails`/`AccountPresence`
// stay defined, unused by real traffic, until that follow-up lands — see
// `PROBLEM_TREE`/`gap_register` for the tracked remaining work. `name` is not
// modelled here (only `build_phone_entities` reads this struct, and it only
// ever used `registered`/`url`, never the platform's self-reported name).
#[derive(Deserialize)]
pub(super) struct AccountPresence {
    #[serde(default)]
    pub(super) registered: Option<bool>,
    #[serde(default)]
    pub(super) url: Option<String>,
}
