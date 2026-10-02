//! Typed HIBP API v3 response models for the library client.
//!
//! Every field here is documented at haveibeenpwned.com/API/v3 (breach model,
//! paste model, subscribed domains, subscription status, the breached-account
//! range response). Fields are optional where the docs say a value may be null
//! or omitted, and unknown fields are ignored because the docs say "these
//! attributes may expand without the API being versioned".

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

/// The full breach model (`/breaches`, `/breach/{name}`, `/latestBreach`,
/// `/breachedaccount/{email}?truncateResponse=false`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct BreachModel {
    /// Stable, unique Pascal-cased breach name.
    pub name: String,
    /// Display title.
    #[serde(default)]
    pub title: Option<String>,
    /// Primary website domain.
    #[serde(default)]
    pub domain: Option<String>,
    /// Date the breach occurred (ISO 8601 date).
    #[serde(default)]
    pub breach_date: Option<String>,
    /// When it was added to HIBP (ISO 8601 datetime).
    #[serde(default)]
    pub added_date: Option<String>,
    /// When it was last modified (ISO 8601 datetime).
    #[serde(default)]
    pub modified_date: Option<String>,
    /// Email addresses loaded.
    #[serde(default)]
    pub pwn_count: Option<u64>,
    /// HTML description.
    #[serde(default)]
    pub description: Option<String>,
    /// Logo URI (PNG).
    #[serde(default)]
    pub logo_path: Option<String>,
    /// Attribution, when the data provider asked for one.
    #[serde(default)]
    pub attribution: Option<String>,
    /// Compromised data classes, alphabetical.
    #[serde(default)]
    pub data_classes: Vec<String>,
    /// Verified flag.
    #[serde(default)]
    pub is_verified: Option<bool>,
    /// Fabricated flag.
    #[serde(default)]
    pub is_fabricated: Option<bool>,
    /// Sensitive flag.
    #[serde(default)]
    pub is_sensitive: Option<bool>,
    /// Retired flag.
    #[serde(default)]
    pub is_retired: Option<bool>,
    /// Spam-list flag.
    #[serde(default)]
    pub is_spam_list: Option<bool>,
    /// Malware-sourced flag.
    #[serde(default)]
    pub is_malware: Option<bool>,
    /// Stealer-log-sourced flag.
    #[serde(default)]
    pub is_stealer_log: Option<bool>,
    /// Subscription-free flag.
    #[serde(default)]
    pub is_subscription_free: Option<bool>,
}

/// One paste (`/pasteaccount/{email}`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct PasteModel {
    /// Paste service (Pastebin, Pastie, …).
    #[serde(default)]
    pub source: Option<String>,
    /// Paste id at the source.
    #[serde(default)]
    pub id: Option<String>,
    /// Paste title; omitted when null.
    #[serde(default)]
    pub title: Option<String>,
    /// Posted at (ISO 8601), may be null.
    #[serde(default)]
    pub date: Option<String>,
    /// Emails found in the paste.
    #[serde(default)]
    pub email_count: Option<u64>,
}

/// One entry of `/breachedaccount/range/{prefix}`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AccountRangeEntry {
    /// Remaining SHA-1 hex after the 6-char prefix.
    pub hash_suffix: String,
    /// Breach names for that hashed account.
    pub websites: Vec<String>,
}

/// One subscribed domain (`/subscribeddomains`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct SubscribedDomain {
    /// The verified domain.
    pub domain_name: String,
    /// Breached addresses at last search.
    #[serde(default)]
    pub pwn_count: Option<u64>,
    /// Breached addresses at last search, excluding spam lists.
    #[serde(default)]
    pub pwn_count_excluding_spam_lists: Option<u64>,
    /// Count locked in at the last subscription renewal.
    #[serde(default)]
    pub pwn_count_excluding_spam_lists_at_last_subscription_renewal: Option<u64>,
    /// When the current subscription ends.
    #[serde(default)]
    pub next_subscription_renewal: Option<String>,
}

/// `/subscription/status`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "PascalCase")]
pub struct SubscriptionStatus {
    /// Plan name, e.g. "Pro 2" or "Core 1".
    pub subscription_name: String,
    /// Human-readable scope.
    #[serde(default)]
    pub description: Option<String>,
    /// Subscription end.
    #[serde(default)]
    pub subscribed_until: Option<String>,
    /// Requests per minute for the breached-account API.
    #[serde(default)]
    pub rpm: Option<u32>,
    /// Largest searchable domain.
    #[serde(default)]
    pub domain_search_max_breached_accounts: Option<u64>,
    /// Domain cap; null means no limit.
    #[serde(default)]
    pub max_breached_domains: Option<u64>,
    /// Stealer-log API access.
    #[serde(default)]
    pub includes_stealer_logs: Option<bool>,
    /// Bulk domain add (DNS/email verification APIs).
    #[serde(default)]
    pub includes_bulk_domain_add: Option<bool>,
    /// Automatic subdomain verification.
    #[serde(default)]
    pub includes_auto_subdomain_verification: Option<bool>,
    /// Customer domains allowed.
    #[serde(default)]
    pub includes_customer_domains: Option<bool>,
    /// k-anonymity email search access.
    #[serde(rename = "IncludesKAnon", default)]
    pub includes_k_anon: Option<bool>,
}

/// `/breacheddomain/{domain}`: alias → breach names.
pub type BreachedDomain = BTreeMap<String, Vec<String>>;

/// `/stealerlogsbyemaildomain/{domain}`: alias → website domains.
pub type StealerLogsByEmailDomain = BTreeMap<String, Vec<String>>;

/// `/breachedaccount/{email}` options.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct BreachedAccountOptions {
    /// `truncateResponse`. `None` keeps the API default (truncated, names
    /// only); `Some(false)` asks for the full breach model.
    pub truncate_response: Option<bool>,
    /// `domain` filter.
    pub domain: Option<String>,
    /// `IncludeUnverified`. `None` keeps the API default (true).
    pub include_unverified: Option<bool>,
}

/// `/breaches` filters.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct BreachesFilter {
    /// `Domain` filter.
    pub domain: Option<String>,
    /// `IsSpamList` filter.
    pub is_spam_list: Option<bool>,
}
