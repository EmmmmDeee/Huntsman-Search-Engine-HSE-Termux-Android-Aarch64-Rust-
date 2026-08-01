//! Gravatar profile API contract: the request hash + the response schema.
//!
//! `GET https://gravatar.com/<md5(trimmed-lowercased-email)>.json` returns a
//! fixed JSON envelope. Both the request-hash and the response shape are a fixed
//! Gravatar contract, not per-module, so — exactly like [`crate::util::ckan`]
//! for CKAN — they live here once. The `gravatar` and `contact_enrich` modules
//! both deserialise into these types and use [`hash`] rather than each keeping a
//! parallel (and drift-prone) copy: `contact_enrich`'s copy had already drifted
//! incomplete, lacking the `accounts` (linked social profiles) that `gravatar`
//! parses (`PROBLEM_TREE` T2.124). Each module keeps its own entity-building; only
//! the parse schema + hash are shared.

use serde::Deserialize;

#[cfg(test)]
mod tests;

/// The Gravatar profile-request hash: MD5 of the email trimmed and ASCII-
/// lowercased (the documented Gravatar identifier — addresses are ASCII, and the
/// canonical gravatar.com examples hash the simple-lowercased form). Pure, so it
/// is unit-testable. Hashing the raw value (`Jane.Doe@Example.com `) is a
/// guaranteed 404 for any address carrying capitals or surrounding whitespace.
#[must_use]
pub fn hash(email: &str) -> String {
    let normalised = email.trim().to_ascii_lowercase();
    crate::core::crypto::md5_hex(normalised.as_bytes())
}

/// Top-level Gravatar profile response: `{ "entry": [ { … } ] }`.
#[derive(Deserialize, Default)]
#[serde(default)]
pub struct Profile {
    pub entry: Vec<Entry>,
}

/// One profile entry — the union of every field the two consuming modules read,
/// so neither drifts from the live schema again.
#[derive(Deserialize, Default)]
#[serde(default)]
pub struct Entry {
    pub hash: Option<String>,
    #[serde(rename = "profileUrl")]
    pub profile_url: Option<String>,
    #[serde(rename = "preferredUsername")]
    pub preferred_username: Option<String>,
    #[serde(rename = "thumbnailUrl")]
    pub thumbnail_url: Option<String>,
    #[serde(rename = "displayName")]
    pub display_name: Option<String>,
    pub name: Option<Name>,
    #[serde(rename = "aboutMe")]
    pub about_me: Option<String>,
    #[serde(rename = "currentLocation")]
    pub current_location: Option<String>,
    #[serde(default)]
    pub accounts: Vec<Account>,
    #[serde(default)]
    pub urls: Vec<UrlEntry>,
    #[serde(default)]
    pub photos: Vec<PhotoEntry>,
    /// Additional owner-published email addresses (distinct from the hashed
    /// lookup email) — direct contact pivots the struct previously dropped.
    #[serde(default)]
    pub emails: Vec<GravatarEmail>,
    /// Employer, as self-reported (`"Automattic"`) — an Organisation pivot.
    #[serde(default)]
    pub company: Option<String>,
    /// Job title / role (`"Lead, WooCommerce"`). NB: snake_case in the live JSON.
    #[serde(default, rename = "job_title")]
    pub job_title: Option<String>,
    /// Owner-listed contact channels (`{type:"contactform", value:"https://…"}`,
    /// phone, …).
    #[serde(default, rename = "contactInfo")]
    pub contact_info: Vec<ContactItem>,
    /// Self-published pronouns (`"he/him"`).
    #[serde(default)]
    pub pronouns: Option<String>,
}

/// An owner-published email address on the profile.
#[derive(Deserialize, Default)]
#[serde(default)]
pub struct GravatarEmail {
    pub value: Option<String>,
    /// Gravatar ships this as the STRING `"true"`/`"false"`.
    pub primary: Option<String>,
}

/// A contact channel the owner listed (`type` is `contactform`, `phone`, …).
#[derive(Deserialize, Default)]
#[serde(default)]
pub struct ContactItem {
    #[serde(rename = "type")]
    pub kind: Option<String>,
    pub value: Option<String>,
}

/// The profile owner's name, in the several shapes Gravatar exposes.
#[derive(Deserialize, Default)]
#[serde(default)]
pub struct Name {
    pub formatted: Option<String>,
    #[serde(rename = "givenName")]
    pub given_name: Option<String>,
    #[serde(rename = "familyName")]
    pub family_name: Option<String>,
}

/// A linked social/service account on the profile.
#[derive(Deserialize, Default)]
#[serde(default)]
pub struct Account {
    /// Stable platform slug, e.g. `twitter`, `github`.
    pub shortname: Option<String>,
    pub domain: Option<String>,
    pub username: Option<String>,
    pub url: Option<String>,
    /// Accepts either shape Gravatar has shipped this flag as: a genuine JSON
    /// boolean (the live API) or the string `"true"`/`"false"` it was originally
    /// typed for. Load-bearing, not defensive excess: because `Account` nests
    /// inside `Entry` inside `Profile`, a type mismatch on this one field fails
    /// the WHOLE profile parse, which a consumer then folds into the same "no
    /// profile" empty result as a real 404 — so every profile with a linked
    /// account (the common, most valuable case) was once silently dropped as a
    /// false miss (`PROBLEM_TREE` T2.101).
    #[serde(deserialize_with = "deserialize_flexible_bool", default)]
    pub verified: Option<bool>,
}

/// A personal URL the owner listed, with its self-asserted label.
#[derive(Deserialize, Default)]
#[serde(default)]
pub struct UrlEntry {
    pub value: Option<String>,
    pub title: Option<String>,
}

/// An avatar/photo entry (`photos[].value` is the image URL).
#[derive(Deserialize, Default)]
#[serde(default)]
pub struct PhotoEntry {
    pub value: Option<String>,
}

/// Deserialize a field that may arrive as a genuine JSON boolean or as the
/// string `"true"`/`"false"`, normalising both to `Option<bool>`. See
/// [`Account::verified`] for why this flexibility is load-bearing.
fn deserialize_flexible_bool<'de, D>(deserializer: D) -> std::result::Result<Option<bool>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum BoolOrString {
        Bool(bool),
        Str(String),
    }
    Ok(match Option::<BoolOrString>::deserialize(deserializer)? {
        Some(BoolOrString::Bool(b)) => Some(b),
        Some(BoolOrString::Str(s)) => Some(s.eq_ignore_ascii_case("true")),
        None => None,
    })
}
