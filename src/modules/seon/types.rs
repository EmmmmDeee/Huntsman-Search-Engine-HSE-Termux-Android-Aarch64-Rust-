//! Deserialisation types for SEON API responses.

use serde::Deserialize;

#[derive(Deserialize)]
pub(super) struct SeonEmailResp {
    #[serde(default)]
    pub(super) success: Option<bool>,
    #[serde(default)]
    pub(super) data: Option<SeonEmailData>,
}

#[derive(Deserialize)]
pub(super) struct SeonEmailData {
    #[serde(default)]
    pub(super) score: Option<f64>,
    #[serde(default)]
    pub(super) deliverable: Option<bool>,
    #[serde(default)]
    pub(super) domain_details: Option<DomainDetails>,
    #[serde(default)]
    pub(super) account_details: Option<AccountDetails>,
}

#[derive(Deserialize)]
pub(super) struct DomainDetails {
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
}

#[derive(Deserialize)]
pub(super) struct AccountDetails {
    #[serde(default)]
    pub(super) facebook: Option<AccountPresence>,
    #[serde(default)]
    pub(super) twitter: Option<AccountPresence>,
    #[serde(default)]
    pub(super) linkedin: Option<AccountPresence>,
    #[serde(default)]
    pub(super) instagram: Option<AccountPresence>,
    #[serde(default)]
    pub(super) github: Option<AccountPresence>,
    #[serde(default)]
    pub(super) google: Option<AccountPresence>,
    #[serde(default)]
    pub(super) apple: Option<AccountPresence>,
    #[serde(default)]
    pub(super) microsoft: Option<AccountPresence>,
    #[serde(default)]
    pub(super) spotify: Option<AccountPresence>,
    #[serde(default)]
    pub(super) skype: Option<AccountPresence>,
}

#[derive(Deserialize)]
pub(super) struct AccountPresence {
    #[serde(default)]
    pub(super) registered: Option<bool>,
    #[serde(default)]
    pub(super) name: Option<String>,
    #[serde(default)]
    pub(super) url: Option<String>,
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
