//! Credential-origin boundary. From refactor overlay feef60a (P4).
//!
//! A credential seen in breach, stealer, or other external data is evidence about the
//! record it appeared in. It is not authentication authority. There is no conversion
//! from `DiscoveredCredential` to `AuthenticationAuthority`: promotion is an explicit
//! operator workflow with provenance. Raw secret material is never stored here; the
//! fingerprint type can only hold a 64-hex digest.

use std::fmt;

use serde::{Deserialize, Serialize};

use crate::error::Error;
use crate::sha256::{hex32, sha256};

const FINGERPRINT_TAG: &[u8] = b"huntsman-credential-fingerprint-v1\0";

/// SHA-256 of a domain-tagged secret, lowercase hex. Equality key only: a guessable
/// password is still guessable from its digest, so this is not secrecy.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct CredentialFingerprint(String);

impl CredentialFingerprint {
    /// Fingerprint a secret. The secret is not retained.
    #[must_use]
    pub fn of_secret(secret: &str) -> Self {
        let mut buf = Vec::with_capacity(FINGERPRINT_TAG.len() + secret.len());
        buf.extend_from_slice(FINGERPRINT_TAG);
        buf.extend_from_slice(secret.as_bytes());
        Self(hex32(&sha256(&buf)))
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl TryFrom<String> for CredentialFingerprint {
    type Error = Error;

    fn try_from(value: String) -> Result<Self, Error> {
        if value.len() == 64
            && value
                .bytes()
                .all(|c| matches!(c, b'0'..=b'9' | b'a'..=b'f'))
        {
            Ok(Self(value))
        } else {
            Err(Error::Invalid(
                "credential fingerprint must be 64 lowercase hex".into(),
            ))
        }
    }
}

impl From<CredentialFingerprint> for String {
    fn from(value: CredentialFingerprint) -> Self {
        value.0
    }
}

impl fmt::Debug for CredentialFingerprint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "CredentialFingerprint({}…)", &self.0[..12])
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DiscoveredCredential {
    pub provider_hint: Option<String>,
    pub fingerprint: CredentialFingerprint,
    pub source_module: String,
    pub source_context: String,
    pub observed_at_unix: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OperatorCredentialRef {
    pub provider_id: String,
    /// Name of the configured credential slot or environment setting. The secret stays
    /// outside the repository and outside this type.
    pub credential_slot: String,
    pub approved_at_unix: u64,
    pub approval_provenance: String,
}

/// Only constructible from an operator reference with provenance.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthenticationAuthority(OperatorCredentialRef);

impl AuthenticationAuthority {
    /// # Errors
    /// `Error::MissingField` when provider, slot, or provenance is blank.
    pub fn operator_approved(reference: OperatorCredentialRef) -> Result<Self, Error> {
        for (name, value) in [
            ("provider_id", &reference.provider_id),
            ("credential_slot", &reference.credential_slot),
            ("approval_provenance", &reference.approval_provenance),
        ] {
            if value.trim().is_empty() {
                return Err(Error::MissingField(name.into()));
            }
        }
        Ok(Self(reference))
    }

    #[must_use]
    pub fn provider_id(&self) -> &str {
        &self.0.provider_id
    }

    #[must_use]
    pub fn credential_slot(&self) -> &str {
        &self.0.credential_slot
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn reference(provenance: &str) -> OperatorCredentialRef {
        OperatorCredentialRef {
            provider_id: "example".into(),
            credential_slot: "HUNTSMAN_EXAMPLE_KEY".into(),
            approved_at_unix: 1,
            approval_provenance: provenance.into(),
        }
    }

    #[test]
    fn auth_authority_requires_operator_reference_with_provenance() {
        let authority = AuthenticationAuthority::operator_approved(reference("operator")).unwrap();
        assert_eq!(authority.provider_id(), "example");
        assert_eq!(authority.credential_slot(), "HUNTSMAN_EXAMPLE_KEY");
        assert!(AuthenticationAuthority::operator_approved(reference("  ")).is_err());
    }

    #[test]
    fn falsify_raw_secret_cannot_be_stored_as_fingerprint() {
        assert!(CredentialFingerprint::try_from("hunter2".to_owned()).is_err());
        let json = r#"{"provider_hint":null,"fingerprint":"hunter2","source_module":"m","source_context":"c","observed_at_unix":1}"#;
        assert!(serde_json::from_str::<DiscoveredCredential>(json).is_err());
    }

    #[test]
    fn fingerprint_is_stable_tagged_and_redacted() {
        let a = CredentialFingerprint::of_secret("CorrectHorseBatteryStaple!");
        assert_eq!(
            a,
            CredentialFingerprint::of_secret("CorrectHorseBatteryStaple!")
        );
        assert_ne!(
            a,
            CredentialFingerprint::of_secret("correcthorsebatterystaple!")
        );
        assert_ne!(
            a.as_str(),
            hex32(&sha256(b"CorrectHorseBatteryStaple!")),
            "domain-tagged, not bare sha256"
        );
        let cred = DiscoveredCredential {
            provider_hint: None,
            fingerprint: a.clone(),
            source_module: "import".into(),
            source_context: "leak page".into(),
            observed_at_unix: 1,
        };
        let round: DiscoveredCredential =
            serde_json::from_str(&serde_json::to_string(&cred).unwrap()).unwrap();
        assert_eq!(round, cred);
        assert!(
            !format!("{cred:?}").contains(a.as_str()),
            "Debug must not print the full digest"
        );
    }
}
