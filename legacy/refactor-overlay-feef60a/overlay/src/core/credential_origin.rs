//! Credential-origin boundary.
//!
//! A credential observed in breach/stealer/external data is evidence about the
//! record in which it appeared. It is not authentication authority. This module
//! makes that distinction explicit and gives authentication code a type it can
//! require.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DiscoveredCredential {
    pub provider_hint: Option<String>,
    /// One-way fingerprint only. Raw discovered secret material must not be
    /// exposed through this evidence type.
    pub fingerprint: String,
    pub source_module: String,
    pub source_context: String,
    pub observed_at_unix: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OperatorCredentialRef {
    pub provider_id: String,
    /// Name of the configured credential slot/environment setting. The secret
    /// itself remains in the existing protected credential store.
    pub credential_slot: String,
    pub approved_at_unix: u64,
    pub approval_provenance: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthenticationAuthority(OperatorCredentialRef);

impl AuthenticationAuthority {
    #[must_use]
    pub fn operator_approved(reference: OperatorCredentialRef) -> Self {
        Self(reference)
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

/// There is intentionally no conversion from `DiscoveredCredential` to
/// `AuthenticationAuthority`. Promotion must be an explicit operator workflow
/// that produces an `OperatorCredentialRef` through the existing credential
/// store, with provenance.
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn auth_authority_requires_operator_reference() {
        let authority = AuthenticationAuthority::operator_approved(OperatorCredentialRef {
            provider_id: "example".into(),
            credential_slot: "HUNTSMAN_EXAMPLE_KEY".into(),
            approved_at_unix: 1,
            approval_provenance: "operator".into(),
        });
        assert_eq!(authority.provider_id(), "example");
        assert_eq!(authority.credential_slot(), "HUNTSMAN_EXAMPLE_KEY");
    }
}
