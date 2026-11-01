//! Deterministic capability negotiation for an autonomous, unrooted runtime.
//! No network, environment, clock, permission or shell access occurs here.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Impact {
    Passive,
    LowImpactActive,
    Intrusive,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Availability {
    Available,
    Degraded,
    Unavailable,
    NotAuthorised,
    TransientFailure,
    Unsupported,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct CapabilityProbe {
    pub platform_supported: bool,
    pub permission_granted: bool,
    pub network_available: bool,
    pub credentials_available: bool,
    pub resource_budget_available: bool,
    pub provider_healthy: bool,
    pub fallback_available: bool,
    /// True only for operations that actually need remote connectivity.
    pub requires_network: bool,
    /// True only when the operation needs an external provider credential.
    pub requires_credentials: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Scope {
    pub target_authorised: bool,
    pub passive_allowed: bool,
    pub low_impact_active_allowed: bool,
    pub intrusive_explicitly_approved: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Decision {
    pub status: Availability,
    pub use_fallback: bool,
    pub retryable: bool,
}

#[must_use]
pub const fn negotiate(probe: CapabilityProbe, scope: Scope, impact: Impact) -> Decision {
    let authorised = scope.target_authorised
        && match impact {
            Impact::Passive => scope.passive_allowed,
            Impact::LowImpactActive => scope.low_impact_active_allowed,
            Impact::Intrusive => scope.intrusive_explicitly_approved,
        };
    if !authorised {
        return Decision {
            status: Availability::NotAuthorised,
            use_fallback: false,
            retryable: false,
        };
    }
    if !probe.platform_supported {
        return Decision {
            status: Availability::Unsupported,
            use_fallback: false,
            retryable: false,
        };
    }
    if !probe.permission_granted || (probe.requires_credentials && !probe.credentials_available) {
        return Decision {
            status: Availability::Unavailable,
            use_fallback: false,
            retryable: false,
        };
    }
    if !probe.resource_budget_available {
        return Decision {
            status: Availability::TransientFailure,
            use_fallback: false,
            retryable: true,
        };
    }
    if probe.requires_network && (!probe.network_available || !probe.provider_healthy) {
        if probe.fallback_available {
            return Decision {
                status: Availability::Degraded,
                use_fallback: true,
                retryable: false,
            };
        }
        return Decision {
            status: Availability::TransientFailure,
            use_fallback: false,
            retryable: true,
        };
    }
    Decision {
        status: Availability::Available,
        use_fallback: false,
        retryable: false,
    }
}

/// Independently evaluate primary and fallback requirements. The fallback is
/// never assumed healthy merely because it exists.
#[must_use]
pub const fn negotiate_with_fallback(
    primary: CapabilityProbe,
    fallback: CapabilityProbe,
    scope: Scope,
    impact: Impact,
) -> Decision {
    let first = negotiate(primary, scope, impact);
    if !matches!(first.status, Availability::TransientFailure) || !primary.fallback_available {
        return first;
    }
    let alternate = negotiate(fallback, scope, impact);
    if matches!(alternate.status, Availability::Available) {
        return Decision {
            status: Availability::Degraded,
            use_fallback: true,
            retryable: false,
        };
    }
    first
}

#[cfg(test)]
mod tests {
    use super::*;

    const OK: CapabilityProbe = CapabilityProbe {
        platform_supported: true,
        permission_granted: true,
        network_available: true,
        credentials_available: true,
        resource_budget_available: true,
        provider_healthy: true,
        fallback_available: false,
        requires_network: true,
        requires_credentials: true,
    };
    const SCOPE: Scope = Scope {
        target_authorised: true,
        passive_allowed: true,
        low_impact_active_allowed: false,
        intrusive_explicitly_approved: false,
    };

    #[test]
    fn fallback_requires_independent_network_and_credentials() {
        let mut primary = OK;
        primary.provider_healthy = false;
        primary.fallback_available = true;
        let mut fallback = OK;
        fallback.network_available = false;
        assert!(!negotiate_with_fallback(primary, fallback, SCOPE, Impact::Passive).use_fallback);
        fallback.network_available = true;
        fallback.credentials_available = false;
        assert!(!negotiate_with_fallback(primary, fallback, SCOPE, Impact::Passive).use_fallback);
        fallback.credentials_available = true;
        assert!(negotiate_with_fallback(primary, fallback, SCOPE, Impact::Passive).use_fallback);
    }

    #[test]
    fn fallback_cannot_override_scope_denial() {
        let mut primary = OK;
        primary.provider_healthy = false;
        primary.fallback_available = true;
        let decision = negotiate_with_fallback(primary, OK, SCOPE, Impact::Intrusive);
        assert_eq!(decision.status, Availability::NotAuthorised);
        assert!(!decision.use_fallback);
    }

    #[test]
    fn passive_is_automatic_when_available() {
        assert_eq!(
            negotiate(OK, SCOPE, Impact::Passive).status,
            Availability::Available
        );
    }

    #[test]
    fn active_and_intrusive_need_explicit_scope() {
        assert_eq!(
            negotiate(OK, SCOPE, Impact::LowImpactActive).status,
            Availability::NotAuthorised
        );
        assert_eq!(
            negotiate(OK, SCOPE, Impact::Intrusive).status,
            Availability::NotAuthorised
        );
    }

    #[test]
    fn absent_permission_is_not_retryable() {
        let mut probe = OK;
        probe.permission_granted = false;
        let d = negotiate(probe, SCOPE, Impact::Passive);
        assert_eq!(d.status, Availability::Unavailable);
        assert!(!d.retryable);
    }

    #[test]
    fn transient_provider_failure_is_retryable() {
        let mut probe = OK;
        probe.provider_healthy = false;
        let d = negotiate(probe, SCOPE, Impact::Passive);
        assert_eq!(d.status, Availability::TransientFailure);
        assert!(d.retryable);
    }

    #[test]
    fn fallback_is_explicitly_reported() {
        let mut probe = OK;
        probe.fallback_available = true;
        let d = negotiate(probe, SCOPE, Impact::Passive);
        assert_eq!(d.status, Availability::Available);
        assert!(!d.use_fallback);
    }

    #[test]
    fn unsupported_platform_does_not_gain_authority() {
        let mut probe = OK;
        probe.platform_supported = false;
        assert_eq!(
            negotiate(probe, SCOPE, Impact::Passive).status,
            Availability::Unsupported
        );
    }

    #[test]
    fn offline_local_operation_remains_available() {
        let mut probe = OK;
        probe.requires_network = false;
        probe.requires_credentials = false;
        probe.network_available = false;
        probe.credentials_available = false;
        probe.provider_healthy = false;
        assert_eq!(
            negotiate(probe, SCOPE, Impact::Passive).status,
            Availability::Available
        );
    }

    #[test]
    fn failed_primary_selects_healthy_fallback() {
        let mut probe = OK;
        probe.provider_healthy = false;
        probe.fallback_available = true;
        let decision = negotiate(probe, SCOPE, Impact::Passive);
        assert_eq!(decision.status, Availability::Degraded);
        assert!(decision.use_fallback);
    }

    #[test]
    fn offline_network_task_is_retryable_without_fallback() {
        let mut probe = OK;
        probe.network_available = false;
        assert_eq!(
            negotiate(probe, SCOPE, Impact::Passive).status,
            Availability::TransientFailure
        );
    }

    #[test]
    fn denied_scope_cannot_be_bypassed_by_fallback() {
        let mut probe = OK;
        probe.network_available = false;
        probe.fallback_available = true;
        assert_eq!(
            negotiate(probe, SCOPE, Impact::Intrusive).status,
            Availability::NotAuthorised
        );
    }

    #[test]
    fn resource_exhaustion_does_not_select_fallback() {
        let mut probe = OK;
        probe.resource_budget_available = false;
        probe.fallback_available = true;
        let decision = negotiate(probe, SCOPE, Impact::Passive);
        assert_eq!(decision.status, Availability::TransientFailure);
        assert!(!decision.use_fallback);
    }

    #[test]
    fn explicit_intrusive_scope_is_required_even_for_passive_targets() {
        let scope = Scope {
            intrusive_explicitly_approved: true,
            ..SCOPE
        };
        assert_eq!(
            negotiate(OK, scope, Impact::Intrusive).status,
            Availability::Available
        );
    }
}
