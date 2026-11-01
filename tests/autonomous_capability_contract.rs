//! External policy contract for a diagnostic-only capability negotiation module.
//! These assertions do not imply that live collection dispatch uses this policy.

use huntsman_recon::autonomous_capability::{
    Availability, CapabilityProbe, Impact, Scope, negotiate,
};

#[test]
fn missing_authority_and_network_are_separate_fail_closed_outcomes() {
    let mut probe = CapabilityProbe {
        platform_supported: true,
        permission_granted: true,
        network_available: true,
        credentials_available: true,
        resource_budget_available: true,
        provider_healthy: true,
        fallback_available: false,
        requires_network: true,
        requires_credentials: false,
    };
    let scope = Scope {
        target_authorised: true,
        passive_allowed: true,
        low_impact_active_allowed: false,
        intrusive_explicitly_approved: false,
    };

    assert_eq!(
        negotiate(probe, scope, Impact::Intrusive).status,
        Availability::NotAuthorised
    );

    probe.network_available = false;
    assert_eq!(
        negotiate(probe, scope, Impact::Passive).status,
        Availability::TransientFailure
    );

    probe.requires_network = false;
    assert_eq!(
        negotiate(probe, scope, Impact::Passive).status,
        Availability::Available
    );
}
