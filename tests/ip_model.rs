use huntsman_recon::ip::{ALL_IP_CLAIM_KINDS, IpClaimKind, IpScope, IpTarget};

#[test]
fn public_ipv4_is_canonical_and_public() {
    let target = IpTarget::parse(" 1.1.1.1 ").expect("public IPv4");
    assert_eq!(target.canonical(), "1.1.1.1");
    assert_eq!(target.scope, IpScope::Public);
    assert!(target.is_public());
}

#[test]
fn public_ipv6_is_canonical_and_public() {
    let target = IpTarget::parse("2606:4700:4700:0:0:0:0:1111").expect("public IPv6");
    assert_eq!(target.canonical(), "2606:4700:4700::1111");
    assert_eq!(target.scope, IpScope::Public);
}

#[test]
fn ipv4_mapped_ipv6_inherits_ipv4_scope() {
    let target = IpTarget::parse("::ffff:192.0.2.9").expect("mapped IPv4");
    assert_eq!(target.canonical(), "192.0.2.9");
    assert_eq!(target.scope, IpScope::DocumentationOrReserved);
    assert!(!target.is_public());
}

#[test]
fn private_loopback_documentation_and_reserved_are_not_public() {
    let cases = [
        ("10.0.0.1", IpScope::Private),
        ("127.0.0.1", IpScope::Loopback),
        ("169.254.1.1", IpScope::LinkLocal),
        ("224.0.0.1", IpScope::Multicast),
        ("0.0.0.0", IpScope::Unspecified),
        ("203.0.113.9", IpScope::DocumentationOrReserved),
        ("2001:db8::1", IpScope::DocumentationOrReserved),
        ("fc00::1", IpScope::Private),
        ("fe80::1", IpScope::LinkLocal),
        ("::1", IpScope::Loopback),
        ("::", IpScope::Unspecified),
    ];
    for (raw, scope) in cases {
        let target = IpTarget::parse(raw).expect(raw);
        assert_eq!(target.scope, scope, "{raw}");
        assert!(!target.is_public(), "{raw}");
    }
}

#[test]
fn invalid_input_is_rejected() {
    for raw in ["", "not-an-ip", "1.2.3.999", "example.com"] {
        assert!(IpTarget::parse(raw).is_err(), "{raw:?}");
    }
}

#[test]
fn ip_claim_model_has_no_person_attribution_variant() {
    assert_ne!(ALL_IP_CLAIM_KINDS, []);
    assert!(ALL_IP_CLAIM_KINDS.contains(&IpClaimKind::Allocation));
    assert!(ALL_IP_CLAIM_KINDS.contains(&IpClaimKind::Routing));
    for kind in ALL_IP_CLAIM_KINDS {
        let label = kind.as_str();
        assert_ne!(label, "person");
        assert_ne!(label, "human");
        assert_ne!(label, "subscriber");
    }
}
