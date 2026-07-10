use super::{OverrideDecision, classify};

const DEFAULT: &str = "https://see-know.icu/api/v1";

#[test]
fn unset_or_blank_uses_default() {
    assert_eq!(classify(None, DEFAULT), OverrideDecision::UseDefault);
    assert_eq!(classify(Some("   "), DEFAULT), OverrideDecision::UseDefault);
    assert_eq!(classify(Some(""), DEFAULT), OverrideDecision::UseDefault);
}

#[test]
fn same_host_override_accepted_silently() {
    // A path/port change on the provider's own host (a pinned API version, a
    // local reverse proxy on the same host) is legitimate and needs no warning.
    assert_eq!(
        classify(Some("https://see-know.icu/api/v2"), DEFAULT),
        OverrideDecision::AcceptSameHost
    );
    assert_eq!(
        classify(Some("  https://see-know.icu/api/v1  "), DEFAULT),
        OverrideDecision::AcceptSameHost
    );
}

#[test]
fn divergent_host_is_flagged_not_silent() {
    // Pointing at a DIFFERENT host than the canonical see-know.icu default (the
    // legacy see-know.eu instance, a self-hosted mirror, or a look-alike) is
    // accepted — self-hosting an alternate instance is legitimate — but reported
    // as divergent so `resolve` WARNs and the redirect can never be silent.
    assert_eq!(
        classify(Some("https://see-know.eu/api/v1"), DEFAULT),
        OverrideDecision::AcceptDivergentHost {
            host: "see-know.eu".to_string(),
        }
    );
}

#[test]
fn non_https_override_refused() {
    // An API key must never be sent over a cleartext / non-https scheme.
    for u in [
        "http://see-know.eu/api/v1",
        "ftp://see-know.eu/api",
        "gopher://see-know.eu/",
    ] {
        assert!(
            matches!(classify(Some(u), DEFAULT), OverrideDecision::Reject { .. }),
            "expected reject for {u}",
        );
    }
}

#[test]
fn private_or_local_host_override_refused() {
    // SSRF: an override at loopback / RFC1918 / link-local cloud-metadata / a
    // local domain must never receive a keyed request. This is the pin the curl
    // path skips, restored here for the override case.
    for u in [
        "https://127.0.0.1/api",
        "https://169.254.169.254/latest/meta-data",
        "https://10.0.0.5:8080/api",
        "https://192.168.1.1/api",
        "https://[::1]/api",
        "https://localhost/api",
        "https://intranet.internal/api",
    ] {
        assert!(
            matches!(classify(Some(u), DEFAULT), OverrideDecision::Reject { .. }),
            "expected reject for {u}",
        );
    }
}

#[test]
fn unparseable_override_refused() {
    for u in ["not a url", "see-know.eu/api", "://nope", "   \t  x"] {
        assert!(
            matches!(classify(Some(u), DEFAULT), OverrideDecision::Reject { .. }),
            "expected reject for {u:?}",
        );
    }
}

#[test]
fn oathnet_default_shape_also_works() {
    // The other call-site's default host, to prove the policy is not see_know
    // specific.
    const OATHNET: &str = "https://oathnet.org/api";
    assert_eq!(
        classify(Some("https://oathnet.org/api/v2"), OATHNET),
        OverrideDecision::AcceptSameHost
    );
    assert_eq!(
        classify(Some("https://0athnet.org/api"), OATHNET),
        OverrideDecision::AcceptDivergentHost {
            host: "0athnet.org".to_string(),
        }
    );
}
