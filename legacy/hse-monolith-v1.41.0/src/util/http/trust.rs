//! Extra TLS trust roots from `SSL_CERT_FILE`, applied additively to the
//! built-in webpki roots on every reqwest client.
//!
//! HSE's HTTP stack is deliberately `rustls-tls` + webpki-roots — self-contained,
//! no C dependencies, identical on Termux/Linux/CI — and that stack consults
//! neither the OS trust store nor the standard `SSL_CERT_FILE` variable. Behind a
//! TLS-inspecting proxy (a corporate network, an enterprise-managed Android
//! fleet, a sandboxed CI runner) every provider request then fails the handshake
//! with `invalid peer certificate: UnknownIssuer`, and the live drift sweep
//! reports the whole fleet "unreachable" — a statement about this device's trust
//! configuration, not about the providers (`PROVIDER FAILURE ≠ ABSENCE`).
//!
//! This module honours the de-facto standard: when `SSL_CERT_FILE` names a PEM
//! bundle, every certificate in it is added as a trust root. Unset leaves the
//! default trust unchanged (the common Termux install). Set but unusable —
//! missing, unreadable, not PEM, or holding no certificate — fails **loud** at
//! the first client build, naming the path and the reason, under the same
//! contract as [`super::build_client`]: an explicitly requested trust
//! configuration that cannot be honoured must never degrade silently into "no
//! extra trust" and a fleet of unexplained handshake failures.
//!
//! The curl fallback transport already honours `CURL_CA_BUNDLE`, so both
//! transports can be pointed at the same bundle.

use std::sync::LazyLock;

/// Parsed once per process; every client build clones the roots out of it.
static EXTRA_ROOTS: LazyLock<Vec<reqwest::Certificate>> = LazyLock::new(|| {
    let Ok(path) = std::env::var("SSL_CERT_FILE") else {
        return Vec::new();
    };
    let path = path.trim().to_string();
    if path.is_empty() {
        return Vec::new();
    }
    // panic justification: the operator explicitly asked for this bundle; a
    // bundle that cannot be honoured is a deployment misconfiguration surfaced
    // once, at first client build, with the path and the cause — the same
    // fail-fast contract `build_client` applies to a TLS backend that cannot
    // initialise. Continuing without it would be a silent fallback.
    let bytes = std::fs::read(&path).unwrap_or_else(|e| {
        panic!("SSL_CERT_FILE={path} is set but the bundle could not be read: {e}")
    });
    parse_bundle(&bytes).unwrap_or_else(|e| panic!("SSL_CERT_FILE={path}: {e}"))
});

/// The extra trust roots to add to every client — empty unless `SSL_CERT_FILE`
/// is set. Panics on first use if it is set but unusable (see the module docs
/// for why that is loud rather than silent).
pub(super) fn extra_root_certs() -> &'static [reqwest::Certificate] {
    &EXTRA_ROOTS
}

/// Parse a PEM bundle into its certificates. `Err` names the problem: malformed
/// PEM, or a bundle holding no certificate at all (a file of comments or keys
/// would otherwise pass as "trust nothing extra" — silently).
pub(super) fn parse_bundle(pem: &[u8]) -> Result<Vec<reqwest::Certificate>, String> {
    let certs = reqwest::Certificate::from_pem_bundle(pem)
        .map_err(|e| format!("not a PEM certificate bundle: {e}"))?;
    if certs.is_empty() {
        return Err("the bundle contains no certificates".to_string());
    }
    Ok(certs)
}

#[cfg(test)]
mod tests {
    use super::parse_bundle;

    /// A self-signed test CA generated for this fixture — public certificate
    /// only, no key, trusted by nothing. It exists so the parser is exercised
    /// against a real PEM without depending on the host's certificate store.
    const TEST_CA: &[u8] = include_bytes!("../../../tests/fixtures/hse_test_ca.pem");

    #[test]
    fn a_real_pem_certificate_parses_to_one_root() {
        assert_eq!(parse_bundle(TEST_CA).expect("valid PEM").len(), 1);
    }

    #[test]
    fn a_bundle_yields_every_certificate_in_it() {
        let two = [TEST_CA, b"\n", TEST_CA].concat();
        assert_eq!(parse_bundle(&two).expect("two-cert bundle").len(), 2);
    }

    #[test]
    fn a_certificate_free_bundle_is_a_loud_error_not_silent_no_trust() {
        assert!(parse_bundle(b"").unwrap_err().contains("no certificates"));
        assert!(
            parse_bundle(b"# a comment and nothing else\n")
                .unwrap_err()
                .contains("no certificates")
        );
    }

    #[test]
    fn malformed_pem_is_rejected_with_the_reason() {
        let err =
            parse_bundle(b"-----BEGIN CERTIFICATE-----\nnot base64!!\n-----END CERTIFICATE-----\n")
                .unwrap_err();
        assert!(err.contains("not a PEM certificate bundle"), "{err}");
    }
}
