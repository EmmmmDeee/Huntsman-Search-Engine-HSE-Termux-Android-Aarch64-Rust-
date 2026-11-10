//! Tests the explicit APK trust boundary without changing Termux defaults.
use huntsman_recon::web_server::ServeConfig;

#[test]
fn ordinary_termux_loopback_still_ignores_a_token() {
    let cfg = ServeConfig::parse("127.0.0.1:8080", Some("z".repeat(64)))
        .expect("legacy loopback");
    assert!(!cfg.needs_token());
}

#[test]
fn apk_loopback_requires_long_random_shaped_token() {
    let token = "a".repeat(64);
    let cfg = ServeConfig::parse_apk_loopback("127.0.0.1:8080", Some(token))
        .expect("configured APK loopback");
    assert!(cfg.needs_token());
    assert!(ServeConfig::parse_apk_loopback("127.0.0.1:8080", None).is_err());
    assert!(ServeConfig::parse_apk_loopback("127.0.0.1:8080", Some("short".into())).is_err());
    assert!(ServeConfig::parse_apk_loopback("127.0.0.1:8080", Some("x".repeat(300))).is_err());
    assert!(ServeConfig::parse_apk_loopback("0.0.0.0:8080", Some("x".repeat(64))).is_err());
}

#[test]
fn apk_loopback_rejects_token_control_characters() {
    assert!(ServeConfig::parse_apk_loopback(
        "127.0.0.1:8080", Some(format!("{}\n", "x".repeat(64)))
    ).is_err());
}
