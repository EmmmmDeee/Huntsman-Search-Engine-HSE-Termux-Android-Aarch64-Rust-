//! Tests the explicit APK trust boundary without changing Termux defaults.
use huntsman_recon::web_server::ServeConfig;

#[test]
fn ordinary_termux_loopback_still_ignores_a_token() {
    let cfg = ServeConfig::parse("127.0.0.1:8080", Some("z".repeat(64))).expect("legacy loopback");
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
    assert!(
        ServeConfig::parse_apk_loopback("127.0.0.1:8080", Some(format!("{}\n", "x".repeat(64))))
            .is_err()
    );
}

#[test]
fn apk_manifest_wires_only_declared_android_adapters() {
    let manifest = include_str!("../android-app/app/src/main/AndroidManifest.xml");
    let launcher =
        include_str!("../android-app/app/src/main/java/com/huntsman/recon/MainActivity.java");
    let job =
        include_str!("../android-app/app/src/main/java/com/huntsman/recon/HealthJobService.java");
    let build = include_str!("../android-app/build-apk.sh");
    let packaging = include_str!("../android-app/app/build.gradle");
    assert!(manifest.contains("android.permission.INTERNET"));
    assert!(manifest.contains("android.permission.RECEIVE_BOOT_COMPLETED"));
    assert!(manifest.contains("android.permission.BIND_JOB_SERVICE"));
    assert!(manifest.contains(".HealthJobService"));
    assert!(manifest.contains(".MainActivity"));
    assert!(launcher.contains("HealthJobService.schedule(this)"));
    assert!(launcher.contains("\"127.0.0.1:0\""));
    assert!(launcher.contains("port = boundPort(server)"));
    assert!(launcher.contains("/api/command"));
    assert!(launcher.contains("setRequestProperty(\"Authorization\", \"Bearer \" + sessionToken)"));
    assert!(launcher.contains("window.huntsmanAndroidSession"));
    assert!(launcher.contains("HSE_APK_LOOPBACK_AUTH"));
    assert!(launcher.contains("new SecureRandom()"));
    assert!(job.contains("setPersisted(true)"));
    assert!(job.contains("setPeriodic(REFRESH_PERIOD_MS)"));
    assert!(job.contains("needsReschedule = process.waitFor() != 0"));
    assert!(job.contains("jobFinished(params, needsReschedule)"));
    assert!(build.contains("--bin huntsman-recon --bin huntsman-key-health"));
    assert!(packaging.contains("useLegacyPackaging = true"));
    assert!(packaging.contains("keepDebugSymbols.add(\"**/libhuntsman.so\")"));
}
