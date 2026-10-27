//! The third-party SDKs an app bundles, found by the Java packages its DEX code references — the
//! analytics, advertising, attribution, crash-reporting and push SDKs that Exodus Privacy and
//! similar tools fingerprint as the trackers in an Android app.
//!
//! A DEX string table holds every type descriptor the code names (`Lcom/google/firebase/...;`), so
//! a class from an embedded SDK leaves its package prefix there whether or not the SDK runs. Each
//! signature below is a stable, well-documented package prefix; a match means the SDK's code is
//! present, a privacy and attribution signal, not proof the app uses it at runtime. The prefixes
//! are matched longest-first, so a specific product (Facebook Audience Network) is named over the
//! vendor's broader SDK when both are present.

use serde::Serialize;

/// One SDK's identifying Java package prefix (a DEX type descriptor begins `L<package path>`),
/// with the name and category to report it under.
pub struct Signature {
    pub prefix: &'static str,
    pub name: &'static str,
    pub category: &'static str,
}

const fn sig(prefix: &'static str, name: &'static str, category: &'static str) -> Signature {
    Signature {
        prefix,
        name,
        category,
    }
}

/// Curated, widely-documented tracker/SDK package prefixes. Not exhaustive; each is stable enough
/// that its presence reliably names the SDK. Kept small and auditable rather than mirroring a full
/// external database.
pub static SIGNATURES: &[Signature] = &[
    // Analytics.
    sig(
        "Lcom/google/firebase/analytics/",
        "Google Firebase Analytics",
        "analytics",
    ),
    sig(
        "Lcom/google/android/gms/analytics/",
        "Google Analytics",
        "analytics",
    ),
    sig("Lcom/flurry/", "Flurry", "analytics"),
    sig("Lcom/amplitude/", "Amplitude", "analytics"),
    sig("Lcom/mixpanel/", "Mixpanel", "analytics"),
    sig("Lcom/segment/analytics/", "Segment", "analytics"),
    sig("Lcom/localytics/", "Localytics", "analytics"),
    sig("Lio/branch/", "Branch", "analytics"),
    sig("Lcom/yandex/metrica/", "Yandex AppMetrica", "analytics"),
    // Advertising.
    sig(
        "Lcom/google/android/gms/ads/",
        "Google AdMob",
        "advertising",
    ),
    sig("Lcom/facebook/ads/", "Meta Audience Network", "advertising"),
    sig("Lcom/unity3d/ads/", "Unity Ads", "advertising"),
    sig("Lcom/unity3d/services/", "Unity Services", "advertising"),
    sig("Lcom/applovin/", "AppLovin", "advertising"),
    sig("Lcom/mopub/", "MoPub", "advertising"),
    sig("Lcom/inmobi/", "InMobi", "advertising"),
    sig("Lcom/vungle/", "Vungle", "advertising"),
    sig("Lcom/chartboost/", "Chartboost", "advertising"),
    sig("Lcom/ironsource/", "ironSource", "advertising"),
    sig("Lcom/adcolony/", "AdColony", "advertising"),
    sig("Lcom/startapp/", "StartApp", "advertising"),
    sig("Lcom/tapjoy/", "Tapjoy", "advertising"),
    // Attribution.
    sig("Lcom/appsflyer/", "AppsFlyer", "attribution"),
    sig("Lcom/adjust/sdk/", "Adjust", "attribution"),
    sig("Lcom/kochava/", "Kochava", "attribution"),
    // Crash and performance.
    sig(
        "Lcom/google/firebase/crashlytics/",
        "Firebase Crashlytics",
        "crash",
    ),
    sig("Lcom/crashlytics/", "Crashlytics", "crash"),
    sig("Lio/sentry/", "Sentry", "crash"),
    sig("Lcom/bugsnag/", "Bugsnag", "crash"),
    sig("Lcom/microsoft/appcenter/", "Microsoft App Center", "crash"),
    sig("Lio/invertase/", "React Native Firebase", "crash"),
    // Push and engagement.
    sig("Lcom/onesignal/", "OneSignal", "push"),
    sig("Lcom/urbanairship/", "Airship", "push"),
    sig("Lcom/braze/", "Braze", "engagement"),
    sig("Lcom/appboy/", "Braze (Appboy)", "engagement"),
    sig("Lcom/clevertap/", "CleverTap", "engagement"),
    // Social sign-in / SDKs (broad vendor prefixes, matched after their specific products above).
    sig("Lcom/facebook/", "Meta (Facebook) SDK", "social"),
];

/// One bundled SDK, as reported.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize)]
pub struct Tracker {
    pub name: String,
    pub category: String,
}

/// The longest signature whose prefix begins `descriptor` (a DEX type descriptor), or `None`. The
/// longest match wins, so a product under a vendor's prefix is named over the vendor's own SDK.
#[must_use]
pub fn detect(descriptor: &[u8]) -> Option<&'static Signature> {
    // Every prefix begins `L`, so a string that does not is rejected before any comparison.
    if descriptor.first() != Some(&b'L') {
        return None;
    }
    SIGNATURES
        .iter()
        .filter(|signature| descriptor.starts_with(signature.prefix.as_bytes()))
        .max_by_key(|signature| signature.prefix.len())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_type_descriptor_names_its_sdk_by_the_longest_matching_prefix() {
        let found = detect(b"Lcom/google/firebase/analytics/FirebaseAnalytics;").unwrap();
        assert_eq!(found.name, "Google Firebase Analytics");
        assert_eq!(found.category, "analytics");
        // Facebook Audience Network is under Lcom/facebook/, and the longer prefix wins.
        assert_eq!(
            detect(b"Lcom/facebook/ads/Ad;").unwrap().name,
            "Meta Audience Network"
        );
        assert_eq!(
            detect(b"Lcom/facebook/login/Login;").unwrap().name,
            "Meta (Facebook) SDK"
        );
    }

    #[test]
    fn a_string_that_is_not_a_known_sdk_descriptor_matches_nothing() {
        assert!(detect(b"Lcom/example/app/Main;").is_none());
        assert!(detect(b"https://api.example.com/").is_none());
        assert!(detect(b"").is_none());
        assert!(
            detect(b"Lcom/google/").is_none(),
            "a vendor root is not itself a signature"
        );
    }

    #[test]
    fn every_signature_prefix_is_a_type_descriptor_and_distinct() {
        let mut prefixes = std::collections::BTreeSet::new();
        for signature in SIGNATURES {
            assert!(
                signature.prefix.starts_with('L') && signature.prefix.ends_with('/'),
                "{} is not an L…/ type-descriptor prefix",
                signature.prefix
            );
            assert!(
                prefixes.insert(signature.prefix),
                "duplicate prefix {}",
                signature.prefix
            );
            assert!(!signature.name.is_empty() && !signature.category.is_empty());
        }
    }
}
