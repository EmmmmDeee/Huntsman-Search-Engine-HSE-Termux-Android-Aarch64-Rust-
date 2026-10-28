//! The cross-platform app framework or game engine an APK is built on, named from the native
//! libraries it bundles. A Flutter app ships `libflutter.so`; a Unity/IL2CPP game ships
//! `libil2cpp.so`; a React Native app ships `libreactnativejni.so` or `libhermes.so`. These engine
//! libraries have stable, well-documented names, so their presence names the framework — a triage
//! and attribution signal the DEX/Java SDK fingerprint cannot give, because it survives stripping
//! and Java obfuscation.
//!
//! This names the build framework, not a product or an author: many unrelated apps share one
//! engine, so a framework is a classification of the app, never a cross-APK pivot between apps.

/// One engine/framework marker: a native library name stem and the framework it identifies.
pub struct Signature {
    /// A known library-name stem. Matching requires a shared-object boundary or a curated
    /// framework-specific suffix; arbitrary prefix collisions are not evidence.
    pub marker: &'static str,
    pub framework: &'static str,
}

const fn sig(marker: &'static str, framework: &'static str) -> Signature {
    Signature { marker, framework }
}

/// Curated, widely-documented engine/framework native-library names. Each stem is distinctive and
/// stable across versions; a match names the engine, never proves a shared build between apps.
pub static SIGNATURES: &[Signature] = &[
    sig("libflutter", "Flutter"),
    sig("libreactnativejni", "React Native"),
    sig("libhermes", "React Native (Hermes)"),
    sig("libil2cpp", "Unity (IL2CPP)"),
    sig("libunity", "Unity"),
    sig("libmonosgen", "Mono (.NET)"),
    sig("libmonodroid", "Xamarin"),
    sig("libxamarin", "Xamarin"),
    sig("libQt5", "Qt"),
    sig("libQt6", "Qt"),
    sig("libcocos2d", "Cocos2d-x"),
    sig("libgodot", "Godot"),
    sig("libUE4", "Unreal Engine"),
    sig("libUnreal", "Unreal Engine"),
    sig("libgdx", "libGDX"),
    sig("libdefold", "Defold"),
];

/// A valid ELF shared-object suffix, including a numeric SONAME version. Never accept arbitrary
/// trailing text such as `.so.impostor` as a framework indicator.
fn shared_object_suffix(suffix: &str) -> bool {
    let Some(version) = suffix.strip_prefix(".so") else {
        return false;
    };
    if version.is_empty() {
        return true;
    }
    version.strip_prefix('.').is_some_and(|parts| {
        !parts.is_empty()
            && parts
                .split('.')
                .all(|part| !part.is_empty() && part.bytes().all(|byte| byte.is_ascii_digit()))
    })
}

fn matches_marker(name: &str, marker: &str) -> bool {
    let Some(suffix) = name.strip_prefix(marker) else {
        return false;
    };
    if shared_object_suffix(suffix) {
        return true;
    }

    match marker {
        "libmonosgen" => suffix
            .strip_prefix("-2.0")
            .is_some_and(shared_object_suffix),
        "libQt5" | "libQt6" => {
            const MODULES: &[&str] = &[
                "Core", "Gui", "Widgets", "Network", "Qml", "Quick", "OpenGL", "Sql", "Xml",
                "Multimedia", "WebEngineCore", "WebView", "Positioning", "Sensors", "Svg", "Test",
            ];
            const ABIS: &[&str] = &["_arm64-v8a", "_armeabi-v7a", "_x86", "_x86_64"];
            MODULES.iter().any(|module| {
                suffix.strip_prefix(module).is_some_and(|tail| {
                    shared_object_suffix(tail)
                        || ABIS.iter().any(|abi| {
                            tail.strip_prefix(abi).is_some_and(shared_object_suffix)
                        })
                })
            })
        }
        "libcocos2d" => ["cpp", "js"]
            .iter()
            .any(|variant| suffix.strip_prefix(variant).is_some_and(shared_object_suffix)),
        "libgodot" => suffix
            .strip_prefix("_android")
            .is_some_and(shared_object_suffix),
        _ => false,
    }
}

/// The framework a single native-library name identifies, or `None`. `name` is a file name such as
/// `libflutter.so` (a bundled library, a `SONAME` or a `DT_NEEDED` entry).
/// A prefix alone is insufficient: unrelated libraries may deliberately share the same stem.
#[must_use]
pub fn framework_of(name: &str) -> Option<&'static str> {
    SIGNATURES
        .iter()
        .find(|signature| matches_marker(name, signature.marker))
        .map(|signature| signature.framework)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_engine_library_name_names_its_framework() {
        assert_eq!(framework_of("libflutter.so"), Some("Flutter"));
        assert_eq!(framework_of("libil2cpp.so"), Some("Unity (IL2CPP)"));
        assert_eq!(framework_of("libreactnativejni.so"), Some("React Native"));
        assert_eq!(framework_of("libhermes.so"), Some("React Native (Hermes)"));
        assert_eq!(framework_of("libmonosgen-2.0.so"), Some("Mono (.NET)"));
        assert_eq!(framework_of("libQt5Core.so"), Some("Qt"));
        assert_eq!(framework_of("libcocos2dcpp.so"), Some("Cocos2d-x"));
    }

    #[test]
    fn an_ordinary_library_names_no_framework() {
        assert_eq!(framework_of("libc.so"), None);
        assert_eq!(framework_of("libnative.so"), None);
        assert_eq!(framework_of("libcrypto.so"), None);
        assert_eq!(framework_of(""), None);
    }

    #[test]
    fn prefix_impostors_never_claim_a_framework() {
        for signature in SIGNATURES {
            let impostor = format!("{}impostor.so", signature.marker);
            assert_eq!(
                framework_of(&impostor),
                None,
                "prefix-only match misclassified {impostor}"
            );
        }
        assert_eq!(framework_of("libQt5CoreImpostor.so"), None);
        assert_eq!(framework_of("libflutter.so.evil"), None);
        assert_eq!(framework_of("libflutter.so/other"), None);
        assert_eq!(framework_of("libflutter.so.1evil"), None);
    }

    #[test]
    fn known_variants_and_numeric_sonames_still_match() {
        assert_eq!(framework_of("libflutter.so.1"), Some("Flutter"));
        assert_eq!(framework_of("libflutter.so.1.2"), Some("Flutter"));
        assert_eq!(framework_of("libmonosgen-2.0.so"), Some("Mono (.NET)"));
        assert_eq!(framework_of("libQt5Core.so"), Some("Qt"));
        assert_eq!(framework_of("libQt6Network_arm64-v8a.so"), Some("Qt"));
        assert_eq!(framework_of("libcocos2dcpp.so"), Some("Cocos2d-x"));
        assert_eq!(framework_of("libgodot_android.so"), Some("Godot"));
    }

    #[test]
    fn every_signature_is_a_lib_stem_with_a_framework_name() {
        for signature in SIGNATURES {
            assert!(
                signature.marker.starts_with("lib"),
                "{} is not a lib name stem",
                signature.marker
            );
            assert!(!signature.marker.contains('.'), "a stem keeps no extension");
            assert!(!signature.framework.is_empty());
        }
    }
}
