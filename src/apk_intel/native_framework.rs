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
    /// Matched as a prefix of a bundled library's file name, `SONAME` or `DT_NEEDED` entry
    /// (`libflutter` matches `libflutter.so`). Stems are distinctive enough that a prefix match
    /// does not collide across frameworks.
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

/// The framework a single native-library name identifies, or `None`. `name` is a file name such as
/// `libflutter.so` (a bundled library, a `SONAME` or a `DT_NEEDED` entry).
#[must_use]
pub fn framework_of(name: &str) -> Option<&'static str> {
    SIGNATURES
        .iter()
        .find(|signature| name.starts_with(signature.marker))
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
