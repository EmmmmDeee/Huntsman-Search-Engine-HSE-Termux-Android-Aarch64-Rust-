//! The URLs compiled into an app's code: every `http://` and `https://` URL in the string table
//! of each DEX file, as `apkleaks` and `MobSF`'s static analysis list the endpoints an app names.
//!
//! The string table is read through `string_ids` exactly as the Dalvik/ART loader locates each
//! string (a ULEB128 UTF-16 length, then NUL-terminated MUTF-8), with every offset bounds-checked.
//! A URL in code is a lead, not an observation: it names an endpoint the app may contact, an SDK's
//! default, documentation or dead code alike, and nothing here contacts it.

use std::collections::BTreeSet;

use serde::Serialize;

use super::sdk::{self, Tracker};
use crate::validation::is_placeholder_domain;
use crate::value_syntax::{canonical_domain, host_only, is_iana_tld};

/// A string table larger than this is read only this far, and the rest is reported as unread.
const MAX_STRINGS: usize = 2_000_000;
/// A string is scanned for URLs only this far.
const MAX_STRING_BYTES: usize = 16 * 1024;
const MAX_URL_BYTES: usize = 2048;
const MAX_LISTED: usize = 512;
/// XML namespace and schema identifiers: URLs by syntax that no app fetches.
const NAMESPACE_HOSTS: [&str; 10] = [
    "schemas.android.com",
    "www.w3.org",
    "w3.org",
    "xmlpull.org",
    "ns.adobe.com",
    "schemas.xmlsoap.org",
    "schemas.microsoft.com",
    "purl.org",
    "java.sun.com",
    "xml.apache.org",
];

/// The URLs and their hosts across every DEX file of one APK.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct CodeUrls {
    pub dex_files_read: usize,
    pub strings_read: usize,
    /// Strings beyond the per-file cap that were not read.
    pub strings_unread: usize,
    pub urls: Vec<String>,
    pub urls_omitted: usize,
    /// The distinct registrable-looking hosts of those URLs, lowercased.
    pub hosts: Vec<String>,
    /// The third-party SDKs the DEX code references, by their package signatures.
    pub trackers: Vec<Tracker>,
    #[serde(skip)]
    seen: BTreeSet<String>,
    #[serde(skip)]
    host_set: BTreeSet<String>,
    #[serde(skip)]
    tracker_set: BTreeSet<&'static str>,
}

fn le32(data: &[u8], at: usize) -> Option<usize> {
    let field = data.get(at..at.checked_add(4)?)?;
    usize::try_from(u32::from_le_bytes([field[0], field[1], field[2], field[3]])).ok()
}

/// The bytes of the string at `offset`: past its ULEB128 length, up to its NUL.
fn string_at(data: &[u8], offset: usize) -> Option<&[u8]> {
    // A ULEB128 is at most five bytes for a 32-bit length.
    for at in (offset..).take(5) {
        let byte = *data.get(at)?;
        if byte & 0x80 == 0 {
            let rest = data.get(at + 1..)?;
            let rest = &rest[..rest.len().min(MAX_STRING_BYTES)];
            let end = rest
                .iter()
                .position(|byte| *byte == 0)
                .unwrap_or(rest.len());
            return Some(&rest[..end]);
        }
    }
    None
}

fn url_byte(byte: u8) -> bool {
    byte.is_ascii_graphic() && !b"\"'<>\\`{}|^".contains(&byte)
}

/// Whether `host` is worth keeping: an IPv4 address, or a valid domain under a real TLD that is
/// neither a reserved placeholder nor an XML namespace.
pub(super) fn wanted_host(host: &str) -> bool {
    if host.parse::<std::net::Ipv4Addr>().is_ok() {
        return true;
    }
    canonical_domain(host).is_some_and(|domain| {
        domain.rsplit('.').next().is_some_and(is_iana_tld)
            && !is_placeholder_domain(&domain)
            && !NAMESPACE_HOSTS.contains(&domain.as_str())
    })
}

impl CodeUrls {
    fn take(&mut self, text: &[u8]) {
        let mut from = 0;
        while let Some(found) = text[from..].windows(7).position(|window| {
            window.eq_ignore_ascii_case(b"http://") || window.eq_ignore_ascii_case(b"https:/")
        }) {
            let start = from + found;
            let length = text[start..]
                .iter()
                .take(MAX_URL_BYTES)
                .take_while(|byte| url_byte(**byte))
                .count();
            from = start + length.max(1);
            let Ok(url) = std::str::from_utf8(&text[start..start + length]) else {
                continue;
            };
            let url = url.trim_end_matches(['.', ',', ';', ')', ']']);
            let host = host_only(url).to_ascii_lowercase();
            if !wanted_host(&host) || !self.seen.insert(url.to_owned()) {
                continue;
            }
            if self.urls.len() < MAX_LISTED {
                self.urls.push(url.to_owned());
            } else {
                self.urls_omitted += 1;
            }
            if self.host_set.insert(host.clone()) {
                self.hosts.push(host);
            }
        }
    }

    /// Reads one DEX file's string table, adding its URLs.
    ///
    /// # Errors
    /// A file that is not DEX, or whose string table lies outside it, is refused.
    pub fn read(&mut self, dex: &[u8]) -> Result<(), String> {
        if dex.len() < 0x70 || &dex[..4] != b"dex\n" || dex[7] != 0 {
            return Err("not a DEX file".to_owned());
        }
        if le32(dex, 40) != Some(0x1234_5678) {
            return Err("DEX file is not little-endian".to_owned());
        }
        let count = le32(dex, 56).ok_or("truncated DEX header")?;
        let ids = le32(dex, 60).ok_or("truncated DEX header")?;
        if ids
            .checked_add(count.checked_mul(4).ok_or("DEX string table overflow")?)
            .is_none_or(|end| end > dex.len())
        {
            return Err("DEX string table lies outside the file".to_owned());
        }
        let read = count.min(MAX_STRINGS);
        for i in 0..read {
            let offset = le32(dex, ids + i * 4).ok_or("truncated DEX string table")?;
            let text = string_at(dex, offset).ok_or("DEX string lies outside the file")?;
            self.take(text);
            self.detect_sdk(text);
        }
        self.dex_files_read += 1;
        self.strings_read += read;
        self.strings_unread += count - read;
        Ok(())
    }

    /// Records the SDK a type descriptor names, once per SDK, the first time it is seen.
    fn detect_sdk(&mut self, text: &[u8]) {
        if let Some(signature) = sdk::detect(text) {
            if self.tracker_set.insert(signature.name) {
                self.trackers.push(Tracker {
                    name: signature.name.to_owned(),
                    category: signature.category.to_owned(),
                });
            }
        }
    }

    /// Sorts what was found, for a stable report.
    pub fn finish(&mut self) {
        self.urls.sort();
        self.hosts.sort();
        self.trackers.sort();
    }
}

#[cfg(test)]
pub(super) mod tests {
    use super::*;

    /// A minimal little-endian DEX file whose string table holds `strings`.
    pub(crate) fn dex_with(strings: &[&str]) -> Vec<u8> {
        let mut dex = vec![0_u8; 0x70];
        dex[..8].copy_from_slice(b"dex\n035\0");
        dex[40..44].copy_from_slice(&0x1234_5678_u32.to_le_bytes());
        let count = u32::try_from(strings.len()).unwrap();
        dex[56..60].copy_from_slice(&count.to_le_bytes());
        dex[60..64].copy_from_slice(&0x70_u32.to_le_bytes());
        let data_start = 0x70 + strings.len() * 4;
        let mut data = Vec::new();
        for string in strings {
            let offset = u32::try_from(data_start + data.len()).unwrap();
            dex.extend_from_slice(&offset.to_le_bytes());
            data.push(u8::try_from(string.encode_utf16().count().min(0x7f)).unwrap());
            data.extend_from_slice(string.as_bytes());
            data.push(0);
        }
        dex.extend_from_slice(&data);
        dex
    }

    #[test]
    fn urls_in_code_are_listed_with_their_hosts_and_noise_is_left_out() {
        let mut found = CodeUrls::default();
        found
            .read(&dex_with(&[
                "Lcom/example/Main;",
                "https://api.fieldtrack.io/v2/report?id=",
                "see \"http://203.0.113.9:8080/upload\" for uploads",
                "http://schemas.android.com/apk/res/android",
                "https://%s/api",
                "https://www.example.com/docs",
                "HTTPS://API.FIELDTRACK.IO/v2/report?id=",
            ]))
            .expect("dex");
        found
            .read(&dex_with(&[
                "https://api.fieldtrack.io/v2/report?id=",
                "https://cdn.fieldtrack.io/x.js)",
            ]))
            .expect("second dex");
        found.finish();
        assert_eq!(found.dex_files_read, 2);
        assert_eq!(found.strings_read, 9);
        assert_eq!(
            found.urls,
            [
                "HTTPS://API.FIELDTRACK.IO/v2/report?id=",
                "http://203.0.113.9:8080/upload",
                "https://api.fieldtrack.io/v2/report?id=",
                "https://cdn.fieldtrack.io/x.js",
            ],
            "deduplicated across files, namespaces, placeholders and templates left out"
        );
        assert_eq!(
            found.hosts,
            ["203.0.113.9", "api.fieldtrack.io", "cdn.fieldtrack.io"]
        );
    }

    #[test]
    fn bundled_sdks_are_named_from_the_type_descriptors_in_code() {
        let mut found = CodeUrls::default();
        found
            .read(&dex_with(&[
                "Lcom/example/field/Main;",
                "Lcom/appsflyer/AppsFlyerLib;",
                "Lcom/google/firebase/analytics/FirebaseAnalytics;",
                "Lcom/google/firebase/analytics/internal/Helper;",
                "Lcom/facebook/ads/InterstitialAd;",
                "Lcom/facebook/login/LoginManager;",
                "https://api.fieldtrack.io/",
            ]))
            .expect("dex");
        found.finish();
        assert_eq!(
            found.trackers,
            [
                Tracker {
                    name: "AppsFlyer".into(),
                    category: "attribution".into()
                },
                Tracker {
                    name: "Google Firebase Analytics".into(),
                    category: "analytics".into()
                },
                Tracker {
                    name: "Meta (Facebook) SDK".into(),
                    category: "social".into()
                },
                Tracker {
                    name: "Meta Audience Network".into(),
                    category: "advertising".into()
                },
            ],
            "each SDK once, sorted, with the longest prefix winning and URLs ignored"
        );
    }

    #[test]
    fn a_file_that_is_not_dex_or_lies_about_its_table_is_refused() {
        let mut found = CodeUrls::default();
        assert!(found.read(b"PK\x03\x04 not dex").is_err());
        let mut dex = dex_with(&["https://api.fieldtrack.io/"]);
        dex[56..60].copy_from_slice(&u32::MAX.to_le_bytes());
        assert!(found.read(&dex).is_err());
        let mut dex = dex_with(&["https://api.fieldtrack.io/"]);
        let at = 0x70;
        dex[at..at + 4].copy_from_slice(&u32::MAX.to_le_bytes());
        assert!(found.read(&dex).is_err());
        assert_eq!(found.dex_files_read, 0);
    }
}
