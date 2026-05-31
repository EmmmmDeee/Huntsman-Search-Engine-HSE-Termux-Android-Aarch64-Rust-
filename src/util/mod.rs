//! Utilities: HTTP client, DNS resolver, key loading, UID generation, Termux helpers.

pub mod abn;
pub mod address_au;
pub mod budget;
pub mod curl;
pub mod curl_client;
pub mod diagnostics;
pub mod domains;
pub mod geohash;
pub mod html;
pub mod http;
pub mod key_pool;
pub mod key_roi;
pub mod keys;
pub mod oathnet;
pub mod oui;
pub mod postcode_au;
pub mod preflight;
pub mod proxy;
pub mod response_cache;
pub mod see_know;
pub mod service_defs;

pub mod url_util {
    pub fn host_from_url(url: &str) -> Option<String> {
        let trimmed = url.trim();
        let after_scheme = trimmed
            .strip_prefix("https://")
            .or_else(|| trimmed.strip_prefix("http://"))
            .unwrap_or(trimmed);
        let host = after_scheme
            .split('/')
            .next()?
            .split(':')
            .next()?
            .to_lowercase();
        if host.is_empty() || !host.contains('.') {
            return None;
        }
        Some(host)
    }
}

pub mod str_util {
    pub fn truncate_safe(s: &str, max: usize) -> &str {
        if s.len() <= max {
            return s;
        }
        let mut end = max;
        while end > 0 && !s.is_char_boundary(end) {
            end -= 1;
        }
        &s[..end]
    }

    /// Fold common Latin diacritics to their base ASCII letter, lowercase, and
    /// drop everything else. Pure and dependency-free (no `deunicode`/ICU — keeps
    /// the Termux single-binary lean). A name like `"José Müller-Łódź"` folds to
    /// the ASCII stem real platforms actually use (`josemullerlodz`), so derived
    /// usernames/emails match. Multi-char expansions (`æ→ae`, `ß→ss`, `þ→th`) are
    /// handled; non-Latin scripts (Arabic, CJK) have no ASCII fold and are
    /// dropped — callers should split into words *before* folding each token.
    pub fn fold_ascii_lower(s: &str) -> String {
        let mut out = String::with_capacity(s.len());
        for ch in s.chars() {
            match ch {
                'a'..='z' | '0'..='9' => out.push(ch),
                'A'..='Z' => out.push(ch.to_ascii_lowercase()),
                'à' | 'á' | 'â' | 'ã' | 'ä' | 'å' | 'À' | 'Á' | 'Â' | 'Ã' | 'Ä' | 'Å' | 'ā'
                | 'ă' | 'ą' => out.push('a'),
                'ç' | 'Ç' | 'ć' | 'č' | 'ĉ' | 'ċ' => out.push('c'),
                'è' | 'é' | 'ê' | 'ë' | 'È' | 'É' | 'Ê' | 'Ë' | 'ē' | 'ĕ' | 'ė' | 'ę' | 'ě' => {
                    out.push('e')
                }
                'ì' | 'í' | 'î' | 'ï' | 'Ì' | 'Í' | 'Î' | 'Ï' | 'ī' | 'ĭ' | 'į' | 'ı' => {
                    out.push('i')
                }
                'ñ' | 'Ñ' | 'ń' | 'ņ' | 'ň' => out.push('n'),
                'ò' | 'ó' | 'ô' | 'õ' | 'ö' | 'ø' | 'Ò' | 'Ó' | 'Ô' | 'Õ' | 'Ö' | 'Ø' | 'ō'
                | 'ŏ' | 'ő' => out.push('o'),
                'ù' | 'ú' | 'û' | 'ü' | 'Ù' | 'Ú' | 'Û' | 'Ü' | 'ū' | 'ŭ' | 'ů' | 'ű' | 'ų' => {
                    out.push('u')
                }
                'ý' | 'ÿ' | 'Ý' | 'Ŷ' | 'ŷ' => out.push('y'),
                'ł' | 'Ł' => out.push('l'),
                'ś' | 'š' | 'ş' | 'Ś' | 'Š' | 'Ş' => out.push('s'),
                'ź' | 'ż' | 'ž' | 'Ź' | 'Ż' | 'Ž' => out.push('z'),
                'ð' | 'Đ' | 'đ' => out.push('d'),
                'ț' | 'ţ' | 'Ț' | 'Ţ' => out.push('t'),
                'ğ' | 'Ğ' => out.push('g'),
                'ř' | 'Ř' => out.push('r'),
                'æ' | 'Æ' => out.push_str("ae"),
                'œ' | 'Œ' => out.push_str("oe"),
                'ß' => out.push_str("ss"),
                'þ' | 'Þ' => out.push_str("th"),
                _ => {}
            }
        }
        out
    }

    #[cfg(test)]
    mod tests {
        use super::fold_ascii_lower;

        #[test]
        fn folds_latin_diacritics() {
            assert_eq!(fold_ascii_lower("José"), "jose");
            assert_eq!(fold_ascii_lower("Müller"), "muller");
            assert_eq!(fold_ascii_lower("Łódź"), "lodz");
            assert_eq!(fold_ascii_lower("Çağrı"), "cagri"); // ç→c, ğ→g, ı→i
            assert_eq!(fold_ascii_lower("Straße"), "strasse"); // ß → ss
            assert_eq!(fold_ascii_lower("Æon"), "aeon"); // æ → ae
            // ASCII passes through lowercased; punctuation/space dropped.
            assert_eq!(fold_ascii_lower("O'Brien-Smith"), "obriensmith");
            // Non-Latin has no ASCII fold → dropped.
            assert_eq!(fold_ascii_lower("علي"), "");
        }
    }
}

pub mod geo {
    use crate::core::error::{Error, Result};

    pub fn parse_coords(value: &str) -> Result<(f64, f64)> {
        let (a, b) = value
            .split_once(',')
            .ok_or_else(|| Error::module("geo", "coordinates must be 'lat,lon'"))?;
        let lat: f64 = a
            .trim()
            .parse()
            .map_err(|_| Error::module("geo", "invalid latitude"))?;
        let lon: f64 = b
            .trim()
            .parse()
            .map_err(|_| Error::module("geo", "invalid longitude"))?;
        Ok((lat, lon))
    }
}

pub mod stats {
    pub fn mode<'a>(items: &[&'a str]) -> Option<&'a str> {
        if items.is_empty() {
            return None;
        }
        let mut counts: std::collections::HashMap<&str, usize> = std::collections::HashMap::new();
        for &item in items {
            *counts.entry(item).or_default() += 1;
        }
        counts
            .into_iter()
            .max_by(|a, b| a.1.cmp(&b.1).then_with(|| a.0.cmp(b.0)))
            .map(|(val, _)| val)
    }

    pub fn mode_or<'a>(items: &[&'a str], fallback: &'a str) -> &'a str {
        mode(items).unwrap_or(fallback)
    }
}

pub mod dns {
    use std::sync::OnceLock;

    use hickory_resolver::{
        TokioResolver,
        config::{CLOUDFLARE, ResolverConfig},
        net::runtime::TokioRuntimeProvider,
    };

    pub fn shared_resolver() -> &'static TokioResolver {
        static RESOLVER: OnceLock<TokioResolver> = OnceLock::new();
        RESOLVER.get_or_init(|| {
            TokioResolver::builder_with_config(
                ResolverConfig::udp_and_tcp(&CLOUDFLARE),
                TokioRuntimeProvider::default(),
            )
            .build()
            .expect("hardcoded Cloudflare resolver config must build")
        })
    }
}

pub mod uid {
    pub fn scan_id(kind: &str, value: &str) -> String {
        crate::core::entity::scan_id(kind, value)
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn scan_id_is_64_hex_chars() {
            let id = scan_id("email", "x@y.com");
            assert_eq!(id.len(), 64);
            assert!(id.chars().all(|c| c.is_ascii_hexdigit()));
        }
    }
}

pub mod termux {
    use std::time::Duration;

    use tokio::process::Command;
    use tokio::time::timeout;

    pub async fn termux_cmd(cmd: &str, args: &[&str], timeout_ms: u64) -> Option<Vec<u8>> {
        let fut = Command::new(cmd).args(args).kill_on_drop(true).output();
        match timeout(Duration::from_millis(timeout_ms), fut).await {
            Err(_) => {
                tracing::debug!(cmd, "termux_cmd: timed out after {timeout_ms}ms");
                None
            }
            Ok(Err(e)) => {
                tracing::debug!(cmd, error = %e, "termux_cmd: spawn/io failed");
                None
            }
            Ok(Ok(output)) if !output.status.success() => {
                tracing::debug!(cmd, code = ?output.status.code(), "termux_cmd: non-zero exit");
                None
            }
            Ok(Ok(output)) => Some(output.stdout),
        }
    }
}

pub mod freq {
    use std::collections::BTreeMap;

    pub fn top_n<'a>(items: impl Iterator<Item = &'a str>, n: usize) -> String {
        let mut counts: BTreeMap<&str, u32> = BTreeMap::new();
        for item in items {
            *counts.entry(item).or_insert(0) += 1;
        }
        let mut ranked: Vec<(&str, u32)> = counts.into_iter().collect();
        ranked.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(b.0)));
        ranked.truncate(n);
        ranked
            .iter()
            .map(|(k, v)| format!("{k}\u{00d7}{v}"))
            .collect::<Vec<_>>()
            .join(", ")
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn top_n_ranks_by_frequency_descending() {
            let items = ["a", "b", "a", "c", "b", "a"];
            let result = top_n(items.iter().copied(), 3);
            assert_eq!(result, "a\u{00d7}3, b\u{00d7}2, c\u{00d7}1");
        }

        #[test]
        fn top_n_truncates() {
            let items = ["x", "y", "z", "x", "y", "x"];
            let result = top_n(items.iter().copied(), 2);
            assert_eq!(result, "x\u{00d7}3, y\u{00d7}2");
        }

        #[test]
        fn top_n_empty_input() {
            let result = top_n(std::iter::empty(), 5);
            assert!(result.is_empty());
        }

        #[test]
        fn top_n_tiebreaker_is_alphabetical() {
            let items = ["b", "a", "c"];
            let result = top_n(items.iter().copied(), 3);
            assert_eq!(result, "a\u{00d7}1, b\u{00d7}1, c\u{00d7}1");
        }
    }
}
