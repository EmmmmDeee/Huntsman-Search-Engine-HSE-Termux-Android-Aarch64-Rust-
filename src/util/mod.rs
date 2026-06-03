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
pub mod log_capture;
pub mod netrotate;
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

    /// Canonical validity check for a geographic coordinate, shared by every
    /// module that turns an external lat/lon into a `Coordinates` entity
    /// (`geo_intel`, `ip_whois_geo`, `wifi_intel`, `mylnikov`, `cell_intel`,
    /// `exif_geo`, `censys`, `device_sensors`, …). Each previously hand-rolled
    /// some subset of these guards — most only rejected `0,0` and let
    /// out-of-range/NaN values through, which then became high-confidence false
    /// fixes that poison the geo-cluster correlator. One definition keeps the
    /// policy consistent.
    ///
    /// Rejects:
    ///   - non-finite values (NaN, ±inf) from malformed JSON,
    ///   - out-of-range values (`|lat| > 90`, `|lon| > 180`), and
    ///   - the `0.0, 0.0` "Null Island" sentinel that geo APIs and the Android
    ///     location stack emit when they have no real fix.
    #[must_use]
    pub fn is_valid_coords(lat: f64, lon: f64) -> bool {
        lat.is_finite()
            && lon.is_finite()
            && (-90.0..=90.0).contains(&lat)
            && (-180.0..=180.0).contains(&lon)
            && !(lat == 0.0 && lon == 0.0)
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn valid_coords_accepts_real_positions() {
            assert!(is_valid_coords(-27.4766, 153.0166)); // Brisbane
            assert!(is_valid_coords(51.5074, -0.1278)); // London
            assert!(is_valid_coords(90.0, 180.0)); // boundaries
            assert!(is_valid_coords(-90.0, -180.0));
        }

        #[test]
        fn valid_coords_rejects_bad_fixes() {
            assert!(!is_valid_coords(0.0, 0.0)); // Null Island
            assert!(!is_valid_coords(91.0, 10.0)); // lat out of range
            assert!(!is_valid_coords(10.0, 181.0)); // lon out of range
            assert!(!is_valid_coords(f64::NAN, 10.0)); // non-finite
            assert!(!is_valid_coords(10.0, f64::INFINITY));
        }
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
            use hickory_resolver::config::LookupIpStrategy;
            let mut builder = TokioResolver::builder_with_config(
                ResolverConfig::udp_and_tcp(&CLOUDFLARE),
                TokioRuntimeProvider::default(),
            );
            // Bound DNS like every other external call (Requirement: a slow or
            // dead service degrades the scan, never freezes it). hickory's
            // defaults are 5s timeout x 2 attempts = ~10s PER lookup, and
            // dns_intel issues A/AAAA/MX/NS/SOA/TXT (+ DNSBL) lookups, so a
            // stalled resolver stacked well past the module's 15s budget — an
            // IP scan was observed wedging ~25s on a single DNSBL AAAA query
            // when IPv6 nameserver connect failed (os error 97) and the
            // resolver paid the full v6→v4 failover tax on every lookup.
            //
            // - timeout 2s, attempts 1: a wedged query fails fast and the scan
            //   moves on, staying inside dns_intel's 15s declaration even when
            //   several lookups are slow.
            // - Ipv4thenIpv6: try the v4 nameserver first so a v6-less host
            //   (this container, many mobile networks) doesn't stall on an
            //   unreachable AAAA nameserver, while v6 still resolves where
            //   available.
            {
                let opts = builder.options_mut();
                opts.timeout = std::time::Duration::from_secs(2);
                opts.attempts = 1;
                opts.ip_strategy = LookupIpStrategy::Ipv4thenIpv6;
            }
            builder
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
    use std::collections::HashMap;
    use std::sync::{LazyLock, Mutex};
    use std::time::{Duration, Instant};

    use tokio::process::Command;
    use tokio::time::timeout;

    /// How long a `termux-*` tool that timed out or failed to spawn is skipped
    /// before we re-probe it. This is the single biggest per-scan time sink on a
    /// phone: with location/telephony/wifi permission ungranted (or no GPS fix),
    /// the sensor tools (`termux-location` 12 s, `termux-wifi-scaninfo` /
    /// `termux-telephony-cellinfo` 5 s each) hang for their FULL timeout on every
    /// scan — ~20-30 s of dead wait per scan. Caching the failure skips them
    /// instantly; the TTL is short enough that granting the permission (or
    /// moving outdoors) is picked up within a few minutes on a long-running
    /// `hse serve`, so we never permanently disable a sensor.
    const UNAVAILABLE_TTL: Duration = Duration::from_secs(300);

    /// `tool name -> instant after which it may be re-probed`. Process-global so
    /// the skip persists across scans (the win) and across the concurrent
    /// sensor modules that share these tools.
    static UNAVAILABLE: LazyLock<Mutex<HashMap<String, Instant>>> =
        LazyLock::new(|| Mutex::new(HashMap::new()));

    fn skip_until(cmd: &str) -> Option<Instant> {
        UNAVAILABLE
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get(cmd)
            .copied()
    }

    fn mark_unavailable(cmd: &str) {
        UNAVAILABLE
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .insert(cmd.to_string(), Instant::now() + UNAVAILABLE_TTL);
    }

    fn mark_available(cmd: &str) {
        UNAVAILABLE
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .remove(cmd);
    }

    /// Run a `termux-*` helper with a hard timeout, returning its stdout on a
    /// clean exit. A tool that timed out or wouldn't spawn is cached as
    /// unavailable for [`UNAVAILABLE_TTL`] and short-circuited on subsequent
    /// calls — so an ungranted sensor permission costs its full timeout at most
    /// once every few minutes, not once per scan.
    pub async fn termux_cmd(cmd: &str, args: &[&str], timeout_ms: u64) -> Option<Vec<u8>> {
        if let Some(until) = skip_until(cmd)
            && Instant::now() < until
        {
            tracing::debug!(cmd, "termux_cmd: skipped (recently unavailable)");
            return None;
        }
        let fut = Command::new(cmd).args(args).kill_on_drop(true).output();
        match timeout(Duration::from_millis(timeout_ms), fut).await {
            Err(_) => {
                tracing::debug!(cmd, "termux_cmd: timed out after {timeout_ms}ms");
                mark_unavailable(cmd);
                None
            }
            Ok(Err(e)) => {
                tracing::debug!(cmd, error = %e, "termux_cmd: spawn/io failed");
                mark_unavailable(cmd);
                None
            }
            Ok(Ok(output)) if !output.status.success() => {
                // A non-zero exit is a real, prompt run (tool present, just no
                // data / a handled error) — responsive, so do NOT penalise it;
                // clear any stale unavailable mark.
                tracing::debug!(cmd, code = ?output.status.code(), "termux_cmd: non-zero exit");
                mark_available(cmd);
                None
            }
            Ok(Ok(output)) => {
                mark_available(cmd);
                Some(output.stdout)
            }
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[tokio::test]
        async fn failed_tool_is_cached_unavailable_then_skipped() {
            let bogus = "termux-selftest-nonexistent-tool-xyz";
            mark_available(bogus); // clean slate

            // First call spawns, fails (ENOENT) → None, and is cached unavailable.
            assert!(termux_cmd(bogus, &[], 500).await.is_none());
            assert!(
                skip_until(bogus).is_some_and(|t| t > Instant::now()),
                "a failed tool must be cached as unavailable"
            );

            // Second call short-circuits via the cache (no spawn, instant None).
            assert!(termux_cmd(bogus, &[], 500).await.is_none());

            // A success/responsive run clears the mark so it can be used again.
            mark_available(bogus);
            assert!(skip_until(bogus).is_none());
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
