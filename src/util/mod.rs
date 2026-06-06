//! Utilities: HTTP client, DNS resolver, key loading, UID generation, Termux helpers.

pub mod abn;
pub mod address_au;
pub mod atomic_file;
pub mod budget;
pub mod ckan;
pub mod curl;
pub mod curl_client;
pub mod diagnostics;
pub mod domains;
pub mod found_keys;
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
pub mod raw_archive;
pub mod response_cache;
pub mod see_know;
pub mod service_defs;
pub mod settings;

pub mod json {
    //! Shared JSON-field extraction helpers used by the breach/OSINT modules
    //! (see_know, oathnet, …). Single definition so the extraction semantics
    //! (treat empty strings as absent) can't drift between providers.
    use serde_json::Value;

    /// The value at `key` as an owned non-empty string, else `None`. An empty
    /// string is treated as absent.
    #[must_use]
    pub fn val_str(item: &Value, key: &str) -> Option<String> {
        item.get(key)
            .and_then(|v| v.as_str())
            .filter(|s| !s.is_empty())
            .map(std::string::ToString::to_string)
    }

    /// The first non-empty string among several candidate `keys`, else `None`.
    #[must_use]
    pub fn val_str_or(item: &Value, keys: &[&str]) -> Option<String> {
        keys.iter().find_map(|k| val_str(item, k))
    }
}

pub mod url_util {
    /// The bare host substring of a URL-ish string: strip a leading `http(s)://`
    /// scheme (case-insensitively — `HTTPS://` is valid per RFC 3986 §3.1), then
    /// everything from the first `/` (path) and `:` (port). Borrows; applies
    /// **no** case-folding or validity policy on the host itself — callers layer
    /// that on (see [`host_from_url`]). A plain host or `host:port` passes through
    /// as its host. Returns `""` when nothing host-like remains.
    #[must_use]
    pub fn host_only(s: &str) -> &str {
        let trimmed = s.trim();
        let after_scheme = ["https://", "http://"]
            .iter()
            .find_map(|scheme| {
                trimmed
                    .get(..scheme.len())
                    .filter(|p| p.eq_ignore_ascii_case(scheme))
                    .map(|_| &trimmed[scheme.len()..])
            })
            .unwrap_or(trimmed);
        after_scheme
            .split('/')
            .next()
            .unwrap_or("")
            .split(':')
            .next()
            .unwrap_or("")
    }

    /// The lowercased host of a URL, or `None` unless it looks like a real domain
    /// (non-empty and contains a `.`). Built on [`host_only`].
    #[must_use]
    pub fn host_from_url(url: &str) -> Option<String> {
        let host = host_only(url).to_lowercase();
        if host.is_empty() || !host.contains('.') {
            return None;
        }
        Some(host)
    }

    #[cfg(test)]
    mod tests {
        use super::{host_from_url, host_only};

        #[test]
        fn host_only_strips_scheme_path_and_port() {
            assert_eq!(host_only("https://Example.com:8443/a/b?x=1"), "Example.com");
            assert_eq!(host_only("http://host.org/"), "host.org");
            assert_eq!(host_only("  bare.host:25 "), "bare.host");
            assert_eq!(host_only("plainhost"), "plainhost");
            assert_eq!(host_only(""), "");
            // Scheme match is case-insensitive (RFC 3986 §3.1)...
            assert_eq!(host_only("HTTPS://Up.Example.com/p"), "Up.Example.com");
            assert_eq!(host_only("HtTp://x.test"), "x.test");
            // ...but the host slice itself is returned verbatim (no case-folding).
            assert_eq!(host_only("https://MixedCase.Net"), "MixedCase.Net");
        }

        #[test]
        fn host_from_url_lowercases_and_requires_a_dot() {
            assert_eq!(
                host_from_url("https://Sub.Example.COM/p"),
                Some("sub.example.com".to_string())
            );
            assert_eq!(host_from_url("http://localhost:8080"), None); // no dot
            assert_eq!(host_from_url(""), None);
        }
    }
}

pub mod spf {
    //! Minimal SPF (RFC 7208) mechanism extraction, shared by the DNS modules so
    //! `dns_intel` and `doh_resolver` can't drift in what they pull out of a
    //! `v=spf1` record (they had: one case-sensitive version check, one
    //! case-insensitive; both silently dropping `ip6:`).

    /// True if `txt` is an SPF record. Per RFC 7208 §4.5 the `v=spf1` version
    /// tag is matched case-insensitively.
    #[must_use]
    pub fn is_spf(txt: &str) -> bool {
        let b = txt.as_bytes();
        b.len() >= 6 && b[..6].eq_ignore_ascii_case(b"v=spf1")
    }

    /// An authorising member of an SPF record that resolves to an entity.
    #[derive(Debug, PartialEq, Eq)]
    pub enum Member<'a> {
        /// An `ip4:` / `ip6:` address with any CIDR suffix stripped — never empty.
        Ip(&'a str),
        /// An `include:` domain — guaranteed non-empty and dotted.
        Include(&'a str),
        /// The `redirect=` modifier's target domain — guaranteed non-empty and
        /// dotted. Delegates the whole SPF policy to another domain (RFC 7208 §6),
        /// so for OSINT it is a related-domain pivot just like an `include:`.
        Redirect(&'a str),
    }

    /// Iterate the `ip4:`/`ip6:`/`include:`/`redirect=` members of an SPF record.
    /// Bare/blank IP mechanisms and empty/dotless or macro-bearing
    /// include/redirect domains are skipped (they would only normalise to junk
    /// entities). Other mechanisms (`a`, `mx`, `ptr`, `exists`, `all`, the `exp=`
    /// modifier) and qualifier prefixes are not interpreted here — callers tag the
    /// domain itself.
    pub fn members(txt: &str) -> impl Iterator<Item = Member<'_>> {
        // A usable include/redirect target is non-empty, dotted, and free of SPF
        // macros (`%{…}`) which don't resolve to a literal domain.
        fn usable_domain(d: &str) -> bool {
            d.contains('.') && !d.contains('%')
        }
        txt.split_whitespace().filter_map(|part| {
            if let Some(ip) = part
                .strip_prefix("ip4:")
                .or_else(|| part.strip_prefix("ip6:"))
            {
                let ip = ip.split('/').next().unwrap_or(ip);
                (!ip.is_empty()).then_some(Member::Ip(ip))
            } else if let Some(inc) = part.strip_prefix("include:") {
                usable_domain(inc).then_some(Member::Include(inc))
            } else if let Some(red) = part.strip_prefix("redirect=") {
                usable_domain(red).then_some(Member::Redirect(red))
            } else {
                None
            }
        })
    }

    #[cfg(test)]
    mod tests {
        use super::{Member, is_spf, members};

        #[test]
        fn is_spf_is_case_insensitive_on_the_version_tag() {
            assert!(is_spf("v=spf1 -all"));
            assert!(is_spf("V=SPF1 ip4:1.2.3.4 -all")); // RFC 7208 §4.5
            assert!(!is_spf("v=dmarc1"));
            assert!(!is_spf("spf1"));
            assert!(!is_spf(""));
        }

        #[test]
        fn members_yields_ip4_ip6_and_includes_skipping_junk() {
            let got: Vec<Member> = members(
                "v=spf1 ip4:198.51.100.0/24 ip6:2001:db8::/32 include:_spf.example.com \
                 ip4: ip6: include: include:localhost a mx -all",
            )
            .collect();
            assert_eq!(
                got,
                vec![
                    Member::Ip("198.51.100.0"),
                    Member::Ip("2001:db8::"), // IPv6 colons preserved, CIDR stripped
                    Member::Include("_spf.example.com"),
                    // bare ip4:/ip6:/include: and dotless include:localhost dropped;
                    // a/mx/-all are not IP/include members.
                ]
            );
        }

        #[test]
        fn members_yields_redirect_target_and_skips_macros() {
            let got: Vec<Member> =
                members("v=spf1 redirect=_spf.example.net include:%{i}._spf.macro.test").collect();
            // The redirect target is surfaced; the macro-bearing include is skipped
            // (a `%{…}` member is not a literal domain).
            assert_eq!(got, vec![Member::Redirect("_spf.example.net")]);
            // A dotless / empty redirect is dropped like a dotless include.
            assert!(
                members("v=spf1 redirect= redirect=localhost")
                    .next()
                    .is_none()
            );
        }
    }
}

pub mod str_util {
    /// A trimmed, non-empty borrow of an optional string field, else `None`.
    /// Whitespace-only is treated as absent. Single definition so the many OSINT
    /// modules that surface "the value if the upstream actually sent one" share
    /// identical semantics instead of each re-deriving them.
    #[must_use]
    pub fn nonempty(o: &Option<String>) -> Option<&str> {
        o.as_deref().map(str::trim).filter(|s| !s.is_empty())
    }

    /// The ASCII digits of `s`, in order, with every other character dropped.
    /// One definition of "keep only the digits" for phone / ABN / ACN / LEI
    /// normalisation (was re-derived inline in ~9 places).
    #[must_use]
    pub fn ascii_digits(s: &str) -> String {
        s.chars().filter(char::is_ascii_digit).collect()
    }

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
        use super::{ascii_digits, fold_ascii_lower, nonempty, truncate_safe};

        #[test]
        fn nonempty_trims_and_treats_blank_as_absent() {
            assert_eq!(nonempty(&Some("  hi ".to_string())), Some("hi"));
            assert_eq!(nonempty(&Some("x".to_string())), Some("x"));
            assert_eq!(nonempty(&Some("   ".to_string())), None);
            assert_eq!(nonempty(&Some(String::new())), None);
            assert_eq!(nonempty(&None), None);
        }

        #[test]
        fn ascii_digits_keeps_only_digits_in_order() {
            assert_eq!(ascii_digits("+61 (4) 123-456"), "614123456");
            assert_eq!(ascii_digits("AS13335"), "13335");
            assert_eq!(ascii_digits("no digits here"), "");
            assert_eq!(ascii_digits(""), "");
            // Non-ASCII digits (e.g. Arabic-Indic ٤) are not ASCII → dropped.
            assert_eq!(ascii_digits("a١2b3"), "23");
        }

        #[test]
        fn truncate_safe_never_splits_a_codepoint() {
            // Caps web_crawler's page body etc. A raw `s[..max]` panics when
            // `max` lands mid-codepoint; truncate_safe must back off to the
            // nearest char boundary instead (for every possible cut point).
            let s = "aé😀b"; // 1 + 2 + 4 + 1 = 8 bytes, char boundaries at 0,1,3,7,8
            for max in 0..=s.len() + 2 {
                let out = truncate_safe(s, max);
                assert!(s.starts_with(out), "must be a prefix (max={max})");
                assert!(out.len() <= max, "must not exceed max (max={max})");
                // Result is always valid UTF-8 by construction (it's a &str), and
                // the call itself must not panic — which is the whole point.
            }
            assert_eq!(truncate_safe(s, 100), s, "<= len returns whole string");
            assert_eq!(truncate_safe("hello", 3), "hel"); // pure-ASCII exact cut
        }

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
    /// module that turns an external lat/lon into a `Coordinates` entity (the
    /// forward geocoders `geocode`/`photon`/`overpass`, the precise-fix sources
    /// `geo_intel`/`exif_geo`/`wifi_intel`/`cell_intel`/`mls`, …). Modules
    /// previously hand-rolled some subset of these guards — most only rejected
    /// `0,0` and let out-of-range/NaN values through, which then became
    /// high-confidence false fixes that poison the geo-cluster correlator. One
    /// definition keeps the policy consistent.
    ///
    /// Rejects:
    ///   - non-finite values (NaN, ±inf) from malformed JSON,
    ///   - out-of-range values (`|lat| > 90`, `|lon| > 180`), and
    ///   - the `0.0, 0.0` "Null Island" sentinel that geo APIs and the Android
    ///     location stack emit when they have no real fix.
    ///
    /// Coarse IP/WiFi-geo providers (`ip_geo`, `ipinfo`, `ipapi`, `ip2location`,
    /// `ipquery`, `wigle`) want [`is_plausible_provider_coord`] instead: it
    /// builds on this but additionally drops the near-null-island placeholder
    /// band those APIs emit. Precise sources stay here so a real equatorial fix
    /// isn't discarded.
    #[must_use]
    pub fn is_valid_coords(lat: f64, lon: f64) -> bool {
        lat.is_finite()
            && lon.is_finite()
            && (-90.0..=90.0).contains(&lat)
            && (-180.0..=180.0).contains(&lon)
            && !(lat == 0.0 && lon == 0.0)
    }

    /// Magnitude (in degrees) below which a *coarse* geolocation provider's
    /// coordinate component is treated as that provider's "no fix" placeholder
    /// rather than a real position. Several IP/WiFi-geo APIs return `0.0000` or a
    /// sub-degree jitter around null island when they have no location.
    pub const NULL_ISLAND_BAND: f64 = 0.01;

    /// Validity check for coordinates coming from a *coarse* IP/WiFi-geolocation
    /// provider (`ipinfo`, `ipapi`, `ip2location`, `ipquery`, `wigle`, …):
    /// [`is_valid_coords`] **and** clear of the near-null-island
    /// [`NULL_ISLAND_BAND`] those providers emit as an "unknown" placeholder (a
    /// `loc` like `0.0000,0.0000` or `0.001,0.001`). Both components must exceed
    /// the band.
    ///
    /// Prefer this over a bare `lat.abs() > 0.01 && lon.abs() > 0.01`: that idiom
    /// (which had been copied across the five providers above) dropped null
    /// island but *silently accepted out-of-range and non-finite values*, which
    /// then became high-confidence false fixes — precisely what
    /// [`is_valid_coords`] exists to reject. Folding the validity check in keeps
    /// the band heuristic while closing that gap in one place.
    #[must_use]
    pub fn is_plausible_provider_coord(lat: f64, lon: f64) -> bool {
        is_valid_coords(lat, lon) && lat.abs() > NULL_ISLAND_BAND && lon.abs() > NULL_ISLAND_BAND
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

        #[test]
        fn plausible_provider_coord_keeps_real_fixes() {
            assert!(is_plausible_provider_coord(-27.4766, 153.0166)); // Brisbane
            assert!(is_plausible_provider_coord(51.5074, -0.1278)); // London
        }

        #[test]
        fn plausible_provider_coord_drops_null_island_band() {
            // The band the IP/WiFi providers emit as "no fix".
            assert!(!is_plausible_provider_coord(0.0, 0.0));
            assert!(!is_plausible_provider_coord(0.001, 0.001));
            // Either component inside the band is enough to drop it.
            assert!(!is_plausible_provider_coord(0.005, 120.0));
            assert!(!is_plausible_provider_coord(45.0, -0.004));
        }

        #[test]
        fn plausible_provider_coord_rejects_out_of_range_and_nonfinite() {
            // The gap the bare `abs() > 0.01` idiom left open: these used to pass
            // straight through into a high-confidence Coordinates entity.
            assert!(!is_plausible_provider_coord(500.0, 999.0));
            assert!(!is_plausible_provider_coord(91.0, 10.0));
            assert!(!is_plausible_provider_coord(10.0, 181.0));
            assert!(!is_plausible_provider_coord(f64::INFINITY, f64::INFINITY));
            assert!(!is_plausible_provider_coord(f64::NAN, 10.0));
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
