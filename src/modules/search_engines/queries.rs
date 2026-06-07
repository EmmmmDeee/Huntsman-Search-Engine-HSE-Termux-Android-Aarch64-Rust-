//! Search query / dork construction for [`super::SearchEngines`].
//!
//! Behaviour-preserving extraction from `mod.rs`: every entry point keeps its
//! name and signature. `mod.rs` re-imports the handful it dispatches
//! (`build_queries`, `detect_region`, `generate_username_variants`,
//! `build_queries_fullname`); the rest are internal to this module.

use super::regional_enabled;
use crate::core::scan::{Target, TargetKind};

/// FullName search-dork set. Extracted verbatim from `build_queries` — the
/// largest, most self-contained arm (~100 lines of person-centric dorks:
/// social/professional, AU people-search, courts/registries, news, diaspora
/// platforms, email-discovery). Pure (`&str -> Vec<String>`) so it is
/// unit-testable in isolation. `v` is the already-trimmed target value.
pub(super) fn build_queries_fullname(v: &str) -> Vec<String> {
    let parts: Vec<&str> = v.split_whitespace().collect();
    let mut q = vec![
        format!("\"{v}\""),
        format!("\"{v}\" site:linkedin.com OR site:facebook.com OR site:twitter.com"),
    ];
    if parts.len() >= 2 {
        let first = parts[0];
        let last = parts[parts.len() - 1];
        let fl = format!("{first} {last}");

        // First+Last without middle names — broader match
        if parts.len() > 2 {
            q.push(format!("\"{fl}\""));
        }

        // Social / professional
        q.push(format!(
            "{fl} site:instagram.com OR site:github.com OR site:reddit.com"
        ));
        q.push(format!("\"{v}\" email OR contact OR profile"));
        q.push(format!(
            "\"{v}\" site:peekyou.com OR site:spokeo.com \
             OR site:nuwber.com OR site:pipl.com"
        ));
        q.push(format!("\"{v}\" address OR location OR city OR suburb"));

        // Middle names as potential usernames (3+ part names)
        if parts.len() >= 3 {
            let middle = parts[1..parts.len() - 1].join(" ");
            // Common username patterns from multi-part names
            let fl_concat = format!("{}{}", first.to_lowercase(), last.to_lowercase());
            // First initial as a CHAR (not byte 0) so a multi-byte initial
            // (e.g. a Greek/Cyrillic given name) can't panic the slice.
            let first_initial: String = first
                .chars()
                .next()
                .map(|c| c.to_lowercase().to_string())
                .unwrap_or_default();
            let fml = format!(
                "{}{}{}",
                first_initial,
                middle.to_lowercase(),
                last.to_lowercase()
            );
            q.push(format!("\"{fl_concat}\" OR \"{fml}\" profile OR account"));
        }

        // Business / corporate
        q.push(format!("\"{v}\" ABN OR ACN OR \"Pty Ltd\" OR director"));

        // Australian people-search directories
        q.push(format!(
            "\"{v}\" site:whitepages.com.au OR site:locatefamily.com \
             OR site:peoplefinder.com.au OR site:searchfind.com.au"
        ));

        // Australian public records — courts, electoral, property.
        // QLD + NSW are the largest jurisdictions by population so
        // they get the dedicated dork; the broader state coverage
        // below catches VIC/WA/SA/TAS/ACT/NT court mentions.
        q.push(format!(
            "\"{v}\" site:courts.qld.gov.au OR site:ecourts.justice.nsw.gov.au \
             OR site:austlii.edu.au OR site:jade.io"
        ));
        q.push(format!(
            "\"{v}\" site:supremecourt.vic.gov.au OR site:supremecourt.wa.gov.au \
             OR site:courts.sa.gov.au OR site:supremecourt.tas.gov.au \
             OR site:courts.act.gov.au OR site:supremecourt.nt.gov.au"
        ));
        // Health-practitioner registry — covers doctors, nurses,
        // dentists, pharmacists, psychologists, physios across
        // every AU state. High-yield when the seed is a medical
        // professional's name.
        q.push(format!("\"{v}\" site:ahpra.gov.au OR site:apra.gov.au"));
        q.push(format!(
            "\"{fl}\" Queensland OR Brisbane OR \"Gold Coast\" OR Cairns"
        ));

        // Email discovery dork — search for the name near email addresses
        q.push(format!(
            "\"{fl}\" \"@gmail.com\" OR \"@hotmail.com\" OR \"@outlook.com\" OR \"@yahoo.com\""
        ));

        // News / media mentions
        q.push(format!(
            "\"{v}\" site:abc.net.au OR site:news.com.au \
             OR site:smh.com.au OR site:couriermail.com.au"
        ));

        // Forum / community (usernames often match real names)
        q.push(format!(
            "\"{fl}\" site:whirlpool.net.au OR site:forums.realestate.com.au \
             OR site:ozbargain.com.au"
        ));

        // Post-Soviet / European social platforms — VK + OK
        // people search. Significant global diaspora presence
        // (incl. ~70k VK users in AU per public estimates), so
        // worth dorking even on Anglophone names.
        q.push(format!("\"{fl}\" site:vk.com OR site:ok.ru"));

        // Telegram public-presence + gaming-platform dorks.
        // Names sometimes appear in channel descriptions,
        // public group rosters, and Steam profile bios.
        q.push(format!(
            "\"{fl}\" site:t.me OR site:steamcommunity.com \
             OR site:twitch.tv"
        ));
    }
    q
}

/// A region autonomously inferred from a seed's own signals (HSE's focus is AU).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Region {
    Au,
}

/// Infer a region from the seed itself — only when it carries a clear signal, so
/// region augmentation never fires on a region-less seed (stays geo-neutral).
pub(super) fn detect_region(target: &Target) -> Option<Region> {
    let v = target.value.trim().to_lowercase();
    let host_au = |h: &str| h.ends_with(".au");
    match target.kind {
        TargetKind::AbnAcn => Some(Region::Au),
        TargetKind::Domain => host_au(&v).then_some(Region::Au),
        TargetKind::Url => crate::util::url_util::host_from_url(&v)
            .filter(|h| host_au(h))
            .map(|_| Region::Au),
        TargetKind::Email => v
            .rsplit_once('@')
            .is_some_and(|(_, d)| host_au(d))
            .then_some(Region::Au),
        TargetKind::Phone => {
            let digits = crate::util::str_util::ascii_digits(&v);
            // `+61` is unambiguous. A *bare* `61…` is only the AU country code at
            // full international length (61 + 9 national digits = 11); gating on
            // that stops a domestic number like the US `610` area code
            // (`610-555-1234` → `6105551234`, 10 digits) from falsely tagging AU.
            let bare_au_cc = digits.len() >= 11 && digits.starts_with("61");
            (v.contains("+61") || bare_au_cc).then_some(Region::Au)
        }
        TargetKind::Address | TargetKind::Organisation => (v.contains("australia")
            || [" nsw", " vic", " qld", " wa", " sa", " tas", " act", " nt"]
                .iter()
                .any(|s| v.contains(s)))
        .then_some(Region::Au),
        _ => None,
    }
}

/// Minimal, autonomous region-scoped dorks appended when regional searching is
/// on. HSE is Australia-focused, so a seed carrying no region signal of its own
/// defaults to AU — every scan then favours Australian sources (`.au` TLDs, AU
/// directories) without losing the geolocation-neutral base queries. A seed with
/// an explicit signal (e.g. a `.uk`-style address) would still report its own
/// region via [`detect_region`]; only the unknown case defaults to AU.
pub(super) fn regional_dorks(target: &Target) -> Vec<String> {
    let region = detect_region(target).unwrap_or(Region::Au);
    let v = target.value.trim();
    if v.is_empty() {
        return Vec::new();
    }
    match region {
        Region::Au => {
            let mut d = vec![format!(
                "\"{v}\" site:com.au OR site:org.au OR site:gov.au OR site:net.au OR site:edu.au"
            )];
            if matches!(
                target.kind,
                TargetKind::FullName
                    | TargetKind::Username
                    | TargetKind::Email
                    | TargetKind::Phone
                    | TargetKind::Organisation
            ) {
                d.push(format!(
                    "\"{v}\" site:whitepages.com.au OR site:yellowpages.com.au \
                     OR site:truelocal.com.au"
                ));
            }
            d
        }
    }
}

/// The dork set for a seed: the geolocation-neutral base, plus minimal
/// autonomous region-scoped dorks when regional searching is toggled on.
pub(super) fn build_queries(target: &Target) -> Vec<String> {
    let mut q = build_queries_base(target);
    if regional_enabled() {
        q.extend(regional_dorks(target));
    }
    q
}

pub(super) fn build_queries_base(target: &Target) -> Vec<String> {
    let v = target.value.trim();
    if v.is_empty() {
        return Vec::new();
    }
    match target.kind {
        TargetKind::Domain => vec![
            format!("site:{v}"),
            format!("site:{v} filetype:pdf OR filetype:doc OR filetype:xls"),
            format!("\"{v}\" \"@{v}\""),
            format!("site:{v} inurl:login OR inurl:admin OR inurl:signin"),
            format!("\"{v}\" ABN OR ACN OR \"Pty Ltd\" OR \"business number\""),
        ],
        TargetKind::Email => {
            let domain = v.rsplit_once('@').map_or("", |(_, d)| d);
            let local = v.split('@').next().unwrap_or("");
            let mut q = vec![format!("\"{v}\""), format!("\"{local}\"")];
            if !domain.is_empty()
                && !["gmail.com", "yahoo.com", "hotmail.com", "outlook.com"].contains(&domain)
            {
                q.push(format!(
                    "\"{v}\" site:linkedin.com OR site:github.com OR site:facebook.com"
                ));
            }
            if local.len() >= 3 {
                q.push(format!(
                    "\"{local}\" site:linkedin.com OR site:twitter.com \
                     OR site:facebook.com OR site:myspace.com"
                ));
                q.push(format!(
                    "\"{local}\" site:peekyou.com OR site:nuwber.com \
                     OR site:spokeo.com OR site:pipl.com"
                ));
                q.push(format!(
                    "{local} site:soundcloud.com OR site:instagram.com \
                     OR site:youtube.com OR site:tiktok.com"
                ));
                q.push(format!("\"{local}\" address OR location OR city"));
                q.push(format!(
                    "\"{local}\" site:whitepages.com.au OR site:locatefamily.com \
                     OR site:peoplefinder.com.au OR site:searchfind.com.au"
                ));
            }
            // Breach-DB direct surfaces. HaveIBeenPwned + DeHashed +
            // IntelX are already covered by their dedicated modules;
            // dorking adds LeakCheck, Snusbase, BreachDirectory, and
            // Scattered-Secrets as supplementary corpora that don't
            // require keys to surface a hit count.
            q.push(format!(
                "\"{v}\" site:leakcheck.io OR site:snusbase.com \
                 OR site:breachdirectory.org OR site:scatteredsecrets.com"
            ));
            // Paste-site dork — Pastebin, paste.ee, Ghostbin, GitHub
            // gists. High-yield for leaked credentials and dumps.
            q.push(format!(
                "\"{v}\" site:pastebin.com OR site:paste.ee \
                 OR site:ghostbin.co OR site:gist.github.com"
            ));
            // Direct credential / password presence indicator. Surfaces
            // mentions where the email is next to a leaked credential.
            q.push(format!("\"{v}\" password OR login OR credentials"));
            q
        }
        // Broad → narrow ladder: start universal (widest net), then narrow into
        // intent, engine syntax, and seed-specific platform dorks.
        TargetKind::Username => vec![
            // ── Tier 1: universal — broadest possible reach ──
            v.to_string(),      // bare handle: every mention, any engine
            format!("\"{v}\""), // exact-match phrase
            // ── Tier 2: intent narrowing via boolean OR ──
            format!("\"{v}\" profile OR account OR username OR bio OR about"),
            format!("\"{v}\" email OR contact OR address"),
            // ── Tier 3: engine syntax — handle in a page title or URL (the
            //    signature of a profile page), via intitle:/inurl: operators ──
            format!("intitle:\"{v}\" OR inurl:{v}"),
            // ── Tier 4: seed-specific platform site: dorks (narrowest) ──
            format!("\"{v}\" site:github.com OR site:gitlab.com OR site:keybase.io"),
            format!(
                "\"{v}\" site:twitter.com OR site:x.com \
                 OR site:reddit.com OR site:instagram.com"
            ),
            format!("\"{v}\" site:linkedin.com OR site:facebook.com OR site:tiktok.com"),
            format!(
                "\"{v}\" site:peekyou.com OR site:nuwber.com \
                 OR site:spokeo.com OR site:pipl.com"
            ),
            // VK + OK (Odnoklassniki) — Russian-language social platforms with
            // large diaspora presence; worth dorking even in English investigations.
            format!("\"{v}\" site:vk.com OR site:ok.ru"),
            // Telegram public channels + mentions (t.me / telegra.ph).
            format!("\"{v}\" site:t.me OR site:telegra.ph"),
            // Gaming platforms — handles here are often unique across an identity.
            format!(
                "\"{v}\" site:steamcommunity.com OR site:twitch.tv \
                 OR site:disboard.org OR site:top.gg"
            ),
            // Community username aggregators — probe hundreds of sites at once.
            format!(
                "\"{v}\" site:whatsmyname.app OR site:namecheckr.com \
                 OR site:check-username.com"
            ),
        ],
        TargetKind::FullName => build_queries_fullname(v),
        TargetKind::Phone => {
            let mut q = vec![format!("\"{v}\"")];
            let digits = crate::util::str_util::ascii_digits(v);
            if digits.len() >= 7 {
                q.push(format!(
                    "\"{v}\" site:whitepages.com OR site:truecaller.com \
                     OR site:whocalledme.com OR site:reversephonelookup.com"
                ));
                q.push(format!("\"{v}\" name OR address OR owner"));
                // Additional reverse-phone OSINT surfaces (Sorrow et al.):
                // NumBuster, GetContact, Sync.me, Callapp — all crowd-
                // sourced caller-ID datasets with broader coverage than
                // Truecaller for non-Anglosphere numbers.
                q.push(format!(
                    "\"{v}\" site:numbuster.com OR site:getcontact.com \
                     OR site:sync.me OR site:callapp.com"
                ));
                // WhatsApp + Telegram presence — `wa.me/<digits>` redirects
                // to a chat if the number is WhatsApp-registered; Telegram
                // `t.me/<digits>` similar. Dorking via Google surfaces
                // public mentions of the number on either platform.
                q.push(format!("\"{v}\" site:wa.me OR site:t.me"));
                // VK + Facebook by-phone search — both platforms let
                // members register with a phone number and the public
                // profile sometimes surfaces it.
                q.push(format!("\"{v}\" site:vk.com OR site:facebook.com"));
            }
            q
        }
        TargetKind::IpAddress => vec![
            format!("\"{v}\""),
            format!("\"{v}\" hostname OR server OR domain"),
            format!("\"{v}\" site:shodan.io OR site:censys.io OR site:zoomeye.org"),
            format!("\"{v}\" location OR city OR country OR ISP"),
        ],
        TargetKind::Organisation => {
            let mut q = vec![
                format!("\"{v}\""),
                format!("\"{v}\" ABN OR ACN OR \"business number\" OR director"),
                format!(
                    "\"{v}\" site:abr.business.gov.au OR site:asic.gov.au \
                     OR site:opencorporates.com"
                ),
                format!("\"{v}\" address OR location OR headquarters"),
                format!("\"{v}\" email OR contact OR phone"),
            ];
            let lower = v.to_lowercase();
            if !lower.contains("pty") && !lower.contains("ltd") {
                q.push(format!("\"{v}\" \"Pty Ltd\" OR \"Limited\" OR \"Inc\""));
            }
            q
        }
        TargetKind::Address => {
            let mut q = vec![format!("\"{v}\"")];
            q.push(format!("\"{v}\" resident OR owner OR tenant OR occupant"));
            q.push(format!(
                "\"{v}\" site:realestate.com.au OR site:domain.com.au \
                 OR site:zillow.com OR site:trulia.com"
            ));
            // AU state land-registry surfaces (per-state title office +
            // strata records). Picks up the formal property descriptor
            // for an address — useful when the breach data has only the
            // street and we need the lot / plan number.
            q.push(format!(
                "\"{v}\" site:nswlrs.com.au OR site:land.vic.gov.au \
                 OR site:landgate.wa.gov.au OR site:landservices.sa.gov.au \
                 OR site:thelist.tas.gov.au OR site:nt.gov.au"
            ));
            // Strata + body-corporate records — directors, occupants of
            // multi-dwelling buildings.
            q.push(format!(
                "\"{v}\" strata OR \"body corporate\" OR \"owners corporation\""
            ));
            q.push(format!("\"{v}\" ABN OR business OR company OR shop"));
            q
        }
        TargetKind::Asn => {
            let asn = if v.starts_with("AS") || v.starts_with("as") {
                v.to_uppercase()
            } else {
                format!("AS{v}")
            };
            vec![
                format!("\"{asn}\""),
                format!("\"{asn}\" site:bgp.he.net OR site:bgpview.io OR site:peeringdb.com"),
                format!("\"{asn}\" abuse OR peering OR prefix OR allocation"),
            ]
        }
        TargetKind::AbnAcn => {
            let digits = crate::util::str_util::ascii_digits(v);
            vec![
                format!("\"{v}\""),
                format!(
                    "\"{digits}\" site:abr.business.gov.au OR site:asic.gov.au \
                     OR site:opencorporates.com"
                ),
                format!("\"{digits}\" ABN OR ACN OR \"business number\" OR director"),
            ]
        }
        TargetKind::Url => {
            let host = v
                .trim_start_matches("https://")
                .trim_start_matches("http://")
                .split('/')
                .next()
                .unwrap_or(v);
            vec![
                format!("\"{v}\""),
                format!("site:{host}"),
                format!("\"{host}\" email OR contact OR about"),
            ]
        }
        TargetKind::Coordinates => {
            if let Some((lat, lon)) = v.split_once(',') {
                let lat = lat.trim();
                let lon = lon.trim();
                vec![
                    format!("\"{lat}\" \"{lon}\""),
                    format!("\"{lat},{lon}\" address OR location OR property"),
                    format!("\"{lat}\" \"{lon}\" site:google.com/maps OR site:openstreetmap.org"),
                ]
            } else {
                Vec::new()
            }
        }
        _ => Vec::new(),
    }
}

// ─── Username variant generation ────────────────────────────────────────────

/// Generate common username variants from a base handle. OSINT best
/// practice: people reuse patterns like underscore/dot swaps, trailing
/// digits, first-initial+lastname. This dramatically increases cross-
/// platform discovery.
pub(super) fn generate_username_variants(base: &str) -> Vec<String> {
    let lower = base.to_lowercase();
    let mut variants = Vec::with_capacity(8);

    // Separator swaps: jerome-despal ↔ jerome_despal ↔ jerome.despal ↔ jeromedespal
    if lower.contains('_') || lower.contains('-') || lower.contains('.') {
        let no_sep: String = lower
            .chars()
            .filter(|c| *c != '_' && *c != '-' && *c != '.')
            .collect();
        let with_under = lower.replace(['-', '.'], "_");
        let with_dash = lower.replace(['_', '.'], "-");
        let with_dot = lower.replace(['_', '-'], ".");
        for v in [no_sep, with_under, with_dash, with_dot] {
            if v != lower && v.len() >= 3 {
                variants.push(v);
            }
        }
    }

    // Trailing digit variants: jdespal → jdespal1, jdespal2
    if !lower.ends_with(|c: char| c.is_ascii_digit()) && lower.len() >= 4 {
        variants.push(format!("{lower}1"));
        variants.push(format!("{lower}2"));
    }

    // Truncation: jdespal → jdespa (off-by-one typos / platform limits). Drop
    // the last CHAR, not byte: `lower[..len-1]` panics when the handle ends in a
    // multi-byte codepoint (e.g. `andré`) by slicing mid-codepoint — the same
    // boundary hazard the name-dork builder guards against above.
    if lower.chars().count() >= 5 {
        let mut chars = lower.chars();
        chars.next_back();
        variants.push(chars.as_str().to_string());
    }

    variants
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn separator_swaps_are_generated_and_deduped() {
        let v = generate_username_variants("jerome.despal");
        assert!(v.contains(&"jeromedespal".to_string())); // separators removed
        assert!(v.contains(&"jerome_despal".to_string())); // → underscore
        assert!(v.contains(&"jerome-despal".to_string())); // → dash
        // The original form is never emitted as its own variant.
        assert!(!v.contains(&"jerome.despal".to_string()));
    }

    #[test]
    fn trailing_digit_and_truncation_variants() {
        let v = generate_username_variants("jdespal");
        assert!(v.contains(&"jdespal1".to_string()));
        assert!(v.contains(&"jdespal2".to_string()));
        assert!(v.contains(&"jdespa".to_string())); // last char dropped
    }

    #[test]
    fn digit_terminated_handles_skip_digit_variants() {
        // Already ends in a digit → no `…1`/`…2` appended.
        let v = generate_username_variants("agent007");
        assert!(!v.iter().any(|s| s.ends_with("0071") || s.ends_with("0072")));
    }

    #[test]
    fn multibyte_handle_truncates_by_char_without_panicking() {
        // Regression: a handle ending in a multi-byte codepoint must not panic
        // on the truncation slice, and must drop a whole char.
        let v = generate_username_variants("andré");
        assert!(v.contains(&"andr".to_string())); // 'é' dropped whole
        assert!(v.iter().all(|s| s != "andré"));

        // Pure non-ASCII handle (every char multi-byte) — also must not panic.
        let _ = generate_username_variants("Ωμέγα");
    }

    #[test]
    fn short_handle_yields_no_variants() {
        // No separators, < 4 chars → nothing (too short to pivot on).
        assert!(generate_username_variants("ab").is_empty());
    }

    #[test]
    fn detect_region_flags_australian_seeds() {
        use crate::core::scan::Target;
        assert_eq!(
            detect_region(&Target::new(TargetKind::Domain, "example.com.au")),
            Some(Region::Au)
        );
        assert_eq!(
            detect_region(&Target::new(TargetKind::Email, "person@deakin.edu.au")),
            Some(Region::Au)
        );
        assert_eq!(
            detect_region(&Target::new(TargetKind::Phone, "+61 412 345 678")),
            Some(Region::Au)
        );
        assert_eq!(
            detect_region(&Target::new(
                TargetKind::Address,
                "10 Queen St, Brisbane QLD"
            )),
            Some(Region::Au)
        );
        // Non-AU seeds → no region.
        assert_eq!(
            detect_region(&Target::new(TargetKind::Domain, "example.com")),
            None
        );
        assert_eq!(
            detect_region(&Target::new(TargetKind::Username, "jdoe")),
            None
        );
    }

    #[test]
    fn detect_region_phone_distinguishes_au_cc_from_us_area_code() {
        use crate::core::scan::Target;
        // Bare AU country code at full international length → AU.
        assert_eq!(
            detect_region(&Target::new(TargetKind::Phone, "61 412 345 678")),
            Some(Region::Au)
        );
        // US `610` area code (10 digits) must NOT be read as AU country code.
        assert_eq!(
            detect_region(&Target::new(TargetKind::Phone, "610-555-1234")),
            None
        );
        // `+61` stays unambiguous regardless of spacing.
        assert_eq!(
            detect_region(&Target::new(TargetKind::Phone, "+61 2 9000 0000")),
            Some(Region::Au)
        );
    }
}
