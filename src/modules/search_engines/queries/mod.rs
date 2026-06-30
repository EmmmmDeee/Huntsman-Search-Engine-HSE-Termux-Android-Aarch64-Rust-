//! Search query / dork construction for [`super::SearchEngines`].
//!
//! Behaviour-preserving extraction from `mod.rs`: every entry point keeps its
//! name and signature. `mod.rs` re-imports the handful it dispatches
//! (`build_queries`, `detect_region`, `generate_username_variants`,
//! `build_queries_fullname`); the rest are internal to this module.

mod exposure;

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
        // Federated / new-social cluster — keyless, profile-bearing.
        q.push(format!(
            "\"{v}\" site:bsky.app OR site:mastodon.social OR site:threads.net"
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

        // UK company/director surfaces — Companies House (find-and-update +
        // beta) for directorship records.
        q.push(format!(
            "\"{v}\" site:find-and-update.company-information.service.gov.uk \
             OR site:beta.companieshouse.gov.uk"
        ));

        // US SEC EDGAR — named individuals appear in filings as officers,
        // directors, or beneficial owners.
        q.push(format!("\"{v}\" site:sec.gov OR site:efts.sec.gov"));

        // EU/global company registry — OpenCorporates lists officers
        // across 140+ jurisdictions.
        q.push(format!(
            "\"{v}\" site:opencorporates.com director OR officer"
        ));

        // Intext body search — name appears near contact details in
        // articles, PDFs, or directories.
        q.push(format!("intext:\"{v}\" email OR phone OR address"));
    }
    q
}

/// A region autonomously inferred from a seed's own signals (HSE's focus is AU).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Region {
    Au,
    Uk,
    Us,
    Eu,
}

/// Infer a region from the seed itself — only when it carries a clear signal, so
/// region augmentation never fires on a region-less seed (stays geo-neutral).
pub(super) fn detect_region(target: &Target) -> Option<Region> {
    let v = target.value.trim().to_lowercase();
    let host_au = |h: &str| h.ends_with(".au");
    let host_uk = |h: &str| h.ends_with(".uk");
    let host_us = |h: &str| h.ends_with(".edu") || h.ends_with(".gov");
    match target.kind {
        TargetKind::AbnAcn => Some(Region::Au),
        TargetKind::Domain => {
            if host_au(&v) {
                Some(Region::Au)
            } else if host_uk(&v) || v.ends_with(".co.uk") {
                Some(Region::Uk)
            } else if host_us(&v) {
                Some(Region::Us)
            } else {
                None
            }
        }
        TargetKind::Url => {
            let host = crate::util::url_util::host_from_url(&v);
            if let Some(ref h) = host {
                if host_au(h) {
                    return Some(Region::Au);
                }
                if host_uk(h) || h.ends_with(".co.uk") {
                    return Some(Region::Uk);
                }
                if host_us(h) {
                    return Some(Region::Us);
                }
            }
            None
        }
        TargetKind::Email => {
            if let Some((_, d)) = v.rsplit_once('@') {
                if host_au(d) {
                    return Some(Region::Au);
                }
                if host_uk(d) || d.ends_with(".co.uk") {
                    return Some(Region::Uk);
                }
                if host_us(d) {
                    return Some(Region::Us);
                }
            }
            None
        }
        TargetKind::Phone => {
            let digits = crate::util::str_util::ascii_digits(&v);
            // `+61` is unambiguous. A *bare* `61…` is only the AU country code at
            // full international length (61 + 9 national digits = 11); gating on
            // that stops a domestic number like the US `610` area code
            // (`610-555-1234` → `6105551234`, 10 digits) from falsely tagging AU.
            let bare_au_cc = digits.len() >= 11 && digits.starts_with("61");
            if v.contains("+61") || bare_au_cc {
                return Some(Region::Au);
            }
            // +44 → UK
            if v.contains("+44") {
                return Some(Region::Uk);
            }
            // +1 with 11 digits (country code 1 + 10 national digits) → US
            let bare_us_cc = digits.len() == 11 && digits.starts_with('1');
            if (v.contains("+1") && digits.len() == 11) || bare_us_cc {
                return Some(Region::Us);
            }
            // EU country codes: +49 DE, +33 FR, +31 NL, +34 ES, +39 IT
            if ["+49", "+33", "+31", "+34", "+39"]
                .iter()
                .any(|cc| v.contains(cc))
            {
                return Some(Region::Eu);
            }
            None
        }
        TargetKind::Address | TargetKind::Organisation => {
            if v.contains("australia")
                || [" nsw", " vic", " qld", " wa", " sa", " tas", " act", " nt"]
                    .iter()
                    .any(|s| v.contains(s))
            {
                Some(Region::Au)
            } else if v.contains("united kingdom")
                || v.contains(".co.uk")
                || [
                    " england",
                    " scotland",
                    " wales",
                    " surrey",
                    " kent",
                    " essex",
                    " yorkshire",
                    " lancashire",
                ]
                .iter()
                .any(|s| v.contains(s))
            {
                Some(Region::Uk)
            } else {
                None
            }
        }
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
        Region::Uk => {
            vec![
                format!("\"{v}\" site:co.uk OR site:org.uk OR site:gov.uk"),
                format!("\"{v}\" site:192.com OR site:ukphonebook.com OR site:thephonebook.co.uk"),
            ]
        }
        Region::Us => {
            vec![
                format!("\"{v}\" site:whitepages.com OR site:spokeo.com OR site:intelius.com"),
                format!("\"{v}\" site:pacer.gov OR site:courtlistener.com"),
            ]
        }
        Region::Eu => Vec::new(),
    }
}

/// The dork set for a seed: the geolocation-neutral base, plus minimal
/// autonomous region-scoped dorks when regional searching is toggled on,
/// plus supplementary exposure/secrets dorks appended after the base set.
pub(super) fn build_queries(target: &Target) -> Vec<String> {
    let base = build_queries_base(target);
    let mut queries = if !regional_enabled() {
        base
    } else {
        interleave_regional(base, regional_dorks(target))
    };
    queries.extend(exposure::build_queries_exposure(target));
    queries
}

/// Order the dork set so Australian regional coverage isn't starved under a tight
/// time budget: run the single strongest base query first (the exact-match), then
/// the AU dorks, then the remaining base queries. Previously the regional dorks
/// were appended last and a budget-limited scan never reached them — the AU focus
/// existed on paper but rarely dispatched. **Pure**, so the ordering is unit-tested
/// without touching the process-global regional flag.
fn interleave_regional(base: Vec<String>, regional: Vec<String>) -> Vec<String> {
    if regional.is_empty() {
        return base;
    }
    if base.is_empty() {
        return regional;
    }
    let mut it = base.into_iter();
    let first = it.next().expect("base non-empty");
    let mut q = Vec::with_capacity(1 + regional.len() + it.len());
    q.push(first);
    q.extend(regional);
    q.extend(it);
    q
}

pub(super) fn build_queries_base(target: &Target) -> Vec<String> {
    let v = target.value.trim();
    if v.is_empty() {
        return Vec::new();
    }
    match target.kind {
        TargetKind::Domain => vec![
            // Bare site:{v} was 50% blocked and only 27% hit rate in live scans;
            // the operator-enriched site: patterns below cover the same index
            // with 99-100% hit rate and no block pressure.
            format!("site:{v} filetype:pdf OR filetype:doc OR filetype:xls"),
            format!("\"{v}\" \"@{v}\""),
            format!("site:{v} inurl:login OR inurl:admin OR inurl:signin"),
            format!("\"{v}\" ABN OR ACN OR \"Pty Ltd\" OR \"business number\""),
            // Exposed config/backup files
            format!("site:{v} ext:sql OR ext:bak OR ext:log OR ext:conf"),
            format!("site:{v} filetype:env OR inurl:wp-config.php OR inurl:configuration.php"),
            format!("site:{v} intext:\"password\" OR intext:\"api_key\" OR intext:\"secret\""),
            // Subdomain discovery via negative site
            format!("site:{v} -site:www.{v}"),
            // Backlinks
            format!("link:{v}"),
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
                    "\"{local}\" site:soundcloud.com OR site:instagram.com \
                     OR site:youtube.com OR site:tiktok.com"
                ));
                q.push(format!(
                    "\"{local}\" site:bsky.app OR site:mastodon.social OR site:threads.net"
                ));
                q.push(format!("\"{local}\" address OR location OR city"));
                q.push(format!(
                    "\"{local}\" site:whitepages.com.au OR site:locatefamily.com \
                     OR site:peoplefinder.com.au OR site:searchfind.com.au \
                     OR site:australialookup.com OR site:personlookup.com.au"
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
            // Credential/hash exposure in body text
            q.push(format!("intext:\"{v}\" password OR hash OR md5 OR sha256"));
            // Code repository mentions
            q.push(format!(
                "\"{v}\" site:github.com OR site:gitlab.com OR site:bitbucket.org"
            ));
            // Temporal breach discovery
            q.push(format!("\"{v}\" breach OR leak OR dump after:2020-01-01"));
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
            // Federated / new-social cluster — keyless, profile-bearing, and rising
            // fast for identity footprints the legacy networks miss.
            format!("\"{v}\" site:bsky.app OR site:mastodon.social OR site:threads.net"),
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
            // Profile page title matching (more precise than intitle: with OR)
            format!("allintitle:\"{v}\""),
            // Code contribution fingerprinting
            format!("\"{v}\" site:github.com OR site:stackoverflow.com OR site:dev.to"),
            // Account aggregators
            format!("\"{v}\" site:keybase.io OR site:about.me OR site:gravatar.com"),
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
                // Recent breach/leak mentions on paste sites
                q.push(format!("\"{v}\" site:pastebin.com OR site:ghostbin.co"));
                // Temporal owner/name discovery
                q.push(format!("intext:\"{v}\" name OR owner after:2018-01-01"));
            }
            q
        }
        TargetKind::IpAddress => vec![
            format!("\"{v}\""),
            format!("\"{v}\" hostname OR server OR domain"),
            format!("\"{v}\" site:shodan.io OR site:censys.io OR site:zoomeye.org"),
            format!("\"{v}\" location OR city OR country OR ISP"),
            // Server exposure
            format!("\"{v}\" inurl:phpmyadmin OR inurl:admin OR inurl:jenkins"),
            // CVE/vulnerability exposure
            format!("\"{v}\" intext:CVE OR vulnerability OR exploit"),
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
            // UK Companies House
            q.push(format!(
                "\"{v}\" site:find-and-update.company-information.service.gov.uk"
            ));
            // US SEC EDGAR
            q.push(format!(
                "\"{v}\" site:sec.gov OR site:efts.sec.gov filing OR report"
            ));
            // OpenCorporates global
            q.push(format!("\"{v}\" site:opencorporates.com"));
            // Intext regulatory filing mentions
            q.push(format!(
                "intext:\"{v}\" annual report OR filing OR director"
            ));
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
        TargetKind::TrackingId => {
            // A tracking ID in quotes finds pages that embed the same ID —
            // the canonical cross-domain co-ownership pivot.
            let base = v.to_ascii_uppercase();
            vec![
                format!("\"{base}\""),
                format!("\"{base}\" site:github.com OR site:gitlab.com"),
                format!("\"{base}\" -site:google.com -site:googletagmanager.com"),
            ]
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
    include!("tests.rs");
}
