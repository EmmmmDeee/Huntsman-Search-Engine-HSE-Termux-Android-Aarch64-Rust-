//! Typosquat / domain-permutation discovery — 15-technique world-class engine.
//!
//! Generates lookalike variants of a target domain and resolves each via the
//! shared DNS resolver, emitting a `Domain` entity for every candidate that
//! carries an **A/AAAA record** (active site) or an **MX record with no A**
//! (phishing-prep: mail infrastructure staged before the deceptive web
//! presence goes live — a high-fidelity early-warning signal).
//!
//! ## Technique coverage (ordered by priority under the candidate cap)
//!
//! 1. `addition` — prepend/append curated phishing keywords with and without a
//!    hyphen separator (e.g. `loginexample`, `example-login`).
//! 2. `homoglyph` — ASCII look-alike single-character substitutions; expanded
//!    table covering leet-speak digits and visual letter pairs.
//! 3. `digraph` — multi-character visual confusables: `rn`↔`m`, `cl`↔`d`,
//!    `vv`↔`w`. Invisible to skimming eyes.
//! 4. `vowel-swap` — replace each vowel with every other vowel.
//! 5. `keyboard` — QWERTY-adjacent key replacements.
//! 6. `omission` — drop one character.
//! 7. `transposition` — swap two adjacent characters.
//! 8. `repetition` — double one character.
//! 9. `bitsquat` — flip one bit of each ASCII byte (hardware-error squatting;
//!    generates real traffic on busy CDNs).
//! 10. `hyphenation` — insert a hyphen between two adjacent characters.
//! 11. `hyphen-removal` — remove each hyphen from a hyphenated label.
//! 12. `plural` — add or remove a trailing `s`.
//! 13. `insertion` — insert every a–z letter at every label position
//!     (catches `youutube`-style extra-character squats).
//! 14. `tld-swap` — swap the TLD from a 28-entry list covering common gTLDs,
//!     AU second-levels, and criminal-favoured ccTLDs.
//! 15. `combo-homoglyph` — two simultaneous ASCII homoglyph substitutions for
//!     labels with ≥ 2 homoglyph-eligible positions.
//!
//! ## Confidence
//!
//! Confidence is technique-dependent rather than a hardcoded flat value:
//! - `addition` + A record: **0.70** — almost certainly deliberate phishing
//!   infrastructure (attacker registered `examplelogin.com`).
//! - `homoglyph` / `digraph`: **0.65** — visual-trick squats are intentional.
//! - `vowel-swap` / `combo-homoglyph`: **0.62**.
//! - `keyboard` / `omission` / `transposition`: **0.55** — could be genuine typo.
//! - `tld-swap` / `insertion` / `repetition`: **0.52**.
//! - `bitsquat` / `hyphenation` / `hyphen-removal` / `plural`: **0.50**.
//! - MX-only (any technique): subtract 0.05 — real but less certain (tagged
//!   `phishing-prep` + `mx-only`).
//!
//! No new dependencies — Termux-clean, pure-Rust, `#![forbid(unsafe_code)]`.

use std::sync::Arc;

use async_trait::async_trait;
use hickory_resolver::proto::rr::RData;
use tokio::sync::Semaphore;

use crate::core::{
    entity::{Entity, EntityKind, Evidence},
    error::Result,
    module::{Module, ModuleCategory, ModuleContext, ModuleResult},
    scan::{Target, TargetKind},
};
use crate::util::dns::shared_resolver;

const SRC: &str = "typosquat";

/// Cap on permutations resolved per scan.  512 accommodates all 15 technique
/// classes for typical 6–12 char labels without exhausting the DNS budget.
const MAX_CANDIDATES: usize = 512;

/// Concurrent DNS slots — raised from 12 to 20 to keep the resolve phase
/// inside the declared timeout even at MAX_CANDIDATES.
const MAX_CONCURRENT: usize = 20;

/// TLD swap targets — 26 entries covering common gTLDs, AU second-levels,
/// English-speaking ccTLDs, and ccTLDs that are statistically over-represented
/// in phishing-domain registrations.
const SWAP_TLDS: &[&str] = &[
    // Common gTLDs
    "com", "net", "org", "co", "io", "app", "online", "site", "xyz",
    // AU focus (primary operator market)
    "com.au", "net.au", "org.au", "edu.au",
    // English-speaking ccTLDs criminals target
    "co.uk", "co.nz", "ca", "in", // Cheap / criminal-favoured TLDs
    "info", "biz", "cc", "pw", "click", "link", // ccTLDs where phishing infra clusters
    "cn", "ru", "de", "eu", "us",
];

/// Phishing-attack keyword prefixes.  Prepended to the brand label (with and
/// without a hyphen separator) to mimic legitimate subdomains or helpers.
const ATTACK_PREFIXES: &[&str] = &[
    "my", "the", "login", "secure", "access", "account", "verify", "www", "go", "get", "real",
    "safe", "new",
];

/// Phishing-attack keyword suffixes.  Appended to the brand label.
const ATTACK_SUFFIXES: &[&str] = &[
    "login", "secure", "account", "verify", "update", "portal", "app", "online", "web", "shop",
    "store", "help", "support", "auth", "access", "signin",
];

/// Vowel set for `vowel-swap` technique.
const VOWELS: &[char] = &['a', 'e', 'i', 'o', 'u'];

/// Compute entity confidence from the generating technique and resolution type.
/// MX-only domains lose 0.05 — they are real phishing-prep signals but not yet
/// confirmed as active sites.
fn technique_confidence(technique: &str, mx_only: bool) -> f64 {
    let base: f64 = match technique {
        "addition" => 0.70,
        "homoglyph" | "digraph" => 0.65,
        "vowel-swap" | "combo-homoglyph" => 0.62,
        "keyboard" | "omission" | "transposition" => 0.55,
        "tld-swap" | "insertion" | "repetition" => 0.52,
        _ => 0.50, // bitsquat, hyphenation, hyphen-removal, plural
    };
    if mx_only {
        (base - 0.05).max(0.45)
    } else {
        base
    }
}

pub struct Typosquat;

#[async_trait]
impl Module for Typosquat {
    fn name(&self) -> &'static str {
        SRC
    }

    fn description(&self) -> &'static str {
        "Generate and resolve typosquat/lookalike domain permutations \
         (15 techniques, A/AAAA + MX-only phishing-prep detection)"
    }

    fn priority(&self) -> u8 {
        34
    }

    fn category(&self) -> ModuleCategory {
        ModuleCategory::DnsRecon
    }

    fn attack_techniques(&self) -> &'static [&'static str] {
        // Gathering victim-owned domain variants (lookalike discovery) maps to
        // T1590.001 Gather Victim Network Information: Domains (TA0043).
        &["T1590.001"]
    }

    fn accepts(&self, t: &Target) -> bool {
        matches!(t.kind, TargetKind::Domain)
    }

    fn produces(&self) -> &'static [EntityKind] {
        const KINDS: &[EntityKind] = &[EntityKind::Domain];
        KINDS
    }

    fn max_timeout_ms(&self) -> u64 {
        // MAX_CANDIDATES candidates, up to 2 DNS lookups each (3 s A then
        // 2 s MX fallback), at MAX_CONCURRENT width.  In practice nearly all
        // candidates are fast NXDOMAIN; 30 s is a safe ceiling.
        30_000
    }

    async fn process(&self, target: &Target, ctx: &ModuleContext) -> Result<ModuleResult> {
        let mut result = ModuleResult::new();
        let original = target.value.trim().trim_end_matches('.').to_lowercase();
        let candidates = permutations(&original, MAX_CANDIDATES);
        if candidates.is_empty() {
            return Ok(result);
        }

        let sem = Arc::new(Semaphore::new(MAX_CONCURRENT));
        let mut set = tokio::task::JoinSet::new();

        for (candidate, technique) in candidates {
            let sem = Arc::clone(&sem);
            set.spawn(async move {
                let _permit = sem.acquire_owned().await.ok()?;
                let resolver = shared_resolver();

                // Phase 1: A / AAAA — active registered domain.
                let a_result = tokio::time::timeout(
                    std::time::Duration::from_secs(3),
                    resolver.lookup_ip(candidate.as_str()),
                )
                .await;

                if let Ok(Ok(lookup)) = a_result {
                    let ips: Vec<String> = lookup.iter().map(|ip| ip.to_string()).collect();
                    if !ips.is_empty() {
                        return Some((candidate, technique, ips.join(", "), false));
                    }
                }

                // Phase 2: MX fallback — phishing-prep detection.
                // A registered domain with MX records but no A/AAAA is a
                // strong indicator of staged attack infrastructure: the actor
                // has set up mail delivery (for spear-phishing) before the
                // deceptive website goes live.  Treat MX-only as a
                // distinct, lower-confidence signal rather than discarding it.
                let mx_result = tokio::time::timeout(
                    std::time::Duration::from_secs(2),
                    resolver.mx_lookup(candidate.as_str()),
                )
                .await;

                if let Ok(Ok(mx_lookup)) = mx_result {
                    let hosts: Vec<String> = mx_lookup
                        .answers()
                        .iter()
                        .filter_map(|rec| {
                            if let RData::MX(mx) = &rec.data {
                                let h = mx.exchange.to_ascii();
                                let h = h.trim_end_matches('.');
                                (!h.is_empty()).then(|| h.to_string())
                            } else {
                                None
                            }
                        })
                        .collect();
                    if !hosts.is_empty() {
                        return Some((candidate, technique, hosts.join(", "), true));
                    }
                }

                None
            });
        }

        let mut hits: Vec<(String, &'static str, String, bool)> = Vec::new();
        while let Some(joined) = set.join_next().await {
            if let Ok(Some(hit)) = joined {
                hits.push(hit);
            }
        }
        // Deterministic output: sort by domain name, then A before MX-only.
        hits.sort_by(|a, b| a.0.cmp(&b.0).then(a.3.cmp(&b.3)));

        for (candidate, technique, resolved, mx_only) in hits {
            let confidence = technique_confidence(technique, mx_only);
            let mut e = Entity::new(EntityKind::Domain, &candidate, confidence, &ctx.scan_id);
            e.tag("typosquat");
            e.tag(format!("typosquat:{technique}"));
            if mx_only {
                e.tag("phishing-prep");
                e.tag("mx-only");
            }
            let resolve_label = if mx_only {
                "MX record (no A — phishing-prep)"
            } else {
                "A record"
            };
            e.add_evidence(
                Evidence::new(
                    SRC,
                    format!(
                        "Registered lookalike of {original} via {technique} \
                         → {resolve_label}: {resolved}"
                    ),
                )
                .with_attr("original", &original)
                .with_attr("technique", technique)
                .with_attr("resolve_type", if mx_only { "mx-only" } else { "a-record" })
                .with_attr("resolved", &resolved),
            );
            result.push(e);
        }
        Ok(result)
    }
}

// ── Permutation engine ────────────────────────────────────────────────────────

/// Generate up to `cap` registered-domain-shaped lookalike permutations of
/// `domain`, paired with the generating technique.  **Pure** (no I/O).
///
/// Splits the domain into its registrable label and public-suffix (e.g.
/// `example` + `com.au`), applies 15 permutation techniques to the label in
/// priority order (most likely to represent real attack infrastructure first),
/// and rebuilds full FQDNs.  The original is never returned; every candidate
/// is syntactically valid and deduplicated.
pub(crate) fn permutations(domain: &str, cap: usize) -> Vec<(String, &'static str)> {
    let domain = domain.trim().trim_end_matches('.').to_lowercase();
    let registrable = crate::util::domains::registrable_domain(&domain).unwrap_or(domain.clone());
    let Some((label, suffix)) = registrable.split_once('.') else {
        return Vec::new();
    };
    if label.is_empty() {
        return Vec::new();
    }
    let chars: Vec<char> = label.chars().collect();

    // Accumulate (technique, label-string) pairs in priority order so that the
    // cap retains the highest-signal candidates when the list is long.
    let mut variants: Vec<(&'static str, String)> = Vec::new();
    let mut push = |tech: &'static str, s: String| variants.push((tech, s));

    // ── 1. Addition — curated phishing keyword prepend / append ───────────────
    // Generated first: deliberately registered `brand-keyword` / `keywordbrand`
    // domains are almost always intentional phishing infrastructure.
    for &prefix in ATTACK_PREFIXES {
        push("addition", format!("{prefix}{label}"));
        push("addition", format!("{prefix}-{label}"));
    }
    for &suffix_kw in ATTACK_SUFFIXES {
        push("addition", format!("{label}{suffix_kw}"));
        push("addition", format!("{label}-{suffix_kw}"));
    }

    // ── 2. Homoglyph — ASCII look-alike single-char substitution ─────────────
    for (i, &c) in chars.iter().enumerate() {
        for &n in homoglyphs(c) {
            let mut v = chars.clone();
            v[i] = n;
            push("homoglyph", v.into_iter().collect());
        }
    }

    // ── 3. Digraph — multi-char visual confusable substitution ────────────────
    // Contractions: two consecutive chars → one look-alike char.
    for i in 0..chars.len().saturating_sub(1) {
        let replacement: Option<char> = match (chars[i], chars[i + 1]) {
            ('r', 'n') => Some('m'),
            ('c', 'l') => Some('d'),
            ('v', 'v') => Some('w'),
            _ => None,
        };
        if let Some(rep) = replacement {
            let mut v: Vec<char> = chars[..i].to_vec();
            v.push(rep);
            v.extend_from_slice(&chars[i + 2..]);
            push("digraph", v.into_iter().collect());
        }
    }
    // Expansions: one char → two visually-similar chars (e.g. `m` → `rn`).
    for (i, &c) in chars.iter().enumerate() {
        let expansion: &[char] = match c {
            'm' => &['r', 'n'],
            'd' => &['c', 'l'],
            'w' => &['v', 'v'],
            _ => &[],
        };
        if !expansion.is_empty() {
            let mut v: Vec<char> = chars[..i].to_vec();
            v.extend_from_slice(expansion);
            v.extend_from_slice(&chars[i + 1..]);
            push("digraph", v.into_iter().collect());
        }
    }

    // ── 4. Vowel-swap — replace each vowel with every other vowel ─────────────
    for (i, &c) in chars.iter().enumerate() {
        if VOWELS.contains(&c) {
            for &v_char in VOWELS {
                if v_char != c {
                    let mut v = chars.clone();
                    v[i] = v_char;
                    push("vowel-swap", v.into_iter().collect());
                }
            }
        }
    }

    // ── 5. Keyboard — QWERTY-adjacent key replacement ─────────────────────────
    for (i, &c) in chars.iter().enumerate() {
        for n in keyboard_neighbors(c).chars() {
            let mut v = chars.clone();
            v[i] = n;
            push("keyboard", v.into_iter().collect());
        }
    }

    // ── 6. Omission — drop one character ──────────────────────────────────────
    for i in 0..chars.len() {
        let mut v = chars.clone();
        v.remove(i);
        push("omission", v.into_iter().collect());
    }

    // ── 7. Transposition — swap two adjacent characters ───────────────────────
    for i in 0..chars.len().saturating_sub(1) {
        let mut v = chars.clone();
        v.swap(i, i + 1);
        push("transposition", v.into_iter().collect());
    }

    // ── 8. Repetition — double one character ──────────────────────────────────
    for i in 0..chars.len() {
        let mut v = chars.clone();
        v.insert(i, chars[i]);
        push("repetition", v.into_iter().collect());
    }

    // ── 9. Bitsquatting — flip one bit of each ASCII byte ────────────────────
    for (i, &c) in chars.iter().enumerate() {
        if !c.is_ascii_alphanumeric() {
            continue;
        }
        for bit in 0..7u8 {
            let flipped = (c as u8) ^ (1 << bit);
            if flipped.is_ascii_lowercase() || flipped.is_ascii_digit() {
                let mut v = chars.clone();
                v[i] = flipped as char;
                push("bitsquat", v.into_iter().collect());
            }
        }
    }

    // ── 10. Hyphenation — insert a hyphen between adjacent characters ─────────
    for i in 1..chars.len() {
        let mut v = chars.clone();
        v.insert(i, '-');
        push("hyphenation", v.into_iter().collect());
    }

    // ── 11. Hyphen-removal — strip hyphens from a hyphenated label ────────────
    // Each hyphen is removed individually; if more than one exists, the
    // all-removed form is also generated as a single variant.
    let hyphen_positions: Vec<usize> = chars
        .iter()
        .enumerate()
        .filter(|&(_, c)| *c == '-')
        .map(|(i, _)| i)
        .collect();
    if !hyphen_positions.is_empty() {
        for &hi in &hyphen_positions {
            let mut v = chars.clone();
            v.remove(hi);
            push("hyphen-removal", v.into_iter().collect());
        }
        if hyphen_positions.len() > 1 {
            let all_removed: String = chars.iter().filter(|&&c| c != '-').collect();
            push("hyphen-removal", all_removed);
        }
    }

    // ── 12. Plural — add or remove a trailing 's' ────────────────────────────
    {
        let with_s: String = chars.iter().collect::<String>() + "s";
        push("plural", with_s);
        if chars.last() == Some(&'s') {
            let without_s: String = chars[..chars.len() - 1].iter().collect();
            push("plural", without_s);
        }
    }

    // ── 13. Insertion — insert every a-z letter at every label position ───────
    // Lowest per-variant signal but catches `youutube`-style extra-char squats
    // not reachable by repetition alone.  Placed late so the cap favours
    // higher-value techniques.
    for i in 0..=chars.len() {
        for ins in 'a'..='z' {
            let mut v = chars.clone();
            v.insert(i, ins);
            push("insertion", v.into_iter().collect());
        }
    }

    // ── 15. Combo-homoglyph — two simultaneous ASCII homoglyph substitutions ──
    // Generated last; covers sophisticated squatters who apply two visual tricks
    // at once.  Only produced when ≥ 2 positions carry homoglyphs.
    let hg_positions: Vec<(usize, &[char])> = chars
        .iter()
        .enumerate()
        .filter_map(|(i, &c)| {
            let h = homoglyphs(c);
            if h.is_empty() { None } else { Some((i, h)) }
        })
        .collect();
    if hg_positions.len() >= 2 {
        for a in 0..hg_positions.len() {
            for b in (a + 1)..hg_positions.len() {
                let (pa, ha) = hg_positions[a];
                let (pb, hb) = hg_positions[b];
                for &ca in ha {
                    for &cb in hb {
                        let mut v = chars.clone();
                        v[pa] = ca;
                        v[pb] = cb;
                        push("combo-homoglyph", v.into_iter().collect());
                    }
                }
            }
        }
    }

    // ── Build output: label variants on original suffix + TLD swaps ───────────
    let mut out: Vec<(String, &'static str)> = Vec::new();
    let mut seen = std::collections::HashSet::new();
    seen.insert(registrable.clone());

    // Label variants on the original suffix (technique order preserved).
    out.extend(
        variants
            .iter()
            .filter(|(_, lbl)| is_valid_label(lbl))
            .filter_map(|(tech, lbl)| {
                let fqdn = format!("{lbl}.{suffix}");
                seen.insert(fqdn.clone()).then_some((fqdn, *tech))
            }),
    );

    // ── 14. TLD swap — original label with every other TLD ───────────────────
    // Added after label variants so the cap prioritises technique-diverse hits.
    out.extend(
        SWAP_TLDS
            .iter()
            .filter(|&&tld| tld != suffix)
            .filter_map(|&tld| {
                let fqdn = format!("{label}.{tld}");
                seen.insert(fqdn.clone()).then_some((fqdn, "tld-swap"))
            }),
    );

    out.truncate(cap);
    out
}

// ── Helper tables ─────────────────────────────────────────────────────────────

/// True iff `s` is a syntactically valid DNS label: 1–63 ASCII alphanumeric
/// or hyphen characters, not starting or ending with a hyphen, no `--`.
fn is_valid_label(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 63
        && !s.starts_with('-')
        && !s.ends_with('-')
        && !s.contains("--")
        && s.chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
}

/// QWERTY-adjacent lowercase keys.  Only the direct neighbours (not diagonals)
/// are included to keep signal-to-noise high — diagonals are reachable by two
/// typos and should be generated by combo techniques, not keyboard alone.
fn keyboard_neighbors(c: char) -> &'static str {
    match c {
        'a' => "qwsz",
        'b' => "vghn",
        'c' => "xdfv",
        'd' => "serfcx",
        'e' => "wsdr",
        'f' => "drtgvc",
        'g' => "ftyhbv",
        'h' => "gyujnb",
        'i' => "ujko",
        'j' => "huikmn",
        'k' => "jiolm",
        'l' => "kop",
        'm' => "njk",
        'n' => "bhjm",
        'o' => "iklp",
        'p' => "ol",
        'q' => "wa",
        'r' => "edft",
        's' => "awedxz",
        't' => "rfgy",
        'u' => "yhji",
        'v' => "cfgb",
        'w' => "qase",
        'x' => "zsdc",
        'y' => "tghu",
        'z' => "asx",
        _ => "",
    }
}

/// Expanded ASCII homoglyph table: characters that are visually near-identical
/// in common proportional fonts and are therefore used by squatters.
/// Includes bidirectional mappings (letter↔digit) and letter-pair confusables.
fn homoglyphs(c: char) -> &'static [char] {
    match c {
        // Letter ↔ digit
        'o' => &['0'],
        '0' => &['o'],
        'l' => &['1', 'i'],
        'i' => &['1', 'l'],
        '1' => &['l', 'i'],
        'e' => &['3'],
        '3' => &['e'],
        'a' => &['4'],
        '4' => &['a'],
        's' => &['5'],
        '5' => &['s'],
        'b' => &['8'],
        '8' => &['b'],
        'g' => &['9', 'q'],
        '9' => &['g'],
        'q' => &['9'],
        'z' => &['2'],
        '2' => &['z'],
        't' => &['7'],
        '7' => &['t'],
        // Letter ↔ letter (visual similarity, not phonetic)
        'u' => &['v'],
        'v' => &['u'],
        _ => &[],
    }
}

#[cfg(test)]
mod tests {
    include!("tests.rs");
}
