//! Typosquat / domain-permutation discovery (dnstwist-style, pure-Rust).
//!
//! Generates lookalike variants of a target domain across nine technique
//! classes, then resolves each via DNS and emits a `Domain` entity **only
//! for the ones that actually resolve** (i.e. are registered). A registered
//! lookalike is a phishing / brand-abuse signal; the expansion loop then runs
//! the full domain-enrichment stack (WHOIS, certs, web-crawl) over each.
//!
//! ## Techniques (ordered by threat signal — cap keeps the highest-value set)
//!
//! | technique        | example (on "paypal.com")           | threat |
//! |------------------|-------------------------------------|--------|
//! | `combo-squat`    | paypallogin.com, loginpaypal.com    | HIGH   |
//! | `homoglyph`      | paypa1.com                          | HIGH   |
//! | `keyboard`       | oaypal.com (p→o adjacent)           | MED    |
//! | `vowel-swap`     | peypal.com (a→e)                    | MED    |
//! | `transposition`  | paypla.com                          | MED    |
//! | `omission`       | aypal.com                           | MED    |
//! | `repetition`     | ppaypal.com                         | LOW    |
//! | `addition`       | pazpal.com (insert z)               | LOW    |
//! | `hyphenation`    | pay-pal.com                         | LOW    |
//! | `bitsquat`       | raypal.com (p bit-flipped)          | LOW    |
//! | `tld-swap`       | paypal.net, paypal.com.au           | VAR    |
//!
//! For each DNS hit, an MX record lookup determines whether the squatted
//! domain can send email — a strong phishing-infrastructure indicator.
//!
//! Pure permutation core (no I/O, unit-tested) + bounded concurrent
//! DNS/MX resolution. No API, no native deps — Termux-clean.

use std::sync::Arc;

use async_trait::async_trait;
use tokio::sync::Semaphore;

use crate::core::{
    entity::{Entity, EntityKind, Evidence},
    error::Result,
    module::{Module, ModuleCategory, ModuleContext, ModuleResult},
    scan::{Target, TargetKind},
};
use crate::util::dns::shared_resolver;

const SRC: &str = "typosquat";

/// Cap on candidate permutations resolved per scan. Combo-squat and the
/// high-signal techniques sort first so the cap retains the most dangerous
/// variants even when the domain generates a large permutation space.
const MAX_CANDIDATES: usize = 512;

/// Concurrent DNS A/AAAA lookups. Higher than before — typosquat is the
/// primary phishing-infrastructure detector and latency matters.
const MAX_DNS_CONCURRENT: usize = 48;

/// Concurrent MX lookups for resolved DNS hits (confirm mail-capable infra).
/// Kept lower: MX is a secondary check, only run on confirmed registrations.
const MAX_MX_CONCURRENT: usize = 16;

/// Combo-squatting keywords (highest-threat class — ordered by prevalence in
/// real phishing campaigns). Prepended and appended to the brand label.
const COMBO_WORDS: &[&str] = &[
    "login", "signin", "secure", "account", "verify", "auth", "access", "update", "support",
    "help", "official", "service", "portal", "pay", "checkout", "bank", "online", "customer",
    "admin", "user", "my", "app", "web", "get", "now",
];

/// TLDs to swap the registered name into — common gTLDs plus the Australian
/// second-levels and popular ccTLDs used by impersonators.
const SWAP_TLDS: &[&str] = &[
    "com", "net", "org", "co", "io", "app", "online", "site", "xyz", "club", "info", "biz",
    "co.nz", "com.au", "net.au", "org.au",
];

pub struct Typosquat;

#[async_trait]
impl Module for Typosquat {
    fn name(&self) -> &'static str {
        SRC
    }

    fn description(&self) -> &'static str {
        "Generate and resolve typosquat/lookalike domain permutations with MX-based phishing-infrastructure detection"
    }

    fn priority(&self) -> u8 {
        34
    }

    fn category(&self) -> ModuleCategory {
        ModuleCategory::DnsRecon
    }

    fn attack_techniques(&self) -> &'static [&'static str] {
        // Look-alike domain properties — ATT&CK Domain Properties (T1590.001).
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
        // MAX_CANDIDATES / MAX_DNS_CONCURRENT rounds × 3s per round +
        // MX followup round + headroom = ~45s.
        45_000
    }

    async fn process(&self, target: &Target, ctx: &ModuleContext) -> Result<ModuleResult> {
        let mut result = ModuleResult::new();
        let original = target.value.trim().trim_end_matches('.').to_lowercase();
        let candidates = permutations(&original, MAX_CANDIDATES);
        if candidates.is_empty() {
            return Ok(result);
        }

        // ── Phase 1: parallel DNS A/AAAA resolution ───────────────────────────
        let resolver = shared_resolver();
        let sem = Arc::new(Semaphore::new(MAX_DNS_CONCURRENT));
        let mut dns_set = tokio::task::JoinSet::new();
        for (candidate, technique) in candidates {
            let sem = Arc::clone(&sem);
            let res = resolver.clone();
            dns_set.spawn(async move {
                let _permit = sem.acquire_owned().await.ok()?;
                match tokio::time::timeout(
                    std::time::Duration::from_secs(3),
                    res.lookup_ip(candidate.as_str()),
                )
                .await
                {
                    Ok(Ok(lookup)) => {
                        let ips: Vec<String> = lookup.iter().map(|ip| ip.to_string()).collect();
                        (!ips.is_empty()).then_some((candidate, technique, ips.join(", ")))
                    }
                    _ => None,
                }
            });
        }

        let mut dns_hits: Vec<(String, &'static str, String)> = Vec::new();
        while let Some(joined) = dns_set.join_next().await {
            if let Ok(Some(hit)) = joined {
                dns_hits.push(hit);
            }
        }
        // Deterministic output regardless of network completion order.
        dns_hits.sort_by(|a, b| a.0.cmp(&b.0));

        if dns_hits.is_empty() {
            return Ok(result);
        }

        // ── Phase 2: MX lookup on DNS hits (phishing mail-capability check) ───
        let sem_mx = Arc::new(Semaphore::new(MAX_MX_CONCURRENT));
        let mut mx_set = tokio::task::JoinSet::new();
        for (candidate, _, _) in &dns_hits {
            let candidate = candidate.clone();
            let sem_mx = Arc::clone(&sem_mx);
            let res = resolver.clone();
            mx_set.spawn(async move {
                let _permit = sem_mx.acquire_owned().await.ok()?;
                let has_mx = tokio::time::timeout(
                    std::time::Duration::from_secs(2),
                    res.mx_lookup(candidate.as_str()),
                )
                .await
                .map(|r| r.is_ok())
                .unwrap_or(false);
                has_mx.then_some(candidate)
            });
        }

        let mut mx_domains: std::collections::HashSet<String> = std::collections::HashSet::new();
        while let Some(joined) = mx_set.join_next().await {
            if let Ok(Some(domain)) = joined {
                mx_domains.insert(domain);
            }
        }

        // ── Phase 3: emit entities ────────────────────────────────────────────
        for (candidate, technique, ips) in dns_hits {
            let conf = technique_confidence(technique);
            let mut e = Entity::new(EntityKind::Domain, &candidate, conf, &ctx.scan_id);
            e.tag("typosquat");
            e.tag(format!("typosquat:{technique}"));

            let has_mx = mx_domains.contains(&candidate);
            if has_mx {
                e.tag("typosquat:has-mx");
            }
            if technique == "combo-squat" {
                e.tag("phishing-indicator");
            }
            if technique == "combo-squat" && has_mx {
                // Combo-squat + live mail = highest-threat phishing infrastructure.
                e.tag("phishing-mail-capable");
            }

            let desc = if has_mx {
                format!(
                    "Registered lookalike of {original} via {technique} → {ips} (MX: live mail)"
                )
            } else {
                format!("Registered lookalike of {original} via {technique} → {ips}")
            };

            e.add_evidence(
                Evidence::new(SRC, desc)
                    .with_attr("original", &original)
                    .with_attr("technique", technique)
                    .with_attr("resolved_ips", &ips)
                    .with_attr("has_mx", if has_mx { "true" } else { "false" }),
            );
            result.push(e);
        }

        Ok(result)
    }
}

// ── Confidence tiering by technique ─────────────────────────────────────────

/// Map technique → base confidence for the emitted Domain entity. Combo-squat
/// is highest (deliberate brand abuse), bitsquat lowest (probabilistic HW fault).
fn technique_confidence(technique: &str) -> f64 {
    match technique {
        "combo-squat" => 0.75,
        "homoglyph" => 0.68,
        "keyboard" => 0.62,
        "vowel-swap" => 0.60,
        "transposition" | "omission" => 0.58,
        "repetition" | "addition" | "hyphenation" => 0.55,
        "tld-swap" => 0.52,
        "bitsquat" => 0.50,
        _ => 0.55,
    }
}

// ── Core permutation engine ──────────────────────────────────────────────────

/// Generate up to `cap` registered-domain-shaped lookalike permutations of
/// `domain`, paired with the technique that produced each. **Pure** (no I/O).
///
/// Splits the domain into its leading label and public-suffix tail (e.g.
/// `example` + `com.au`), permutes the label by the eleven typo classes
/// (ordered highest-threat first), and adds TLD swaps. Deduplicated,
/// deterministic order, capped.
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

    // All (technique, variant-label) pairs — ordered most-useful first so the
    // cap retains the highest-signal candidates.
    let mut variants: Vec<(&'static str, String)> = Vec::new();
    let mut push = |tech: &'static str, s: String| variants.push((tech, s));

    // 1. Combo-squatting — highest-threat class; deliberate brand abuse.
    //    Produces {label}{word} and {word}{label}, with and without hyphen.
    for word in COMBO_WORDS {
        push("combo-squat", format!("{label}{word}"));
        push("combo-squat", format!("{word}{label}"));
        push("combo-squat", format!("{label}-{word}"));
        push("combo-squat", format!("{word}-{label}"));
    }

    // 2. Homoglyph substitution (ASCII look-alikes).
    for (i, &c) in chars.iter().enumerate() {
        for &n in homoglyphs(c) {
            let mut v = chars.clone();
            v[i] = n;
            push("homoglyph", v.into_iter().collect());
        }
    }

    // 3. Keyboard-adjacent replacement.
    for (i, &c) in chars.iter().enumerate() {
        for n in keyboard_neighbors(c).chars() {
            let mut v = chars.clone();
            v[i] = n;
            push("keyboard", v.into_iter().collect());
        }
    }

    // 4. Vowel-swap — replace each vowel with every other vowel.
    //    Catches subtle confusion like "google" → "goegle" or "gaogle".
    const VOWELS: &[char] = &['a', 'e', 'i', 'o', 'u'];
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

    // 5. Transposition — swap adjacent chars.
    for i in 0..chars.len().saturating_sub(1) {
        let mut v = chars.clone();
        v.swap(i, i + 1);
        push("transposition", v.into_iter().collect());
    }

    // 6. Omission — drop one char.
    for i in 0..chars.len() {
        let mut v = chars.clone();
        v.remove(i);
        push("omission", v.into_iter().collect());
    }

    // 7. Repetition — double one char.
    for i in 0..chars.len() {
        let mut v = chars.clone();
        v.insert(i, chars[i]);
        push("repetition", v.into_iter().collect());
    }

    // 8. Addition — insert a keyboard-adjacent character at each position.
    //    Bounded: only inserts the direct keyboard neighbours of the char at i
    //    (not all 26) to keep the candidate count tractable.
    for i in 0..chars.len() {
        for n in keyboard_neighbors(chars[i]).chars() {
            let mut v = chars.clone();
            v.insert(i, n);
            push("addition", v.into_iter().collect());
        }
    }

    // 9. Hyphenation — insert a hyphen between two chars.
    for i in 1..chars.len() {
        let mut v = chars.clone();
        v.insert(i, '-');
        push("hyphenation", v.into_iter().collect());
    }

    // 10. Bitsquatting — flip one bit of an ASCII letter/digit.
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

    // ── Dedup + cap ──────────────────────────────────────────────────────────
    let mut out: Vec<(String, &'static str)> = Vec::new();
    let mut seen = std::collections::HashSet::new();
    seen.insert(registrable.clone());

    // Label permutations against the original suffix (preserve technique order).
    out.extend(
        variants
            .iter()
            .filter(|(_, lbl)| is_valid_label(lbl))
            .filter_map(|(tech, lbl)| {
                let fqdn = format!("{lbl}.{suffix}");
                seen.insert(fqdn.clone()).then_some((fqdn, *tech))
            }),
    );

    // TLD swaps on the original label.
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

// ── Label validation ─────────────────────────────────────────────────────────

/// A syntactically valid DNS label: 1–63 chars of `[a-z0-9-]`, not
/// leading/trailing/double hyphen, and not empty.
pub(crate) fn is_valid_label(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 63
        && !s.starts_with('-')
        && !s.ends_with('-')
        && !s.contains("--")
        && s.chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
}

// ── Keyboard adjacency (QWERTY) ──────────────────────────────────────────────

/// QWERTY-adjacent lowercase keys for the keyboard-substitution and
/// addition technique classes.
pub(crate) fn keyboard_neighbors(c: char) -> &'static str {
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

// ── ASCII homoglyphs ─────────────────────────────────────────────────────────

/// ASCII homoglyphs — characters commonly swapped to look near-identical in
/// fonts used by browsers and email clients.
pub(crate) fn homoglyphs(c: char) -> &'static [char] {
    match c {
        'o' => &['0'],
        '0' => &['o'],
        'l' => &['1', 'i'],
        'i' => &['1', 'l'],
        '1' => &['l', 'i'],
        'e' => &['3'],
        'a' => &['4'],
        's' => &['5'],
        'b' => &['8'],
        'g' => &['9'],
        'z' => &['2'],
        _ => &[],
    }
}

#[cfg(test)]
mod tests {
    include!("tests.rs");
}
