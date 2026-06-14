//! Typosquat / domain-permutation discovery (dnstwist-style, pure-Rust).
//!
//! Generates lookalike variants of a target domain — character omission,
//! repetition, transposition, keyboard-adjacent replacement, homoglyph, hyphen
//! insertion, bitsquatting, and TLD swap (with an Australian `.com.au`/`.net.au`
//! /`.org.au` focus) — then resolves each via the shared DNS resolver and emits
//! a `Domain` entity **only for the ones that actually resolve** (i.e. are
//! registered). A registered lookalike of a brand domain is a phishing /
//! brand-abuse signal; the expansion loop then runs the full domain-enrichment
//! stack (WHOIS, certs, web-crawl) over each.
//!
//! Pure permutation core (no I/O, unit-tested) + bounded concurrent resolution.
//! No API, no native deps — Termux-clean.

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

/// Cap on candidate permutations resolved per scan. Bounds the DNS work a long
/// domain would otherwise generate; the highest-signal techniques are produced
/// first so the cap keeps the most useful candidates.
const MAX_CANDIDATES: usize = 128;

/// Concurrent DNS lookups (matches `dns_intel`'s brute-force budget — polite on
/// a mobile link while keeping the resolve phase a few seconds).
const MAX_CONCURRENT: usize = 12;

/// TLDs to swap the registered name into — common gTLDs plus the Australian
/// second-levels (a `.com.au` brand's lookalikes frequently sit on `.net.au` /
/// `.com` / `.co`).
const SWAP_TLDS: &[&str] = &[
    "com", "net", "org", "co", "io", "app", "online", "site", "xyz", "com.au", "net.au", "org.au",
];

pub struct Typosquat;

#[async_trait]
impl Module for Typosquat {
    fn name(&self) -> &'static str {
        SRC
    }

    fn description(&self) -> &'static str {
        "Generate and resolve typosquat/lookalike domain permutations (registered ones only)"
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
        // Up to MAX_CANDIDATES DNS lookups at MAX_CONCURRENT width.
        15_000
    }

    async fn process(&self, target: &Target, ctx: &ModuleContext) -> Result<ModuleResult> {
        let mut result = ModuleResult::new();
        let original = target.value.trim().trim_end_matches('.').to_lowercase();
        let candidates = permutations(&original, MAX_CANDIDATES);
        if candidates.is_empty() {
            return Ok(result);
        }

        let resolver = shared_resolver();
        let sem = Arc::new(Semaphore::new(MAX_CONCURRENT));
        let mut set = tokio::task::JoinSet::new();
        for (candidate, technique) in candidates {
            let sem = Arc::clone(&sem);
            set.spawn(async move {
                let _permit = sem.acquire_owned().await.ok()?;
                match tokio::time::timeout(
                    std::time::Duration::from_secs(3),
                    resolver.lookup_ip(candidate.as_str()),
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

        // Collect, then sort for deterministic output (JoinSet completes in
        // network order). Candidates are unique, so the ordering is total.
        let mut hits: Vec<(String, &'static str, String)> = Vec::new();
        while let Some(joined) = set.join_next().await {
            if let Ok(Some(hit)) = joined {
                hits.push(hit);
            }
        }
        hits.sort_by(|a, b| a.0.cmp(&b.0));

        for (candidate, technique, ips) in hits {
            let mut e = Entity::new(EntityKind::Domain, &candidate, 0.55, &ctx.scan_id);
            e.tag("typosquat");
            e.tag(format!("typosquat:{technique}"));
            e.add_evidence(
                Evidence::new(
                    SRC,
                    format!(
                        "Registered lookalike of {original} via {technique} → resolves to {ips}"
                    ),
                )
                .with_attr("original", &original)
                .with_attr("technique", technique)
                .with_attr("resolved_ips", &ips),
            );
            result.push(e);
        }
        Ok(result)
    }
}

/// Generate up to `cap` registered-domain-shaped lookalike permutations of
/// `domain`, paired with the technique that produced each. **Pure** (no I/O).
///
/// Splits the domain into its leading label and public-suffix tail (e.g.
/// `example` + `com.au`), permutes the label by the eight typo classes, and adds
/// TLD swaps; the original is never returned and every candidate is a
/// syntactically valid hostname. Deduplicated, deterministic order, capped.
pub(crate) fn permutations(domain: &str, cap: usize) -> Vec<(String, &'static str)> {
    let domain = domain.trim().trim_end_matches('.').to_lowercase();
    // Reduce to the registrable domain, then split label | suffix on the first dot.
    let registrable = crate::util::domains::registrable_domain(&domain).unwrap_or(domain);
    let Some((label, suffix)) = registrable.split_once('.') else {
        return Vec::new();
    };
    if label.is_empty() {
        return Vec::new();
    }
    let chars: Vec<char> = label.chars().collect();
    let n = chars.len();

    // (technique, variant-label) — ordered most-useful first so the cap keeps signal.
    let mut variants: Vec<(&'static str, String)> = Vec::new();
    let mut push = |tech: &'static str, s: String| variants.push((tech, s));

    // Build a label from `chars` with the char at `i` replaced by `c` — no clone
    // of the whole `Vec<char>`, pre-sized to the label length.
    let replace_at = |i: usize, c: char| -> String {
        let mut s = String::with_capacity(n);
        for (j, &ch) in chars.iter().enumerate() {
            s.push(if j == i { c } else { ch });
        }
        s
    };

    // Omission — drop one char.
    for i in 0..n {
        let mut s = String::with_capacity(n.saturating_sub(1));
        s.extend(chars[..i].iter().chain(chars[i + 1..].iter()));
        push("omission", s);
    }
    // Transposition — swap adjacent chars.
    for i in 0..n.saturating_sub(1) {
        let mut s = String::with_capacity(n);
        s.extend(chars[..i].iter());
        s.push(chars[i + 1]);
        s.push(chars[i]);
        s.extend(chars[i + 2..].iter());
        push("transposition", s);
    }
    // Repetition — double one char.
    for i in 0..n {
        let mut s = String::with_capacity(n + 1);
        s.extend(chars[..=i].iter());
        s.extend(chars[i..].iter());
        push("repetition", s);
    }
    // Keyboard-adjacent replacement.
    for (i, &c) in chars.iter().enumerate() {
        for nb in keyboard_neighbors(c).chars() {
            push("keyboard", replace_at(i, nb));
        }
    }
    // Homoglyph substitution (ASCII look-alikes).
    for (i, &c) in chars.iter().enumerate() {
        for &nb in homoglyphs(c) {
            push("homoglyph", replace_at(i, nb));
        }
    }
    // Hyphenation — insert a hyphen between two chars.
    for i in 1..n {
        let mut s = String::with_capacity(n + 1);
        s.extend(chars[..i].iter());
        s.push('-');
        s.extend(chars[i..].iter());
        push("hyphenation", s);
    }
    // Bitsquatting — flip one bit of an ASCII letter/digit.
    for (i, &c) in chars.iter().enumerate() {
        if !c.is_ascii_alphanumeric() {
            continue;
        }
        for bit in 0..7u8 {
            let flipped = (c as u8) ^ (1 << bit);
            if flipped.is_ascii_lowercase() || flipped.is_ascii_digit() {
                push("bitsquat", replace_at(i, flipped as char));
            }
        }
    }

    let mut out: Vec<(String, &'static str)> = Vec::new();
    let mut seen = std::collections::HashSet::new();
    seen.insert(registrable.clone());

    // Label permutations on the original suffix.
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

/// A syntactically valid DNS label: 1–63 chars of `[a-z0-9-]`, not
/// leading/trailing/double hyphen.
fn is_valid_label(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 63
        && !s.starts_with('-')
        && !s.ends_with('-')
        && !s.contains("--")
        && s.chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
}

/// QWERTY-adjacent lowercase keys for the common typo-substitution class.
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

/// ASCII homoglyphs — characters commonly swapped to look near-identical.
fn homoglyphs(c: char) -> &'static [char] {
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
