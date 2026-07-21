//! Typosquat / domain-permutation discovery (dnstwist-grade, pure-Rust).
//!
//! Generates lookalike variants of a target domain across the full fuzzer set —
//! **IDN homoglyph** (non-ASCII Cyrillic/Greek confusables emitted as their
//! registrable `xn--` Punycode form), ASCII homoglyph, omission, transposition,
//! repetition, vowel swap, keyboard-adjacent replacement, keyboard insertion,
//! bitsquatting, hyphenation, character addition, and TLD swap (with an
//! Australian `.com.au`/`.net.au`/`.org.au` focus) — ranks them most-similar
//! first by Levenshtein distance, then resolves each via the shared DNS resolver
//! and emits a `Domain` entity **only for the ones that actually resolve** (i.e.
//! are registered). A registered lookalike of a brand domain is a phishing /
//! brand-abuse signal; the expansion loop then runs the full domain-enrichment
//! stack (WHOIS, certs, web-crawl) over each.
//!
//! The IDN-homoglyph class is the differentiator: a resolving `xn--` lookalike
//! is the near-invisible spoof real attacks use, and the [`punycode`] encoder
//! produces exactly the on-the-wire label a registrar accepts — no `idna`
//! dependency, just RFC 3492.
//!
//! Pure permutation core (no I/O, unit-tested incl. canonical Punycode vectors)
//! + bounded concurrent resolution. No API, no native deps — Termux-clean.

use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use tokio::sync::Semaphore;

/// Session-level dedup: tracks registrable domains already fully processed by
/// this module within one `hse` invocation. Real scan data showed `behindthename.com`
/// dispatched 30 times (once per subdomain discovered), each triggering up to
/// MAX_CANDIDATES DNS lookups for the same typosquat candidates. A second run
/// on the same registrable domain produces zero new findings.
static SEEN_REGISTRABLE: std::sync::LazyLock<Mutex<std::collections::HashSet<String>>> =
    std::sync::LazyLock::new(|| Mutex::new(std::collections::HashSet::new()));

use crate::core::{
    confidence,
    entity::{Entity, EntityKind, Evidence},
    error::Result,
    module::{Module, ModuleCategory, ModuleContext, ModuleResult},
    scan::{Target, TargetKind},
};
use crate::util::dns::shared_resolver;

mod punycode;

const SRC: &str = "typosquat";

/// Cap on candidate permutations resolved per scan. Bounds the DNS work a long
/// domain would otherwise generate; the highest-signal techniques are produced
/// first so the cap keeps the most useful candidates.
const MAX_CANDIDATES: usize = 128;

/// Concurrent DNS lookups (matches `dns_intel`'s brute-force budget — polite on
/// a mobile link while keeping the resolve phase a few seconds).
const MAX_CONCURRENT: usize = 12;

/// Clear the session dedup set at the start of each scan. Installed into the
/// engine's per-scan reset hook ([`crate::core::hooks::reset_per_scan`]). Without
/// it the process-global [`SEEN_REGISTRABLE`] set (a) grows without bound across a
/// long-lived `serve` / `live` process and (b) silently suppresses ALL typosquat
/// findings for any registrable domain scanned a SECOND time — a cross-scan
/// data-loss. Resetting per scan preserves the intended WITHIN-scan dedup (a
/// registrable domain dispatched once per discovered subdomain resolves its
/// candidates only once) while bounding growth to a single scan's domains.
pub fn reset_seen() {
    let mut set = SEEN_REGISTRABLE
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    set.clear();
}

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
        "Typosquat recon — generates lookalike domain permutations and resolves the registered ones to surface active impostors"
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

        // Skip if we already fully processed this registrable domain in this scan —
        // repeated subdomains of the same apex (e.g. api.behindthename.com,
        // admin.behindthename.com) reduce to the same permutation set.
        let reg =
            crate::util::domains::registrable_domain(&original).unwrap_or_else(|| original.clone());
        {
            let mut seen = SEEN_REGISTRABLE
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            if !seen.insert(reg.clone()) {
                return Ok(result);
            }
        }

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
            let mut e = Entity::new(
                EntityKind::Domain,
                &candidate,
                confidence::MEDIUM_HIGH,
                &ctx.scan_id,
            );
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
/// `example` + `com.au`), permutes the label across the full fuzzer set
/// (IDN/ASCII homoglyph, omission, transposition, repetition, vowel swap,
/// keyboard replacement/insertion, bitsquat, hyphenation, addition), and adds
/// TLD swaps; the original is never returned and every candidate is a
/// syntactically valid hostname (IDN variants in their `xn--` form). Ranked
/// most-similar-first by edit distance, deduplicated, deterministic, and capped.
pub(crate) fn permutations(domain: &str, cap: usize) -> Vec<(String, &'static str)> {
    let domain = domain.trim().trim_end_matches('.').to_lowercase();
    // Reduce to the registrable domain, then split label | suffix on the first dot.
    let registrable =
        crate::util::domains::registrable_domain(&domain).unwrap_or_else(|| domain.clone());
    let Some((label, suffix)) = registrable.split_once('.') else {
        return Vec::new();
    };
    if label.is_empty() {
        return Vec::new();
    }
    let chars: Vec<char> = label.chars().collect();

    // (technique, emitted-label, visual-label). Collected in **signal priority**
    // order so that, after the stable Levenshtein sort below, the highest-value
    // candidates survive the cap when equally similar. For ASCII techniques the
    // emitted and visual labels are identical; an IDN-homoglyph emits its `xn--`
    // ACE form while keeping the Unicode spelling as the visual for ranking, so
    // it scores as the single-character swap a human sees, not the long ACE.
    let mut cands: Vec<(&'static str, String, String)> = Vec::new();

    // IDN homoglyph — a non-ASCII confusable (Cyrillic/Greek lookalike), emitted
    // as its registrable `xn--` Punycode form. The highest-signal class: a
    // resolving `xn--` lookalike is a deliberate, near-invisible spoof.
    for (i, &c) in chars.iter().enumerate() {
        for &g in confusables(c) {
            let mut v = chars.clone();
            v[i] = g;
            let visual: String = v.iter().collect();
            if let Some(ace) = punycode::to_ascii_label(&visual) {
                cands.push(("homoglyph-idn", ace, visual));
            }
        }
    }
    // ASCII homoglyph — digit/letter look-alikes (o→0, e→3, l→1).
    for (i, &c) in chars.iter().enumerate() {
        for &g in homoglyphs(c) {
            let mut v = chars.clone();
            v[i] = g;
            let s: String = v.iter().collect();
            cands.push(("homoglyph", s.clone(), s));
        }
    }
    // Omission — drop one char.
    for i in 0..chars.len() {
        let mut v = chars.clone();
        v.remove(i);
        let s: String = v.into_iter().collect();
        cands.push(("omission", s.clone(), s));
    }
    // Transposition — swap adjacent chars.
    for i in 0..chars.len().saturating_sub(1) {
        let mut v = chars.clone();
        v.swap(i, i + 1);
        let s: String = v.into_iter().collect();
        cands.push(("transposition", s.clone(), s));
    }
    // Repetition — double one char.
    for i in 0..chars.len() {
        let mut v = chars.clone();
        v.insert(i, chars[i]);
        let s: String = v.into_iter().collect();
        cands.push(("repetition", s.clone(), s));
    }
    // Vowel swap — replace a vowel with another (the most common real mistype).
    const VOWELS: &[char] = &['a', 'e', 'i', 'o', 'u'];
    for (i, &c) in chars.iter().enumerate() {
        if VOWELS.contains(&c) {
            for &v2 in VOWELS.iter().filter(|&&w| w != c) {
                let mut v = chars.clone();
                v[i] = v2;
                let s: String = v.into_iter().collect();
                cands.push(("vowel-swap", s.clone(), s));
            }
        }
    }
    // Keyboard-adjacent replacement.
    for (i, &c) in chars.iter().enumerate() {
        for n in keyboard_neighbors(c).chars() {
            let mut v = chars.clone();
            v[i] = n;
            let s: String = v.into_iter().collect();
            cands.push(("keyboard", s.clone(), s));
        }
    }
    // Insertion — slip a keyboard-adjacent key in beside the one it neighbours.
    for (i, &c) in chars.iter().enumerate() {
        for n in keyboard_neighbors(c).chars() {
            let mut v = chars.clone();
            v.insert(i, n);
            let s: String = v.into_iter().collect();
            cands.push(("insertion", s.clone(), s));
        }
    }
    // Bitsquatting — flip one bit of an ASCII letter/digit (DRAM/cosmic-ray
    // bit-flips routed to an attacker-registered neighbour).
    for (i, &c) in chars.iter().enumerate() {
        if !c.is_ascii_alphanumeric() {
            continue;
        }
        for bit in 0..7u8 {
            let flipped = (c as u8) ^ (1 << bit);
            if flipped.is_ascii_lowercase() || flipped.is_ascii_digit() {
                let mut v = chars.clone();
                v[i] = flipped as char;
                let s: String = v.into_iter().collect();
                cands.push(("bitsquat", s.clone(), s));
            }
        }
    }
    // Hyphenation — insert a hyphen between two chars.
    for i in 1..chars.len() {
        let mut v = chars.clone();
        v.insert(i, '-');
        let s: String = v.into_iter().collect();
        cands.push(("hyphenation", s.clone(), s));
    }
    // Addition — append a single letter or digit.
    for b in (b'a'..=b'z').chain(b'0'..=b'9') {
        let s = format!("{label}{}", b as char);
        cands.push(("addition", s.clone(), s));
    }

    let mut out: Vec<(String, &'static str, usize)> = Vec::new();
    let mut seen = std::collections::HashSet::new();
    seen.insert(registrable.clone());

    // Label permutations on the original suffix. An emitted label is kept when it
    // is a valid LDH label, or an `xn--` ACE label (whose internal `--` the
    // generator's stricter `is_valid_label` rejects but the punycode layer has
    // already validated). Distance is measured on the *visual* form so an IDN
    // swap scores as the one-character spoof a human sees.
    for (tech, emit_label, visual_label) in &cands {
        if !(is_valid_label(emit_label) || emit_label.starts_with("xn--")) {
            continue;
        }
        let fqdn = format!("{emit_label}.{suffix}");
        if !seen.insert(fqdn.clone()) {
            continue;
        }
        let dist = levenshtein(&format!("{visual_label}.{suffix}"), &registrable);
        out.push((fqdn, tech, dist));
    }
    // TLD swaps on the original label.
    for &tld in SWAP_TLDS {
        if tld == suffix {
            continue;
        }
        let fqdn = format!("{label}.{tld}");
        if seen.insert(fqdn.clone()) {
            let dist = levenshtein(&fqdn, &registrable);
            out.push((fqdn, "tld-swap", dist));
        }
    }

    // Stable sort by edit distance — most-similar first — keeping the priority
    // collection order within an equal distance, so the cap retains the
    // highest-signal candidates.
    out.sort_by_key(|&(_, _, dist)| dist);
    out.truncate(cap);
    out.into_iter()
        .map(|(fqdn, tech, _)| (fqdn, tech))
        .collect()
}

/// Levenshtein (edit) distance between two strings, over Unicode scalar values.
/// Two rolling rows, so `O(min·max)` time and `O(max)` space. Used to rank
/// candidates most-similar-first; comparing scalars (not bytes) keeps a single
/// Cyrillic-for-Latin swap at distance 1.
fn levenshtein(a: &str, b: &str) -> usize {
    let a: Vec<char> = a.chars().collect();
    let b: Vec<char> = b.chars().collect();
    let (m, n) = (a.len(), b.len());
    if m == 0 {
        return n;
    }
    if n == 0 {
        return m;
    }
    let mut prev: Vec<usize> = (0..=n).collect();
    let mut curr = vec![0usize; n + 1];
    for i in 1..=m {
        curr[0] = i;
        for j in 1..=n {
            let cost = usize::from(a[i - 1] != b[j - 1]);
            curr[j] = (prev[j] + 1).min(curr[j - 1] + 1).min(prev[j - 1] + cost);
        }
        std::mem::swap(&mut prev, &mut curr);
    }
    prev[n]
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

/// Non-ASCII confusables — curated, high-confidence Unicode lookalikes (Cyrillic,
/// Greek, and a few Latin/Armenian) for each ASCII letter, deduplicated. These
/// drive the IDN-homoglyph fuzzer: each is substituted in, then the label is
/// Punycode-encoded to the `xn--` form a registrar and resolver see. Only the
/// genuinely deceptive swaps are listed — a noisy table would bury the signal.
fn confusables(c: char) -> &'static [char] {
    match c {
        'a' => &['\u{0430}', '\u{03B1}'], // Cyrillic а, Greek α
        'c' => &['\u{0441}', '\u{03F2}'], // Cyrillic с, Greek lunate ϲ
        'd' => &['\u{0501}'],             // Cyrillic ԁ
        'e' => &['\u{0435}'],             // Cyrillic е
        'g' => &['\u{0261}'],             // Latin script ɡ
        'h' => &['\u{04BB}'],             // Cyrillic һ
        'i' => &['\u{0456}', '\u{0131}'], // Cyrillic і, dotless ı
        'j' => &['\u{0458}'],             // Cyrillic ј
        'k' => &['\u{043A}'],             // Cyrillic к
        'l' => &['\u{04CF}'],             // Cyrillic palochka ӏ
        'm' => &['\u{043C}'],             // Cyrillic м
        'n' => &['\u{0578}'],             // Armenian ո
        'o' => &['\u{043E}', '\u{03BF}'], // Cyrillic о, Greek ο
        'p' => &['\u{0440}', '\u{03C1}'], // Cyrillic р, Greek ρ
        's' => &['\u{0455}'],             // Cyrillic ѕ
        't' => &['\u{03C4}'],             // Greek τ
        'u' => &['\u{03C5}'],             // Greek υ
        'v' => &['\u{03BD}', '\u{0475}'], // Greek ν, Cyrillic ѵ
        'w' => &['\u{051D}'],             // Cyrillic ԝ
        'x' => &['\u{0445}', '\u{03C7}'], // Cyrillic х, Greek χ
        'y' => &['\u{0443}', '\u{03B3}'], // Cyrillic у, Greek γ
        _ => &[],
    }
}

#[cfg(test)]
mod tests {
    include!("tests.rs");
}
