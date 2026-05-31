//! Pure, network-free name → identity derivation.
//!
//! This is the engine behind the [`super::NameIntel`] module and a faithful,
//! bounded port of the methodology in NAMINT (<https://seintpl.github.io/NAMINT/>):
//!
//!   * **Login permutations** — ~40 `first`/`middle`/`last`/`number` handle
//!     shapes (`first.last`, `flast`, `firstl`, `last.first`, hyphen/underscore
//!     joins, middle-initial blends, year suffixes).
//!   * **Email permutations** — the highest-signal handle shapes crossed with a
//!     configurable provider set (NAMINT's iCloud/Yahoo/Hotmail/MSN plus the
//!     ubiquitous Gmail/Outlook/Proton), bounded so a single name target never
//!     floods the entity graph.
//!   * **Gravatar avatars** — the MD5-over-email primitive NAMINT uses, computed
//!     with the crate's existing `md-5`/`hex` deps (no new dependency, no C).
//!   * **Search-query pivots** — ready-to-click Google/Bing/DuckDuckGo/Yandex
//!     dorks plus per-platform people-search URLs (LinkedIn, Facebook, X,
//!     Instagram, TikTok, GitHub, WhatsMyName, Epieos).
//!
//! Every output is bounded by a `MAX_*` cap so the work a name target generates
//! is constant-bounded — important on low-power Termux/aarch64 devices.

use url::form_urlencoded::byte_serialize;

// ── Output caps (keep a single name target constant-bounded) ────────────────
pub(super) const MAX_USERNAMES: usize = 24;
pub(super) const MAX_EMAILS: usize = 16;
pub(super) const MAX_PIVOTS: usize = 18;

// ── Confidence weights ──────────────────────────────────────────────────────
/// Real-world-common handle shapes (`first.last`, `firstlast`, `flast`, …).
const W_PRIMARY: f64 = 0.42;
/// Plausible but less common shapes (reversed, hyphen/underscore joins).
const W_SECONDARY: f64 = 0.30;
/// Middle-name blends.
const W_MIDDLE: f64 = 0.28;
/// Year/number-suffixed shapes.
const W_YEAR: f64 = 0.30;

/// Speculative permuted email — deliberately below the default expansion floor
/// (0.50) so a `--depth` scan does not auto-spend API budget on guesses.
pub(super) const EMAIL_CONF: f64 = 0.30;
/// Investigation pivot — a lead for the operator, not a finding.
pub(super) const PIVOT_CONF: f64 = 0.20;

/// NAMINT's default provider set, modernised. Overridable at runtime via the
/// `HUNTSMAN_EMAIL_DOMAINS` environment variable (comma-separated).
const DEFAULT_DOMAINS: &[&str] = &[
    "gmail.com",
    "outlook.com",
    "icloud.com",
    "yahoo.com",
    "hotmail.com",
    "proton.me",
];

/// A parsed personal name plus an optional trailing number (e.g. a birth year).
///
/// `first`/`middle`/`last` are ASCII-folded, lowercased handle tokens safe for
/// byte slicing. `display_words` preserves human-facing capitalisation for
/// search-query construction.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedName {
    pub first: String,
    pub middle: Option<String>,
    pub last: String,
    pub number: Option<String>,
    pub display_words: Vec<String>,
}

impl ParsedName {
    /// `"First Middle Last"` with display capitalisation, for quoted searches.
    pub fn display_full(&self) -> String {
        self.display_words.join(" ")
    }
    pub fn display_first(&self) -> &str {
        &self.display_words[0]
    }
    pub fn display_last(&self) -> &str {
        self.display_words.last().expect("≥2 words guaranteed")
    }
    /// `"First-Last"` form used for path-style people URLs (e.g. Facebook).
    fn display_hyphen(&self) -> String {
        self.display_words.join("-")
    }
    /// A universally-valid alphanumeric handle (`firstlast`) for path-style
    /// profile URLs (Instagram, WhatsMyName) where dots/underscores vary.
    fn plain_handle(&self) -> String {
        format!("{}{}", self.first, self.last)
    }
}

/// A derived handle paired with its base confidence.
pub struct ScoredHandle {
    pub handle: String,
    pub weight: f64,
}

/// A ready-to-click investigation lead.
pub struct Pivot {
    pub platform: &'static str,
    pub url: String,
}

/// Parse a free-form name string into [`ParsedName`].
///
/// Returns `None` when fewer than two alphabetic tokens survive cleaning (a
/// single name cannot seed `first`/`last` permutations). An optional 2–4 digit
/// run anywhere in the input is captured as `number` (NAMINT's "year" field),
/// e.g. `"Jordan Meyers 1987"`.
pub fn parse(raw: &str) -> Option<ParsedName> {
    let number = extract_number(raw);

    // Tokenise on whitespace and commas; clean each token to letters plus
    // internal hyphen/apostrophe; keep tokens that retain a letter.
    let display_words: Vec<String> = raw
        .split(|c: char| c.is_whitespace() || c == ',')
        .filter_map(clean_display_token)
        .collect();

    if display_words.len() < 2 {
        return None;
    }

    let first = sanitize(&display_words[0]);
    let last = sanitize(display_words.last().unwrap());
    if first.is_empty() || last.is_empty() {
        return None;
    }
    let middle = if display_words.len() >= 3 {
        let m = sanitize(&display_words[1]);
        (!m.is_empty()).then_some(m)
    } else {
        None
    };

    Some(ParsedName {
        first,
        middle,
        last,
        number,
        display_words,
    })
}

/// Read the email provider list from the environment, falling back to
/// [`DEFAULT_DOMAINS`]. Invalid entries (no dot) are dropped.
pub fn email_domains() -> Vec<String> {
    match std::env::var("HUNTSMAN_EMAIL_DOMAINS") {
        Ok(v) if !v.trim().is_empty() => {
            let parsed: Vec<String> = v
                .split(',')
                .map(|d| d.trim().trim_start_matches('@').to_ascii_lowercase())
                .filter(|d| d.contains('.') && !d.is_empty())
                .collect();
            if parsed.is_empty() {
                default_domains()
            } else {
                parsed
            }
        }
        _ => default_domains(),
    }
}

fn default_domains() -> Vec<String> {
    DEFAULT_DOMAINS.iter().map(|s| s.to_string()).collect()
}

/// Generate scored login/username permutations, deduplicated (keeping the
/// highest weight) and capped at [`MAX_USERNAMES`], best-first.
pub fn usernames(p: &ParsedName) -> Vec<ScoredHandle> {
    let f = p.first.as_str();
    let l = p.last.as_str();
    let fi = initial(f);
    let li = initial(l);

    let mut raw: Vec<(String, f64)> = Vec::new();

    // Primary — the shapes that dominate real-world account handles.
    for h in [
        format!("{f}.{l}"),
        format!("{f}{l}"),
        format!("{fi}{l}"),
        format!("{f}_{l}"),
        format!("{f}{li}"),
    ] {
        raw.push((h, W_PRIMARY));
    }

    // Secondary — reversed and punctuation-joined variants, plus bare tokens.
    for h in [
        format!("{l}.{f}"),
        format!("{l}{f}"),
        format!("{l}{fi}"),
        format!("{f}{li}"),
        format!("{f}.{li}"),
        format!("{l}_{f}"),
        format!("{f}-{l}"),
        format!("{l}-{f}"),
        format!("{fi}.{l}"),
        format!("{l}.{fi}"),
        format!("{fi}_{l}"),
        format!("{fi}-{l}"),
        f.to_string(),
        l.to_string(),
    ] {
        raw.push((h, W_SECONDARY));
    }

    // Middle-name blends.
    if let Some(m) = p.middle.as_deref() {
        let mi = initial(m);
        for h in [
            format!("{f}{m}{l}"),
            format!("{l}{f}{m}"),
            format!("{f}{mi}{l}"),
            format!("{fi}{mi}{l}"),
            format!("{l}{fi}{mi}"),
            format!("{m}{l}"),
            format!("{l}{m}"),
            m.to_string(),
        ] {
            raw.push((h, W_MIDDLE));
        }
    }

    // Year/number-suffixed shapes (NAMINT appends the number to logins).
    if let Some(n) = p.number.as_deref() {
        let mut suffixed = vec![
            format!("{f}.{l}{n}"),
            format!("{f}{l}{n}"),
            format!("{fi}{l}{n}"),
            format!("{f}{n}"),
            format!("{l}{n}"),
        ];
        if let Some(m) = p.middle.as_deref() {
            suffixed.push(format!("{f}{m}{l}{n}"));
        }
        for h in suffixed {
            raw.push((h, W_YEAR));
        }
    }

    dedup_top(raw, MAX_USERNAMES)
}

/// Generate speculative emails: the highest-signal handle shapes crossed with
/// `domains`, capped at [`MAX_EMAILS`]. Handle-major ordering so the most
/// probable patterns appear across providers first.
pub fn emails(p: &ParsedName, domains: &[String]) -> Vec<String> {
    let f = p.first.as_str();
    let l = p.last.as_str();
    let fi = initial(f);
    let li = initial(l);

    let mut logins: Vec<String> = vec![
        format!("{f}.{l}"),
        format!("{f}{l}"),
        format!("{fi}{l}"),
        format!("{f}_{l}"),
        format!("{l}.{f}"),
        format!("{f}{li}"),
    ];
    if let Some(m) = p.middle.as_deref() {
        logins.push(format!("{f}{m}{l}"));
    }
    if let Some(n) = p.number.as_deref() {
        logins.push(format!("{f}.{l}{n}"));
        logins.push(format!("{f}{l}{n}"));
    }

    let mut out = Vec::with_capacity(MAX_EMAILS);
    let mut seen = std::collections::HashSet::new();
    for login in &logins {
        for dom in domains {
            if out.len() >= MAX_EMAILS {
                return out;
            }
            let addr = format!("{login}@{dom}");
            if seen.insert(addr.clone()) {
                out.push(addr);
            }
        }
    }
    out
}

/// Gravatar avatar URL for an email — `MD5(lowercased, trimmed email)`.
/// `d=404` makes the URL resolve only when an avatar actually exists, which is
/// itself a weak existence signal for the address.
pub fn gravatar_url(email: &str) -> String {
    use md5::{Digest, Md5};
    let mut h = Md5::new();
    h.update(email.trim().to_ascii_lowercase().as_bytes());
    format!(
        "https://www.gravatar.com/avatar/{}?d=404&s=200",
        hex::encode(h.finalize())
    )
}

/// Build the ordered set of search-query / people-search pivots, capped at
/// [`MAX_PIVOTS`]. `top_email`, when present, unlocks the email-resolution
/// pivots (Epieos).
pub fn pivots(p: &ParsedName, top_email: Option<&str>) -> Vec<Pivot> {
    let name = p.display_full();
    let qn = q(&format!("\"{name}\""));
    let first = q(p.display_first());
    let last = q(p.display_last());
    let handle = p.plain_handle();
    let fb = p.display_hyphen();

    let mut out: Vec<Pivot> = vec![
        pv(
            "Google — web",
            format!("https://www.google.com/search?q={qn}"),
        ),
        pv(
            "Google — face images",
            format!("https://www.google.com/search?q={qn}&tbm=isch&tbs=itp:face"),
        ),
        pv(
            "Google — email exposure",
            format!(
                "https://www.google.com/search?q={}",
                q(&format!("\"{name}\" (email OR contact OR \"@\")"))
            ),
        ),
        pv(
            "Google — phone exposure",
            format!(
                "https://www.google.com/search?q={}",
                q(&format!("\"{name}\" (phone OR mobile OR tel OR contact)"))
            ),
        ),
        pv(
            "Google — documents",
            format!(
                "https://www.google.com/search?q={}",
                q(&format!(
                    "\"{name}\" filetype:pdf OR filetype:docx OR filetype:xlsx"
                ))
            ),
        ),
        pv(
            "Google — pastes",
            format!(
                "https://www.google.com/search?q={}",
                q(&format!("\"{name}\" site:pastebin.com OR site:throwbin.io"))
            ),
        ),
        pv("Bing — web", format!("https://www.bing.com/search?q={qn}")),
        pv(
            "DuckDuckGo — web",
            format!("https://duckduckgo.com/?q={qn}"),
        ),
        pv(
            "Yandex — face images",
            format!("https://yandex.com/images/search?text={qn}&type=face"),
        ),
        pv(
            "LinkedIn — people",
            format!("https://www.linkedin.com/pub/dir?firstName={first}&lastName={last}"),
        ),
        pv(
            "Facebook — public",
            format!("https://www.facebook.com/public/{fb}"),
        ),
        pv(
            "X / Twitter — people",
            format!("https://x.com/search?q={qn}&f=user"),
        ),
        pv(
            "Instagram — handle",
            format!("https://www.instagram.com/{handle}/"),
        ),
        pv(
            "TikTok — people",
            format!("https://www.tiktok.com/search/user?q={}", q(&name)),
        ),
        pv(
            "GitHub — users",
            format!("https://github.com/search?q={}&type=users", q(&name)),
        ),
        pv(
            "WhatsMyName — username",
            format!("https://whatsmyname.app/?q={handle}"),
        ),
    ];

    if let Some(email) = top_email {
        out.push(pv(
            "Epieos — email lookup",
            format!("https://epieos.com/?q={}", q(email)),
        ));
    }

    out.truncate(MAX_PIVOTS);
    out
}

// ── Internal helpers ────────────────────────────────────────────────────────

fn pv(platform: &'static str, url: String) -> Pivot {
    Pivot { platform, url }
}

/// First character of an ASCII-folded token. Callers guarantee non-empty.
fn initial(s: &str) -> char {
    s.chars().next().unwrap_or('x')
}

/// Percent-encode a query-string value (spaces become `+`).
fn q(s: &str) -> String {
    byte_serialize(s.as_bytes()).collect()
}

/// First 2–4 digit run in the input, captured as the NAMINT "number"/year.
fn extract_number(raw: &str) -> Option<String> {
    let mut run = String::new();
    for c in raw.chars() {
        if c.is_ascii_digit() {
            run.push(c);
        } else if !run.is_empty() {
            if (2..=4).contains(&run.len()) {
                return Some(run);
            }
            run.clear();
        }
    }
    (2..=4).contains(&run.len()).then_some(run)
}

/// Clean a raw token to its display form: letters plus internal hyphen/
/// apostrophe, outer punctuation trimmed. `None` if no letter survives.
fn clean_display_token(tok: &str) -> Option<String> {
    let kept: String = tok
        .chars()
        .filter(|c| c.is_alphabetic() || *c == '-' || *c == '\'')
        .collect();
    let kept = kept.trim_matches(|c| c == '-' || c == '\'').to_string();
    if kept.chars().any(|c| c.is_alphabetic()) {
        Some(titlecase(&kept))
    } else {
        None
    }
}

/// Uppercase the first character, preserve the remainder as typed
/// (so `mcdonald` → `Mcdonald` but `McDonald` is left intact).
fn titlecase(s: &str) -> String {
    let mut chars = s.chars();
    match chars.next() {
        Some(first) => first.to_uppercase().collect::<String>() + chars.as_str(),
        None => String::new(),
    }
}

/// ASCII-fold to lowercase letters only — safe for byte slicing and handle use.
fn sanitize(s: &str) -> String {
    s.chars()
        .filter(|c| c.is_ascii_alphabetic())
        .map(|c| c.to_ascii_lowercase())
        .collect()
}

/// Deduplicate `(handle, weight)` pairs keeping the highest weight per handle,
/// drop empties, then return the top `cap` ordered by weight desc, then handle.
fn dedup_top(raw: Vec<(String, f64)>, cap: usize) -> Vec<ScoredHandle> {
    use std::collections::HashMap;
    let mut best: HashMap<String, f64> = HashMap::new();
    for (h, w) in raw {
        if h.is_empty() {
            continue;
        }
        best.entry(h)
            .and_modify(|cur| {
                if w > *cur {
                    *cur = w;
                }
            })
            .or_insert(w);
    }
    let mut v: Vec<ScoredHandle> = best
        .into_iter()
        .map(|(handle, weight)| ScoredHandle { handle, weight })
        .collect();
    v.sort_by(|a, b| {
        b.weight
            .partial_cmp(&a.weight)
            .unwrap_or(std::cmp::Ordering::Equal)
            .then_with(|| a.handle.cmp(&b.handle))
    });
    v.truncate(cap);
    v
}

#[cfg(test)]
mod tests {
    use super::*;

    fn p(s: &str) -> ParsedName {
        parse(s).expect("parses")
    }

    #[test]
    fn parses_two_part_name() {
        let n = p("Jordan Meyers");
        assert_eq!(n.first, "jordan");
        assert_eq!(n.last, "meyers");
        assert_eq!(n.middle, None);
        assert_eq!(n.number, None);
        assert_eq!(n.display_full(), "Jordan Meyers");
    }

    #[test]
    fn parses_three_part_and_year() {
        let n = p("jordan leigh meyers 1987");
        assert_eq!(n.first, "jordan");
        assert_eq!(n.middle.as_deref(), Some("leigh"));
        assert_eq!(n.last, "meyers");
        assert_eq!(n.number.as_deref(), Some("1987"));
        // Display capitalises the leading letter without mangling the rest.
        assert_eq!(n.display_full(), "Jordan Leigh Meyers");
    }

    #[test]
    fn single_token_is_rejected() {
        assert!(parse("Jordan").is_none());
        assert!(parse("   1987   ").is_none());
        assert!(parse("").is_none());
    }

    #[test]
    fn folds_punctuation_and_accents() {
        let n = p("José O'Brien-Smith");
        // Apostrophe/hyphen folded out of handle tokens; accent dropped.
        assert_eq!(n.first, "jos");
        assert_eq!(n.last, "obriensmith");
    }

    #[test]
    fn handles_comma_separator() {
        let n = p("Meyers, Jordan");
        assert_eq!(n.first, "meyers");
        assert_eq!(n.last, "jordan");
    }

    #[test]
    fn usernames_cover_namint_core_shapes() {
        let u: Vec<String> = usernames(&p("Jordan Meyers"))
            .into_iter()
            .map(|s| s.handle)
            .collect();
        for want in [
            "jordan.meyers",
            "jordanmeyers",
            "jmeyers",
            "jordan_meyers",
            "jordanm",
            "meyers.jordan",
            "meyersjordan",
            "jordan-meyers",
        ] {
            assert!(u.contains(&want.to_string()), "missing {want}: {u:?}");
        }
    }

    #[test]
    fn usernames_include_middle_blends() {
        let u: Vec<String> = usernames(&p("Jordan Leigh Meyers"))
            .into_iter()
            .map(|s| s.handle)
            .collect();
        assert!(u.contains(&"jordanleighmeyers".to_string()));
        assert!(u.contains(&"jlmeyers".to_string())); // f + m_i + l
        assert!(u.contains(&"jordanlmeyers".to_string())); // f + m_i + l
    }

    #[test]
    fn usernames_include_year_suffix() {
        let u: Vec<String> = usernames(&p("Jordan Meyers 87"))
            .into_iter()
            .map(|s| s.handle)
            .collect();
        assert!(u.iter().any(|h| h.ends_with("87")), "no year suffix: {u:?}");
    }

    #[test]
    fn usernames_bounded_and_deduped() {
        let u = usernames(&p("Ana Bo Ce De Ef"));
        assert!(u.len() <= MAX_USERNAMES);
        let mut set = std::collections::HashSet::new();
        for s in &u {
            assert!(set.insert(s.handle.clone()), "dup: {}", s.handle);
        }
        // Best-first ordering by weight.
        for w in u.windows(2) {
            assert!(w[0].weight >= w[1].weight);
        }
    }

    #[test]
    fn primary_outranks_secondary() {
        let u = usernames(&p("Jordan Meyers"));
        let by = |h: &str| u.iter().find(|s| s.handle == h).map(|s| s.weight);
        assert!(by("jordan.meyers").unwrap() > by("meyers.jordan").unwrap());
    }

    #[test]
    fn emails_cross_logins_and_domains() {
        let domains = vec!["gmail.com".to_string(), "proton.me".to_string()];
        let e = emails(&p("Jordan Meyers"), &domains);
        assert!(e.contains(&"jordan.meyers@gmail.com".to_string()));
        assert!(e.contains(&"jordan.meyers@proton.me".to_string()));
        assert!(e.iter().all(|a| a.contains('@')));
        assert!(e.len() <= MAX_EMAILS);
    }

    #[test]
    fn emails_are_bounded_under_many_domains() {
        let domains: Vec<String> = (0..50).map(|i| format!("d{i}.com")).collect();
        let e = emails(&p("Jordan Leigh Meyers 90"), &domains);
        assert_eq!(e.len(), MAX_EMAILS);
        let set: std::collections::HashSet<_> = e.iter().collect();
        assert_eq!(set.len(), e.len(), "no duplicate addresses");
    }

    #[test]
    fn gravatar_is_stable_md5_and_case_insensitive() {
        // Reference MD5 of "jordan@example.com".
        let a = gravatar_url("Jordan@Example.com");
        let b = gravatar_url("  jordan@example.com ");
        assert_eq!(a, b, "gravatar must normalise case/whitespace");
        assert!(a.contains("/avatar/"));
        // 32 hex chars between /avatar/ and ?.
        let hash = a
            .split("/avatar/")
            .nth(1)
            .and_then(|t| t.split('?').next())
            .unwrap();
        assert_eq!(hash.len(), 32);
        assert!(hash.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn pivots_are_bounded_and_encoded() {
        let n = p("Jordan Leigh Meyers");
        let pv = pivots(&n, Some("jordan.meyers@gmail.com"));
        assert!(pv.len() <= MAX_PIVOTS);
        assert!(!pv.is_empty());
        for piv in &pv {
            assert!(piv.url.starts_with("https://"), "non-https: {}", piv.url);
            // The quoted name must be percent-encoded, never raw spaces/quotes.
            assert!(!piv.url.contains(' '), "raw space in {}", piv.url);
            assert!(!piv.url.contains('"'), "raw quote in {}", piv.url);
        }
        assert!(pv.iter().any(|x| x.platform.starts_with("Google")));
        assert!(pv.iter().any(|x| x.platform.starts_with("Epieos")));
    }

    #[test]
    fn pivots_without_email_skip_epieos() {
        let n = p("Jordan Meyers");
        let pv = pivots(&n, None);
        assert!(!pv.iter().any(|x| x.platform.starts_with("Epieos")));
    }

    #[test]
    fn default_domains_used_without_env() {
        // Not asserting against env (tests share a process); just shape.
        let d = default_domains();
        assert!(d.contains(&"gmail.com".to_string()));
        assert!(d.iter().all(|x| x.contains('.')));
    }
}
