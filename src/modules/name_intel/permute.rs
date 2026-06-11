//! Pure, network-free name → identity derivation.
//!
//! This is the engine behind the [`super::NameIntel`] module and a faithful,
//! bounded port of the methodology in NAMINT (<https://seintpl.github.io/NAMINT/>):
//!
//!   * **Login permutations** — ~40 `first`/`middle`/`last`/`number` handle
//!     shapes (`first.last`, `flast`, `firstl`, `last.first`, hyphen/underscore
//!     joins, middle-initial blends, year suffixes).
//!   * **Email permutations** — likely handle shapes crossed with a configurable
//!     provider set (the mainstream consumer mailboxes ordinary people actually
//!     hold — Gmail, the Microsoft outlook/hotmail/live family, Yahoo, iCloud,
//!     AOL, Proton), ranked by `P(handle) × P(provider)` so the bounded budget
//!     is spent on the addresses the *median* person is likeliest to hold, and
//!     capped so a single name target never floods the entity graph.
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
/// Emails are the widest fan-out (handle shapes × every provider) and the
/// lowest-signal permutation — pure guesses across mailbox providers. Capped
/// tighter than usernames so a name seed doesn't flood the Browse table with
/// near-duplicate addresses.
pub(super) const MAX_EMAILS: usize = 12;
pub(super) const MAX_PIVOTS: usize = 24;

// ── Confidence weights ──────────────────────────────────────────────────────
/// Real-world-common handle shapes (`first.last`, `firstlast`, `flast`, …).
///
/// Kept strictly below the 0.40 Probable floor: a name-derived handle is an
/// *unconfirmed guess*, so it stays a Candidate (matching this module's
/// "low-confidence candidate entities" contract) until a discovery module
/// observes it live — at which point the second source lifts its `c_effective`
/// and AU-035 fires. (Previously 0.42 put the top shapes in the Probable tier,
/// ranking guesses as if they were findings.)
const W_PRIMARY: f64 = 0.38;
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
/// The scan subject itself — the Person the operator named as the seed. Lands in
/// the Probable tier (≥ 0.40): clearly the anchor, well above the speculative
/// derivations (0.20–0.38), but below Verified (≥ 0.75) since HSE has not yet
/// externally corroborated that this person exists.
pub(super) const SUBJECT_CONF: f64 = 0.60;

/// NAMINT's default provider set, modernised. Overridable at runtime via the
/// `HUNTSMAN_EMAIL_DOMAINS` environment variable (comma-separated).
const DEFAULT_DOMAINS: &[&str] = &[
    "gmail.com",
    "outlook.com",
    "hotmail.com",
    "yahoo.com",
    "icloud.com",
    "live.com",
    "aol.com",
    "proton.me",
    // Australian ISP mailboxes (Telstra/Bigpond — large AU residential user base)
    "bigpond.com",
    "bigpond.net.au",
];

/// Real-world consumer-mailbox share, used to rank `handle@provider` guesses so
/// the budget (`MAX_EMAILS`) is spent on the addresses an *arbitrary* person is
/// most likely to actually hold. Gmail dwarfs every other consumer provider;
/// the Microsoft family (outlook/hotmail/live) and Yahoo form the next tier;
/// Apple iCloud and the legacy AOL base trail; privacy-focused Proton is rare in
/// the general population. Domains supplied via `HUNTSMAN_EMAIL_DOMAINS` that we
/// don't recognise get a neutral mid weight so an operator's custom provider is
/// still tried, just not ranked above Gmail.
fn provider_weight(domain: &str) -> f64 {
    match domain {
        "gmail.com" | "googlemail.com" => 1.0,
        "outlook.com" | "hotmail.com" | "live.com" | "msn.com" => 0.6,
        "yahoo.com" | "ymail.com" => 0.5,
        "icloud.com" | "me.com" | "mac.com" => 0.45,
        "aol.com" => 0.4,
        "gmx.com" | "gmx.net" | "mail.com" => 0.35,
        "bigpond.com" | "bigpond.net.au" | "telstra.com" => 0.35,
        "proton.me" | "protonmail.com" | "pm.me" | "tutanota.com" => 0.3,
        _ => 0.4,
    }
}

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
        // `parse()` guarantees ≥2 words, but the fields are `pub` — a
        // directly-constructed `ParsedName` must degrade to "" rather than
        // panic (under `panic="abort"` a panic in `hse serve` aborts the
        // whole process).
        self.display_words.first().map_or("", String::as_str)
    }
    pub fn display_last(&self) -> &str {
        self.display_words.last().map_or("", String::as_str)
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
/// single name cannot seed search pivots). The ASCII-folded `first`/`last`
/// handle tokens may be empty for non-Latin scripts; the caller skips
/// username/email permutation in that case but still emits search pivots. An
/// optional 2–4 digit run anywhere in the input is captured as `number`
/// (NAMINT's "year" field), e.g. `"Jordan Meyers 1987"`.
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

    // ASCII-folded handle tokens. These may be empty for non-Latin names
    // (e.g. Cyrillic/CJK), in which case username/email permutation is skipped
    // by the caller but the display-name search pivots still generate.
    let first = sanitize(display_words.first().map_or("", String::as_str));
    let last = sanitize(display_words.last().map_or("", String::as_str));
    let middle = if display_words.len() >= 3 {
        let m = sanitize(display_words.get(1).map_or("", String::as_str));
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
    // Non-Latin names ASCII-fold to empty handle tokens; there are no
    // meaningful login/email permutations without a first+last handle.
    if p.first.is_empty() || p.last.is_empty() {
        return Vec::new();
    }
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

    // Secondary — reversed and punctuation-joined variants. Bare single-token
    // handles (`first` or `last` alone) are deliberately excluded: a lone given
    // or family name is not a distinguishing handle — it matches countless
    // unrelated people and only padded the candidate list with noise.
    for h in [
        format!("{l}.{f}"),
        format!("{l}{f}"),
        format!("{l}{fi}"),
        format!("{f}.{li}"),
        format!("{l}_{f}"),
        format!("{f}-{l}"),
        format!("{l}-{f}"),
        format!("{fi}.{l}"),
        format!("{l}.{fi}"),
        format!("{fi}_{l}"),
        format!("{fi}-{l}"),
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

/// Generate speculative emails: likely handle shapes crossed with `domains`,
/// ranked by **P(handle) × P(provider)** and capped at [`MAX_EMAILS`].
///
/// The previous handle-major ordering sprayed the single shape `first.last`
/// across *every* provider before trying any other shape — so a budget of 8
/// over six providers spent five slots on `first.last@{icloud,yahoo,proton,…}`
/// and never reached `firstlast@gmail.com`, even though, for an arbitrary
/// person, the latter is far likelier to exist. Ranking the full cross-product
/// by the product of handle commonality and provider market share puts the
/// budget where the median person's real address actually lives (top shapes on
/// Gmail and the Microsoft/Yahoo tier) before spending it on long-tail combos.
pub fn emails(p: &ParsedName, domains: &[String]) -> Vec<String> {
    // Non-Latin names ASCII-fold to empty handle tokens; there are no
    // meaningful login/email permutations without a first+last handle.
    if p.first.is_empty() || p.last.is_empty() {
        return Vec::new();
    }
    let f = p.first.as_str();
    let l = p.last.as_str();
    let fi = initial(f);
    let li = initial(l);

    // (handle, commonality weight) — the shapes real mailboxes most often take,
    // weighted by how common each is. `first.last`/`firstlast` dominate; the
    // initial-blends and reversed/number forms trail.
    let mut logins: Vec<(String, f64)> = vec![
        (format!("{f}.{l}"), 1.00),
        (format!("{f}{l}"), 0.95),
        (format!("{fi}{l}"), 0.70),
        (format!("{f}_{l}"), 0.60),
        (format!("{f}{li}"), 0.45),
        (format!("{l}.{f}"), 0.40),
    ];
    if let Some(m) = p.middle.as_deref() {
        logins.push((format!("{f}{m}{l}"), 0.50));
    }
    if let Some(n) = p.number.as_deref() {
        logins.push((format!("{f}.{l}{n}"), 0.45));
        logins.push((format!("{f}{l}{n}"), 0.42));
    }

    // Full cross-product scored by P(handle) × P(provider), then taken best
    // first. A stable sort keeps the (handle, provider) declaration order as the
    // deterministic tie-break so identical scores resolve identically.
    let mut scored: Vec<(f64, String)> = Vec::with_capacity(logins.len() * domains.len());
    let mut seen = std::collections::HashSet::new();
    for (login, hw) in &logins {
        for dom in domains {
            let addr = format!("{login}@{dom}");
            if seen.insert(addr.clone()) {
                scored.push((hw * provider_weight(dom), addr));
            }
        }
    }
    scored.sort_by(|a, b| b.0.partial_cmp(&a.0).unwrap_or(std::cmp::Ordering::Equal));
    scored
        .into_iter()
        .take(MAX_EMAILS)
        .map(|(_, addr)| addr)
        .collect()
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
    let has_handle = !handle.is_empty();
    // Percent-encode the hyphen-joined display name like every other pivot value,
    // so a non-Latin name doesn't embed raw UTF-8 in the Facebook path.
    let fb = q(&p.display_hyphen());

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
            "TikTok — people",
            format!("https://www.tiktok.com/search/user?q={}", q(&name)),
        ),
        pv(
            "GitHub — users",
            format!("https://github.com/search?q={}&type=users", q(&name)),
        ),
        // AU-specific pivots (T1593.001 — Search Open Websites: Social Media)
        pv(
            "Seek.com.au — job profile",
            format!("https://www.seek.com.au/jobs?keywords={}", q(&name)),
        ),
        pv(
            "WhitePages AU — residential",
            format!(
                "https://www.whitepages.com.au/residential/name/search?search={}",
                q(&name)
            ),
        ),
        pv(
            "Google AU — site:*.com.au",
            format!(
                "https://www.google.com.au/search?q={}",
                q(&format!("\"{name}\" site:com.au"))
            ),
        ),
        pv(
            "Google — ABN/ACN lookup",
            format!(
                "https://www.google.com/search?q={}",
                q(&format!("\"{name}\" ABN OR ACN OR director"))
            ),
        ),
    ];

    if has_handle {
        out.push(pv(
            "Instagram — handle",
            format!("https://www.instagram.com/{handle}/"),
        ));
        out.push(pv(
            "WhatsMyName — username",
            format!("https://whatsmyname.app/?q={handle}"),
        ));
    }

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
    // Collect every 2–4 digit run, then prefer a 4-digit run (a likely birth
    // year) over shorter ones; fall back to the first run otherwise. This keeps
    // `"Jordan 12 Meyers 1987"` → `1987` rather than the leading `12`.
    let mut runs: Vec<String> = Vec::new();
    let mut run = String::new();
    for c in raw.chars() {
        if c.is_ascii_digit() {
            run.push(c);
        } else {
            if (2..=4).contains(&run.len()) {
                runs.push(std::mem::take(&mut run));
            }
            run.clear();
        }
    }
    if (2..=4).contains(&run.len()) {
        runs.push(run);
    }
    runs.iter()
        .find(|r| r.len() == 4)
        .or_else(|| runs.first())
        .cloned()
}

/// Clean a raw token to its display form: letters plus internal hyphen/
/// apostrophe, outer punctuation trimmed. `None` if no letter survives.
fn clean_display_token(tok: &str) -> Option<String> {
    let kept: String = tok
        .chars()
        .filter(|c| c.is_alphabetic() || *c == '-' || *c == '\'')
        .collect();
    let kept = kept.trim_matches(|c| c == '-' || c == '\'').to_string();
    // After filtering to letters (+ internal hyphen/apostrophe) and trimming
    // those, any non-empty remainder is guaranteed to contain a letter.
    if kept.is_empty() {
        None
    } else {
        Some(titlecase(&kept))
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

/// Fold a display token to a lowercase ASCII handle token, safe for byte
/// slicing. Delegates to the shared [`crate::util::str_util::fold_ascii_lower`] so Latin diacritics
/// map to their base letter (`José` → `jose`, `Müller` → `muller`) and derived
/// handles match what platforms actually use; non-Latin scripts have no ASCII
/// fold and yield an empty token (handled by the caller).
fn sanitize(s: &str) -> String {
    crate::util::str_util::fold_ascii_lower(s)
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
    fn display_accessors_never_panic_on_degenerate_name() {
        // `ParsedName` has public fields, so a value can be built bypassing
        // `parse()`'s ≥2-word guarantee. The public accessors must degrade to
        // "" instead of panicking (an index/`expect` would abort `hse serve`
        // under panic="abort"). Regression guard for that latent panic.
        let empty = ParsedName {
            first: String::new(),
            middle: None,
            last: String::new(),
            number: None,
            display_words: Vec::new(),
        };
        assert_eq!(empty.display_first(), "");
        assert_eq!(empty.display_last(), "");
        assert_eq!(empty.display_full(), "");

        // Normal parsed names still report the right first/last words.
        let n = p("Jordan Lee Meyers");
        assert_eq!(n.display_first(), "Jordan");
        assert_eq!(n.display_last(), "Meyers");
    }

    #[test]
    fn extract_number_prefers_four_digit_year() {
        // A leading 2-digit run must not shadow the real 4-digit birth year.
        assert_eq!(p("Jordan 12 Meyers 1987").number.as_deref(), Some("1987"));
        // With no 4-digit run present, the first 2–4 digit run is taken.
        assert_eq!(p("Jordan Meyers 71").number.as_deref(), Some("71"));
    }

    #[test]
    fn non_latin_name_yields_pivots_but_no_handles() {
        // Cyrillic ASCII-folds to empty handle tokens: the name still parses so
        // display-name search pivots generate, but username/email permutation
        // (which needs ASCII handles) is empty.
        let n = parse(
            "\u{0418}\u{0432}\u{0430}\u{043d} \u{041f}\u{0435}\u{0442}\u{0440}\u{043e}\u{0432}",
        )
        .expect("non-Latin name parses for pivots");
        assert!(n.first.is_empty() && n.last.is_empty());
        assert!(usernames(&n).is_empty(), "no ASCII handle => no usernames");
        assert!(emails(&n, &default_domains()).is_empty());
        let pivots = pivots(&n, None);
        assert!(!pivots.is_empty(), "display-name pivots still generate");
        // Handle-only platforms are skipped when there is no ASCII handle.
        assert!(
            !pivots
                .iter()
                .any(|pv| pv.platform.starts_with("Instagram")
                    || pv.platform.starts_with("WhatsMyName")),
            "handle-only pivots must be skipped without an ASCII handle"
        );
        assert!(pivots.iter().any(|pv| pv.url.contains("google.com/search")));
    }

    #[test]
    fn latin_diacritics_fold_to_ascii_handles() {
        // Migrant/EU names must derive matchable ASCII handles, not drop the
        // accented letter (José → jose, not jos).
        let n = p("José Müller");
        assert_eq!(n.first, "jose");
        assert_eq!(n.last, "muller");
        assert!(usernames(&n).iter().any(|u| u.handle == "jose.muller"));
        // Display form preserves the original accents for quoted searches.
        assert_eq!(n.display_full(), "José Müller");
    }

    #[test]
    fn folds_punctuation_and_accents() {
        let n = p("José O'Brien-Smith");
        // Apostrophe/hyphen folded out of handle tokens; Latin accent folded to
        // its base letter (é → e) so the handle matches real-world accounts.
        assert_eq!(n.first, "jose");
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
    fn derived_usernames_stay_below_the_probable_floor() {
        // Derived handles are unconfirmed guesses — every one must classify as
        // Candidate (c_eff < 0.40) until a discovery module corroborates it, per
        // name_intel's documented "low-confidence candidate" contract. Guards
        // every handle weight (incl. W_PRIMARY) against drifting back over the
        // 0.40 floor, where a pure guess would masquerade as a Probable finding.
        use crate::core::entity::{Classification, Entity, EntityKind};
        let handles = usernames(&p("Jordan Leigh Meyers 1987"));
        let max_w = handles.iter().map(|u| u.weight).fold(0.0_f64, f64::max);
        assert!(
            max_w < 0.40,
            "strongest derived handle weight {max_w} must stay below the 0.40 Probable floor"
        );
        for u in &handles {
            let e = Entity::new(EntityKind::Username, &u.handle, u.weight, "s");
            assert_eq!(
                e.classify(),
                Classification::Candidate,
                "derived handle '{}' (w={}) must stay a Candidate",
                u.handle,
                u.weight
            );
        }
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
    fn emails_rank_common_provider_and_shape_first() {
        // The average person's address is far likelier to be a top shape on a
        // mainstream provider than `first.last` on a rare one. With Gmail and
        // Proton both available, every Gmail guess must outrank the Proton one,
        // and `firstlast@gmail` (a top shape on the modal provider) must beat
        // `first.last@proton` (top shape, long-tail provider).
        let domains = vec!["proton.me".to_string(), "gmail.com".to_string()];
        let e = emails(&p("Jordan Meyers"), &domains);
        let pos = |needle: &str| e.iter().position(|a| a == needle);
        let gmail_flat = pos("jordanmeyers@gmail.com").expect("firstlast@gmail present");
        let proton_dot = pos("jordan.meyers@proton.me").expect("first.last@proton present");
        assert!(
            gmail_flat < proton_dot,
            "firstlast@gmail must rank above first.last@proton; got {e:?}"
        );
        // first.last@gmail — top shape × top provider — is the single best guess.
        assert_eq!(
            e.first().map(String::as_str),
            Some("jordan.meyers@gmail.com")
        );
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
