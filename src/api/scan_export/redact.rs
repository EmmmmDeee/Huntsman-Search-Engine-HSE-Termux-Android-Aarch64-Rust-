//! Redaction of proprietary breach/intel **source identities** from the
//! shareable scan exports (CSV, `report.json`, GEXF, `events.log`).
//!
//! The operator pays for and relies on a private set of breach / leak / stealer
//! and paid-OSINT data providers (SeekNow, OathNet, DeHashed, …). A scan result
//! handed to a *customer* must not reveal WHICH providers produced a finding —
//! that provider set is the operator's tradecraft. Every finding's evidence and
//! every scan event names its producing module, so those names are genericised
//! on the way out of the four *download* endpoints.
//!
//! Scope: this genericises only the *provider identity*, never the finding
//! itself — the datum, its confidence, and its provenance TYPE (that it came
//! from a breach source) are preserved, so the export stays fully useful. The
//! operator's own full-detail views are deliberately UNAFFECTED: the live web-UI
//! panels (served by the `/entities`, `/network`, … JSON endpoints), the operator
//! scan debug bundle (built via the non-redacting `download_response_operator`
//! path and labelled "operator only" in the UI), and `hse export` in the shell
//! all keep the real source names.
//!
//! Three passes, in this order, over the whole body:
//!   1. a URL or hostname that names a provider is replaced WHOLE by
//!      `[redacted-url]` (`REDACTED_URL`) — before any name is touched, because swapping only the
//!      name inside `https://see-know.ru` yields `https://<label>.ru`, a
//!      plausible address nobody observed (the old single-label redactor wrote
//!      `breach-source.com` / `breach-source.io` into customer files);
//!   2. a provider's key env var (`HUNTSMAN_SEEKNOW_KEY`) becomes
//!      `HUNTSMAN_[redacted]_KEY` — the "needs API key …" skip reasons print it;
//!   3. every remaining spelling of a provider becomes that provider's own
//!      `[breach-source-N]` placeholder, so the log's per-module
//!      start/done/error accounting survives without naming anyone.

use crate::core::module::ModuleCategory;
use regex::{Captures, Regex};
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::sync::LazyLock;

/// The stem of every provider placeholder: a sensitive module is shown as
/// `[breach-source-N]`, `N` being its 1-based position in the sorted canonical
/// list ([`sensitive_modules`]). One `N` per provider keeps two providers
/// distinguishable in the export (ten modules collapsing onto one label made
/// the log's module accounting unreadable) while naming neither. The brackets
/// make it unmistakably synthetic and can never sit inside a hostname.
///
/// `N` is stable for a given build's module set, NOT across builds that add a
/// breach module (the later positions shift), and — because the module list is
/// public source — a reader holding that exact build can map `N` back to a
/// module. It hides the provider from a casual reader of the file, not from one
/// who reverse-engineers the build.
pub const REDACTED_LABEL: &str = "breach-source";

/// What a URL or hostname that names a sensitive provider is replaced with —
/// WHOLE, so no fragment of it (a TLD, a path) is left to read as a different,
/// plausible address. Bracketed in the `[redacted]` style of
/// [`crate::util::redact::REDACTED`].
pub const REDACTED_URL: &str = "[redacted-url]";

/// Placeholder for a match whose spelling has no entry in the per-provider map —
/// only reachable through a Unicode case-fold (`ſ` for `s`) the map's lowercase
/// keys do not carry. Still names nobody.
const GENERIC_PLACEHOLDER: &str = "[breach-source]";

/// Paid/proprietary breach-intel providers the `Breach`-category registry
/// sweep does NOT catch: `oathnet_pro` is `People`-categorised, so the sweep
/// skips it entirely. The operator named OathNet and Seek-Know specifically.
/// Add any other paid provider here as it is integrated; the
/// `every_breach_category_source_is_redacted` test guards the `Breach`-category
/// set automatically.
const EXTRA_SENSITIVE_MODULES: &[&str] = &["oathnet_pro"];

/// Spellings a provider's source label appears as that its module `name()`
/// does not derive: the stealer path stamps the bare `oathnet`, and the
/// "SeekNow" brand is spelled `seek_know` / "Seek-Know" as well as `see_know`.
/// Each maps to its module, so it shares that module's placeholder. Spelled
/// once each in `snake_case`: [`spellings`] derives the spaced, hyphenated and
/// run-together forms ("seek-know", "seekknow", …).
const EXTRA_ALIASES: &[(&str, &[&str])] =
    &[("oathnet_pro", &["oathnet"]), ("see_know", &["seek_know"])];

/// A URL (any `scheme://`) or a bare hostname, with any port and path/query —
/// the shapes a provider identity rides out in when it is part of an address.
/// Labels admit `_` so `see_know.rs`-style tokens are treated as one address.
/// The path stops at whitespace, quotes, `<>`, a backslash (a JSON escape),
/// brackets, `,` and `|`, so it never runs across a CSV/JSON/XML delimiter —
/// the address is replaced whole, and swallowing an unquoted CSV comma with it
/// would shift every later column of the row.
const URL_PATTERN: &str = r#"(?i)(?:[a-z][a-z0-9+.-]*://)?[a-z0-9_](?:[a-z0-9_-]*[a-z0-9_])?(?:\.[a-z0-9_](?:[a-z0-9_-]*[a-z0-9_])?)+(?::[0-9]+)?(?:[/?#][^\s"'<>\\()\[\]{}|^`,]*)?"#;

/// The canonical, sorted sensitive-module list: every `Breach`-category
/// module's source name (authoritative and self-maintaining — a newly added
/// breach module is covered without editing this file) plus
/// [`EXTRA_SENSITIVE_MODULES`]. A provider's placeholder `N` is its 1-based
/// position here, which is why this is a sorted set rather than registry order.
fn sensitive_modules() -> Vec<String> {
    let mut names: BTreeSet<String> = crate::modules::registry()
        .iter()
        .filter(|m| m.category() == ModuleCategory::Breach)
        .map(|m| m.name().to_string())
        .collect();
    names.extend(EXTRA_SENSITIVE_MODULES.iter().map(|&e| e.to_string()));
    names.into_iter().collect()
}

/// Every spelling of one provider name, lowercased: a module `name()` is
/// `snake_case`, but the evidence SUMMARIES that land in the exported artifacts
/// spell the same provider with spaces, hyphens or run together —
/// `pwned_passwords` writes "HIBP Pwned Passwords: …", see_know writes
/// "SeekNow record from …". `_`, ` ` and `-` are interchangeable word
/// separators here, so each name yields its `_`/space/`-`/joined forms.
fn spellings(name: &str) -> BTreeSet<String> {
    let lower = name.to_lowercase();
    let words: Vec<&str> = lower
        .split(['_', ' ', '-'])
        .filter(|w| !w.is_empty())
        .collect();
    ["_", " ", "-", ""]
        .into_iter()
        .map(|sep| words.join(sep))
        .filter(|s| !s.is_empty())
        .collect()
}

/// Record every [`spellings`] form of `name` as belonging to module `i`. The
/// first claim wins, so a later-derived alias can never re-point a spelling
/// already owned by another module.
fn claim(owner: &mut BTreeMap<String, usize>, name: &str, i: usize) {
    for s in spellings(name) {
        owner.entry(s).or_insert(i);
    }
}

/// `s` reduced to its lowercase ASCII letters and digits — the form an env-var
/// stem and a module name are compared in (`STOLEN_TAX` ↔ `stolen_tax`,
/// `SEEKNOW` ↔ `see_know`).
fn compact(s: &str) -> String {
    s.to_ascii_lowercase()
        .chars()
        .filter(char::is_ascii_alphanumeric)
        .collect()
}

/// A module's own name plus its [`EXTRA_ALIASES`], each [`compact`]ed.
fn compact_names(module: &str) -> Vec<String> {
    let mut names = vec![compact(module)];
    for (owner, aliases) in EXTRA_ALIASES {
        if *owner == module {
            names.extend(aliases.iter().copied().map(compact));
        }
    }
    names
}

/// Which sensitive module (index into `modules`) a key env var's stem names —
/// `HUNTSMAN_BREACHDIR_KEY`'s `BREACHDIR` names `breachdirectory`. An exact
/// match wins; otherwise one side must be a prefix of the other, and at least
/// four characters long so a short stem cannot claim an unrelated module. The
/// module's [`EXTRA_ALIASES`] count as its names (`OATHNET` → `oathnet_pro`).
fn module_for_stem(stem: &str, modules: &[String]) -> Option<usize> {
    let stem = compact(stem);
    let prefix_of = |a: &str| {
        a.len().min(stem.len()) >= 4 && (a.starts_with(stem.as_str()) || stem.starts_with(a))
    };
    modules
        .iter()
        .position(|m| compact_names(m).contains(&stem))
        .or_else(|| {
            modules
                .iter()
                .position(|m| compact_names(m).iter().any(|n| prefix_of(n.as_str())))
        })
}

/// The provider brand a [`signup_hint`](crate::util::keys::signup_hint) opens
/// with: the text before its first ` — `, minus any parenthesised aside —
/// "SeekNow (see-know.ru) — https://…" → "SeekNow", "Intelligence X — free
/// tier at …" → "Intelligence X". `None` for a hint without that shape.
fn hint_brand(hint: &str) -> Option<&str> {
    let (head, _) = hint.split_once(" — ")?;
    let brand = head.split(" (").next().unwrap_or(head).trim();
    (!brand.is_empty()).then_some(brand)
}

/// Whether `hay` contains `needle` as a whole token — bounded on both sides by
/// a non-alphanumeric character or the string's end — the same boundary rule
/// the name pass applies. Both sides are expected lowercase.
fn contains_token(hay: &str, needle: &str) -> bool {
    hay.match_indices(needle).any(|(i, _)| {
        let before = hay[..i].chars().next_back();
        let after = hay[i + needle.len()..].chars().next();
        !before.is_some_and(char::is_alphanumeric) && !after.is_some_and(char::is_alphanumeric)
    })
}

/// The compiled redactor. Built once ([`REDACTOR`]); `None` only when the
/// sensitive set is empty.
struct Redactor {
    /// [`URL_PATTERN`], compiled.
    url: Regex,
    /// Whole-token alternation of the sensitive providers' key env-var names,
    /// or `None` when no key env maps to a sensitive module.
    env: Option<Regex>,
    /// Lowercased key env var → (its module's index, its replacement).
    key_envs: BTreeMap<String, (usize, String)>,
    /// Every sensitive spelling (capture group 1), case-insensitive, between
    /// non-alphanumeric boundaries — see [`Redactor::build`].
    names: Regex,
    /// Lowercased spelling → its provider's `[breach-source-N]` placeholder.
    placeholder: HashMap<String, String>,
    /// [`sensitive_modules`], kept so the tests can name a placeholder's owner.
    #[cfg_attr(not(test), allow(dead_code))]
    modules: Vec<String>,
}

static REDACTOR: LazyLock<Option<Redactor>> = LazyLock::new(Redactor::build);

impl Redactor {
    fn build() -> Option<Self> {
        let modules = sensitive_modules();
        if modules.is_empty() {
            return None;
        }
        // Spelling → owning module. The modules' own names are claimed first,
        // so no later-derived alias can re-point one at another placeholder.
        let mut owner: BTreeMap<String, usize> = BTreeMap::new();
        for (i, m) in modules.iter().enumerate() {
            claim(&mut owner, m, i);
        }
        for (m, aliases) in EXTRA_ALIASES {
            if let Some(i) = modules.iter().position(|x| x == m) {
                for a in *aliases {
                    claim(&mut owner, a, i);
                }
            }
        }
        // Each sensitive provider's key env var, and what its signup hint
        // prints. The engine's "needs API key {env} — {signup_hint}" skip
        // reason is a scan event, so it lands in events.log verbatim: the env
        // name, the display brand ("Intelligence X", "Stolen.tax") and the
        // signup host all name the provider, and none of them is derivable
        // from the module name. Derived from the key registry rather than
        // hand-listed, so a new provider's hint is covered with its key.
        let hint_url = Regex::new(r"(?i)https?://([a-z0-9.-]+)[^\s)]*").ok()?;
        let mut key_envs: BTreeMap<String, (usize, String)> = BTreeMap::new();
        for &env in crate::util::keys::KNOWN_KEYS {
            let Some((stem, suffix)) = env
                .strip_prefix("HUNTSMAN_")
                .and_then(|r| r.rsplit_once('_'))
            else {
                continue;
            };
            let Some(i) = module_for_stem(stem, &modules) else {
                continue;
            };
            key_envs.insert(
                env.to_ascii_lowercase(),
                (
                    i,
                    format!("HUNTSMAN_{}_{suffix}", crate::util::redact::REDACTED),
                ),
            );
            // The stem is a spelling too (`breachdir`), wherever else it shows.
            claim(&mut owner, stem, i);
            let Some(hint) = crate::util::keys::signup_hint(env) else {
                continue;
            };
            if let Some(brand) = hint_brand(hint) {
                claim(&mut owner, brand, i);
            }
            // A signup host is claimed only when its URL does not already
            // name the provider: `haveibeenpwned.com` must be added for hibp,
            // but BreachDirectory's hint is a RapidAPI marketplace URL that
            // carries the provider only in its PATH — claiming `rapidapi.com`
            // itself would hide every other API sold there. That URL is still
            // redacted whole, by pass 1, because it contains `breachdirectory`.
            for c in hint_url.captures_iter(hint) {
                let url = c[0].to_lowercase();
                let named = owner
                    .iter()
                    .any(|(s, &j)| j == i && contains_token(&url, s));
                if !named {
                    let host = c[1].to_lowercase();
                    claim(&mut owner, host.strip_prefix("www.").unwrap_or(&host), i);
                }
            }
        }
        // Longest-first, so a longer label (`oathnet-pro`) is matched whole
        // before a shorter label it contains (`oathnet`), independent of the
        // regex engine's alternation-ordering semantics.
        let mut ordered: Vec<&String> = owner.keys().collect();
        ordered.sort_by(|a, b| b.len().cmp(&a.len()).then_with(|| a.cmp(b)));
        let alt = ordered
            .iter()
            .map(|s| regex::escape(s))
            .collect::<Vec<_>>()
            .join("|");
        // Boundaries are "not a letter or digit" rather than `\b`: `\b` treats
        // `_` as a word character, so `HUNTSMAN_SEEKNOW_KEY` and `_DEHASHED_`
        // sailed through, while a longer alphanumeric token that merely
        // CONTAINS a name (a subject value) must still be left alone. The
        // boundary characters are consumed by the match, so the name itself is
        // group 1 and [`Redactor::replace_names`] steps by hand.
        //
        // Case-INSENSITIVE: module `name()`s are lowercase but evidence
        // summaries carry the capitalised brand ("OathNet: N matching breach
        // record(s)…", "SeekNow record from …"), which lands in the CSV
        // `evidence` column and `report.json`. The provider names are
        // distinctive, so `(?i)` carries no realistic over-match risk.
        let names = Regex::new(&format!(
            r"(?i)(?:^|[^\p{{L}}\p{{N}}])({alt})(?:[^\p{{L}}\p{{N}}]|$)"
        ))
        .ok()?;
        let env = if key_envs.is_empty() {
            None
        } else {
            let alt = key_envs
                .keys()
                .map(|e| regex::escape(e))
                .collect::<Vec<_>>()
                .join("|");
            Some(Regex::new(&format!(r"(?i)\b(?:{alt})\b")).ok()?)
        };
        let placeholder = owner
            .into_iter()
            .map(|(s, i)| (s, format!("[{REDACTED_LABEL}-{}]", i + 1)))
            .collect();
        Some(Self {
            url: Regex::new(URL_PATTERN).ok()?,
            env,
            key_envs,
            names,
            placeholder,
            modules,
        })
    }

    fn redact(&self, body: &str) -> String {
        // 1. Addresses first, whole — see the module doc.
        let body = self
            .url
            .replace_all(body, |c: &Captures| self.redact_address(&c[0]))
            .into_owned();
        // 2. Key env vars.
        let body = match &self.env {
            Some(re) => re
                .replace_all(&body, |c: &Captures| {
                    self.key_envs
                        .get(&c[0].to_ascii_lowercase())
                        .map_or_else(|| c[0].to_string(), |(_, rep)| rep.clone())
                })
                .into_owned(),
            None => body,
        };
        // 3. Every remaining spelling → its provider's placeholder.
        self.replace_names(&body)
    }

    /// One URL/hostname match: [`REDACTED_URL`] if it names a provider
    /// anywhere (host, path or query), otherwise untouched. Trailing sentence
    /// punctuation belongs to the prose, not the address, so it is kept.
    fn redact_address(&self, m: &str) -> String {
        let core = m.trim_end_matches(['.', ',', ';', ':', '!', '?']);
        if self.names.is_match(core) {
            format!("{REDACTED_URL}{}", &m[core.len()..])
        } else {
            m.to_string()
        }
    }

    /// Replace each group-1 match of [`Redactor::names`]. Stepped by hand
    /// (not `replace_all`) because the regex consumes the boundary character
    /// after a name: resuming at the name's END lets that same character open
    /// the next match, so `dehashed,intelx` redacts both.
    fn replace_names(&self, body: &str) -> String {
        let mut out = String::with_capacity(body.len());
        let mut last = 0;
        while let Some(m) = self.names.captures_at(body, last).and_then(|c| c.get(1)) {
            out.push_str(&body[last..m.start()]);
            out.push_str(
                self.placeholder
                    .get(&m.as_str().to_lowercase())
                    .map_or(GENERIC_PLACEHOLDER, String::as_str),
            );
            // A name is never empty, so this always advances.
            last = m.end();
        }
        out.push_str(&body[last..]);
        out
    }
}

/// Genericise every proprietary breach/intel provider identity in `body`,
/// leaving the finding itself intact: addresses naming a provider become
/// [`REDACTED_URL`], its key env vars `HUNTSMAN_[redacted]_KEY`, and every other
/// spelling that provider's `[breach-source-N]` placeholder. Whole-token
/// matching, so a coincidental substring is never redacted. Idempotent: no
/// replacement contains a sensitive spelling or an address.
#[must_use]
pub fn redact_sensitive_sources(body: &str) -> String {
    match &*REDACTOR {
        Some(r) => r.redact(body),
        None => body.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The placeholder a bare provider spelling redacts to.
    fn placeholder_of(spelling: &str) -> String {
        redact_sensitive_sources(spelling)
    }

    #[test]
    fn redacts_named_paid_provider_but_keeps_public_sources() {
        // `oathnet_pro` is the paid provider the operator named; it is
        // `People`-categorised, so it is covered via EXTRA_SENSITIVE_MODULES.
        assert!(!redact_sensitive_sources("source: oathnet_pro").contains("oathnet_pro"));
        assert!(redact_sensitive_sources("via oathnet_pro").contains(REDACTED_LABEL));
        // Public, non-secret sources are preserved — they are not tradecraft.
        let out = redact_sensitive_sources("source: whois\nsource: github_user\n");
        assert!(out.contains("whois") && out.contains("github_user"));
    }

    #[test]
    fn covers_every_spelling_of_the_named_providers() {
        // `breach_rich` stamps the HYPHENATED source label ("see-know" /
        // "oathnet-pro") and the stealer path stamps bare "oathnet" — distinct
        // from the underscore module name()s. Every spelling the operator named
        // must be redacted whole (not partially, leaving a recognisable stub).
        for tag in [
            "see_know",
            "see-know",
            "seeknow",
            "oathnet_pro",
            "oathnet-pro",
            "oathnet",
        ] {
            let out = redact_sensitive_sources(&format!(r#"{{"source":"{tag}"}}"#));
            assert!(
                !out.contains(tag),
                "source tag {tag:?} leaked through redaction: {out}"
            );
            assert!(out.contains(REDACTED_LABEL), "expected label for {tag:?}");
        }
    }

    #[test]
    fn every_breach_category_source_is_redacted() {
        // Drift guard: the sensitive set is registry-derived, so a NEW
        // breach-category module is hidden automatically. This asserts it.
        let breach: Vec<String> = crate::modules::registry()
            .iter()
            .filter(|m| m.category() == ModuleCategory::Breach)
            .map(|m| m.name().to_string())
            .collect();
        assert!(!breach.is_empty(), "expected some breach-category modules");
        for name in &breach {
            assert!(
                !redact_sensitive_sources(&format!("source: {name}")).contains(name.as_str()),
                "breach-category source {name} leaked through redaction"
            );
        }
    }

    #[test]
    fn whole_token_match_leaves_longer_tokens_intact() {
        // A longer alphanumeric token that merely CONTAINS a source name (no
        // letter/digit boundary) must survive untouched — only the bare
        // provider token is hit.
        let name = crate::modules::registry()
            .iter()
            .find(|m| m.category() == ModuleCategory::Breach)
            .map(|m| m.name().to_string())
            .expect("a breach-category module");
        let longer = format!("{name}xyz");
        assert!(
            redact_sensitive_sources(&format!("value={longer}")).contains(&longer),
            "a longer token containing a source name must not be partially redacted"
        );
    }

    #[test]
    fn redacts_capitalised_brand_in_evidence_summaries() {
        // The exact summary strings the providers write, which flow into the CSV
        // `evidence` column and report.json. A case-sensitive match would leak the
        // capitalised brand verbatim.
        for (summary, brand) in [
            (
                "OathNet: 3 matching breach record(s) of 12 — LinkedIn, Collection1",
                "OathNet",
            ),
            ("SeekNow record from MyFitnessPal", "SeekNow"),
            ("SeekNow email of jane@example.com", "SeekNow"),
            ("DeHashed record from Adobe", "DeHashed"),
        ] {
            let out = redact_sensitive_sources(summary);
            assert!(
                !out.contains(brand),
                "provider brand {brand:?} leaked in summary: {out}"
            );
            // The surrounding RESULT detail (the breach-corpus names) stays.
            assert!(
                out.contains("breach record")
                    || out.contains("record from")
                    || out.contains("email of")
            );
        }
        // The underlying breach-corpus names are result detail and must remain,
        // and so must a subject address at a non-provider domain.
        assert!(redact_sensitive_sources("OathNet: 1 record — LinkedIn").contains("LinkedIn"));
        assert!(
            redact_sensitive_sources("SeekNow email of jane@example.com")
                .contains("jane@example.com")
        );
    }

    #[test]
    fn idempotent() {
        for body in [
            "source: oathnet_pro",
            "needs API key HUNTSMAN_SEEKNOW_KEY — SeekNow (see-know.ru) — https://see-know.ru",
            "see https://intelx.io/signup and dehashed.com; DeHashed, IntelX",
        ] {
            let once = redact_sensitive_sources(body);
            assert_eq!(redact_sensitive_sources(&once), once, "{body}");
        }
    }

    #[test]
    fn every_breach_source_is_redacted_in_its_spaced_and_hyphenated_spellings_too() {
        // Evidence summaries carry the brand as prose ("HIBP Pwned Passwords:
        // …"), not the snake_case module name. Every multi-word breach source
        // must be hidden in all three spellings, case-insensitively.
        let multiword: Vec<String> = crate::modules::registry()
            .iter()
            .filter(|m| m.category() == ModuleCategory::Breach && m.name().contains('_'))
            .map(|m| m.name().to_string())
            .collect();
        assert!(
            !multiword.is_empty(),
            "expected at least one multi-word breach-category module"
        );
        for name in &multiword {
            for spelling in [name.replace('_', " "), name.replace('_', "-")] {
                // Title-case the words the way a summary would print them.
                let prose: String = spelling
                    .split(' ')
                    .map(|w| {
                        let mut c = w.chars();
                        c.next().map_or(String::new(), |f| {
                            f.to_uppercase().collect::<String>() + c.as_str()
                        })
                    })
                    .collect::<Vec<_>>()
                    .join(" ");
                let out =
                    redact_sensitive_sources(&format!("HIBP {prose}: value seen in 3 breach(es)"));
                assert!(
                    !out.to_lowercase().contains(&spelling.to_lowercase()),
                    "`{prose}` (from `{name}`) leaked through redaction: {out}"
                );
            }
        }
        // The concrete case that motivated this.
        let out = redact_sensitive_sources("HIBP Pwned Passwords: value seen in 3 breach(es)");
        assert!(!out.contains("Pwned Passwords"), "{out}");
    }

    /// The defect: `\b` matches at `.` and `/`, so swapping only the name inside
    /// an address wrote a plausible, never-observed domain into the customer's
    /// file — `https://see-know.ru` → `https://breach-source.ru`,
    /// `dehashed.com` → `breach-source.com`. Each real address from the
    /// exported log must now be replaced whole by the fixed marker.
    #[test]
    fn redaction_never_fabricates_a_domain() {
        let fabricated =
            Regex::new(r"(?i)breach-source[^\s]*\.[a-z]{2,}|\]\.[a-z]{2,}").expect("valid regex");
        for url in [
            "https://see-know.ru",
            "dehashed.com",
            "https://intelx.io/signup",
            "niamonx.io",
            "https://oathnet.org",
            "https://rapidapi.com/rohan-patra/api/breachdirectory",
        ] {
            let body = format!(r#"{{"reason":"key at {url} — see {url}."}}"#);
            let out = redact_sensitive_sources(&body);
            assert_eq!(
                out,
                format!(r#"{{"reason":"key at {REDACTED_URL} — see {REDACTED_URL}."}}"#),
                "{url} must be replaced whole, with the prose around it intact"
            );
            assert!(
                !fabricated.is_match(&out),
                "{url} → fabricated domain: {out}"
            );
        }
        // An address that names no provider is left exactly as it was.
        let benign = "https://example.com/a?b=1 and mail.example.org";
        assert_eq!(redact_sensitive_sources(benign), benign);
        // The address is replaced whole but never past a CSV delimiter: an
        // unquoted comma after it survives, so the row keeps its columns.
        let row = redact_sensitive_sources("x,https://dehashed.com/search,DeHashed record");
        assert_eq!(row.matches(',').count(), 2, "{row}");
        assert!(row.starts_with(&format!("x,{REDACTED_URL},[")), "{row}");
    }

    #[test]
    fn redaction_covers_env_var_key_names() {
        // `\b` treats `_` as a word character, so every key env var name —
        // printed in each "needs API key …" skip reason — passed through.
        for env in [
            "HUNTSMAN_SEEKNOW_KEY",
            "HUNTSMAN_OATHNET_KEY",
            "HUNTSMAN_DEHASHED_KEY",
            "HUNTSMAN_INTELX_KEY",
            "HUNTSMAN_NIAMONX_KEY",
            "HUNTSMAN_STOLEN_TAX_KEY",
            "HUNTSMAN_BREACHDIR_KEY",
        ] {
            assert_eq!(
                redact_sensitive_sources(&format!("export {env}=x")),
                "export HUNTSMAN_[redacted]_KEY=x",
                "{env}"
            );
        }
        // A provider name inside any other identifier is caught too, and no
        // part of it survives.
        let out = redact_sensitive_sources("HUNTSMAN_SEEKNOW_SCAN_CAP=750 HSE_X_DEHASHED_Y");
        assert!(
            !out.to_lowercase().contains("seeknow") && !out.to_lowercase().contains("dehashed"),
            "{out}"
        );
        // A non-sensitive provider's key is not tradecraft and stays named.
        assert_eq!(
            redact_sensitive_sources("HUNTSMAN_SHODAN_KEY"),
            "HUNTSMAN_SHODAN_KEY"
        );
    }

    #[test]
    fn distinct_providers_keep_distinct_placeholders() {
        // One label for every provider made per-module start/done accounting
        // in the log unreadable. Each provider now keeps its own placeholder,
        // shared by all of its spellings and stable within and across bodies.
        let see_know = placeholder_of("see_know");
        for spelling in ["see-know", "SeekNow", "Seek-Know", "seek know", "SEE_KNOW"] {
            assert_eq!(placeholder_of(spelling), see_know, "{spelling}");
        }
        let oathnet = placeholder_of("oathnet_pro");
        for spelling in ["oathnet", "OathNet", "oathnet-pro"] {
            assert_eq!(placeholder_of(spelling), oathnet, "{spelling}");
        }
        let dehashed = placeholder_of("dehashed");
        assert_eq!(placeholder_of("DeHashed"), dehashed);
        assert_ne!(see_know, dehashed);
        assert_ne!(see_know, oathnet);
        assert_ne!(dehashed, oathnet);
        // Clearly synthetic, and never a name.
        let shape = Regex::new(r"^\[breach-source-[0-9]+\]$").expect("valid regex");
        for p in [&see_know, &oathnet, &dehashed] {
            assert!(shape.is_match(p), "{p}");
        }
        // Within one body — the events.log case — each keeps its own.
        let out = redact_sensitive_sources(
            r#"{"kind":"module_start","module":"see_know"}
{"kind":"module_start","module":"dehashed"}
{"kind":"module_done","module":"see-know","found":2}"#,
        );
        assert_eq!(out.matches(see_know.as_str()).count(), 2, "{out}");
        assert_eq!(out.matches(dehashed.as_str()).count(), 1, "{out}");
        // Every sensitive module has its own placeholder — no two collide.
        let r = REDACTOR.as_ref().expect("redactor built");
        let all: BTreeSet<String> = r
            .modules
            .iter()
            .map(|m| placeholder_of(m.as_str()))
            .collect();
        assert_eq!(all.len(), r.modules.len(), "{all:?}");
    }

    /// Drift guard for the signup hints: every sensitive provider's key env,
    /// display brand and signup domain — the three things the engine's
    /// "needs API key {env} — {signup_hint}" skip reason prints — must be gone
    /// from a redacted reason. The explicit table pins the providers seen in
    /// real exports (and fails if a hint is reworded out from under it); the
    /// loop covers every key the redactor maps to a sensitive module.
    #[test]
    fn every_sensitive_signup_hint_brand_and_domain_is_redacted() {
        let reason_for = |env: &str| {
            let hint = crate::util::keys::signup_hint(env)
                .unwrap_or_else(|| panic!("{env} has a signup hint"));
            (hint, format!("needs API key {env} — {hint}"))
        };
        for (env, brand, domain) in [
            ("HUNTSMAN_SEEKNOW_KEY", "SeekNow", "see-know.ru"),
            ("HUNTSMAN_OATHNET_KEY", "OathNet", "oathnet.org"),
            ("HUNTSMAN_DEHASHED_KEY", "DeHashed", "dehashed.com"),
            ("HUNTSMAN_INTELX_KEY", "Intelligence X", "intelx.io"),
            ("HUNTSMAN_NIAMONX_KEY", "NiamonX", "niamonx.io"),
            (
                "HUNTSMAN_BREACHDIR_KEY",
                "BreachDirectory",
                "rohan-patra/api/breachdirectory",
            ),
            ("HUNTSMAN_STOLEN_TAX_KEY", "Stolen.tax", "stolen.tax"),
            (
                "HUNTSMAN_HIBP_KEY",
                "Have I Been Pwned",
                "haveibeenpwned.com",
            ),
        ] {
            let (hint, reason) = reason_for(env);
            assert!(
                hint.contains(brand) && hint.contains(domain),
                "{env}'s hint no longer names {brand:?}/{domain:?} — update this table: {hint}"
            );
            let out = redact_sensitive_sources(&reason).to_lowercase();
            for leaked in [env, brand, domain] {
                assert!(
                    !out.contains(&leaked.to_lowercase()),
                    "{leaked:?} survived redaction of {env}'s skip reason: {out}"
                );
            }
            assert!(out.contains("huntsman_[redacted]_key"), "{out}");
        }

        let r = REDACTOR.as_ref().expect("redactor built");
        let url = Regex::new(r"https?://([A-Za-z0-9.-]+)").expect("valid regex");
        for (env, (i, _)) in &r.key_envs {
            let env = env.to_ascii_uppercase();
            let Some(hint) = crate::util::keys::signup_hint(&env) else {
                continue;
            };
            let out =
                redact_sensitive_sources(&format!("needs API key {env} — {hint}")).to_lowercase();
            let brand = hint.split(" — ").next().unwrap_or_default();
            let brand = brand.split(" (").next().unwrap_or_default().to_lowercase();
            assert!(
                !out.contains(&brand) && !out.contains(&env.to_lowercase()),
                "{env} ({}) leaked its brand/env: {out}",
                r.modules[*i]
            );
            for c in url.captures_iter(hint) {
                let host = c[1].to_lowercase();
                assert!(
                    !out.contains(&host),
                    "{env} leaked its signup host {host}: {out}"
                );
            }
        }
    }

    /// Drift guard for the key-env derivation: every sensitive module that
    /// needs a key must have that key's env var recognised, or its "needs API
    /// key" skip reason would name it (and its hint's brand and host) in every
    /// shareable log. A new keyed breach module whose env stem does not match
    /// its name fails here.
    #[test]
    fn every_keyed_sensitive_module_has_its_key_env_redacted() {
        use crate::core::module::ModuleCost;
        let r = REDACTOR.as_ref().expect("redactor built");
        let registry = crate::modules::registry();
        for (i, name) in r.modules.iter().enumerate() {
            let Some(m) = registry.iter().find(|m| m.name() == name.as_str()) else {
                continue;
            };
            if matches!(m.cost(), ModuleCost::Free) {
                continue;
            }
            assert!(
                r.key_envs.values().any(|(j, _)| *j == i),
                "keyed sensitive module {name} has no key env mapped to it"
            );
        }
    }
}
