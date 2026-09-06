//! The providers `hse batch` renders for, and how each one wants a list.
//!
//! Every entry is grounded in the provider's own documentation, read at the
//! URL in `evidence`; a provider whose search contract could not be verified
//! is not listed (RULE 1: no assumed contracts). Most high-yield breach and
//! stealer-log sites take ONE value per search and auto-detect what it is, so
//! their list is the values themselves, one per line; DeHashed is the one that
//! wants an explicit `field:value`, so it gets a [`LineSyntax::Prefixed`] map.
//!
//! `accepts` is intentionally conservative — only the selector kinds the
//! provider's own docs say it indexes. Kinds outside that set are skipped for
//! that provider rather than pasted into a box that would reject them.

use super::SelectorKind;

/// How one query line is spelled for a provider.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LineSyntax {
    /// The bare value — the provider's search box auto-detects the kind, or the
    /// operator picks the kind from a selector/dropdown next to a plain box.
    Bare,
    /// `field:value`, with the provider's field name for each selector kind. A
    /// value containing whitespace is wrapped in double quotes (e.g. DeHashed's
    /// documented `name:"John Smith"`).
    Prefixed(&'static [(SelectorKind, &'static str)]),
}

/// One provider's search contract.
#[derive(Debug, Clone, Copy)]
pub struct Site {
    /// Stable id used on the command line and in the API (`--site`).
    pub id: &'static str,
    /// The provider's own spelling of its name.
    pub name: &'static str,
    /// Where to paste: the search or bulk page.
    pub url: &'static str,
    /// One sentence telling the operator how the list is consumed there.
    pub how: &'static str,
    /// Selector kinds the provider indexes; other kinds are skipped for it.
    pub accepts: &'static [SelectorKind],
    /// How each line is spelled.
    pub syntax: LineSyntax,
    /// The provider page the contract was read from.
    pub evidence: &'static str,
}

use SelectorKind::{Domain, Email, Ip, Name, Phone, Username};

/// DeHashed's field names, from its "How to Search Properly" article.
const DEHASHED_FIELDS: &[(SelectorKind, &str)] = &[
    (Email, "email"),
    (Username, "username"),
    (Phone, "phone"),
    (Domain, "domain"),
    (Ip, "ip_address"),
    (Name, "name"),
];

/// The registry, in the order sections are printed: the sites the request
/// named first, then the other high-yield services.
pub static SITES: &[Site] = &[
    Site {
        id: "oathnet",
        name: "OathNet",
        url: "https://oathnet.org/",
        how: "One value per search in the search box (auto-detected: email, username, domain, \
              IP). With an API key the same lines are the `terms` array of one bulk breach or \
              stealer job.",
        accepts: &[Email, Username, Domain, Ip],
        syntax: LineSyntax::Bare,
        evidence: "https://docs.oathnet.org/introduction/quickstart",
    },
    Site {
        id: "seeknow",
        name: "SeekNow",
        url: "https://see-know.ru/",
        how: "One value per search in the universal search box (auto-detected, or pick the \
              type); no multi-line input is documented, so paste one line at a time.",
        accepts: &[Email, Username, Phone, Domain, Ip, Name],
        syntax: LineSyntax::Bare,
        evidence: "https://see-know.ru/",
    },
    Site {
        id: "stolen-tax",
        name: "Stolen (stolen.tax)",
        url: "https://stolen.tax/",
        how: "One value per search in the dashboard — Combined Search auto-detects across the \
              modules; open a single module to force a selector type. Bulk input is API-only \
              (v2 endpoints, bearer token).",
        accepts: &[Email, Username, Phone, Domain, Ip, Name],
        syntax: LineSyntax::Bare,
        evidence: "https://stolen.tax/docs/",
    },
    Site {
        id: "dehashed",
        name: "DeHashed",
        url: "https://dehashed.com/search",
        how: "One `field:value` per search; the search box also auto-detects a bare value \
              across all fields. Names with spaces are quoted (name:\"John Smith\").",
        accepts: &[Email, Username, Phone, Domain, Ip, Name],
        syntax: LineSyntax::Prefixed(DEHASHED_FIELDS),
        evidence: "https://support.dehashed.com/hc/en-us/articles/360000867094-How-to-Search-Properly",
    },
    Site {
        id: "leakcheck",
        name: "LeakCheck",
        url: "https://leakcheck.io/",
        how: "Paste into BulkCheck: one value per line, up to 100,000 lines; each line's type \
              is auto-detected (email, username, phone). Domain and keyword need the API's \
              explicit type.",
        accepts: &[Email, Username, Phone],
        syntax: LineSyntax::Bare,
        evidence: "https://leakcheck.io/faq-questions",
    },
    Site {
        id: "snusbase",
        name: "Snusbase",
        url: "https://snusbase.com/search",
        how: "One value per search in the search box; pick the type (email, username, IP, \
              name, domain). With an API key the same lines are the `terms` array of one \
              /data/search POST.",
        accepts: &[Email, Username, Ip, Name, Domain],
        syntax: LineSyntax::Bare,
        evidence: "https://docs.snusbase.com/",
    },
    Site {
        id: "intelx",
        name: "Intelligence X",
        url: "https://intelx.io/",
        how: "One selector per search in the search box (email, domain, IP, or phone) — \
              full-text terms like a person's name are rejected. Phone numbers need an \
              international code.",
        accepts: &[Email, Domain, Ip, Phone],
        syntax: LineSyntax::Bare,
        evidence: "https://help.intelx.io/docs/get-started/selector/",
    },
    Site {
        id: "leak-lookup",
        name: "Leak-Lookup",
        url: "https://leak-lookup.com/",
        how: "One value per search in the Search panel; tick the field(s) to search by (email, \
              username, IP, phone, domain). With an API key it is `type` + `query` per request.",
        accepts: &[Email, Username, Ip, Phone, Domain],
        syntax: LineSyntax::Bare,
        evidence: "https://leak-lookup.com/docs/search",
    },
    Site {
        id: "hibp",
        name: "Have I Been Pwned",
        url: "https://haveibeenpwned.com/",
        how: "One email per search on the front page; there is no bulk option, so paste one \
              at a time. Domain search needs verified domain ownership.",
        accepts: &[Email],
        syntax: LineSyntax::Bare,
        evidence: "https://support.haveibeenpwned.com/hc/en-au/articles/15599376840207-Is-there-a-way-to-query-email-addresses-in-bulk",
    },
    Site {
        id: "hackcheck",
        name: "HackCheck",
        url: "https://hackcheck.io/",
        how: "One value per search in the search box (pick the field); the free web tier \
              returns breach counts and data-source references. The REST API and full records \
              are paid and IP-allowlisted, so paste one line at a time by hand.",
        accepts: &[Email, Username, Domain, Ip, Phone, Name],
        syntax: LineSyntax::Bare,
        evidence: "https://github.com/hackcheckio/hackcheck-ts",
    },
    Site {
        id: "leakpeek",
        name: "LeakPeek",
        url: "https://leakpeek.com/",
        how: "One value per search; pick the type. Registration is required and full results \
              sit behind a paid tier, so paste one line at a time.",
        accepts: &[Email, Username, Domain, Ip, Name, Phone],
        syntax: LineSyntax::Bare,
        evidence: "https://leakpeek.com/",
    },
    Site {
        id: "osintleak",
        name: "OSINTLeak",
        url: "https://osintleak.com/",
        how: "One value per search in the Community web UI (free 20 searches/day, account \
              required; the API is a paid tier). Paste one line at a time.",
        accepts: &[Email, Username, Phone],
        syntax: LineSyntax::Bare,
        evidence: "https://docs.osintleak.com/api/search",
    },
    Site {
        id: "pentester",
        name: "Pentester.com Data Breach Check",
        url: "https://pentester.com/checker/",
        how: "One email in the free, no-registration form; it checks ~16B infostealer records \
              and returns which breaches and which categories of data were exposed. Paste one \
              at a time (the keyed api.pentester.com API is paid and blocks automation).",
        accepts: &[Email],
        syntax: LineSyntax::Bare,
        evidence: "https://pentester.com/checker/",
    },
];

/// Look a provider up by its `--site` id (case-insensitive).
#[must_use]
pub fn find(id: &str) -> Option<&'static Site> {
    SITES.iter().find(|s| s.id.eq_ignore_ascii_case(id.trim()))
}

/// Every registered id, for help text and error messages.
#[must_use]
pub fn ids() -> Vec<&'static str> {
    SITES.iter().map(|s| s.id).collect()
}
