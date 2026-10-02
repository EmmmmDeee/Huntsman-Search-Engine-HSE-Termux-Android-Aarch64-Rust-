//! The providers `hse batch` renders for, and how each one wants a list.
//!
//! Every entry is grounded in the provider's own documentation, read at the
//! URL in `evidence`; a provider whose search contract could not be verified
//! is not listed (RULE 1: no assumed contracts). Most high-yield breach and
//! stealer-log sites take ONE value per search and auto-detect what it is, so
//! their list is the values themselves, one per line; DeHashed is the one that
//! wants an explicit `field:value`, so it gets a [`LineSyntax::Prefixed`] map.
//!
//! Providers carry a [`SiteClass`]: the default **breach** and stealer-log
//! sites, and the **genealogy** / vital-records / archive sites whose terms or
//! robots rules bar automation — HSE never fetches those, it only writes the
//! name query for the operator to paste. `hse batch --class` and the API
//! `?class=` select between them; [`resolve`] is the one authority both use.
//!
//! `accepts` is intentionally conservative — only the selector kinds the
//! provider's own docs say it indexes. Kinds outside that set are skipped for
//! that provider rather than pasted into a box that would reject them.

use super::SelectorKind;

/// Which family a provider belongs to, so `hse batch --class` (and the API
/// `?class=`) can render one family without the other.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SiteClass {
    /// A breach or stealer-log lookup site — the default class.
    Breach,
    /// A genealogy, vital-records or archive site whose terms or robots rules
    /// bar automation: HSE never fetches it, it only writes the name query for
    /// the operator to paste by hand.
    Genealogy,
}

impl SiteClass {
    /// The lower-case class name used on the command line, in the API
    /// `?class=` parameter and in JSON output.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Breach => "breach",
            Self::Genealogy => "genealogy",
        }
    }
}

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
    /// Which family the provider belongs to (breach by default, or genealogy).
    pub class: SiteClass,
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
        class: SiteClass::Breach,
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
        class: SiteClass::Breach,
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
        class: SiteClass::Breach,
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
        class: SiteClass::Breach,
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
        class: SiteClass::Breach,
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
        class: SiteClass::Breach,
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
        class: SiteClass::Breach,
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
        class: SiteClass::Breach,
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
        class: SiteClass::Breach,
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
        class: SiteClass::Breach,
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
        class: SiteClass::Breach,
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
        class: SiteClass::Breach,
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
        class: SiteClass::Breach,
    },
    // ── Genealogy / vital records / archives: manual contracts ──────────────
    // Each of these sites either forbids automated access in its terms or
    // robots rules, or answers automation with a bot-block, so HSE does not
    // fetch them; it writes the name query for the operator to paste. URLs
    // and, where the page was readable, form fields were live-verified on
    // 2026-09-06; a site whose search page answered HTTP 403 to automation
    // exists (a wrong path answers 404) but its form was not read, so its
    // contract names no fields. The automated genealogy sources are modules:
    // `wikitree`, `openarch`, `chronicling_america`, `europeana`.
    Site {
        id: "ancestry",
        name: "Ancestry",
        url: "https://www.ancestry.com/search/",
        how: "One name per search in the people search; the site's terms bar automated \
              access and it blocks automated requests — paste by hand.",
        accepts: &[Name],
        syntax: LineSyntax::Bare,
        evidence: "https://www.ancestry.com/search/",
        class: SiteClass::Genealogy,
    },
    Site {
        id: "familysearch",
        name: "FamilySearch",
        url: "https://www.familysearch.org/en/search/record/results",
        how: "First name and last name of the historical-records search (`q.givenName`, \
              `q.surname`); a free account is needed to view records and the site's robots \
              rules bar automated record access — paste by hand.",
        accepts: &[Name],
        syntax: LineSyntax::Bare,
        evidence: "https://www.familysearch.org/en/search/record/results",
        class: SiteClass::Genealogy,
    },
    Site {
        id: "myheritage",
        name: "MyHeritage",
        url: "https://www.myheritage.com/research",
        how: "One name per search in the research search; the site's terms bar automated \
              access — paste by hand.",
        accepts: &[Name],
        syntax: LineSyntax::Bare,
        evidence: "https://www.myheritage.com/research",
        class: SiteClass::Genealogy,
    },
    Site {
        id: "findagrave",
        name: "Find a Grave",
        url: "https://www.findagrave.com/memorial/search",
        how: "One name per search in the memorial search; the site blocks automated \
              requests — paste by hand.",
        accepts: &[Name],
        syntax: LineSyntax::Bare,
        evidence: "https://www.findagrave.com/memorial/search",
        class: SiteClass::Genealogy,
    },
    Site {
        id: "geneanet",
        name: "Geneanet",
        url: "https://en.geneanet.org/fonds/individus/",
        how: "One name per search in the individuals search; the site blocks automated \
              requests — paste by hand.",
        accepts: &[Name],
        syntax: LineSyntax::Bare,
        evidence: "https://en.geneanet.org/fonds/individus/",
        class: SiteClass::Genealogy,
    },
    Site {
        id: "ryerson",
        name: "Ryerson Index",
        url: "https://ryersonindex.org/search.php",
        how: "Surname (`search_sn`) and given name (`search_gn`) fields of the notice \
              search — Australian death and funeral notices; the site's robots rules \
              disallow automated searching — paste by hand.",
        accepts: &[Name],
        syntax: LineSyntax::Bare,
        evidence: "https://ryersonindex.org/search.php",
        class: SiteClass::Genealogy,
    },
    Site {
        id: "austcemindex",
        name: "Australian Cemeteries Index",
        url: "https://austcemindex.com/",
        how: "Family name (`family_name`) and given names (`given_names`) fields of the \
              name search; the site's bot protection blocks automated requests — paste \
              by hand.",
        accepts: &[Name],
        syntax: LineSyntax::Bare,
        evidence: "https://austcemindex.com/",
        class: SiteClass::Genealogy,
    },
    Site {
        id: "nsw-bdm",
        name: "NSW Births, Deaths & Marriages (family history)",
        url: "https://familyhistory.bdm.nsw.gov.au/lifelink/familyhistory/search",
        how: "One name per search in the family history search; the site blocks \
              automated requests — paste by hand.",
        accepts: &[Name],
        syntax: LineSyntax::Bare,
        evidence: "https://familyhistory.bdm.nsw.gov.au/lifelink/familyhistory/search",
        class: SiteClass::Genealogy,
    },
    Site {
        id: "vic-bdm",
        name: "Victoria Births, Deaths & Marriages (eFamily History)",
        url: "https://my.rio.bdm.vic.gov.au/efamily-history/",
        how: "One name per search in the eFamily History search (a browser app; nothing \
              to fetch server-side) — paste by hand.",
        accepts: &[Name],
        syntax: LineSyntax::Bare,
        evidence: "https://my.rio.bdm.vic.gov.au/efamily-history/",
        class: SiteClass::Genealogy,
    },
    Site {
        id: "qld-bdm",
        name: "Queensland Births, Deaths & Marriages (family history)",
        url: "https://www.familyhistory.bdm.qld.gov.au/",
        how: "Family name and given names fields of the family history search \
              (`exactTermsFamilynameOnly`, `exactTermsGivennamesOnly`; a browser app) — \
              paste by hand.",
        accepts: &[Name],
        syntax: LineSyntax::Bare,
        evidence: "https://www.familyhistory.bdm.qld.gov.au/",
        class: SiteClass::Genealogy,
    },
    Site {
        id: "naa-recordsearch",
        name: "National Archives of Australia — RecordSearch",
        url: "https://recordsearch.naa.gov.au/",
        how: "One name per NameSearch (service, immigration and naturalisation records); \
              the site blocks automated requests — paste by hand.",
        accepts: &[Name],
        syntax: LineSyntax::Bare,
        evidence: "https://recordsearch.naa.gov.au/",
        class: SiteClass::Genealogy,
    },
    Site {
        id: "awm-people",
        name: "Australian War Memorial — people",
        url: "https://www.awm.gov.au/advanced-search/people",
        how: "One name per search in the people search (Roll of Honour, embarkation and \
              honours rolls); the site's robots rules disallow automated searching — \
              paste by hand.",
        accepts: &[Name],
        syntax: LineSyntax::Bare,
        evidence: "https://www.awm.gov.au/advanced-search/people",
        class: SiteClass::Genealogy,
    },
    Site {
        id: "cwgc",
        name: "Commonwealth War Graves Commission — Find War Dead",
        url: "https://www.cwgc.org/find-records/find-war-dead/",
        how: "One name per search in Find War Dead; the site blocks automated requests — \
              paste by hand.",
        accepts: &[Name],
        syntax: LineSyntax::Bare,
        evidence: "https://www.cwgc.org/find-records/find-war-dead/",
        class: SiteClass::Genealogy,
    },
    Site {
        id: "tna-discovery",
        name: "The National Archives (UK) — Discovery",
        url: "https://discovery.nationalarchives.gov.uk/",
        how: "One name per search in the Discovery search box (`_q`) — wills, service \
              records and catalogue entries; the site's search API answered nothing to \
              HSE's automated checks — paste by hand.",
        accepts: &[Name],
        syntax: LineSyntax::Bare,
        evidence: "https://discovery.nationalarchives.gov.uk/",
        class: SiteClass::Genealogy,
    },
    Site {
        id: "freebmd",
        name: "FreeBMD",
        url: "https://www.freebmd.org.uk/cgi/search.pl",
        how: "Surname and given name fields of the search form (England & Wales civil \
              registration index); the site's robots rules disallow automated searching \
              — paste by hand.",
        accepts: &[Name],
        syntax: LineSyntax::Bare,
        evidence: "https://www.freebmd.org.uk/cgi/search.pl",
        class: SiteClass::Genealogy,
    },
    Site {
        id: "freecen",
        name: "FreeCEN",
        url: "https://www.freecen.org.uk/search_queries/new",
        how: "First name and last name fields of the census search query \
              (`search_query[first_name]`, `search_query[last_name]`) — paste by hand.",
        accepts: &[Name],
        syntax: LineSyntax::Bare,
        evidence: "https://www.freecen.org.uk/search_queries/new",
        class: SiteClass::Genealogy,
    },
    Site {
        id: "freereg",
        name: "FreeREG",
        url: "https://www.freereg.org.uk/search_queries/new",
        how: "First name and last name fields of the parish-register search query \
              (`search_query[first_name]`, `search_query[last_name]`) — paste by hand.",
        accepts: &[Name],
        syntax: LineSyntax::Bare,
        evidence: "https://www.freereg.org.uk/search_queries/new",
        class: SiteClass::Genealogy,
    },
    Site {
        id: "irish-genealogy",
        name: "Irish Genealogy — civil records",
        url: "https://civilrecords.irishgenealogy.ie/churchrecords/civil-search.jsp",
        how: "One name per search in the civil records search; the site blocks automated \
              requests — paste by hand.",
        accepts: &[Name],
        syntax: LineSyntax::Bare,
        evidence: "https://civilrecords.irishgenealogy.ie/churchrecords/civil-search.jsp",
        class: SiteClass::Genealogy,
    },
    Site {
        id: "nz-bdm",
        name: "New Zealand Births, Deaths & Marriages — historical records",
        url: "https://www.bdmhistoricalrecords.dia.govt.nz/",
        how: "One name per search in the historical records search — paste by hand.",
        accepts: &[Name],
        syntax: LineSyntax::Bare,
        evidence: "https://www.bdmhistoricalrecords.dia.govt.nz/",
        class: SiteClass::Genealogy,
    },
    Site {
        id: "paperspast",
        name: "Papers Past (National Library of New Zealand)",
        url: "https://paperspast.natlib.govt.nz/newspapers",
        how: "One name per search in the newspapers search box (`query`); the site's bot \
              protection blocks automated requests — paste by hand.",
        accepts: &[Name],
        syntax: LineSyntax::Bare,
        evidence: "https://paperspast.natlib.govt.nz/newspapers",
        class: SiteClass::Genealogy,
    },
    Site {
        id: "legacy",
        name: "Legacy.com obituaries",
        url: "https://www.legacy.com/obituaries/search",
        how: "One name per search in the obituary search; the site blocks automated \
              requests — paste by hand.",
        accepts: &[Name],
        syntax: LineSyntax::Bare,
        evidence: "https://www.legacy.com/obituaries/search",
        class: SiteClass::Genealogy,
    },
    Site {
        id: "geni",
        name: "Geni",
        url: "https://www.geni.com/search",
        how: "One name per search in the people search; the API requires an authorised \
              app — paste by hand.",
        accepts: &[Name],
        syntax: LineSyntax::Bare,
        evidence: "https://www.geni.com/search",
        class: SiteClass::Genealogy,
    },
    Site {
        id: "gedbas",
        name: "GEDBAS (genealogy.net)",
        url: "https://gedbas.genealogy.net/search/simple",
        how: "One name per search in the simple search; the site's bot check blocks \
              automated requests — paste by hand.",
        accepts: &[Name],
        syntax: LineSyntax::Bare,
        evidence: "https://gedbas.genealogy.net/search/simple",
        class: SiteClass::Genealogy,
    },
    Site {
        id: "nara-catalog",
        name: "US National Archives catalog",
        url: "https://catalog.archives.gov/",
        how: "One name per search in the catalog search box; the API needs an issued key \
              and the site's robots rules disallow automation — paste by hand.",
        accepts: &[Name],
        syntax: LineSyntax::Bare,
        evidence: "https://catalog.archives.gov/",
        class: SiteClass::Genealogy,
    },
    Site {
        id: "forebears",
        name: "Forebears surnames",
        url: "https://forebears.io/surnames",
        how: "One surname per search in the surnames search box (`q`) — origin and \
              distribution, not individuals; the site's robots rules disallow automated \
              surname pages — paste the surname by hand.",
        accepts: &[Name],
        syntax: LineSyntax::Bare,
        evidence: "https://forebears.io/surnames",
        class: SiteClass::Genealogy,
    },
    Site {
        id: "obituaries-australia",
        name: "Obituaries Australia (ANU)",
        url: "https://oa.anu.edu.au/obituaries/search/",
        how: "One name per search in the search box (`query`); the site answered HSE's \
              automated queries with HTTP 400 — paste by hand.",
        accepts: &[Name],
        syntax: LineSyntax::Bare,
        evidence: "https://oa.anu.edu.au/obituaries/search/",
        class: SiteClass::Genealogy,
    },
    Site {
        id: "adb",
        name: "Australian Dictionary of Biography (ANU)",
        url: "https://adb.anu.edu.au/biographies/search/",
        how: "One name per search in the search box (`query`); the site answered HSE's \
              automated queries with HTTP 400 — paste by hand.",
        accepts: &[Name],
        syntax: LineSyntax::Bare,
        evidence: "https://adb.anu.edu.au/biographies/search/",
        class: SiteClass::Genealogy,
    },
    Site {
        id: "scotlandspeople",
        name: "ScotlandsPeople",
        url: "https://www.scotlandspeople.gov.uk/",
        how: "Surname and forename fields of the people search (registration required) — \
              paste by hand.",
        accepts: &[Name],
        syntax: LineSyntax::Bare,
        evidence: "https://www.scotlandspeople.gov.uk/",
        class: SiteClass::Genealogy,
    },
    Site {
        id: "deceased-online",
        name: "Deceased Online",
        url: "https://www.deceasedonline.com/",
        how: "One name per search in the burial and cremation search (registration \
              required) — paste by hand.",
        accepts: &[Name],
        syntax: LineSyntax::Bare,
        evidence: "https://www.deceasedonline.com/",
        class: SiteClass::Genealogy,
    },
    Site {
        id: "rootsweb-worldconnect",
        name: "RootsWeb WorldConnect",
        url: "https://wc.rootsweb.com/",
        how: "One name per search in the WorldConnect tree search; the site blocks \
              automated requests — paste by hand.",
        accepts: &[Name],
        syntax: LineSyntax::Bare,
        evidence: "https://wc.rootsweb.com/",
        class: SiteClass::Genealogy,
    },
    Site {
        id: "familytreenow",
        name: "FamilyTreeNow",
        url: "https://www.familytreenow.com/",
        how: "One name per search in the people search; the site blocks automated \
              requests — paste by hand.",
        accepts: &[Name],
        syntax: LineSyntax::Bare,
        evidence: "https://www.familytreenow.com/",
        class: SiteClass::Genealogy,
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

/// The providers `hse batch` and the API `batch.txt` render, from an explicit
/// `--site` selection and a `--class` filter — the one authority both surfaces
/// share so their selection can never drift.
///
/// When `site` names providers (each element may be a comma list) exactly those
/// are returned, de-duplicated by id, in the order named, whatever their class;
/// an unknown id is an `Err` naming it and listing the known ids. When `site`
/// names none, the `class` filter selects: `breach` (the default; an empty or
/// whitespace value means breach), `genealogy`, or `all` — an unknown class is
/// an `Err` listing the three. The `Err` string is ready to show the operator.
///
/// # Errors
/// Returns the operator-facing message when a `--site` id or a `--class` value
/// is not recognised.
pub fn resolve(site: &[&str], class: &str) -> Result<Vec<&'static Site>, String> {
    let wanted: Vec<&str> = site
        .iter()
        .flat_map(|s| s.split(','))
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .collect();
    // An explicit --site wins over --class: the operator gets exactly what they
    // named, whatever family it is in.
    if !wanted.is_empty() {
        let mut chosen: Vec<&'static Site> = Vec::new();
        let mut unknown: Vec<String> = Vec::new();
        for w in wanted {
            match find(w) {
                Some(s) if !chosen.iter().any(|c| c.id == s.id) => chosen.push(s),
                Some(_) => {}
                None => unknown.push(w.to_string()),
            }
        }
        if !unknown.is_empty() {
            // Name the concept, not a surface's spelling: the CLI prefixes
            // `batch:` and the API returns this to a `?site=` caller, so a bare
            // "site" reads correctly for both rather than leaking `--site`.
            return Err(format!(
                "unknown site {} — known providers: {}",
                unknown.join(", "),
                ids().join(", ")
            ));
        }
        return Ok(chosen);
    }
    // No site named: the class filter decides. An omitted / empty value is
    // breach, matching the CLI default and preserving the pre-class behaviour.
    // Matched case-insensitively, like `--site` id lookup (`find`) and the
    // `--format` value, so `Genealogy` / `ALL` are not surprising errors.
    let want = match class.trim().to_ascii_lowercase().as_str() {
        "" | "breach" => Some(SiteClass::Breach),
        "genealogy" => Some(SiteClass::Genealogy),
        "all" => None,
        _ => {
            return Err(format!(
                "unknown class {:?} — expected breach, genealogy or all",
                class.trim()
            ));
        }
    };
    Ok(SITES
        .iter()
        .filter(|s| want.is_none_or(|c| s.class == c))
        .collect())
}
