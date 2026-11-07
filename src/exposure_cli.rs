//! End-to-end front-end for `huntsman-recon exposure`.
//!
//! The address is canonicalised once, then the account-keyed legs of
//! [`breach_hybrid::exposure_order`] run at once, each on a thread of its own, and their answers
//! fold in that order: HIBP `breachedaccount`, then the stolen.tax cascade, then `OathNet` breach
//! search, then `DeHashed` exact-match search (addresses only). A lookup waits for its slowest leg,
//! not for every leg in turn, and its report is the one the legs gave when they ran in turn.
//! The keyless legs (Pwned Passwords, the HIBP
//! catalogue) are not keyed on an address and are not run here. Each HIBP breach
//! becomes evidence on the seed email entity, tagged `breach` or `stealer-log`;
//! stolen.tax entities are taken as that module builds them. Each `OathNet` breach
//! database becomes evidence on the seed email entity carrying its exposure metadata
//! (dataset, record count, exposed field types, dates) and every non-credential value
//! its records hold, a field whose name holds one of [`oathnet::CREDENTIAL_MARKERS`]
//! (an [`oathnet::NOT_A_CREDENTIAL`] aside), or a list or object with such a field
//! inside, only as exposed; the usernames and
//! other addresses in its records become pivots. Each `DeHashed` breach database
//! becomes evidence on the seed email entity the same way: dataset, record count,
//! whether a password or hash is exposed, the exposed field types and every
//! non-credential value its records hold, by the one rule both legs follow
//! ([`crate::breach_record`]), with the same pivots. Everything flows
//! through `merge_by_uid`, `lookup_report` (lineage) and `lookup_save`. A leg
//! without its key makes no request and records `NotConfigured`, never a zero.
//!
//! Each HIBP breach is also an [`Incident`]: the public context of the breach as
//! the source describes it. Its HTML description becomes a bounded plain-text
//! summary and the http(s) links the description itself gives; no URL is built
//! or guessed, so a domain stays a domain. The report text closes with an
//! incidents section, every third-party value written through
//! [`escape_controls`]. An incident describes a public breach, never the person:
//! being listed is evidence, not a verdict. A fabricated or spam-list incident is
//! flagged in the evidence, the entity tags and the text.
//!
//! When no breach source answered, the lookup ends from its rows through
//! [`crate::source_outcome::SourceReach`]: a request refused before sending is a refusal (exit
//! 77), otherwise no usable response (exit 69); a source that answered, even with an error, and
//! the seed alone, make it print.

use std::path::PathBuf;

use crate::breach_hybrid::{self, BreachLeg};
use crate::canonical::{canonical_email, canonical_url};
use crate::concurrent::{self, Job};
use crate::dehashed::{
    self, DehashedClient,
    exposure::{ExposureBreach, ExposureSearch},
};
use crate::entity::{Entity, EntityKind, Evidence, EvidenceProvenance, merge_by_uid};
use crate::error::Error;
use crate::hibp::client::HibpClient;
use crate::hibp::error::HibpError;
use crate::hibp::types::{BreachModel, BreachedAccountOptions};
use crate::html_text::{Markup, Piece, attribute, html_to_text};
use crate::http::Transport;
use crate::keys::Keys;
use crate::lookup_args::LookupTokens;
use crate::lookup_report;
use crate::module_selection::Selection;
use crate::oathnet::{self, OathnetError};
use crate::source_outcome::{SourceExecutionOutcome, SourceOutcomeKind, SourceReach, SourceRun};
use crate::stolen_tax::{self, StolenTaxError};
use crate::tags;
use crate::textnorm::{decode_html_entities, escape_controls, is_escaped};

pub const EXPOSURE_USAGE: &str = "usage: huntsman-recon exposure ADDR|HANDLE [--save FILE]";
pub const EXPOSURE_HELP: &str = "\
exposure ADDR|HANDLE [--save FILE]
Canonicalise the email address ADDR or the username HANDLE and run the keyed breach legs at once, reported in this order: HIBP breached-account (addresses only), then the stolen.tax cascade, then OathNet breach search, then DeHashed exact-match search (addresses only). The lookup takes as long as its slowest leg. A leg without its key makes no request and reports not_configured. Results are lineage-rendered entities. Then incidents=N (none when HIBP gave no answer) and, per HIBP breach sorted by name (a name the source repeats is shown once, keeping every flag any of its records sets): an incident row (title, breach and added dates, domain, account count, verified, flags), a caution row for a fabricated or spam-list breach, its summary, data classes, attribution, and the reference links its own description gives. This is public context about each breach, not a finding about the person. Then oathnet_breaches=N (none when OathNet gave no answer) and one oathnet_breach row per breach database: records, title, breach date, indexed range, whether a password or hash is exposed, and the exposed field types (at most 64, each named in ASCII letters, digits and _ within 48 bytes and shown in lower case; a field named otherwise is left out), followed by one oathnet_value row (field=value) per distinct non-credential value its records hold (at most 64 per field; a value over 1024 bytes is left out, never cut). A field whose name holds pass, pwd, hash or salt in any case is a credential, except that a pass beginning passport does not count: neither its value nor a list or object holding such a field at any depth is shown or kept. The row says a password or hash is exposed when such a field whose words name one holds a value, as a field or inside a list or object, even if the field's name is left out: a word beginning password, passwd, passwort, passphrase or passcode, a word pwd, pwdhash, passhash, userpass or salt, or pass or hash alone or beside another such word or one such as user, old or md5, but never a field that describes one (pwdLastSet, password_changed_at). Then dehashed_breaches=N (none when DeHashed gave no answer) and one dehashed_breach row per breach database: records, whether a password or hash is exposed and the exposed field types, each followed by one dehashed_value row per distinct non-credential value its records hold, as OathNet's are; a password, hash or salt is shown only as exposed, never its value. --save FILE writes an unverified ledger that verify can reload.";

/// Source label for the HIBP breached-account leg.
pub const SOURCE: &str = crate::hibp::ACCOUNT_SOURCE;
/// The module a lookup asks for HIBP's account search by.
pub const HIBP_MODULE: &str = "hibp";
/// Source label for the stolen.tax leg.
pub const STOLEN_TAX_SOURCE: &str = stolen_tax::SOURCE;
/// Source label for the `OathNet` leg.
pub const OATHNET_SOURCE: &str = oathnet::SOURCE;
/// Source label for the `DeHashed` leg. The same label the standalone collector uses, so both
/// paths relaying one `DeHashed` dataset share one evidence root family.
pub const DEHASHED_SOURCE: &str = dehashed::COLLECTOR_ID;

/// The longest incident summary or attribution, in characters. Longer text is cut on a character
/// boundary and ends with [`ELLIPSIS`], which counts toward the limit.
pub const MAX_SUMMARY_CHARS: usize = 600;
/// The most reference links kept for one incident, in the order its description first gives them.
pub const MAX_REFERENCE_LINKS: usize = 8;
/// The longest reference link kept, in bytes, after canonicalisation. A longer one is dropped,
/// never shortened, so every link shown is one the source wrote.
pub const MAX_REFERENCE_BYTES: usize = 2048;
/// Ends a summary or attribution that [`MAX_SUMMARY_CHARS`] cut short.
pub use crate::html_text::ELLIPSIS;

/// The label of the HIBP fabricated flag.
const FABRICATED: &str = "fabricated";
/// The label of the HIBP spam-list flag.
const SPAM_LIST: &str = "spam-list";
/// The label of the HIBP stealer-log flag.
const STEALER_LOG: &str = "stealer-log";
/// Every status flag label, in the order an incident lists its flags.
const STATUS_LABELS: [&str; 7] = [
    FABRICATED,
    SPAM_LIST,
    "malware",
    STEALER_LOG,
    "sensitive",
    "retired",
    "subscription-free",
];

/// One status flag the source sets on an incident, and the value it gives.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StatusFlag {
    /// `fabricated`, `spam-list`, `malware`, `stealer-log`, `sensitive`, `retired` or
    /// `subscription-free`.
    pub label: &'static str,
    /// The value the source gives.
    pub set: bool,
}

/// The public context of one breach incident the address is listed in, as the source states it.
/// It describes the incident, never the person.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Incident {
    /// The source's stable breach name.
    pub name: String,
    /// The display title.
    pub title: Option<String>,
    /// The breached service's domain, as the source gives it. It is never turned into a link.
    pub domain: Option<String>,
    /// When the breach happened.
    pub breach_date: Option<String>,
    /// When the source added it.
    pub added_date: Option<String>,
    /// When the source last changed it.
    pub modified_date: Option<String>,
    /// How many accounts the source loaded from it.
    pub pwn_count: Option<u64>,
    /// Whether the source considers it verified.
    pub verified: Option<bool>,
    /// The kinds of data it exposed, as the source names them.
    pub data_classes: Vec<String>,
    /// Every status flag the source sends, in a fixed order. A flag it omits is absent.
    pub status: Vec<StatusFlag>,
    /// The description as plain text, at most [`MAX_SUMMARY_CHARS`] characters.
    pub summary: Option<String>,
    /// The canonical http(s) links the description gives (the public coverage the source cites),
    /// first-seen order, without repeats, at most [`MAX_REFERENCE_LINKS`].
    pub references: Vec<String>,
    /// The credit the data provider asked for, as plain text, at most [`MAX_SUMMARY_CHARS`].
    pub attribution: Option<String>,
}

impl Incident {
    /// The incident HIBP describes with `breach`.
    #[must_use]
    pub fn from_breach(breach: &BreachModel) -> Self {
        let description = breach.description.as_deref();
        // The values in `STATUS_LABELS` order.
        let values = [
            breach.is_fabricated,
            breach.is_spam_list,
            breach.is_malware,
            breach.is_stealer_log,
            breach.is_sensitive,
            breach.is_retired,
            breach.is_subscription_free,
        ];
        let status = STATUS_LABELS
            .into_iter()
            .zip(values)
            .filter_map(|(label, value)| value.map(|set| StatusFlag { label, set }))
            .collect();
        Self {
            name: breach.name.clone(),
            title: breach.title.clone(),
            domain: breach.domain.clone(),
            breach_date: breach.breach_date.clone(),
            added_date: breach.added_date.clone(),
            modified_date: breach.modified_date.clone(),
            pwn_count: breach.pwn_count,
            verified: breach.is_verified,
            data_classes: breach.data_classes.clone(),
            status,
            summary: description.and_then(|html| html_to_text(html, MAX_SUMMARY_CHARS)),
            references: description
                .map(|html| reference_links(html, MAX_REFERENCE_LINKS))
                .unwrap_or_default(),
            attribution: breach
                .attribution
                .as_deref()
                .and_then(|html| html_to_text(html, MAX_SUMMARY_CHARS)),
        }
    }

    /// The labels of the flags the source sets to true, in [`Incident::status`] order.
    pub fn flags(&self) -> impl Iterator<Item = &'static str> + '_ {
        self.status
            .iter()
            .filter(|flag| flag.set)
            .map(|flag| flag.label)
    }

    /// Whether the source sets the flag `label`.
    #[must_use]
    pub fn has_flag(&self, label: &str) -> bool {
        self.flags().any(|flag| flag == label)
    }

    /// The value the source gives the flag `label`, or `None` when it omits it.
    fn flag_value(&self, label: &str) -> Option<bool> {
        self.status
            .iter()
            .find(|flag| flag.label == label)
            .map(|flag| flag.set)
    }

    /// Folds `later`, a record the source gave after this one under the same name, into this
    /// one. A descriptive field (title, domain, dates, account count, data classes, summary,
    /// references, attribution) keeps the first value given and takes the later one only where
    /// this record has none. The status flags and `verified` are merged so that a caution is
    /// never lost: a flag either record sets to true is set, and the incident is verified only
    /// when no record says otherwise.
    fn absorb(&mut self, later: Self) {
        fn fill<T>(first: &mut Option<T>, later: Option<T>) {
            if first.is_none() {
                *first = later;
            }
        }
        fn fill_list<T>(first: &mut Vec<T>, later: Vec<T>) {
            if first.is_empty() {
                *first = later;
            }
        }
        self.status = STATUS_LABELS
            .into_iter()
            .filter_map(|label| {
                let values = [self.flag_value(label), later.flag_value(label)];
                let given = values.iter().any(Option::is_some);
                given.then(|| StatusFlag {
                    label,
                    set: values.contains(&Some(true)),
                })
            })
            .collect();
        self.verified = self
            .verified
            .into_iter()
            .chain(later.verified)
            .reduce(|a, b| a && b);
        fill(&mut self.title, later.title);
        fill(&mut self.domain, later.domain);
        fill(&mut self.breach_date, later.breach_date);
        fill(&mut self.added_date, later.added_date);
        fill(&mut self.modified_date, later.modified_date);
        fill(&mut self.pwn_count, later.pwn_count);
        fill(&mut self.summary, later.summary);
        fill(&mut self.attribution, later.attribution);
        fill_list(&mut self.data_classes, later.data_classes);
        fill_list(&mut self.references, later.references);
    }
}

/// One incident per breach name, sorted by name. HIBP documents a breach name as unique, so only
/// a malformed or hostile answer repeats one; records that share a name are folded into the first
/// of them in source order with [`Incident::absorb`], so no flag one of them sets is dropped.
fn merge_incidents(mut incidents: Vec<Incident>) -> Vec<Incident> {
    // A stable sort: records that share a name stay in source order.
    incidents.sort_by(|a, b| a.name.cmp(&b.name));
    let mut merged: Vec<Incident> = Vec::with_capacity(incidents.len());
    for incident in incidents {
        match merged.last_mut() {
            Some(last) if last.name == incident.name => last.absorb(incident),
            _ => merged.push(incident),
        }
    }
    merged
}

/// What a flag that changes how an incident should be read means, in the source's terms.
fn caution(flag: &str) -> Option<&'static str> {
    match flag {
        FABRICATED => Some(
            "the source flags this incident as fabricated: it is unlikely to have come from the \
             named service and usually holds little or no legitimate data",
        ),
        SPAM_LIST => Some(
            "the source flags this incident as a spam list: its data did not come from a \
             security compromise",
        ),
        _ => None,
    }
}

/// The evidence attribute that holds the flag `label`: `spam-list` is `breach_spam_list`.
fn flag_attribute(label: &str) -> String {
    format!("breach_{}", label.replace('-', "_"))
}

/// The configured legs. `None` means that leg has no operator key. The legs run at once, so a
/// leg's transport is shared with its thread and must be `Sync`.
#[derive(Clone, Copy, Default)]
pub struct Sources<'a> {
    pub hibp: Option<&'a HibpClient>,
    pub stolen_tax: Option<(&'a (dyn Transport + Sync), &'a Keys)>,
    pub oathnet: Option<(&'a (dyn Transport + Sync), &'a Keys)>,
    pub dehashed: Option<&'a DehashedClient>,
    /// The modules the lookup asks; `None` asks every one. A leg it leaves out sends nothing and
    /// leaves no row, configured or not.
    pub selection: Option<&'a Selection>,
}

impl Sources<'_> {
    /// Whether a lookup of `selector` would reach at least one keyed leg it asks: HIBP or
    /// `DeHashed` for an address, stolen.tax or `OathNet` for either. Another lookup of the same
    /// selector runs exposure when this holds, so a configured paid source is never left out of it.
    #[must_use]
    pub fn reach(&self, selector: &str) -> bool {
        let email = canonical_email(selector).is_some();
        let email_only = email
            && ((self.hibp.is_some() && self.runs(HIBP_MODULE))
                || (self.dehashed.is_some() && self.runs(DEHASHED_SOURCE)));
        canonical_selector(selector).is_some()
            && (email_only
                || (self.stolen_tax.is_some() && self.runs(STOLEN_TAX_SOURCE))
                || (self.oathnet.is_some() && self.runs(OATHNET_SOURCE)))
    }

    /// Whether the lookup asks `module`.
    #[must_use]
    pub fn runs(&self, module: &str) -> bool {
        self.selection
            .is_none_or(|selection| selection.runs(module))
    }
}

/// Fold an exposure `report` into another lookup's `entities` and `outcomes` for the same
/// selector, and render the combined report: one entity and outcome table, then the incidents
/// `OathNet` and `DeHashed` sections. The seed entity both lookups emit is merged by uid. On an error,
/// `entities` and `outcomes` are left as they were.
///
/// # Errors
/// The report renderer's error.
pub fn fold_into(
    entities: &mut Vec<Entity>,
    outcomes: &mut Vec<SourceExecutionOutcome>,
    report: Report,
) -> Result<String, String> {
    let Report {
        entities: found,
        outcomes: ran,
        incidents,
        oathnet,
        dehashed,
    } = report;
    let mut all_entities = entities.clone();
    all_entities.extend(found);
    merge_by_uid(&mut all_entities);
    let mut all_outcomes = outcomes.clone();
    all_outcomes.extend(ran);
    let mut text = lookup_report::render(&all_entities, &all_outcomes)?;
    text.push_str(&render_incidents(incidents.as_deref()));
    text.push_str(&render_oathnet(oathnet.as_deref()));
    text.push_str(&render_dehashed(dehashed.as_deref()));
    *entities = all_entities;
    *outcomes = all_outcomes;
    Ok(text)
}

/// The line that stands for an exposure run that gave no report, so the lookup it rode along
/// with still says the keyed legs were tried: `exposure=unavailable reason=...`.
#[must_use]
pub fn unavailable_line(reason: &str) -> String {
    format!("exposure=unavailable reason={}\n", escape_controls(reason))
}

#[derive(Debug, Clone, PartialEq, Default)]
pub struct Report {
    pub entities: Vec<Entity>,
    pub outcomes: Vec<SourceExecutionOutcome>,
    /// The breach incidents HIBP lists the address in, sorted by breach name, one per name
    /// (records that share a name are merged, see [`Incident::absorb`]). The HIBP evidence is
    /// built from these same incidents. `None` when HIBP gave no answer (no key, or a failed
    /// request), which is not a zero.
    pub incidents: Option<Vec<Incident>>,
    /// The breach databases `OathNet` lists the address in, sorted by name. `None` when `OathNet`
    /// gave no answer (no key, or a failed request), which is not a zero.
    pub oathnet: Option<Vec<oathnet::Breach>>,
    /// The breach databases `DeHashed` lists the address in, sorted by name. `None` when
    /// `DeHashed` gave no answer (no key, or a failed request), which is not a zero.
    pub dehashed: Option<Vec<ExposureBreach>>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExposureArgs {
    /// A canonical email address or username, as [`canonical_selector`] gives it.
    pub selector: String,
    pub save: Option<PathBuf>,
}

impl ExposureArgs {
    /// # Errors
    /// Invalid or missing address, repeated `--save`, or an unknown option.
    pub fn parse(args: &[String]) -> Result<Self, Error> {
        let (raw, save) = LookupTokens::single(args, "exposure needs exactly one ADDR")?;
        let selector = canonical_selector(&raw)
            .ok_or_else(|| Error::invalid_value("not an email address or username"))?;
        Ok(Self { selector, save })
    }
}

/// How an exposure lookup ended. A lookup no breach source answered ends through [`SourceReach`]:
/// a refusal is [`ExposureRun::Network`] (exit 77), no response is [`ExposureRun::Failed`] (exit
/// 69); a source that answered, even with an error, still prints, as does the seed alone.
pub type ExposureRun = SourceRun<Report>;

/// The selector an exposure lookup is keyed on: a canonical email address, else a username by
/// the `username` command's rule. An address always wins, so `a@b.com` is never a handle.
#[must_use]
pub fn canonical_selector(raw: &str) -> Option<String> {
    canonical_email(raw).or_else(|| crate::username_cli::canonical_username(raw).ok())
}

/// Run every configured account-keyed breach leg for `selector`, an email address or a
/// username. HIBP and `DeHashed` search addresses only, so a username skips them without a
/// request or an outcome; stolen.tax and `OathNet` search either. The legs run at once and fold
/// in [`breach_hybrid::exposure_order`].
#[must_use]
pub fn run(sources: Sources<'_>, selector: &str, now_unix: u64) -> ExposureRun {
    let report = match collect(sources, selector, now_unix) {
        Ok(report) => report,
        Err(why) => return ExposureRun::Failed(why),
    };
    let value = canonical_selector(selector).unwrap_or_default();

    // No breach source answered: the lookup ends from its rows. A request refused before sending
    // is a refusal (exit 77); a source reached but silent is no usable response (exit 69); a
    // source that answered with an error still prints, as does the seed alone.
    if let Some(run) =
        SourceReach::of(&report.outcomes).stopped(&format!("no source answered for {value}"))
    {
        return run;
    }
    match lookup_report::render(&report.entities, &report.outcomes) {
        Ok(mut text) => {
            text.push_str(&render_incidents(report.incidents.as_deref()));
            text.push_str(&render_oathnet(report.oathnet.as_deref()));
            text.push_str(&render_dehashed(report.dehashed.as_deref()));
            ExposureRun::Printed { text, report }
        }
        Err(msg) => ExposureRun::Failed(msg),
    }
}

/// Run every leg [`run`] runs and return what they gave, every row kept, however the legs ended:
/// a lookup that folds the legs in reports a refused or silent leg as its row, never drops it.
///
/// # Errors
/// `selector` is neither an email address nor a username.
pub fn collect(sources: Sources<'_>, selector: &str, now_unix: u64) -> Result<Report, String> {
    let Some(value) = canonical_selector(selector) else {
        return Err("not an email address or username".into());
    };
    let kind = if canonical_email(&value).is_some() {
        EntityKind::Email
    } else {
        EntityKind::Username
    };
    let scan_id = crate::entity::scan_id("exposure", &value);
    let mut report = Report {
        entities: vec![seed_entity(&kind, &value, &scan_id)],
        outcomes: Vec::new(),
        incidents: None,
        oathnet: None,
        dehashed: None,
    };
    let seed = (&kind, value.as_str());
    let jobs: Vec<Job<'_, Option<LegRun>>> = breach_hybrid::exposure_order(true)
        .into_iter()
        .filter(|&leg| searches(leg, &kind) && sources.runs(leg_module(leg)))
        .map(|leg| {
            let scan_id = scan_id.as_str();
            Box::new(move || run_leg(sources, leg, seed, scan_id, now_unix))
                as Job<'_, Option<LegRun>>
        })
        .collect();
    // Folded in the legs' order, so the entities and outcomes are the ones the legs gave when they
    // ran one after another.
    for ran in concurrent::all(jobs).into_iter().flatten() {
        let LegRun { outcome, found } = ran;
        report.entities.extend(found.entities);
        report.incidents = report.incidents.or(found.incidents);
        report.oathnet = report.oathnet.or(found.oathnet);
        report.dehashed = report.dehashed.or(found.dehashed);
        report.outcomes.push(outcome);
    }
    merge_by_uid(&mut report.entities);
    Ok(report)
}

/// What one leg gave: its outcome row, and what it found (entities and its own section). How the
/// leg ended is read from its `outcome` row, like every other front-end's.
struct LegRun {
    outcome: SourceExecutionOutcome,
    found: Report,
}

/// Whether `leg` is run for a selector of `kind`. The keyless legs are not keyed on a selector,
/// and HIBP and `DeHashed` search addresses only, so a username sends them nothing.
fn searches(leg: BreachLeg, kind: &EntityKind) -> bool {
    match leg {
        BreachLeg::PwnedPasswords | BreachLeg::HibpCatalog => false,
        BreachLeg::HibpAccount | BreachLeg::DeHashed => *kind == EntityKind::Email,
        BreachLeg::StolenTax | BreachLeg::OathNet => true,
    }
}

/// The module a scan chooses `leg` by.
fn leg_module(leg: BreachLeg) -> &'static str {
    match leg {
        BreachLeg::PwnedPasswords | BreachLeg::HibpCatalog | BreachLeg::HibpAccount => HIBP_MODULE,
        BreachLeg::StolenTax => STOLEN_TAX_SOURCE,
        BreachLeg::OathNet => OATHNET_SOURCE,
        BreachLeg::DeHashed => DEHASHED_SOURCE,
    }
}

/// Run one keyed leg on its own [`Report`]; a leg without its key makes no request. `None` for a
/// keyless leg, which is not keyed on a selector.
fn run_leg(
    sources: Sources<'_>,
    leg: BreachLeg,
    seed: (&EntityKind, &str),
    scan_id: &str,
    now_unix: u64,
) -> Option<LegRun> {
    let mut found = Report::default();
    let outcome = match leg {
        BreachLeg::HibpAccount => match sources.hibp {
            None => missing_key(SOURCE, now_unix),
            Some(client) => hibp_leg(client, seed.1, scan_id, now_unix, &mut found),
        },
        BreachLeg::StolenTax => match sources.stolen_tax {
            None => missing_key(STOLEN_TAX_SOURCE, now_unix),
            Some((transport, keys)) => {
                stolen_tax_leg(transport, keys, seed.1, scan_id, now_unix, &mut found)
            }
        },
        BreachLeg::OathNet => match sources.oathnet {
            None => missing_key(OATHNET_SOURCE, now_unix),
            Some((transport, keys)) => {
                oathnet_leg(transport, keys, seed, scan_id, now_unix, &mut found)
            }
        },
        BreachLeg::DeHashed => match sources.dehashed {
            None => missing_key(DEHASHED_SOURCE, now_unix),
            Some(client) => dehashed_leg(client, seed.1, scan_id, now_unix, &mut found),
        },
        BreachLeg::PwnedPasswords | BreachLeg::HibpCatalog => return None,
    };
    Some(LegRun { outcome, found })
}

/// The incidents section that follows the lookup report. The first line is `incidents=N`, or
/// `incidents=none` when HIBP gave no answer. Each incident then has tab-separated rows, each led
/// by its kind and the breach name: one `incident` row (title, breach date, added date, domain,
/// account count, verified, flags; `unknown` for a value the source omits), a `caution` row for
/// each flag that changes how it should be read, then `summary`, `data_classes` and `attribution`
/// when the source gives them, and one `reference` row per link. Every value is written through
/// [`escape_controls`], so description text can neither drive the terminal nor forge a row.
fn render_incidents(incidents: Option<&[Incident]>) -> String {
    let Some(incidents) = incidents else {
        return "incidents=none\n".to_owned();
    };
    let mut out = format!("incidents={}\n", incidents.len());
    for incident in incidents {
        let name = escape_controls(&incident.name);
        let text = |value: &Option<String>| known(value.as_deref().map(escape_controls));
        let flags: Vec<&str> = incident.flags().collect();
        let flag_list = if flags.is_empty() {
            "none".to_owned()
        } else {
            flags.join(",")
        };
        let row = [
            "incident".to_owned(),
            name.clone(),
            format!("title={}", text(&incident.title)),
            format!("breach_date={}", text(&incident.breach_date)),
            format!("added={}", text(&incident.added_date)),
            format!("domain={}", text(&incident.domain)),
            format!(
                "accounts={}",
                known(incident.pwn_count.map(|n| n.to_string()))
            ),
            format!(
                "verified={}",
                known(incident.verified.map(|v| v.to_string()))
            ),
            format!("flags={flag_list}"),
        ];
        push_row(&mut out, &row);
        for message in flags.iter().filter_map(|flag| caution(flag)) {
            push_row(
                &mut out,
                &["caution".to_owned(), name.clone(), message.to_owned()],
            );
        }
        let classes = incident.data_classes.join(", ");
        for (kind, value) in [
            ("summary", incident.summary.as_deref()),
            (
                "data_classes",
                Some(classes.as_str()).filter(|c| !c.is_empty()),
            ),
            ("attribution", incident.attribution.as_deref()),
        ] {
            if let Some(value) = value {
                push_row(
                    &mut out,
                    &[kind.to_owned(), name.clone(), escape_controls(value)],
                );
            }
        }
        for link in &incident.references {
            push_row(
                &mut out,
                &["reference".to_owned(), name.clone(), escape_controls(link)],
            );
        }
    }
    out
}

/// The `OathNet` section that follows the incidents: `oathnet_breaches=N`, or `none` when `OathNet`
/// gave no answer, then one tab-separated `oathnet_breach` row per breach database, in name order:
/// records, title, breach date, indexed range, whether a password or hash is exposed, and the
/// exposed field types, each followed by one `oathnet_value` row per distinct non-credential value
/// its records hold. Every value is written through [`escape_controls`].
fn render_oathnet(breaches: Option<&[oathnet::Breach]>) -> String {
    let Some(breaches) = breaches else {
        return "oathnet_breaches=none\n".to_owned();
    };
    let mut out = format!("oathnet_breaches={}\n", breaches.len());
    for breach in breaches {
        let text = |value: &Option<String>| known(value.as_deref().map(escape_controls));
        let fields: Vec<&str> = breach.fields.iter().map(String::as_str).collect();
        let row = [
            "oathnet_breach".to_owned(),
            escape_controls(&breach.dbname),
            format!("records={}", breach.records),
            format!("title={}", text(&breach.title)),
            format!("breach_date={}", text(&breach.breach_date)),
            format!("first_indexed={}", text(&breach.first_indexed)),
            format!("last_indexed={}", text(&breach.last_indexed)),
            format!("password_exposed={}", breach.password_exposed),
            format!(
                "fields={}",
                if fields.is_empty() {
                    "unknown".to_owned()
                } else {
                    fields.join(",")
                }
            ),
        ];
        push_row(&mut out, &row);
        for (field, values) in &breach.values {
            for value in values {
                push_row(
                    &mut out,
                    &[
                        "oathnet_value".to_owned(),
                        escape_controls(&breach.dbname),
                        format!("{}={}", escape_controls(field), escape_controls(value)),
                    ],
                );
            }
        }
    }
    out
}

/// The `DeHashed` section that follows the `OathNet` section: `dehashed_breaches=N`, or `none`
/// when `DeHashed` gave no answer, then one tab-separated `dehashed_breach` row per breach
/// database, in name order: how many records hold the address, whether any of them exposes a
/// password or a hash, and the exposed field types, each followed by one `dehashed_value` row per
/// distinct non-credential value its records hold, as `OathNet`'s section does. Every value is
/// written through [`escape_controls`].
fn render_dehashed(breaches: Option<&[ExposureBreach]>) -> String {
    let Some(breaches) = breaches else {
        return "dehashed_breaches=none\n".to_owned();
    };
    let mut out = format!("dehashed_breaches={}\n", breaches.len());
    for breach in breaches {
        let fields: Vec<&str> = breach.fields.iter().map(String::as_str).collect();
        let row = [
            "dehashed_breach".to_owned(),
            escape_controls(&breach.dbname),
            format!("records={}", breach.records),
            format!("password_exposed={}", breach.password_exposed),
            format!(
                "fields={}",
                if fields.is_empty() {
                    "unknown".to_owned()
                } else {
                    escape_controls(&fields.join(","))
                }
            ),
        ];
        push_row(&mut out, &row);
        for (field, values) in &breach.values {
            for value in values {
                push_row(
                    &mut out,
                    &[
                        "dehashed_value".to_owned(),
                        escape_controls(&breach.dbname),
                        format!("{}={}", escape_controls(field), escape_controls(value)),
                    ],
                );
            }
        }
    }
    out
}

/// `value` as the report shows it, or `unknown` when the source omits it.
fn known(value: Option<String>) -> String {
    value.unwrap_or_else(|| "unknown".to_owned())
}

/// Appends one row of already escaped fields, tab-separated and ending in a newline.
fn push_row(out: &mut String, fields: &[String]) {
    out.push_str(&fields.join("\t"));
    out.push('\n');
}

fn missing_key(source: &str, now_unix: u64) -> SourceExecutionOutcome {
    // The HIBP account API needs a key only to automate the check. An individual can
    // check their own address for free on the website, so the HIBP leg names that route
    // rather than reporting a bare dead end.
    let detail = if source == SOURCE {
        "no operator key configured; no request made. Check this address for free at \
         https://haveibeenpwned.com/ (the key only automates the API)"
    } else {
        "no operator key configured; no request made"
    };
    SourceExecutionOutcome::failed(
        source,
        now_unix,
        SourceOutcomeKind::NotConfigured,
        None,
        detail,
    )
}

fn hibp_leg(
    client: &HibpClient,
    email: &str,
    scan_id: &str,
    now_unix: u64,
    report: &mut Report,
) -> SourceExecutionOutcome {
    let options = BreachedAccountOptions::full_model();
    match client.breached_account(email, &options) {
        Ok(breaches) if breaches.is_empty() => {
            report.incidents = Some(Vec::new());
            SourceExecutionOutcome::valid_zero(SOURCE, now_unix)
        }
        Ok(breaches) => {
            // Merged before the evidence is built, so the evidence, the tags, the incidents
            // section and the found count all describe the same one record per breach name.
            let incidents = merge_incidents(breaches.iter().map(Incident::from_breach).collect());
            report.entities.extend(
                incidents
                    .iter()
                    .map(|incident| breach_entity(email, scan_id, incident)),
            );
            let outcome = SourceExecutionOutcome::success(SOURCE, now_unix, incidents.len());
            let outcome = if incidents.len() < breaches.len() {
                outcome.with_detail(format!(
                    "the source gave {} records for {} breach names; records that share a name \
                     are merged and keep every flag any of them sets",
                    breaches.len(),
                    incidents.len()
                ))
            } else {
                outcome
            };
            report.incidents = Some(incidents);
            outcome
        }
        Err(err) => {
            let outcome = SourceExecutionOutcome::failed(
                SOURCE,
                now_unix,
                outcome_kind(&err),
                err.http_status(),
                err.to_string(),
            );
            match err {
                // HIBP's client waits on the pause as sent; the outcome records it within the
                // bound every other leg's fetch applies.
                HibpError::RateLimited {
                    retry_after: Some(retry_after),
                } => outcome.with_retry_after(
                    retry_after
                        .as_secs()
                        .min(crate::fetch::MAX_RETRY_AFTER_SECS),
                ),
                _ => outcome,
            }
        }
    }
}

fn stolen_tax_leg(
    transport: &dyn Transport,
    keys: &Keys,
    email: &str,
    scan_id: &str,
    now_unix: u64,
    report: &mut Report,
) -> SourceExecutionOutcome {
    match stolen_tax::lookup(transport, keys, email, scan_id, now_unix) {
        Ok(got) => {
            let found = got.entities.len();
            report.entities.extend(got.entities);
            let outcome = SourceExecutionOutcome::success(STOLEN_TAX_SOURCE, now_unix, found);
            let mut notes: Vec<String> = got
                .truncation
                .into_iter()
                .map(|why| format!("partial: {why}"))
                .collect();
            if got.unnamed_rows > 0 {
                notes.push(format!(
                    "{} row(s) name no breach or stealer host",
                    got.unnamed_rows
                ));
            }
            if notes.is_empty() {
                outcome
            } else {
                outcome.with_detail(notes.join("; "))
            }
        }
        Err(err) => {
            // The row keeps the kind the first failed path saw, so `SourceReach` reads a path
            // that got no response as a no-response (exit 69) and a path the source answered
            // with an error as reached, never as a refusal. A budget spent before any path was
            // sent (no failure to name) is the lookup's own timeout.
            let kind = match &err {
                StolenTaxError::MissingKey => SourceOutcomeKind::NotConfigured,
                StolenTaxError::Refused(_) => SourceOutcomeKind::RefusedBeforeSending,
                StolenTaxError::BudgetExhausted { failed, .. } => failed
                    .first()
                    .map_or(SourceOutcomeKind::BodyTimeout, |first| first.kind),
                StolenTaxError::Failed(first) => first.kind,
            };
            SourceExecutionOutcome::failed(STOLEN_TAX_SOURCE, now_unix, kind, None, err.to_string())
        }
    }
}

fn oathnet_leg(
    transport: &dyn Transport,
    keys: &Keys,
    seed: (&EntityKind, &str),
    scan_id: &str,
    now_unix: u64,
    report: &mut Report,
) -> SourceExecutionOutcome {
    let query = if *seed.0 == EntityKind::Email {
        oathnet::Query::Email(seed.1)
    } else {
        oathnet::Query::Username(seed.1)
    };
    match oathnet::search(transport, keys, query, now_unix) {
        Ok(search) => {
            report
                .entities
                .extend(oathnet_entities(seed, scan_id, &search));
            let outcome = if search.records == 0 {
                SourceExecutionOutcome::valid_zero(OATHNET_SOURCE, now_unix)
            } else {
                SourceExecutionOutcome::success(OATHNET_SOURCE, now_unix, search.breaches.len())
            }
            .with_http_status(200);
            let mut notes: Vec<String> = search.truncation().into_iter().collect();
            if search.unnamed_records > 0 {
                notes.push(format!(
                    "{} record(s) name no breach database",
                    search.unnamed_records
                ));
            }
            report.oathnet = Some(search.breaches);
            if notes.is_empty() {
                outcome
            } else {
                outcome.with_detail(notes.join("; "))
            }
        }
        Err(err) => {
            let outcome = SourceExecutionOutcome::failed(
                OATHNET_SOURCE,
                now_unix,
                err.outcome_kind(),
                err.http_status(),
                err.to_string(),
            );
            match err {
                OathnetError::RateLimited {
                    retry_after: Some(secs),
                } => outcome.with_retry_after(secs),
                _ => outcome,
            }
        }
    }
}

/// One seed entity per `OathNet` breach database, carrying that breach's exposure metadata and the
/// non-credential values its records hold, then one pivot per distinct username and address in the
/// records other than the seed. A credential field's value never reaches an entity:
/// [`oathnet::decode`] keeps only that one was exposed (see [`oathnet::CREDENTIAL_MARKERS`]).
fn oathnet_entities(
    (seed_kind, seed): (&EntityKind, &str),
    scan_id: &str,
    search: &oathnet::Search,
) -> Vec<Entity> {
    let mut entities = Vec::new();
    for breach in &search.breaches {
        let mut entity = Entity::new(seed_kind.clone(), seed, 0.85, scan_id);
        entity.tag(tags::BREACH);
        if breach.password_exposed {
            entity.tag(tags::PASSWORD_AT_RISK);
        }
        let fields: Vec<&str> = breach.fields.iter().map(String::as_str).collect();
        let mut evidence = Evidence::new(
            EvidenceProvenance::for_scan(OATHNET_SOURCE, scan_id),
            format!(
                "Address listed in OathNet breach database {}",
                breach.dbname
            ),
        )
        .with_attr("dbname", &breach.dbname)
        .with_attr("records", breach.records.to_string())
        .with_attr("exposed_fields", fields.join(","))
        .with_attr("password_exposed", breach.password_exposed.to_string());
        for (key, value) in [
            ("breach_title", breach.title.as_deref()),
            ("breach_domain", breach.domain.as_deref()),
            ("breach_date", breach.breach_date.as_deref()),
            ("first_indexed", breach.first_indexed.as_deref()),
            ("last_indexed", breach.last_indexed.as_deref()),
        ] {
            if let Some(value) = value {
                evidence = evidence.with_attr(key, value);
            }
        }
        if let Some(count) = breach.pwn_count {
            evidence = evidence.with_attr("pwn_count", count.to_string());
        }
        // The de-redacted payload: every non-credential value each exposed field held (cleartext
        // passwords, hashes and salts are held back in `oathnet.rs`), keyed `value_<field>` so it
        // cannot clobber the metadata attributes above.
        for (field, values) in &breach.values {
            let joined = values.iter().cloned().collect::<Vec<_>>().join(", ");
            evidence = evidence.with_attr(format!("value_{field}"), joined);
        }
        entity.add_evidence(evidence);
        entities.push(entity);
    }
    let pivot_note = "Seen in an OathNet breach record that holds the queried address";
    // The seed itself is not a pivot. Records quote it as stored, so compare canonical forms.
    let is_seed = |kind: &EntityKind, value: &str| {
        kind == seed_kind && canonical_selector(value).as_deref() == Some(seed)
    };
    let others = search
        .emails
        .iter()
        .map(|other| (EntityKind::Email, other))
        .chain(search.usernames.iter().map(|u| (EntityKind::Username, u)))
        .filter(|(kind, value)| !is_seed(kind, value));
    for (kind, value) in others {
        let mut entity = Entity::new(kind, value, 0.50, scan_id);
        entity.add_evidence(Evidence::new(
            EvidenceProvenance::for_scan(OATHNET_SOURCE, scan_id),
            pivot_note,
        ));
        entities.push(entity);
    }
    entities
}

fn dehashed_leg(
    client: &DehashedClient,
    email: &str,
    scan_id: &str,
    now_unix: u64,
    report: &mut Report,
) -> SourceExecutionOutcome {
    match dehashed::exposure::search_email(client, email) {
        Ok(search) => {
            report
                .entities
                .extend(dehashed_entities(email, scan_id, &search));
            let outcome = if search.records == 0 {
                SourceExecutionOutcome::valid_zero(DEHASHED_SOURCE, now_unix)
            } else {
                SourceExecutionOutcome::success(DEHASHED_SOURCE, now_unix, search.breaches.len())
            }
            .with_http_status(200);
            let mut notes: Vec<String> = search.truncation().into_iter().collect();
            if search.unnamed_records > 0 {
                notes.push(format!(
                    "{} record(s) name no breach database",
                    search.unnamed_records
                ));
            }
            if let Some(balance) = search.balance {
                notes.push(format!("{balance} search credit(s) left"));
            }
            report.dehashed = Some(search.breaches);
            if notes.is_empty() {
                outcome
            } else {
                outcome.with_detail(notes.join("; "))
            }
        }
        Err(err) => err.outcome(DEHASHED_SOURCE, now_unix),
    }
}

/// One email entity per `DeHashed` breach database, carrying that breach's exposure metadata and
/// every non-credential value its records hold (`value_<field>`, as `OathNet`'s evidence does),
/// then one pivot per distinct username and per other address in the records. No cleartext
/// password, hash or salt reaches an entity: [`dehashed::exposure::search_email`] keeps none.
fn dehashed_entities(email: &str, scan_id: &str, search: &ExposureSearch) -> Vec<Entity> {
    let mut entities = Vec::new();
    for breach in &search.breaches {
        let mut entity = Entity::new(EntityKind::Email, email, 0.85, scan_id);
        entity.tag(tags::BREACH);
        if breach.password_exposed {
            entity.tag(tags::PASSWORD_AT_RISK);
        }
        let evidence = Evidence::new(
            EvidenceProvenance::for_scan(DEHASHED_SOURCE, scan_id),
            format!(
                "Address listed in DeHashed breach database {}",
                breach.dbname
            ),
        )
        .with_attr("database_name", &breach.dbname)
        .with_attr("records", breach.records.to_string())
        .with_attr("password_exposed", breach.password_exposed.to_string());
        let mut evidence = evidence.with_attr(
            "exposed_fields",
            breach
                .fields
                .iter()
                .map(String::as_str)
                .collect::<Vec<_>>()
                .join(","),
        );
        if breach.unstructured_records > 0 {
            evidence = evidence.with_attr(
                "unstructured_records",
                breach.unstructured_records.to_string(),
            );
        }
        // The de-redacted payload, keyed `value_<field>` so it cannot clobber the attributes above.
        for (field, values) in &breach.values {
            let joined = values.iter().cloned().collect::<Vec<_>>().join(", ");
            evidence = evidence.with_attr(format!("value_{field}"), joined);
        }
        entity.add_evidence(evidence);
        entities.push(entity);
    }
    let pivot_note = "Seen in a DeHashed breach record that holds the queried address";
    let others = search
        .emails
        .iter()
        .filter(|other| canonical_email(other).as_deref() != Some(email))
        .map(|other| (EntityKind::Email, other));
    let usernames = search.usernames.iter().map(|u| (EntityKind::Username, u));
    for (kind, value) in others.chain(usernames) {
        let mut entity = Entity::new(kind, value, 0.50, scan_id);
        entity.add_evidence(Evidence::new(
            EvidenceProvenance::for_scan(DEHASHED_SOURCE, scan_id),
            pivot_note,
        ));
        entities.push(entity);
    }
    entities
}

/// The outcome a failed HIBP lookup records. A failure without a response keeps the cause the
/// fetch observed, as the `OathNet` and `DeHashed` legs do.
fn outcome_kind(err: &HibpError) -> SourceOutcomeKind {
    match err {
        HibpError::MissingKey => SourceOutcomeKind::NotConfigured,
        HibpError::Unauthorized(_) | HibpError::Forbidden(_) => SourceOutcomeKind::AuthRejected,
        HibpError::PlanNotEntitled { .. } => SourceOutcomeKind::EntitlementDenied,
        HibpError::RateLimited { .. } => SourceOutcomeKind::RateLimited,
        HibpError::Server { .. } => SourceOutcomeKind::Upstream5xx,
        HibpError::BadRequest(_) | HibpError::UnexpectedStatus { .. } => {
            SourceOutcomeKind::Upstream4xx
        }
        HibpError::Decode(_) => SourceOutcomeKind::SchemaDrift,
        HibpError::Transport { kind, .. } | HibpError::NotAnAnswer(kind) => *kind,
        HibpError::Refused => SourceOutcomeKind::RefusedBeforeSending,
        HibpError::InvalidInput(_) | HibpError::OAuth(_) => SourceOutcomeKind::Inconclusive,
    }
}

fn seed_entity(kind: &EntityKind, value: &str, scan_id: &str) -> Entity {
    let mut entity = Entity::new(kind.clone(), value, 0.99, scan_id);
    entity.tag("seed");
    let what = if *kind == EntityKind::Email {
        "email selector the lookup was asked"
    } else {
        "username selector the lookup was asked"
    };
    entity.add_evidence(Evidence::new(
        EvidenceProvenance::for_scan("seed", scan_id),
        what,
    ));
    entity
}

/// The address as listed in one HIBP incident. The evidence keeps every field of the incident:
/// the plain-text summary, the reference links (space-separated; a kept link holds no
/// whitespace), the dates, the attribution and each status flag the source sends.
fn breach_entity(email: &str, scan_id: &str, incident: &Incident) -> Entity {
    let mut entity = Entity::new(EntityKind::Email, email, 0.90, scan_id);
    if incident.has_flag(STEALER_LOG) {
        entity.tag(tags::STEALER_LOG);
    }
    entity.tag(tags::BREACH);
    if incident.has_flag(FABRICATED) {
        entity.tag(tags::FABRICATED_BREACH);
    }
    if incident.has_flag(SPAM_LIST) {
        entity.tag(tags::SPAM_LIST);
    }

    let cautions: Vec<&str> = incident
        .flags()
        .filter(|flag| caution(flag).is_some())
        .collect();
    let summary = if cautions.is_empty() {
        format!("Address listed in HIBP breach {}", incident.name)
    } else {
        format!(
            "Address listed in HIBP breach {}, which the source flags as {}",
            incident.name,
            cautions.join(" and ")
        )
    };
    let mut evidence = Evidence::new(EvidenceProvenance::for_scan(SOURCE, scan_id), summary)
        .with_attr("breach_name", &incident.name)
        .with_attr("data_classes", incident.data_classes.join(", "));
    let references = incident.references.join(" ");
    for (key, value) in [
        ("breach_title", incident.title.as_deref()),
        ("breach_domain", incident.domain.as_deref()),
        ("breach_date", incident.breach_date.as_deref()),
        ("breach_added_date", incident.added_date.as_deref()),
        ("breach_modified_date", incident.modified_date.as_deref()),
        ("breach_attribution", incident.attribution.as_deref()),
        ("breach_summary", incident.summary.as_deref()),
        (
            "breach_references",
            Some(references.as_str()).filter(|links| !links.is_empty()),
        ),
    ] {
        if let Some(value) = value {
            evidence = evidence.with_attr(key, value);
        }
    }
    if let Some(count) = incident.pwn_count {
        evidence = evidence.with_attr("pwn_count", count.to_string());
    }
    if let Some(verified) = incident.verified {
        evidence = evidence.with_attr("breach_verified", verified.to_string());
    }
    for flag in &incident.status {
        evidence = evidence.with_attr(flag_attribute(flag.label), flag.set.to_string());
    }
    entity.add_evidence(evidence);
    entity
}

/// The http(s) links of the anchor (`a`) tags in `html`, canonicalised by [`canonical_url`],
/// in first-seen order without repeats, at most `max`. A `javascript:`, `data:`, `mailto:` or
/// relative link, an empty `href`, a link longer than [`MAX_REFERENCE_BYTES`] and one holding
/// whitespace or a control character are dropped. Only links the source wrote are returned.
fn reference_links(html: &str, max: usize) -> Vec<String> {
    let mut links: Vec<String> = Vec::new();
    for piece in Markup::new(html) {
        if links.len() >= max {
            break;
        }
        let Piece::Tag {
            name,
            end: false,
            attrs,
        } = piece
        else {
            continue;
        };
        if !name.eq_ignore_ascii_case("a") {
            continue;
        }
        let Some(link) = attribute(attrs, "href").and_then(reference_url) else {
            continue;
        };
        if !links.contains(&link) {
            links.push(link);
        }
    }
    links
}

/// The canonical form of one `href` value when it is a usable http(s) link.
fn reference_url(href: &str) -> Option<String> {
    let decoded = decode_html_entities(href);
    let url = canonical_url(decoded.trim())?;
    let clean = url.len() <= MAX_REFERENCE_BYTES
        && !url.chars().any(|c| c.is_whitespace() || is_escaped(c));
    clean.then_some(url)
}

#[cfg(test)]
mod tests;
