//! Collection front-end for `huntsman-recon people`.
//!
//! Lookup runs [`crate::asic_persons`], [`crate::asic_director`], [`crate::wikidata`] and
//! [`crate::acnc`] over
//! one injected [`crate::http::Transport`]. One source's [`Error::Invalid`] or `BotWaf` does not
//! abort the others. All entities from all sources are merged via [`crate::entity::merge_by_uid`],
//! which deduplicates records with the same UID and calls [`crate::entity::Entity::absorb`]
//! to combine attributes. The merged report is rendered by [`crate::lookup_report::render`],
//! which feeds the evidence through [`crate::lineage::resolve_with_lineage`]. Tests inject
//! fakes; live sources are not run here. Saving a ledger is handled by [`crate::lookup_save`],
//! and the `--save` option is read by [`crate::lookup_args`]; this module reads only NAME.

use std::path::PathBuf;

use crate::acnc;
use crate::asic_director;
use crate::asic_persons;
use crate::canonical::canonical_name;
use crate::entity::{Entity, merge_by_uid};
use crate::error::Error;
use crate::http::Transport;
use crate::lookup_args::LookupTokens;
use crate::lookup_report;
use crate::source_outcome::{SourceExecutionOutcome, SourceOutcomeKind, SourceRun};
use crate::textnorm::name_tokens;
use crate::wikidata;

pub const PEOPLE_USAGE: &str = "usage: huntsman-recon people NAME [--save FILE]";
pub const PEOPLE_HELP: &str = "\
people NAME [--save FILE]
Look up NAME on the keyless ASIC people and director registers, Wikidata, and the ACNC charity register. Fewer than two alphabetic tokens makes no request. One source failure does not abort the others. --save FILE writes an unverified ledger that verify can reload; skip does not write.

The lookup queries independent sources:
  1. ASIC people register (company associates and sole traders)
  2. ASIC director register (company director records)
  3. Wikidata (top public item, QID-scoped candidate, never name-only identity corroboration)
  4. ACNC charity register (registered charities and not-for-profits matched by name)

Results are merged only by canonical entity UID. Name-matched Wikidata items and ACNC organisations are source-scoped candidates, not automatic cross-register identity corroboration; precise identifiers retain their normal correlation keys.";

/// Merged entities and outcomes from every people source that ran.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct Report {
    pub entities: Vec<Entity>,
    pub outcomes: Vec<SourceExecutionOutcome>,
}
/// Parsed `people` arguments. The name is the positional tokens joined with spaces.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeopleArgs {
    pub name: String,
    pub save: Option<PathBuf>,
}

impl PeopleArgs {
    /// # Errors
    /// [`Error::Invalid`] when NAME is missing, `--save` has no path, `--save` is
    /// repeated, or an unknown option is present.
    pub fn parse(args: &[String]) -> Result<Self, Error> {
        let LookupTokens {
            positional: name_parts,
            save,
        } = LookupTokens::split(args)?;
        if name_parts.is_empty() {
            return Err(Error::Invalid("missing NAME".into()));
        }
        Ok(Self {
            name: name_parts.join(" "),
            save,
        })
    }
}

/// Result of one `people` invocation, before the binary maps it to an exit code.
pub type PeopleRun = SourceRun<Report>;

/// What a name of fewer than two alphabetic tokens prints: no register is asked and nothing is
/// saved.
pub const SKIP_LINE: &str = "people: skipped (need two alphabetic tokens)\n";

/// Look up `name` over `transport` and render entities, outcomes, and lineage, asking each
/// register only when the transport's lookup asks its module ([`Transport::runs_module`]).
/// A single-token name prints the skip line and makes no request.
#[must_use]
pub fn run<T: Transport + ?Sized>(transport: &T, name: &str, now_unix: u64) -> PeopleRun {
    let name = canonical_name(name);
    if name_tokens(&name).len() < 2 {
        return PeopleRun::Printed {
            text: SKIP_LINE.into(),
            report: Report::default(),
        };
    }

    let scan_id = crate::entity::scan_id("person", &name);
    let mut report = Report::default();
    let mut network = None;
    let mut failed = None;

    if transport.runs_module(asic_persons::SRC) {
        collect(
            asic_persons::SRC,
            asic_persons::lookup(transport, &name, &scan_id, now_unix)
                .map(|found| (found.entities, found.outcomes)),
            now_unix,
            &mut report,
            &mut network,
            &mut failed,
        );
    }
    if transport.runs_module(asic_director::SRC) {
        collect(
            asic_director::SRC,
            asic_director::lookup(transport, &name, &scan_id, now_unix)
                .map(|found| (found.entities, found.outcomes)),
            now_unix,
            &mut report,
            &mut network,
            &mut failed,
        );
    }
    if transport.runs_module(wikidata::SOURCE) {
        // Wikidata resolves the name to its top public item: a Person candidate when the item is a
        // human, never a confirmed identity. Reuses the keyless wikidata source client, so a people
        // lookup is no longer Australia-only. A single outcome folds in like the register legs.
        collect(
            wikidata::SOURCE,
            wikidata::lookup(transport, &name, &scan_id, now_unix)
                .map(|found| (scope_wikidata_items(found.entities), vec![found.outcome])),
            now_unix,
            &mut report,
            &mut network,
            &mut failed,
        );
    }
    if transport.runs_module(acnc::SRC) {
        // The ACNC charity register: a `people NAME` that names a charity or not-for-profit folds
        // in the registered organisation, its ABN (an AbnAcn correlation key; the ASIC and GLEIF
        // legs key on the 9-digit ACN, so an 11-digit ABN does not auto-join those), its official
        // website (a lead into the domain-recon cluster) and its registered address. A single
        // outcome folds in like the other register legs.
        collect(
            acnc::SRC,
            acnc::lookup(transport, &name, &scan_id, now_unix)
                .map(|found| (scope_acnc_charities(found.entities), vec![found.outcome])),
            now_unix,
            &mut report,
            &mut network,
            &mut failed,
        );
    }

    // Entities with identical UIDs from different sources are merged: duplicate records
    // are combined into one entity whose observation set includes evidence from all sources.
    // This consolidates cases where one person has records across multiple registers.
    merge_by_uid(&mut report.entities);
    if !usable(&report) {
        if let Some(msg) = network {
            return PeopleRun::Network(msg);
        }
        if let Some(msg) = failed {
            return PeopleRun::Failed(msg);
        }
        return PeopleRun::Failed("nothing collected".into());
    }

    match lookup_report::render(&report.entities, &report.outcomes) {
        Ok(text) => PeopleRun::Printed { text, report },
        Err(msg) => PeopleRun::Failed(msg),
    }
}

/// A name-matched ACNC charity is not proven to be the same organisation as an ASIC row
/// with an identical legal name. Scope only its Organisation identity within the composed
/// people lookup, using its checksum-valid ABN when available. This also keeps different
/// registered charities with the same legal name distinct. Preserve the source label as
/// evidence; precise ABN, website and address entities retain their normal canonical keys.
fn scope_acnc_charities(mut entities: Vec<Entity>) -> Vec<Entity> {
    for entity in &mut entities {
        if entity.kind != crate::entity::EntityKind::Organisation {
            continue;
        }
        let label = entity.raw_value.clone();
        let abn = entity
            .evidence
            .iter()
            .find_map(|evidence| evidence.attributes.get("ABN"))
            .filter(|abn| crate::au_id::is_valid_abn(abn));
        let suffix = abn.map_or_else(
            || "name-only candidate".to_owned(),
            |abn| format!("ABN {abn}"),
        );
        let scoped = Entity::new(
            entity.kind.clone(),
            format!("{label} [ACNC {suffix}]"),
            entity.confidence,
            entity.scan_id.clone(),
        );
        entity.uid = scoped.uid;
        entity.value = scoped.value;
        entity.raw_value = scoped.raw_value;
        entity.tag("acnc-organisation-scoped");
        for evidence in &mut entity.evidence {
            evidence
                .attributes
                .entry("source_label".into())
                .or_insert_with(|| label.clone());
        }
    }
    entities
}

/// A shared display name is not a verified cross-register identity. Wikidata items have
/// stable QIDs, while ASIC rows often identify people by name alone. Keep the source's
/// original label in evidence, but scope the item entity's canonical key to its QID so
/// same-name strangers cannot merge or inflate corroboration. Other pivot entities keep
/// their normal canonical keys, but remain lead-only: a name-search hit is not
/// sufficient attribution to dispatch its domain or username recursively.
/// This only affects the composed people lookup.
fn scope_wikidata_items(mut entities: Vec<Entity>) -> Vec<Entity> {
    for entity in &mut entities {
        if !matches!(
            entity.kind,
            crate::entity::EntityKind::Person
                | crate::entity::EntityKind::Organisation
                | crate::entity::EntityKind::Other
        ) {
            entity.tag(wikidata::NAME_SEARCH_LEAD_TAG);
            continue;
        }
        let Some(qid) = entity
            .evidence
            .iter()
            .find_map(|evidence| evidence.attributes.get("qid"))
        else {
            continue;
        };
        let label = entity.raw_value.clone();
        let scoped = Entity::new(
            entity.kind.clone(),
            format!("{label} [Wikidata {qid}]"),
            entity.confidence,
            entity.scan_id.clone(),
        );
        entity.uid = scoped.uid;
        entity.value = scoped.value;
        entity.raw_value = scoped.raw_value;
        entity.tag("wikidata-item-scoped");
        for evidence in &mut entity.evidence {
            evidence
                .attributes
                .entry("source_label".into())
                .or_insert_with(|| label.clone());
        }
    }
    entities
}

fn collect(
    module: &'static str,
    result: Result<(Vec<Entity>, Vec<SourceExecutionOutcome>), Error>,
    now_unix: u64,
    report: &mut Report,
    network: &mut Option<String>,
    failed: &mut Option<String>,
) {
    match result {
        Ok((entities, outcomes)) => {
            report.entities.extend(entities);
            report.outcomes.extend(outcomes);
        }
        Err(Error::Network(msg)) => {
            network.get_or_insert(msg.clone());
            report.outcomes.push(SourceExecutionOutcome::failed(
                module,
                now_unix,
                SourceOutcomeKind::ConnectFailure,
                None,
                msg,
            ));
        }
        Err(Error::Invalid(msg)) => {
            failed.get_or_insert(msg.clone());
            report.outcomes.push(SourceExecutionOutcome::failed(
                module,
                now_unix,
                SourceOutcomeKind::Inconclusive,
                None,
                msg,
            ));
        }
        Err(e) => {
            let msg = e.to_string();
            failed.get_or_insert(msg.clone());
            report.outcomes.push(SourceExecutionOutcome::failed(
                module,
                now_unix,
                SourceOutcomeKind::Inconclusive,
                None,
                msg,
            ));
        }
    }
}

fn usable(report: &Report) -> bool {
    !report.entities.is_empty()
        || report
            .outcomes
            .iter()
            .any(|outcome| outcome.kind.is_accepted())
}

/// Whether NAME has the two alphabetic tokens a person lookup needs. The scan router
/// uses this to tell a name from a mistyped phone or handle before it routes a guess.
#[must_use]
pub fn is_name(name: &str) -> bool {
    name_tokens(&canonical_name(name)).len() >= 2
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::{html_ok, json_ok};
    use std::cell::RefCell;
    use std::collections::HashMap;

    #[test]
    fn same_name_wikidata_item_does_not_merge_with_unrelated_asic_identity() {
        use crate::entity::{EntityKind, Evidence, EvidenceProvenance};

        for kind in [
            EntityKind::Person,
            EntityKind::Organisation,
            EntityKind::Other,
        ] {
            let mut asic = Entity::new(kind.clone(), "Jane Example", 0.7, "scan");
            asic.add_evidence(Evidence::new(
                EvidenceProvenance::for_scan("asic_persons", "scan"),
                "independent ASIC record",
            ));
            let mut wikidata = Entity::new(kind, "Jane Example", 0.6, "scan");
            wikidata.add_evidence(
                Evidence::new(
                    EvidenceProvenance::for_scan("wikidata", "scan"),
                    "candidate item, not verified identity",
                )
                .with_attr("qid", "Q42"),
            );
            let mut entities = vec![asic, wikidata];
            assert_eq!(entities[0].uid, entities[1].uid, "precondition");
            entities = scope_wikidata_items(entities);
            merge_by_uid(&mut entities);
            assert_eq!(entities.len(), 2, "same name must not fuse distinct people");
            assert_eq!(entities[0].source_count(), 1);
            assert_eq!(entities[1].source_count(), 1);
            assert_ne!(entities[0].uid, entities[1].uid);
            assert!(entities[1].raw_value.contains("[Wikidata Q42]"));
            assert_eq!(
                entities[1].evidence[0]
                    .attributes
                    .get("source_label")
                    .map(String::as_str),
                Some("Jane Example")
            );
        }
    }

    #[test]
    fn wikidata_name_search_pivots_are_retained_as_unverified_leads() {
        use crate::entity::{EntityKind, Evidence, EvidenceProvenance};

        let mut person = Entity::new(EntityKind::Person, "Jane Example", 0.6, "scan");
        person.add_evidence(
            Evidence::new(
                EvidenceProvenance::for_scan("wikidata", "scan"),
                "candidate item",
            )
            .with_attr("qid", "Q42"),
        );
        let mut domain = Entity::new(EntityKind::Domain, "stranger.example", 0.55, "scan");
        domain.add_evidence(
            Evidence::new(
                EvidenceProvenance::for_scan("wikidata", "scan"),
                "website for unverified candidate",
            )
            .with_attr("qid", "Q42"),
        );
        let entities = scope_wikidata_items(vec![person, domain]);
        assert_eq!(entities.len(), 2);
        assert!(entities[0].has_tag("wikidata-item-scoped"));
        assert!(!entities[0].has_tag(wikidata::NAME_SEARCH_LEAD_TAG));
        assert_eq!(entities[1].value, "stranger.example");
        assert_eq!(entities[1].confidence, 0.55);
        assert!(entities[1].has_tag(wikidata::NAME_SEARCH_LEAD_TAG));
        assert_eq!(
            entities[1].evidence[0]
                .attributes
                .get("qid")
                .map(String::as_str),
            Some("Q42"),
        );
    }

    #[test]
    fn acnc_name_matches_do_not_merge_unrelated_organisations() {
        // A legal-name match alone cannot corroborate an ASIC organisation. Two charities
        // sharing a name but bearing distinct valid ABNs must also remain distinct.
        let candidate = |source: &str, abn: Option<&str>| {
            let mut entity =
                Entity::new(EntityKind::Organisation, "The Smith Family", 0.60, "scan");
            let mut evidence = Evidence::new(
                EvidenceProvenance::for_scan(source, "scan"),
                "name match only",
            );
            if let Some(abn) = abn {
                evidence = evidence.with_attr("ABN", abn);
            }
            entity.add_evidence(evidence);
            entity
        };
        let asic = candidate("asic_persons", None);
        let acnc = scope_acnc_charities(vec![
            candidate("acnc", Some("28000030179")),
            candidate("acnc", Some("28000030228")),
            candidate("acnc", None),
        ]);
        assert_eq!(acnc.len(), 3);
        assert_ne!(acnc[0].uid, acnc[1].uid);
        assert_ne!(acnc[0].uid, acnc[2].uid);
        assert_eq!(
            acnc[0].evidence[0]
                .attributes
                .get("source_label")
                .map(String::as_str),
            Some("The Smith Family"),
        );
        let mut combined = vec![asic];
        combined.extend(acnc);
        merge_by_uid(&mut combined);
        assert_eq!(
            combined.len(),
            4,
            "a name-only ACNC candidate must not inflate ASIC corroboration",
        );
        assert!(combined.iter().all(|entity| entity.source_count() == 1));
    }

    #[test]
    fn a_name_needs_two_alphabetic_tokens_of_at_least_two_characters() {
        assert!(is_name("Émile Zola"));
        // One accented letter is one character, so it is not a token of a name, though it is
        // two bytes in UTF-8.
        assert!(!is_name("É Lovelace"));
        assert!(!is_name("Ada"));
    }

    use crate::acnc::CHARITY_RES;
    use crate::asic_persons::{ADVISER_RES, BANNED_RES, CREDIT_RES};
    use crate::http::{Request, Response, TransportFailure};
    use crate::relation::{self, RelationKind};
    use crate::source_outcome::SourceOutcomeKind;
    const BANNED: &str = r##"{
  "BD_PER_NAME":"ABBOTT, BILL","BD_PER_TYPE":"Banned Securities",
  "BD_PER_START_DT":"29/03/1994","BD_PER_END_DT":"29/03/1999",
  "BD_PER_DOC_NUM":"#004289112","BD_PER_ADD_LOCAL":"TEMPLESTOWE LOWER",
  "BD_PER_ADD_STATE":"VIC","BD_PER_ADD_PCODE":"3107","BD_PER_COMMENTS":"No comment made"}"##;

    struct Fake {
        by_id: RefCell<HashMap<String, Result<Response, TransportFailure>>>,
        html: RefCell<Vec<(String, Response)>>,
        seen: RefCell<Vec<String>>,
    }

    impl Fake {
        fn new(script: HashMap<String, Result<Response, TransportFailure>>) -> Self {
            Self {
                by_id: RefCell::new(script),
                html: RefCell::default(),
                seen: RefCell::default(),
            }
        }

        fn html(self, needle: &str, response: Response) -> Self {
            self.html.borrow_mut().push((needle.to_owned(), response));
            self
        }
    }

    impl Transport for Fake {
        fn send(&self, request: &Request) -> Result<Response, TransportFailure> {
            self.seen.borrow_mut().push(request.url.clone());
            if let Some(id) = request
                .url
                .split("resource_id=")
                .nth(1)
                .and_then(|rest| rest.split('&').next())
            {
                return self
                    .by_id
                    .borrow_mut()
                    .remove(id)
                    .unwrap_or_else(|| panic!("unexpected resource {id}"));
            }
            // Wikidata's keyless entity search. An empty result set is the live endpoint's answer
            // for a name it does not resolve, so a people scan's wikidata leg is a clean valid_zero
            // here rather than an incidental parse drift off the HTML fallback below.
            if request.url.contains("wbsearchentities") {
                return Ok(json_ok(r#"{"search":[]}"#));
            }
            let html = self.html.borrow();
            if let Some((_, response)) =
                html.iter().find(|(needle, _)| request.url.contains(needle))
            {
                return Ok(Response {
                    status: response.status,
                    headers: response.headers.clone(),
                    body: response.body.clone(),
                    truncated: response.truncated,
                });
            }
            // Explicit negative fixture: an arbitrary 2xx page is inconclusive.
            Ok(html_ok("<html><body>no matches</body></html>"))
        }
    }

    struct BlockAll;

    impl Transport for BlockAll {
        fn send(&self, request: &Request) -> Result<Response, TransportFailure> {
            Err(TransportFailure {
                kind: SourceOutcomeKind::ConnectFailure,
                detail: format!("egress-policy: {}", request.url),
                blocked: true,
            })
        }
    }

    fn challenge() -> Response {
        Response {
            status: 403,
            headers: vec![("content-type".into(), "text/html".into())],
            body: b"<html>just a moment cloudflare</html>".to_vec(),
            truncated: false,
        }
    }

    /// Every source leg a two-token people scan runs: `asic_persons` (its banned, adviser and
    /// credit datasets), `asic_director`, `wikidata`, and the `acnc` charity register. Each leg
    /// makes one request, folds in one outcome and persists one ledger entry, so the three counts
    /// coincide — every leg here is a single-request `valid_zero`.
    const PEOPLE_SOURCE_REQUESTS: usize = 6;

    fn empty_script() -> HashMap<String, Result<Response, TransportFailure>> {
        let empty = json_ok(r#"{"success":true,"result":{"records":[]}}"#);
        HashMap::from([
            (BANNED_RES.into(), Ok(empty.clone())),
            (ADVISER_RES.into(), Ok(empty.clone())),
            (CREDIT_RES.into(), Ok(empty.clone())),
            (CHARITY_RES.into(), Ok(empty)),
        ])
    }

    #[test]
    fn missing_name_is_invalid() {
        assert!(matches!(
            PeopleArgs::parse(&[]),
            Err(Error::Invalid(msg)) if msg == "missing NAME"
        ));
    }

    #[test]
    fn parse_joins_name_and_accepts_save() {
        let parsed = PeopleArgs::parse(&[
            "Bill".into(),
            "--save".into(),
            "out.json".into(),
            "Abbott".into(),
        ])
        .unwrap();
        assert_eq!(parsed.name, "Bill Abbott");
        assert_eq!(
            parsed.save.as_deref(),
            Some(PathBuf::from("out.json").as_path())
        );
    }

    #[test]
    fn parse_rejects_unknown_option_and_bare_save() {
        assert!(PeopleArgs::parse(&["Bill".into(), "--depth".into()]).is_err());
        assert!(PeopleArgs::parse(&["--save".into()]).is_err());
        assert!(PeopleArgs::parse(&["--save".into(), "--save".into(), "x".into()]).is_err());
    }

    #[test]
    fn single_token_prints_skip_and_makes_no_request() {
        let fake = Fake::new(HashMap::new());
        match run(&fake, "Madonna", 1) {
            PeopleRun::Printed { text, report } => {
                assert!(text.contains("skipped"), "{text}");
                assert!(!text.contains("lineage="), "{text}");
                let entities = &report.entities;
                assert!(entities.is_empty(), "{entities:?}");
                let outcomes = &report.outcomes;
                assert!(outcomes.is_empty(), "{outcomes:?}");
            }
            other => panic!("{other:?}"),
        }
        let seen = fake.seen.borrow();
        assert!(seen.is_empty(), "{seen:?}");
    }

    #[test]
    fn scripted_hit_prints_entities_and_dataset_lineage() {
        let mut script = empty_script();
        script.insert(
            BANNED_RES.into(),
            Ok(json_ok(&format!(
                r#"{{"success":true,"result":{{"records":[{BANNED}]}}}}"#
            ))),
        );
        let fake = Fake::new(script);
        match run(&fake, "Bill Abbott", 1) {
            PeopleRun::Printed { text, report } => {
                assert!(text.contains("Bill Abbott"), "{text}");
                assert!(text.contains("asic_persons.banned"), "{text}");
                assert!(
                    text.contains("dataset\tasic banned & disqualified persons"),
                    "person evidence must count as the banned dataset family: {text}"
                );
                assert!(!report.entities.is_empty(), "{report:?}");
                assert_eq!(fake.seen.borrow().len(), PEOPLE_SOURCE_REQUESTS);
            }
            other => panic!("{other:?}"),
        }
    }

    const ADVISER_LINKED: &str = r#"{
  "ADV_NAME":"POPOV, MARSEL","ADV_ROLE":"Authorised Representative","ADV_ROLE_STATUS":"Current",
  "OVERALL_REGISTRATION_STATUS":"Registered",
  "LICENCE_NAME":"VIRIDIAN ADVISORY PTY LTD","LICENCE_NUMBER":"34605438042",
  "LICENCE_CONTROLLED_BY":"NATIONAL AUSTRALIA BANK LIMITED [Date Ceased: 21/08/2023] ~ MLC WEALTH LIMITED ~ MELISSA  GOODIN",
  "REP_APPOINTED_BY":"VIRIDIAN FINANCIAL GROUP LTD","REP_APPOINTED_NUM":"000315094"}"#;

    /// The relations the analysis derives from one adviser record, as `(from, kind, to)` over
    /// the entities' display values.
    fn adviser_relations(record: &str) -> Vec<(String, RelationKind, String)> {
        let mut script = empty_script();
        script.insert(
            ADVISER_RES.into(),
            Ok(json_ok(&format!(
                r#"{{"success":true,"result":{{"records":[{record}]}}}}"#
            ))),
        );
        let report = match run(&Fake::new(script), "Marsel Popov", 1) {
            PeopleRun::Printed { report, .. } => report,
            other => panic!("{other:?}"),
        };
        let name = |uid: &str| {
            report
                .entities
                .iter()
                .find(|entity| entity.uid == uid)
                .map(|entity| entity.raw_value.to_ascii_uppercase())
                .expect("relation endpoint is an entity of the report")
        };
        relation::derive_all(&report.entities, "scan")
            .into_iter()
            .filter(|edge| {
                matches!(
                    edge.kind,
                    RelationKind::MemberOf | RelationKind::ControlledBy
                )
            })
            .map(|edge| (name(&edge.from_uid), edge.kind, name(&edge.to_uid)))
            .collect()
    }

    #[test]
    fn an_advisers_licensee_appointing_firm_and_controller_are_relations() {
        let mut relations = adviser_relations(ADVISER_LINKED);
        relations.sort();
        let edge = |from: &str, kind, to: &str| (from.to_owned(), kind, to.to_owned());
        assert_eq!(
            relations,
            vec![
                edge(
                    "MARSEL POPOV",
                    RelationKind::MemberOf,
                    "VIRIDIAN ADVISORY PTY LTD"
                ),
                edge(
                    "MARSEL POPOV",
                    RelationKind::MemberOf,
                    "VIRIDIAN FINANCIAL GROUP LTD"
                ),
                edge(
                    "VIRIDIAN ADVISORY PTY LTD",
                    RelationKind::ControlledBy,
                    "MLC WEALTH LIMITED"
                ),
            ],
            "the controller whose control ceased, and the person who controls the licensee, are \
             entities but not control relations"
        );
    }

    #[test]
    fn a_ceased_authorisation_is_evidence_but_not_a_membership() {
        let ceased = ADVISER_LINKED.replace(
            r#""ADV_ROLE_STATUS":"Current""#,
            r#""ADV_ROLE_STATUS":"Ceased""#,
        );
        let relations = adviser_relations(&ceased);
        assert!(
            !relations
                .iter()
                .any(|(_, kind, _)| *kind == RelationKind::MemberOf),
            "{relations:?}"
        );
        assert!(
            relations
                .iter()
                .any(|(_, kind, _)| *kind == RelationKind::ControlledBy),
            "the licensee's own control does not depend on the adviser's role: {relations:?}"
        );
    }

    #[test]
    fn joined_args_are_the_lookup_name() {
        let fake = Fake::new(empty_script());
        let parsed = PeopleArgs::parse(&["Jane".into(), "Citizen".into()]).unwrap();
        match run(&fake, &parsed.name, 1) {
            PeopleRun::Printed { text, report } => {
                assert!(text.starts_with("entities=0\n"), "{text}");
                assert!(text.contains("asic_persons.banned\tvalid_zero"), "{text}");
                assert!(text.contains("asic_director\tvalid_zero"), "{text}");
                assert!(!text.contains("lineage="), "{text}");
                let entities = &report.entities;
                assert!(entities.is_empty(), "{entities:?}");
                assert_eq!(report.outcomes.len(), PEOPLE_SOURCE_REQUESTS);
            }
            other => panic!("{other:?}"),
        }
        assert_eq!(fake.seen.borrow().len(), PEOPLE_SOURCE_REQUESTS);
    }

    #[test]
    fn valid_zero_report_saves_and_reloads() {
        let fake = Fake::new(empty_script());
        match run(&fake, "Jane Citizen", 1) {
            PeopleRun::Printed { report, .. } => {
                let dir = std::env::temp_dir()
                    .join(format!("huntsman-people-cli-save-{}", std::process::id()));
                let _ = std::fs::remove_dir_all(&dir);
                std::fs::create_dir_all(&dir).unwrap();
                let path = dir.join("people.json");
                let entries = crate::lookup_save::save(
                    &path,
                    &report.entities,
                    &report.outcomes,
                    crate::lookup_save::PEOPLE_POLICY,
                )
                .unwrap();
                assert_eq!(entries.len(), PEOPLE_SOURCE_REQUESTS);
                let loaded = crate::ledger::load_chain(&path).unwrap();
                assert_eq!(loaded, entries);
                let admitted = crate::ledger::admitted(&loaded);
                assert!(admitted.is_empty(), "{admitted:?}");
                let _ = std::fs::remove_dir_all(&dir);
            }
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn director_challenge_does_not_abort_asic_valid_zero() {
        let fake = Fake::new(empty_script()).html("connectonline.asic.gov.au", challenge());
        match run(&fake, "Jane Citizen", 1) {
            PeopleRun::Printed { text, report } => {
                assert!(text.contains("asic_persons.banned\tvalid_zero"), "{text}");
                assert!(
                    text.contains("asic_director\tinconclusive")
                        || text.contains("asic_director\tbot_waf"),
                    "director WAF must be recorded without aborting: {text}"
                );
                assert!(
                    report
                        .outcomes
                        .iter()
                        .any(|o| o.module == "asic_persons.banned" && o.kind.is_accepted()),
                    "{report:?}"
                );
            }
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn all_sources_blocked_is_network() {
        match run(&BlockAll, "Jane Citizen", 1) {
            PeopleRun::Network(msg) => assert!(msg.contains("egress-policy"), "{msg}"),
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn a_people_scan_runs_wikidata_and_attributes_it_to_its_own_component() {
        // A people lookup now also queries Wikidata beside the ASIC registers. An empty search is
        // a clean zero; the saved-ledger provenance must attribute the wikidata outcome to its own
        // canonical component, not the asic_persons default.
        struct WikidataPeople;
        impl Transport for WikidataPeople {
            fn send(&self, request: &Request) -> Result<Response, TransportFailure> {
                let body: &str = if request.url.contains("wbsearchentities") {
                    r#"{"search":[]}"#
                } else {
                    r#"{"success":true,"result":{"records":[],"total":0}}"#
                };
                Ok(json_ok(body))
            }
            fn runs_module(&self, _module: &str) -> bool {
                true
            }
        }
        let report = match run(&WikidataPeople, "Ada Lovelace", 1) {
            PeopleRun::Printed { report, .. } => report,
            other => panic!("{other:?}"),
        };
        assert!(
            report.outcomes.iter().any(|o| o.module == wikidata::SOURCE),
            "the wikidata leg must run for a people scan: {report:?}"
        );
        let ledger = crate::lookup_save::chain(
            &report.entities,
            &report.outcomes,
            crate::lookup_save::PEOPLE_POLICY,
        )
        .unwrap();
        assert!(
            ledger
                .iter()
                .any(|entry| entry.claim.source == wikidata::SOURCE
                    && entry.claim.component == "src/wikidata.rs"),
            "wikidata evidence must persist under src/wikidata.rs, not the asic default"
        );
    }
}
