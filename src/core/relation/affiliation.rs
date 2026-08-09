//! `core::relation::affiliation` — the person↔organisation edge family.
//!
//! # The gap this closes
//! The engine already collects affiliation intelligence in volume: ASIC director
//! searches, OpenCorporates officer records, GLEIF Level 2 corporate families,
//! LinkedIn experience and education, AFS licensees and their controllers, ABR
//! business names, curated wallet labels. Until these builders, every one of
//! those findings landed in the graph as a **disconnected `Organisation` node**.
//! A person scan that established "director of Acme Pty Ltd, registered office
//! 12 Smith St" produced three unlinked nodes and no statement that any of them
//! had anything to do with the subject; the tie survived only as a string inside
//! an evidence attribute, invisible to path-finding, clustering, the network
//! synthesis and the dossier's CONNECTIONS section.
//!
//! # What is derived
//! | Builder | Edge | Direction | Grounded in |
//! |---|---|---|---|
//! | [`derive_officership`] | [`OfficerOf`](RelationKind::OfficerOf) | Person → Org | `asic_director`, `opencorporates` |
//! | [`derive_employment`] | [`EmployedBy`](RelationKind::EmployedBy) | Person → Org | `proxycurl`, `gravatar`, `fullcontact`, `oathnet_pro`, `asic_persons` |
//! | [`derive_membership`] | [`MemberOf`](RelationKind::MemberOf) | Person → Org | `proxycurl` (a listed alma mater) |
//! | [`derive_corporate_control`] | [`ControlledBy`](RelationKind::ControlledBy) | Org → Org/Person | `gleif_lei` (Level 2 consolidation), `asic_persons` (AFS licence control) |
//! | [`derive_asset_operator`] | [`OperatedBy`](RelationKind::OperatedBy) | asset → Org/Domain | `chain_intel` (wallet labels), `employer_pivot` (business contact pages), and the eleven infrastructure modules that name an IP/ASN's operator |
//! | [`derive_org_identity`] | [`IdentifiedBy`](RelationKind::IdentifiedBy) / [`LocatedAt`](RelationKind::LocatedAt) | Org → identifier / place | `asic_director`, `asic_business_names`, `asic_banned_orgs`, `abn_lookup`, `acnc_charities`, `gleif_lei`, `hunter_io` |
//!
//! Each constant below names the exact modules that ground it, so the coverage
//! table above is checkable against the tree rather than taken on trust.
//!
//! # Rules every builder here holds to
//! Identical to the rest of [`super`], and non-negotiable:
//!
//! * **Deterministic** — the edge set and their ids depend only on the entity
//!   slice, never on iteration order. Every builder sorts its output
//!   ([`sort_edges`]) and dedups on the endpoint pair.
//! * **Evidence- or tag-grounded** — an edge is emitted only where a module
//!   actually recorded the tie. Every attribute key in this file is emitted
//!   somewhere in `src/modules`; every tag is one a module actually sets. There
//!   are no speculative keys, because a key nothing emits is dead precision-risk
//!   the day some future module gives it a different meaning.
//! * **Named endpoints only** — both ends must be entities already present in the
//!   set. A registry name that matches nothing links nothing; inventing the
//!   missing endpoint would be fabrication.
//! * **Confidence is carried, and damped where the tie is inferred** — the edge
//!   takes the weaker endpoint's confidence, scaled by
//!   [`SUBJECT_AFFILIATION_DAMP`] on the one path that infers rather than reads
//!   the person (see below).
//!
//! # The two grounding paths, and why one is damped
//! **Named** — the organisation-side record names the person (`director_name =
//! JANE CITIZEN`), or the person-side record names the organisation
//! (`current_companies = Acme Pty Ltd`). Both ends are stated by the source, so
//! the edge carries full endpoint trust.
//!
//! **Subject-scoped** — some modules emit the affiliation as a *tagged
//! organisation* with no back-reference to the person, because the person was
//! the module's own scan target and re-stating them was redundant (`proxycurl`'s
//! `current-employer`, `asic_persons`' `afs-licensee`). The tie is real but the
//! entity set alone does not say *whose* it is, so — exactly as
//! [`derive_identity_ownership`](super::derive_identity_ownership) does for
//! fingerprint-bound handles — it binds only to the scan's SUBJECT Person(s) and
//! is damped. An incidental Person surfaced mid-scan can never accrete the
//! subject's employers.

use crate::core::entity::{Entity, EntityKind};

use super::builders::{by_name, clean_token, sort_edges, subject_persons};
use super::types::{Relation, RelationKind};

/// Evidence keys whose value names a PERSON holding a registered office at the
/// organisation the evidence is attached to.
///
/// Deliberately just these two, and deliberately NOT the generic
/// `PERSON_NAME_ATTRS` the identity builders use: `owner` / `contact_name` /
/// `holder` name someone connected to a record, which is not the same claim as
/// "a registry publishes this person as an officeholder". Widening the list
/// would quietly restate soft ties as filed ones — the precise distinction
/// [`RelationKind::OfficerOf`] exists to make.
///
/// * `director_name` — `asic_director` (ASIC Connect director search)
/// * `officer_name` — `opencorporates` (officer records)
const OFFICER_NAME_ATTRS: &[&str] = &["director_name", "officer_name"];

/// Evidence keys, on a PERSON's own record, whose value names the organisation(s)
/// they work for. `current_companies` is `proxycurl`'s list of the profile's
/// still-open LinkedIn experience entries.
const EMPLOYER_NAME_ATTRS: &[&str] = &["current_companies"];

/// Separator [`EMPLOYER_NAME_ATTRS`] values are joined on by the emitting module
/// (`proxycurl` writes `current.join(", ")`). Split on it so a multi-employer
/// profile links to each employer rather than to a single non-existent
/// `"Acme Pty Ltd, Foo Inc"` organisation.
const EMPLOYER_LIST_SEP: &str = ", ";

/// Evidence keys whose value names the ORGANISATION a record belongs to — the
/// join key for [`derive_org_identity`].
///
/// * `company_name` — `asic_director`, `opencorporates`
/// * `org` — `gleif_lei`, `acnc_charities`
/// * `business_name` — `asic_business_names`
/// * `organisation` — `asic_banned_orgs`
/// * `licensee` — `asic_persons`
/// * `known_name` — `chain_intel`
///
/// `registrant_org` is deliberately ABSENT: a domain's registrant is already the
/// [`RegisteredBy`](RelationKind::RegisteredBy) edge
/// [`derive_registration`](super::derive_registration) emits, and restating it
/// here would double-count one WHOIS fact as two different relations.
const ORG_NAME_ATTRS: &[&str] = &[
    "company_name",
    "org",
    "business_name",
    "organisation",
    "licensee",
    "known_name",
];

/// `(tag, edge)` — an `Organisation` carrying `tag` is an affiliation OF THE
/// SCAN'S SUBJECT, of that edge kind, recorded by a module that had the subject
/// as its own target and so did not repeat the name in an attribute.
///
/// Every entry is a tag a module actually sets, and every module in the tree that
/// mints an employer/education `Organisation` is represented (swept across
/// `src/modules`; a tag is listed only where each setter means precisely this):
/// * `current-employer` — `proxycurl`: a LinkedIn experience with no end date.
/// * `employer` — `gravatar` (a profile's company, with its job title) and
///   `fullcontact` (the top-level organisation plus structured employment).
/// * `employer-field` — `oathnet_pro`: a breach record's
///   `company`/`organization`/`organisation`/`workplace` field.
/// * `afs-licensee` — `asic_persons`: the AFS licensee an adviser operates under.
/// * `authorised-rep-firm` — `asic_persons`: the corporate authorised
///   representative that appointed the adviser.
/// * `education` — `proxycurl`: a listed alma mater.
const SUBJECT_AFFILIATION_TAGS: &[(&str, RelationKind)] = &[
    ("current-employer", RelationKind::EmployedBy),
    ("employer", RelationKind::EmployedBy),
    ("employer-field", RelationKind::EmployedBy),
    ("afs-licensee", RelationKind::EmployedBy),
    ("authorised-rep-firm", RelationKind::EmployedBy),
    ("education", RelationKind::MemberOf),
];

/// Confidence damp for a SUBJECT-SCOPED affiliation edge
/// ([`SUBJECT_AFFILIATION_TAGS`]). The affiliation itself is sourced, but the
/// binding to *this* Person is inferred from the entity being the scan's subject
/// rather than read off the record, so it grades below a named tie — the same
/// treatment, and for the same reason, as the fingerprint path in
/// [`derive_identity_ownership`](super::derive_identity_ownership).
///
/// Above that path's damp (0.6) on purpose: a subject-scoped organisation was
/// emitted by a module dispatched ON the subject, so the inference is "which of
/// the scan's people does this belong to" — much narrower than "does this handle
/// belong to this person at all".
const SUBJECT_AFFILIATION_DAMP: f64 = 0.75;

/// Evidence attribute naming the organisation a GLEIF Level 2 relative was
/// reached THROUGH — the seed of the corporate family (`gleif_lei`).
const CORPORATE_VIA_ORG_ATTR: &str = "via_org";

/// Evidence attribute carrying which Level 2 role the relative plays, so the
/// edge can be oriented child → controller rather than merely "related"
/// (`gleif_lei`). Values are the module's own `Kinship::tag()` strings.
const CORPORATE_ROLE_ATTR: &str = "relationship_role";

/// The [`CORPORATE_ROLE_ATTR`] values meaning "the relative stands ABOVE the
/// seed" — the seed is the child, the relative the controller.
const ROLES_RELATIVE_IS_PARENT: &[&str] = &["corporate-parent", "ultimate-parent"];

/// The [`CORPORATE_ROLE_ATTR`] value meaning "the relative sits BELOW the seed" —
/// the edge flips, because it is the relative that is controlled.
const ROLE_RELATIVE_IS_CHILD: &str = "corporate-subsidiary";

/// Evidence attribute naming the ORGANISATION that the entity carrying it
/// controls — `asic_persons` records the AFS licensee under a controller entity
/// (which may itself be an `Organisation` or a `Person`). The edge is emitted
/// licensee → controller, i.e. the inverse of where the attribute lives.
const CONTROLS_ATTR: &str = "controls_licensee";

/// Evidence attribute naming the ORGANISATION that operates the asset carrying
/// it — `chain_intel` writes Blockscout's curated label onto the `CryptoAddress`
/// as well as onto the label's own `Organisation` entity.
const ASSET_OPERATOR_ORG_ATTR: &str = "known_name";

/// Evidence attribute naming the employer DOMAIN whose own contact pages
/// published the business contact point carrying it (`employer_pivot`). The site
/// is the operator's published identity, so the asset links to the Domain.
const ASSET_OPERATOR_DOMAIN_ATTR: &str = "employer_domain";

/// Infrastructure kinds an `Organisation`'s evidence can NAME as the network it
/// operates — the widest single source family in the tree.
///
/// **Eleven modules** mint an `Organisation` for the operator / ISP / hosting
/// provider / ASN holder behind an address or an autonomous system, and every one
/// of them writes the asset into the evidence by the same convention the DNS
/// modules use for [`derive_resolution`](super::derive_resolution) — in the
/// summary text: `shodan` ("Organisation for {ip}", "ISP for {ip}"), `censys`
/// ("Network operator for {ip}"), `criminal_ip` and `ip_geo` and `ip_whois_geo`
/// ("IP org for {ip}"), `ip_registry` ("Operator of {asn_label}", plus an `asn`
/// attribute), `netlas`, `zoomeye`, `abuseipdb`, `ipqs`, `ripestat`. Until this
/// path, every one of those organisations was an orphan node: the scan knew
/// "Cloudflare" was *somewhere* in the result set but not that it ran the address.
///
/// `Domain` is deliberately EXCLUDED, and that exclusion is the precision gate.
/// An IP literal, a CIDR prefix and an `AS####` label appear in an
/// `Organisation`'s evidence for exactly one reason — a module recorded that
/// organisation as the network's operator. A DOMAIN appears in an organisation's
/// evidence for a dozen unrelated reasons (a registrant record, a search hit, a
/// canonical site), so matching one would mint operator claims the source never
/// made. Domains reach their organisation through the attribute-keyed paths
/// instead ([`ORG_OWNED_IDENTIFIER_ATTRS`] / [`ORG_NAME_ATTRS`]).
const OPERATED_ASSET_KINDS: &[EntityKind] =
    &[EntityKind::IpAddress, EntityKind::Cidr, EntityKind::Asn];

/// Evidence attribute, on an `Organisation`, naming the autonomous system it
/// operates (`ip_geo`, `ip_registry`). Read as a keyed attribute in addition to
/// the summary sweep because these two modules put the ASN ONLY here.
///
/// Kept to this ONE key rather than sweeping every attribute value: an
/// organisation's evidence can carry an address for reasons that are not
/// operatorship (a registrant record's `resolved_ips`, say), and a keyed `asn`
/// is an unambiguous operator assertion where an arbitrary attribute is not.
const ASSET_OPERATOR_ASN_ATTR: &str = "asn";

/// Identifier kinds an `Organisation` can be [`IdentifiedBy`](RelationKind::IdentifiedBy).
///
/// `AbnAcn` is the registry number; `Domain` / `Url` the organisation's web
/// identity; `Email` / `Phone` its published contact points. `Username` is
/// excluded — a handle is a persona, and the persona layer
/// ([`AliasOf`](RelationKind::AliasOf) / [`SameIdentity`](RelationKind::SameIdentity))
/// already models it.
const ORG_IDENTIFIER_KINDS: &[EntityKind] = &[
    EntityKind::AbnAcn,
    EntityKind::Domain,
    EntityKind::Url,
    EntityKind::Email,
    EntityKind::Phone,
];

/// Evidence attributes, on an `ORGANISATION`, whose value is that organisation's
/// OWN identifier — the reverse of [`ORG_NAME_ATTRS`], which reads the same tie
/// off the identifier's record instead.
///
/// Both directions are needed because the modules split on which side they stamp:
/// `hunter_io` resolves an organisation for a domain and writes `domain` onto the
/// ORGANISATION; `asic_director` writes `company_name` onto the ACN. Reading only
/// one side would silently drop every source that chose the other.
///
/// * `abn` — `abn_lookup`, `asic_business_names` (the org's own ABN)
/// * `acn` — `asic_director`, `asic_banned_orgs` (the org's own ACN)
/// * `domain` — `hunter_io` (the organisation's canonical domain)
const ORG_OWNED_IDENTIFIER_ATTRS: &[&str] = &["abn", "acn", "domain"];

/// Place kinds an `Organisation` can be [`LocatedAt`](RelationKind::LocatedAt) —
/// the same pair the person-side [`derive_residency`](super::derive_residency)
/// uses, so a registered office and a residence are modelled identically.
const ORG_PLACE_KINDS: &[EntityKind] = &[EntityKind::Address, EntityKind::Coordinates];

/// Every distinct, trimmed, non-empty value of the evidence attributes in
/// `attrs` on `e`, in stable (evidence, attribute) order.
///
/// Shared by every builder in this file so they can't drift on attribute
/// matching (case-insensitive), trimming, or ordering.
fn attr_values<'a>(e: &'a Entity, attrs: &[&str]) -> Vec<&'a str> {
    use std::collections::HashSet;

    let mut seen: HashSet<&str> = HashSet::new();
    let mut out: Vec<&str> = Vec::new();
    for ev in &e.evidence {
        for (k, v) in &ev.attributes {
            if !attrs.iter().any(|a| k.eq_ignore_ascii_case(a)) {
                continue;
            }
            let v = v.trim();
            if !v.is_empty() && seen.insert(v) {
                out.push(v);
            }
        }
    }
    out
}

/// The first value of the `attr` evidence attribute on `e`, trimmed, or `None`
/// when absent or blank. For the attributes a module writes at most once per
/// evidence record (`relationship_role`, `via_org`).
fn attr_value<'a>(e: &'a Entity, attr: &str) -> Option<&'a str> {
    e.evidence
        .iter()
        .flat_map(|ev| &ev.attributes)
        .find(|(k, v)| k.eq_ignore_ascii_case(attr) && !v.trim().is_empty())
        .map(|(_, v)| v.trim())
}

/// Push `from → to` of `kind` unless the pair is a self-loop or already emitted,
/// carrying the weaker endpoint's confidence scaled by `damp`.
///
/// The single emission point for this file: every builder routes through it, so
/// dedup, self-loop rejection and the confidence rule are stated once.
fn push_edge(
    out: &mut Vec<Relation>,
    seen: &mut std::collections::HashSet<(String, String)>,
    from: &Entity,
    to: &Entity,
    kind: RelationKind,
    damp: f64,
    scan_id: &str,
) {
    if from.uid == to.uid || !seen.insert((from.uid.clone(), to.uid.clone())) {
        return;
    }
    out.push(Relation::new(
        from.uid.as_str(),
        to.uid.as_str(),
        kind,
        from.confidence.min(to.confidence) * damp,
        scan_id,
    ));
}

/// Derive [`OfficerOf`](RelationKind::OfficerOf) edges (Person → Organisation)
/// from a companies register that PUBLISHES the officeholder.
///
/// Reads the organisation side: an `Organisation` whose evidence carries
/// [`OFFICER_NAME_ATTRS`] naming a Person present in the scan. That is exactly
/// how the two grounding modules record it — `asic_director` attaches
/// `director_name` + `company_name` to every entity it mints from a result row,
/// and `opencorporates` attaches `officer_name` + `officer_position` to the
/// company it found the officer at.
///
/// Any present Person may be the officer, not just the subject: a register that
/// names someone has attributed them itself, and an officer surfaced alongside
/// the subject (a co-director) is precisely the associate the graph should show.
/// Deduped per (person, org); deterministic output order.
pub fn derive_officership(entities: &[Entity], scan_id: &str) -> Vec<Relation> {
    use std::collections::HashSet;

    let person_by_name = by_name(entities, &EntityKind::Person);
    if person_by_name.is_empty() {
        return Vec::new();
    }

    let mut seen: HashSet<(String, String)> = HashSet::new();
    let mut out = Vec::new();
    for org in entities
        .iter()
        .filter(|e| e.kind == EntityKind::Organisation)
    {
        for name in attr_values(org, OFFICER_NAME_ATTRS) {
            if let Some(&p) = person_by_name.get(name.to_lowercase().as_str()) {
                push_edge(
                    &mut out,
                    &mut seen,
                    p,
                    org,
                    RelationKind::OfficerOf,
                    1.0,
                    scan_id,
                );
            }
        }
    }
    sort_edges(&mut out);
    out
}

/// Derive [`EmployedBy`](RelationKind::EmployedBy) edges (Person → Organisation).
///
/// Two grounded paths, the named one preferred:
///   * **named** — the Person's own record lists their employers
///     ([`EMPLOYER_NAME_ATTRS`], split on [`EMPLOYER_LIST_SEP`]); each listed name
///     that matches a present `Organisation` links at full endpoint trust.
///   * **subject-scoped** — an `Organisation` tagged as an employer
///     ([`SUBJECT_AFFILIATION_TAGS`]) links to the scan's subject Person(s),
///     damped by [`SUBJECT_AFFILIATION_DAMP`]. Skipped for a pair the named path
///     already linked, so a profile-listed employer is never downgraded by also
///     being tagged.
///
/// Deduped per (person, org); deterministic output order.
pub fn derive_employment(entities: &[Entity], scan_id: &str) -> Vec<Relation> {
    derive_person_affiliation(entities, scan_id, RelationKind::EmployedBy)
}

/// Derive [`MemberOf`](RelationKind::MemberOf) edges (Person → Organisation) — an
/// affiliation that is neither employment nor a registered office: a listed alma
/// mater, a professional body's register.
///
/// Subject-scoped only ([`SUBJECT_AFFILIATION_TAGS`], damped by
/// [`SUBJECT_AFFILIATION_DAMP`]): the grounding modules record a membership as a
/// tagged `Organisation` on the subject's own profile and no source in the tree
/// currently publishes a *member name* attribute the way the registers publish an
/// officer name. If one lands, it belongs on the named path in
/// [`derive_person_affiliation`], not in a new builder.
pub fn derive_membership(entities: &[Entity], scan_id: &str) -> Vec<Relation> {
    derive_person_affiliation(entities, scan_id, RelationKind::MemberOf)
}

/// The shared Person → Organisation affiliation pass, run once per edge `kind`.
///
/// Both paths in one function so the named path can suppress the damped one for
/// the same pair — the ordering guarantee that keeps a profile-listed employer at
/// full trust. `kind` selects which [`SUBJECT_AFFILIATION_TAGS`] rows apply and,
/// for [`EmployedBy`](RelationKind::EmployedBy), whether the named path runs at
/// all (the employer attributes are employment-specific).
fn derive_person_affiliation(
    entities: &[Entity],
    scan_id: &str,
    kind: RelationKind,
) -> Vec<Relation> {
    use std::collections::HashSet;

    let subjects = subject_persons(entities);
    let org_by_name = by_name(entities, &EntityKind::Organisation);
    if org_by_name.is_empty() {
        return Vec::new();
    }

    let mut seen: HashSet<(String, String)> = HashSet::new();
    let mut out = Vec::new();

    // ── Named: the person's own record lists the organisation ────────────
    if kind == RelationKind::EmployedBy {
        for p in entities.iter().filter(|e| e.kind == EntityKind::Person) {
            for listed in attr_values(p, EMPLOYER_NAME_ATTRS) {
                for name in listed.split(EMPLOYER_LIST_SEP).map(str::trim) {
                    if let Some(&org) = org_by_name.get(name.to_lowercase().as_str()) {
                        push_edge(&mut out, &mut seen, p, org, kind, 1.0, scan_id);
                    }
                }
            }
        }
    }

    // ── Subject-scoped: a tagged organisation binds to the subject ───────
    if !subjects.is_empty() {
        let tags: Vec<&str> = SUBJECT_AFFILIATION_TAGS
            .iter()
            .filter(|(_, k)| *k == kind)
            .map(|(t, _)| *t)
            .collect();
        for org in entities
            .iter()
            .filter(|e| e.kind == EntityKind::Organisation)
            .filter(|e| tags.iter().any(|t| e.has_tag(t)))
        {
            for s in &subjects {
                push_edge(
                    &mut out,
                    &mut seen,
                    s,
                    org,
                    kind,
                    SUBJECT_AFFILIATION_DAMP,
                    scan_id,
                );
            }
        }
    }

    sort_edges(&mut out);
    out
}

/// Derive [`ControlledBy`](RelationKind::ControlledBy) edges — the corporate
/// hierarchy, oriented child → controller so a chain of them walks UP the tree.
///
/// Two registers ground it, and both record the edge on the RELATIVE rather than
/// on the entity being described, so each needs its own orientation rule:
///
/// * **GLEIF Level 2** (`gleif_lei`) — a relative carries
///   [`CORPORATE_VIA_ORG_ATTR`] naming the seed it was reached through, plus
///   [`CORPORATE_ROLE_ATTR`] saying which way the consolidation runs. A
///   `corporate-parent` / `ultimate-parent` relative stands above the seed
///   (`seed → relative`); a `corporate-subsidiary` relative sits below it
///   (`relative → seed`). An unrecognised role value links nothing — GLEIF could
///   add a relationship type whose direction this code has not been taught, and
///   guessing would invert an ownership claim.
/// * **ASIC AFS licence control** (`asic_persons`) — a controller entity carries
///   [`CONTROLS_ATTR`] naming the licensee `Organisation` it controls, so the
///   edge runs `licensee → controller`. The controller may itself be a Person
///   (an individual controlling a licence), which the edge permits.
///
/// Full endpoint trust: both are register-published relationships, not
/// inferences. Deduped per (child, controller); deterministic output order.
pub fn derive_corporate_control(entities: &[Entity], scan_id: &str) -> Vec<Relation> {
    use std::collections::HashSet;

    let org_by_name = by_name(entities, &EntityKind::Organisation);
    if org_by_name.is_empty() {
        return Vec::new();
    }

    let mut seen: HashSet<(String, String)> = HashSet::new();
    let mut out = Vec::new();

    // ── GLEIF Level 2 corporate family ───────────────────────────────────
    for relative in entities
        .iter()
        .filter(|e| e.kind == EntityKind::Organisation)
    {
        let (Some(via), Some(role)) = (
            attr_value(relative, CORPORATE_VIA_ORG_ATTR),
            attr_value(relative, CORPORATE_ROLE_ATTR),
        ) else {
            continue;
        };
        let Some(&seed) = org_by_name.get(via.to_lowercase().as_str()) else {
            continue;
        };
        let pair = if ROLES_RELATIVE_IS_PARENT.iter().any(|r| r == &role) {
            (seed, relative)
        } else if role == ROLE_RELATIVE_IS_CHILD {
            (relative, seed)
        } else {
            // An unmapped relationship role: direction unknown, so no edge.
            continue;
        };
        push_edge(
            &mut out,
            &mut seen,
            pair.0,
            pair.1,
            RelationKind::ControlledBy,
            1.0,
            scan_id,
        );
    }

    // ── ASIC AFS licence control ─────────────────────────────────────────
    for controller in entities {
        for licensee_name in attr_values(controller, &[CONTROLS_ATTR]) {
            if let Some(&licensee) = org_by_name.get(licensee_name.to_lowercase().as_str()) {
                push_edge(
                    &mut out,
                    &mut seen,
                    licensee,
                    controller,
                    RelationKind::ControlledBy,
                    1.0,
                    scan_id,
                );
            }
        }
    }

    sort_edges(&mut out);
    out
}

/// Derive [`OperatedBy`](RelationKind::OperatedBy) edges (asset → operator) — the
/// edge that NAMES who runs an asset.
///
/// * **Curated wallet label** ([`ASSET_OPERATOR_ORG_ATTR`], `chain_intel`) — the
///   asset carries the label that a present `Organisation` entity was minted
///   from, so the address links to the exchange / service behind it. Restricted
///   to non-`Organisation` assets so the label's own entity can't self-link.
/// * **Employer site contact page** ([`ASSET_OPERATOR_DOMAIN_ATTR`],
///   `employer_pivot`) — a business Phone / Address / Email / Url extracted from
///   a company's own site carries the domain it was published on, so the contact
///   point links to that site's `Domain`. Restricted to non-`Domain` assets for
///   the same reason.
/// * **Named network operator** ([`OPERATED_ASSET_KINDS`]) — an `Organisation`
///   whose evidence NAMES an IP / CIDR / ASN present in the scan, either in the
///   summary (the convention all eleven infrastructure modules follow, mined with
///   the same tokeniser [`derive_resolution`](super::derive_resolution) uses) or
///   in a keyed [`ASSET_OPERATOR_ASN_ATTR`]. The edge runs asset → organisation,
///   so an address resolves to the provider that runs it.
///
/// Full endpoint trust: in every case the source published the asset AS the
/// operator's, rather than the engine inferring it. Deduped per (asset,
/// operator); deterministic output order.
pub fn derive_asset_operator(entities: &[Entity], scan_id: &str) -> Vec<Relation> {
    use std::collections::{HashMap, HashSet};

    let org_by_name = by_name(entities, &EntityKind::Organisation);
    let domain_by_name = by_name(entities, &EntityKind::Domain);
    // Infrastructure assets keyed by their stored (already normalised) value, so
    // a summary token can be matched exactly — the same index shape, and the same
    // exact-match-only rule, as `derive_resolution`'s domain lookup. Keying on the
    // bare value is safe here (unlike the identifier index in
    // [`derive_org_identity`]) because the three kinds' value shapes are
    // structurally disjoint: a CIDR needs a `/`, an ASN is `AS`-prefixed, and
    // neither is a parseable IP literal — so no two can collide on one key.
    let asset_by_value: HashMap<&str, &Entity> = entities
        .iter()
        .filter(|e| OPERATED_ASSET_KINDS.contains(&e.kind))
        .map(|e| (e.value.as_str(), e))
        .collect();
    if org_by_name.is_empty() && domain_by_name.is_empty() {
        return Vec::new();
    }

    let mut seen: HashSet<(String, String)> = HashSet::new();
    let mut out = Vec::new();

    // ── Named network operator: the organisation names what it runs ──────
    if !asset_by_value.is_empty() {
        for org in entities
            .iter()
            .filter(|e| e.kind == EntityKind::Organisation)
        {
            for ev in &org.evidence {
                let named = ev.summary.split_whitespace().map(clean_token).chain(
                    ev.attributes
                        .iter()
                        .filter(|(k, _)| k.eq_ignore_ascii_case(ASSET_OPERATOR_ASN_ATTR))
                        .map(|(_, v)| v.trim()),
                );
                for token in named {
                    if let Some(&asset) = asset_by_value.get(token) {
                        push_edge(
                            &mut out,
                            &mut seen,
                            asset,
                            org,
                            RelationKind::OperatedBy,
                            1.0,
                            scan_id,
                        );
                    }
                }
            }
        }
    }

    for asset in entities {
        if asset.kind != EntityKind::Organisation {
            for label in attr_values(asset, &[ASSET_OPERATOR_ORG_ATTR]) {
                if let Some(&org) = org_by_name.get(label.to_lowercase().as_str()) {
                    push_edge(
                        &mut out,
                        &mut seen,
                        asset,
                        org,
                        RelationKind::OperatedBy,
                        1.0,
                        scan_id,
                    );
                }
            }
        }
        if asset.kind != EntityKind::Domain {
            for host in attr_values(asset, &[ASSET_OPERATOR_DOMAIN_ATTR]) {
                // Fold the host exactly as the Domain entity normaliser does, so a
                // `www.`-prefixed or mixed-case attribute still finds its node.
                let key = crate::core::entity::normalise(&EntityKind::Domain, host);
                if let Some(&d) = domain_by_name.get(key.as_str()) {
                    push_edge(
                        &mut out,
                        &mut seen,
                        asset,
                        d,
                        RelationKind::OperatedBy,
                        1.0,
                        scan_id,
                    );
                }
            }
        }
    }
    sort_edges(&mut out);
    out
}

/// Derive an ORGANISATION's own identity and place edges — the organisational
/// mirror of [`derive_identity_ownership`](super::derive_identity_ownership) and
/// [`derive_residency`](super::derive_residency), which bind identifiers and
/// places to a *Person* only.
///
/// Emits both [`IdentifiedBy`](RelationKind::IdentifiedBy) (Org → its ABN/ACN,
/// domain, site, email or phone — [`ORG_IDENTIFIER_KINDS`]) and
/// [`LocatedAt`](RelationKind::LocatedAt) (Org → its registered office /
/// registered address — [`ORG_PLACE_KINDS`]), reading the tie from **whichever
/// side the source stamped it on**:
///   * the record names its organisation ([`ORG_NAME_ATTRS`]) — `asic_director`
///     attaches `company_name` to every entity it mints from a result row,
///     `gleif_lei` / `acnc_charities` / `asic_business_names` do the same with
///     their own key;
///   * the organisation names its own identifier
///     ([`ORG_OWNED_IDENTIFIER_ATTRS`]) — `hunter_io` resolves an organisation
///     for a domain and stamps `domain` on the ORGANISATION, `abn_lookup` stamps
///     the org's own `abn`.
///
/// Reading only one direction would silently drop every source that chose the
/// other, which is why both run here rather than in separate builders.
///
/// This is what turns `asic_director`'s output from four unlinked nodes into a
/// company with an ACN and a registered office. Full endpoint trust — the
/// register stated the ownership. Deduped per (org, other); deterministic output
/// order.
pub fn derive_org_identity(entities: &[Entity], scan_id: &str) -> Vec<Relation> {
    use std::collections::{HashMap, HashSet};

    let org_by_name = by_name(entities, &EntityKind::Organisation);
    if org_by_name.is_empty() {
        return Vec::new();
    }
    // Identifier entities keyed by `(kind, stored value)` for the
    // organisation-side direction — exact match only, so a stray attribute can
    // never invent an endpoint.
    //
    // The KIND is part of the key deliberately. Two identifier kinds can share a
    // value (the `_` arm of the entity normaliser leaves an `AbnAcn` untouched,
    // so nothing stops one from carrying a domain-shaped string), and a
    // value-only index would then keep whichever the slice happened to yield
    // last — an order-dependent endpoint, which this layer must never have.
    // Within one kind a duplicate is impossible: same kind + same normalised
    // value IS the same uid, so entities dedup before they get here.
    let identifier_by_value: HashMap<(&EntityKind, &str), &Entity> = entities
        .iter()
        .filter(|e| ORG_IDENTIFIER_KINDS.contains(&e.kind))
        .map(|e| ((&e.kind, e.value.as_str()), e))
        .collect();

    let mut seen: HashSet<(String, String)> = HashSet::new();
    let mut out = Vec::new();

    // ── Record-side: the identifier / place names its organisation ───────
    for e in entities {
        let kind = if ORG_IDENTIFIER_KINDS.contains(&e.kind) {
            RelationKind::IdentifiedBy
        } else if ORG_PLACE_KINDS.contains(&e.kind) {
            RelationKind::LocatedAt
        } else {
            continue;
        };
        for name in attr_values(e, ORG_NAME_ATTRS) {
            if let Some(&org) = org_by_name.get(name.to_lowercase().as_str()) {
                push_edge(&mut out, &mut seen, org, e, kind, 1.0, scan_id);
            }
        }
    }

    // ── Organisation-side: the organisation names its own identifier ─────
    for org in entities
        .iter()
        .filter(|e| e.kind == EntityKind::Organisation)
    {
        for raw in attr_values(org, ORG_OWNED_IDENTIFIER_ATTRS) {
            // Fold the attribute the way each candidate kind's own entity
            // normaliser folds a value, so a `www.`-prefixed or mixed-case
            // identifier still finds its node — and so this builder never
            // invents a fold of its own.
            let found = ORG_IDENTIFIER_KINDS.iter().find_map(|k| {
                let key = crate::core::entity::normalise(k, raw);
                identifier_by_value.get(&(k, key.as_str())).copied()
            });
            if let Some(id) = found {
                push_edge(
                    &mut out,
                    &mut seen,
                    org,
                    id,
                    RelationKind::IdentifiedBy,
                    1.0,
                    scan_id,
                );
            }
        }
    }

    sort_edges(&mut out);
    out
}

#[cfg(test)]
mod tests;
