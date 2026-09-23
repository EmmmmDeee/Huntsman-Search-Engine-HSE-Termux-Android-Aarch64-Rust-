//! The precision authority: how finely a `Coordinates` value locates anything,
//! graded from the provenance of its evidence rather than from its six printed
//! decimals.
//!
//! # Why provenance, and why the COARSEST row
//!
//! A coordinate's value never says how it was made. `-33.868800,151.209300`
//! looks like a doorway; it is the Sydney row of `util::city_coords`, minted by
//! a search snippet that said "Sydney". The only honest source of precision is
//! the evidence: which module produced the value, and what that module said it
//! matched (`place_type`, `feature_code`, an accuracy radius, the address it
//! was asked to geocode).
//!
//! Every originating record on one entity is an account of ONE datum — entities
//! merge by value, so identical six-decimal values from different origins are
//! the same point. If any of those accounts says "this is a city centroid",
//! then the point is a city centroid, however confidently a sibling record
//! reports a street: the centroid explanation is what makes the values
//! identical. So [`assess`] takes the coarsest originating record, never the
//! finest (the correlator's old `min` read a centroid's `geocode` leg as a 40 m
//! rooftop). The single exemption is a MEASURED fix (a device GPS, a photo, a
//! Wi-Fi survey good to a street or better): a measurement is an observation
//! of this very point with its own error bar, so neither a coarser account
//! from a non-measuring source nor a gazetteer coincidence overrides it — only
//! the measurements themselves (the coarsest of them) and the value's own
//! printed decimals grade it. The converse case is a COUNTRY signal (a phone
//! prefix, an email's ccTLD): it is not an account of the value at all, only
//! of a country, minted at a stand-in that is some real city's row — so it
//! grades a point only when nothing else on it explains the value. Any other
//! originating record does, whether or not its source is classified: nothing
//! lands on a city's row to six decimals except by looking that city up.
//!
//! # What is not an account of the point
//!
//! Annotators — facts a module looked up BY the point (its statistical area,
//! its cadastral parcel, its sunrise, the Wi-Fi density around it) and the
//! engine's own bookkeeping records — say nothing about how precise the point
//! is, so they never set its precision ([`is_annotator_row`]). The modules that
//! accept a `Coordinates` target are listed, with what they leave on the point
//! they were asked about, in [`COORDINATE_TARGET_MODULES`]; a registry test
//! keeps that table complete.

use crate::core::correlator::{
    GeoSourceClass, class_locates_subject_directly, geo_source_class, is_anchoring_geo_source,
    precision_radius_m,
};
use crate::core::entity::{Entity, EntityKind, Evidence};
use crate::util::city_coords::TabulatedCentroid;
use crate::util::place_grain::{AdminGrain, StreetGrain, is_name_of_queried_place, place_naming};

/// Prefix of the `fix-grain:<grain>` tag the engine's admission stamp writes on
/// a `Coordinates` [`assess`] grades as an area ([`FixPrecision::is_area`]) —
/// `fix-grain:locality`, `fix-grain:suburb`, … — so a reader of the event log,
/// an export or a recalled scan sees the grain the point was admitted at, and
/// [`assess`] reads it back as a floor that no later re-grading can go below.
pub const FIX_GRAIN_TAG_PREFIX: &str = "fix-grain:";

/// Reduce `tags` to ONE `fix-grain:` stamp, the coarsest — the grain a point
/// admitted at several grains honestly has, since [`assess`] reads every stamp
/// as a floor and so already grades it at the coarsest.
///
/// The engine re-decides the stamp on every in-memory merge
/// (`engine::enrich::enrich_geospatial`), but a store merge unions tags: a
/// point checkpointed at `fix-grain:locality` and re-stamped `fix-grain:region`
/// in a later round was written back carrying both, so the JSON, CSV and GEXF
/// tag columns showed two contradictory grains for one point — and a scan
/// recovered from its event log (which re-runs the enrichment) showed one. The
/// store calls this after each merge. Order of the other tags is untouched;
/// the kept stamp takes the first stamp's position. Pure, idempotent.
pub fn collapse_fix_grain_tags(tags: &mut Vec<String>) {
    let coarsest = tags
        .iter()
        .filter_map(|t| {
            t.strip_prefix(FIX_GRAIN_TAG_PREFIX)
                .and_then(FixGrain::parse)
        })
        .max();
    let Some(coarsest) = coarsest else {
        return;
    };
    let keep = coarsest.tag();
    let mut kept = false;
    tags.retain_mut(|t| {
        if !t.starts_with(FIX_GRAIN_TAG_PREFIX) {
            return true;
        }
        if kept {
            return false;
        }
        kept = true;
        t.clone_from(&keep);
        true
    });
}

/// Prefix of the `fix-radius:<metres>m` tag HSE's CSV importer writes on a
/// re-imported `Coordinates` — the radius the exporting scan graded the point
/// at, from the export's `fix_radius_m` column. [`assess`] reads it back as a
/// radius floor.
///
/// Why the grade must travel: the CSV carries each record's source and
/// summary, but not its attributes, so a re-imported record is graded by its
/// source class alone. A beaconDB fix recorded at `accuracy_m=1500` (a suburb,
/// ±2 km) came back as the Wi-Fi class default, 75 m — a street, labelled
/// "±80 m", 25x finer than the scan that found it; a forward geocode capped at
/// its input came back as a 40 m rooftop. A floor only ever coarsens, so a
/// re-import can lose precision it cannot reconstruct but never gain any.
pub const FIX_RADIUS_TAG_PREFIX: &str = "fix-radius:";

/// The radius [`assess`] grades a `Coordinates` entity at, rounded UP to a
/// whole metre — `None` for any other kind, an unparseable value, or a point
/// with no radius at all (a country signal, [`FixBasis::CountrySignal`]). The
/// CSV export's `fix_radius_m` column, which the importer carries back as a
/// floor ([`FIX_RADIUS_TAG_PREFIX`]). A plain ceiling, not the
/// one-significant-figure display rounding: that keeps a rung floor such as
/// `5000.000…1` on "5 km", and a floor of `5000` would re-import a locality as
/// a suburb.
///
/// A country signal's cell is EMPTY rather than a number: it claims no disc,
/// and any finite figure would be one (`u64::MAX` metres would be a nonsense
/// disc bigger than the Earth). Its grade still travels, because the tags
/// that make it a country signal ([`COUNTRY_SIGNAL_TAGS`]) are in the export's
/// tag column and the importer keeps them.
#[must_use]
#[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)] // ≥ 0, ≤ Earth.
pub fn fix_radius_ceil_m(e: &Entity) -> Option<u64> {
    if e.kind != EntityKind::Coordinates || crate::util::geohash::parse_coords(&e.value).is_none() {
        return None;
    }
    let r = assess(e).radius_m;
    r.is_finite().then(|| r.max(0.0).ceil() as u64)
}

/// The `fix-radius:<metres>m` tag ([`FIX_RADIUS_TAG_PREFIX`]) for `metres`.
#[must_use]
pub fn fix_radius_tag(metres: u64) -> String {
    format!("{FIX_RADIUS_TAG_PREFIX}{metres}m")
}

/// The rungs a coordinate's precision is graded on, finest first. `Ord`, so the
/// `max` of two grains is the coarser.
///
/// Each rung is the largest radius it admits ([`FixGrain::ceiling_m`]): a
/// point is good to 50 m, a street to 300 m, a suburb to 5 km, a locality (a
/// town or city) to 30 km, a region (a state, a district) to 150 km; beyond
/// that, only the country is known.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum FixGrain {
    /// ≤ 50 m — a building or a doorway.
    Point,
    /// ≤ 300 m — a street or a block.
    Street,
    /// ≤ 5 km — a suburb or a postcode.
    Suburb,
    /// ≤ 30 km — a town or a city.
    Locality,
    /// ≤ 150 km — a state, province or district.
    Region,
    /// Beyond 150 km — the country and nothing finer.
    Country,
}

impl FixGrain {
    /// Every rung, finest first.
    pub const ALL: [Self; 6] = [
        Self::Point,
        Self::Street,
        Self::Suburb,
        Self::Locality,
        Self::Region,
        Self::Country,
    ];

    /// The largest radius (metres) this rung admits; `None` for
    /// [`FixGrain::Country`], which is unbounded.
    #[must_use]
    pub const fn ceiling_m(self) -> Option<f64> {
        match self {
            Self::Point => Some(50.0),
            Self::Street => Some(300.0),
            Self::Suburb => Some(5_000.0),
            Self::Locality => Some(30_000.0),
            Self::Region => Some(150_000.0),
            Self::Country => None,
        }
    }

    /// The rung a radius falls on: the finest whose ceiling admits it.
    #[must_use]
    pub fn from_radius_m(radius_m: f64) -> Self {
        Self::ALL
            .into_iter()
            .find(|g| g.ceiling_m().is_none_or(|c| radius_m <= c))
            .unwrap_or(Self::Country)
    }

    /// The smallest radius graded on this rung — the next representable value
    /// above the finer rung's ceiling — so a floor raised to a rung lands ON it
    /// (`from_radius_m(g.floor_m()) == g`) without inventing a larger figure.
    #[must_use]
    pub fn floor_m(self) -> f64 {
        match self {
            Self::Point => 0.0,
            Self::Street => 50.0_f64.next_up(),
            Self::Suburb => 300.0_f64.next_up(),
            Self::Locality => 5_000.0_f64.next_up(),
            Self::Region => 30_000.0_f64.next_up(),
            Self::Country => 150_000.0_f64.next_up(),
        }
    }

    /// One rung coarser; [`FixGrain::Country`] stays.
    #[must_use]
    pub const fn coarser(self) -> Self {
        match self {
            Self::Point => Self::Street,
            Self::Street => Self::Suburb,
            Self::Suburb => Self::Locality,
            Self::Locality => Self::Region,
            Self::Region | Self::Country => Self::Country,
        }
    }

    /// The lowercase name used in the `fix-grain:` tag.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Point => "point",
            Self::Street => "street",
            Self::Suburb => "suburb",
            Self::Locality => "locality",
            Self::Region => "region",
            Self::Country => "country",
        }
    }

    /// Inverse of [`FixGrain::as_str`].
    #[must_use]
    pub fn parse(s: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|g| g.as_str() == s)
    }

    /// The `fix-grain:<grain>` tag ([`FIX_GRAIN_TAG_PREFIX`]).
    #[must_use]
    pub fn tag(self) -> String {
        format!("{FIX_GRAIN_TAG_PREFIX}{}", self.as_str())
    }
}

/// What kind of account decided a coordinate's precision.
///
/// `Ord` in the order a tie between two equally coarse accounts is broken — the
/// later variant wins — so the most explanatory account names the basis: a
/// centroid explains a coincident geocode, not the reverse.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum FixBasis {
    /// No originating record at all — only annotations or nothing.
    Unknown,
    /// The operator's own seed value.
    Operator,
    /// A measurement with its own error bar: a device GPS, a photo's EXIF, a
    /// Wi-Fi or cell survey.
    Measured,
    /// A provider that reported the place (a registry, a directory, a profile,
    /// a snippet, a phone area code) — located to the grain of what it reports.
    Provider,
    /// A COUNTRY-grain inference ([`is_country_signal`]): a phone number's
    /// dialling prefix, an email's ccTLD or name-pattern locale. It names a
    /// country and no position within it, so its radius is unbounded and its
    /// point is only a stand-in — never a disc around that point.
    CountrySignal,
    /// A forward geocode of an address string.
    ForwardGeocode,
    /// A named map feature's own position (a Wikipedia place, an OSM POI) — the
    /// point IS that feature, not an address of anyone.
    MappedFeature,
    /// A centroid standing in for an area (a city, a postcode, a region).
    Centroid,
}

/// The place a centroid stands for — what an honest label names instead of the
/// street that happens to contain the centroid.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum StandsFor {
    /// A tabulated postcode (its principal locality's centroid, or a register's
    /// postcode-grain record).
    Postcode {
        /// The 4-digit postcode.
        code: String,
        /// Its state code, when known.
        state: Option<String>,
    },
    /// A tabulated city, suburb or regional centre.
    Gazetteer {
        /// Display name ("Brisbane", "Toowong").
        name: String,
        /// Its state code, when in Australia.
        state: Option<String>,
    },
    /// A leading-two-digit postcode region.
    PostcodeRegion {
        /// The two leading digits.
        prefix: String,
        /// Its state code.
        state: Option<String>,
    },
    /// The input a forward geocode was asked about, when the input — not the
    /// geocoder's hit — decided the grain ("Ian Thorpe, North Carolina").
    Input(String),
}

impl StandsFor {
    fn from_tabulated(c: TabulatedCentroid) -> Self {
        let own = |s: Option<&'static str>| s.map(str::to_string);
        match c {
            TabulatedCentroid::Postcode { code, state } => Self::Postcode {
                code,
                state: own(state),
            },
            TabulatedCentroid::City { name, state } => Self::Gazetteer {
                name,
                state: own(state),
            },
            TabulatedCentroid::PostcodeRegion { prefix, state } => Self::PostcodeRegion {
                prefix: prefix.to_string(),
                state: own(state),
            },
        }
    }
}

/// How precisely a coordinate locates anything, as [`assess`] graded it.
#[derive(Debug, Clone, PartialEq)]
pub struct FixPrecision {
    /// The rung [`FixPrecision::radius_m`] falls on.
    pub grain: FixGrain,
    /// The radius (metres) the point is honestly good to — never finer than
    /// any originating record's own radius.
    pub radius_m: f64,
    /// What kind of account decided it.
    pub basis: FixBasis,
    /// The place a centroid stands for, when known.
    pub stands_for: Option<StandsFor>,
    /// Whether some account gave POSITIVE evidence the point is an area — a
    /// gazetteer coincidence, a city lookup, an Address centroid, a geocoder's
    /// declared area grain or GeoNames feature class, a forward geocode capped
    /// by an input that names no street, or an existing `coarse` tag. Never set
    /// by the unknown-provenance default: a point graded coarse only because
    /// nothing classified its source is not thereby demoted from pivoting
    /// (an unclassified precise emitter must not lose its expansion).
    pub positive_coarse: bool,
}

impl FixPrecision {
    /// Whether the point is AN AREA standing in for a place — positive coarse
    /// evidence at suburb grain or coarser. The one predicate behind the
    /// engine's `coarse` admission stamp and its pivot gate.
    #[must_use]
    pub fn is_area(&self) -> bool {
        self.positive_coarse && self.grain >= FixGrain::Suburb
    }
}

/// The evidence source the engine writes the operator's seed under (the
/// subject anchor, `engine::enrich::seed_anchor_entity`).
const SEED_SOURCE: &str = "seed";

/// What a module that accepts a `Coordinates` TARGET leaves on the point it was
/// asked about — the table [`is_annotator_row`] reads to keep a lookup made BY
/// a point from grading that point, and the basis its other coordinate records
/// carry. A registry test (`place::tests`) asserts every registered module that
/// accepts a `Coordinates` target is listed, so a new one cannot silently start
/// counting as an originator.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum CoordinateTargetRole {
    /// Every record it leaves on the queried point annotates it (the ASGS
    /// statistical areas, the solar phases).
    Annotator,
    /// Annotates the queried point with the cadastral parcel containing it
    /// (a record carrying `lotplan`/`lot`/`plan`/`parcel_type`). Its other
    /// coordinate record is an Address's own source carried onto a centroid by
    /// `address_to_coords_pass`, graded as that centroid.
    AnnotatesParcel,
    /// Annotates the queried point with aggregates about its surroundings
    /// (`node_count`, `categories`), and emits each mapped feature it found at
    /// that feature's own position.
    AnnotatesAndMaps,
    /// Annotates the queried point with the Wi-Fi density around it
    /// (`density`), and emits each network at its own surveyed position.
    AnnotatesAndMeasures,
    /// Emits the named map features near the point, each at its own position.
    MapsFeatures,
    /// Measures a position: the operator's own device, or the radios and
    /// towers around it.
    Measures,
    /// Answers a point with `Address` entities (a reverse geocode) and records
    /// nothing on any `Coordinates`; the same module's forward geocodes are
    /// graded by the forward-geocode rules.
    ReverseGeocodes,
    /// Emits no `Coordinates` for a point (a local-network sensor that a
    /// deliberately local seed engages).
    NoCoordinates,
    /// Searches the web for the coordinate AS TEXT; any coordinate it emits is
    /// one a page printed or a snippet's place it looked up, graded by the rules
    /// for those records (a known-city lookup is a centroid), never a lookup
    /// made by the queried point.
    SearchesText,
}

/// Every registered module that accepts a `Coordinates` target, with its
/// [`CoordinateTargetRole`]. Sorted by name.
pub(crate) const COORDINATE_TARGET_MODULES: &[(&str, CoordinateTargetRole)] = &[
    ("au_geo", CoordinateTargetRole::Annotator),
    ("auspost", CoordinateTargetRole::ReverseGeocodes),
    ("cell_intel", CoordinateTargetRole::Measures),
    ("cell_local", CoordinateTargetRole::Measures),
    ("device_sensors", CoordinateTargetRole::Measures),
    ("geocode", CoordinateTargetRole::ReverseGeocodes),
    ("local_net", CoordinateTargetRole::NoCoordinates),
    ("opencellid", CoordinateTargetRole::Measures),
    ("overpass", CoordinateTargetRole::AnnotatesAndMaps),
    ("photon", CoordinateTargetRole::ReverseGeocodes),
    ("qld_cadastre", CoordinateTargetRole::AnnotatesParcel),
    ("search_engines", CoordinateTargetRole::SearchesText),
    ("signal_radar", CoordinateTargetRole::Measures),
    ("sunrise_sunset", CoordinateTargetRole::Annotator),
    ("wifi_intel", CoordinateTargetRole::Measures),
    ("wigle", CoordinateTargetRole::AnnotatesAndMeasures),
    ("wiki_geosearch", CoordinateTargetRole::MapsFeatures),
    ("wikidata_geo", CoordinateTargetRole::MapsFeatures),
];

/// The [`CoordinateTargetRole`] of an evidence source, when it is a module that
/// accepts a `Coordinates` target.
fn role_of(source: &str) -> Option<CoordinateTargetRole> {
    COORDINATE_TARGET_MODULES
        .iter()
        .find(|(name, _)| *name == source)
        .map(|&(_, role)| role)
}

/// Whether an evidence record is NOT an account of the point's position, and
/// so never sets its precision:
///
/// * it is flagged an annotation ([`Evidence::is_annotation`], REQ-GEO-008);
/// * it is one of the engine's own records — the geospatial enrichment, a
///   recall, a cross-scan carry-over, a consensus or corroboration promotion
///   (`hse_core::is_non_corroborating_source`, and the `*_corroboration`
///   promotion sources) — except the operator's seed, which IS the value;
/// * its source only ever annotates a queried point
///   ([`CoordinateTargetRole::Annotator`]), or it has the shape of that
///   module's annotation ([`CoordinateTargetRole`]) — which is how a record
///   written before the annotation flag existed is still recognised in a
///   stored or recalled scan.
#[must_use]
pub(crate) fn is_annotator_row(ev: &Evidence) -> bool {
    if ev.is_annotation {
        return true;
    }
    let src = ev.source.as_str();
    if src == SEED_SOURCE {
        return false;
    }
    if crate::core::entity::is_non_corroborating_source(src) || src.ends_with("_corroboration") {
        return true;
    }
    let has = |k: &str| ev.attributes.contains_key(k);
    match role_of(src) {
        Some(CoordinateTargetRole::Annotator) => true,
        Some(CoordinateTargetRole::AnnotatesParcel) => {
            ["lotplan", "lot", "plan", "parcel_type"]
                .into_iter()
                .any(has)
                && !has(crate::core::engine::ADDR_ENTITY_UID_ATTR)
        }
        Some(CoordinateTargetRole::AnnotatesAndMaps) => has("node_count") || has("categories"),
        Some(CoordinateTargetRole::AnnotatesAndMeasures) => has("density"),
        _ => false,
    }
}

/// The radius (metres) a geocoder's OWN description of what it matched implies,
/// or `None` when it matched something at least as precise as a geocoder's
/// class default — or when nothing recognisable was reported.
///
/// `geocode` (Nominatim) and `photon` both return a `type` naming the grain of
/// the hit, written to the `place_type` evidence attribute (and Photon's OSM
/// class to `osm_value`); `address_to_coords_pass` writes the same vocabulary
/// for the centroid it derived. A flat 40 m whether the geocoder pinpointed a
/// house or returned a state centroid was a `sqrt(1000/40)` = **5x** fusion
/// multiplier for a point that may be a hundred kilometres from the subject
/// (REQ-GEO-002).
///
/// # Only ever coarsens
///
/// Every radius here exceeds the `Geocode` class default (40 m) and every
/// reader takes a `max`, so this can reduce a record's pull and never increase
/// it. An unrecognised or absent grain falls back to the class radius, so a
/// provider adding a new `type` string degrades to that rather than to a guess.
/// `administrative` (Nominatim's type for a boundary of unstated level — a
/// city, a county or a state) is read as at least a city, the finest level it
/// can be; the input cap in [`assess`] coarsens it further when the input named
/// only a state.
///
/// Moved here from the correlator (it was `correlator::rules::location`'s
/// private table) so the fusion radius, the admission stamp and the pivot gate
/// read one table (REQ-GEOLABEL-007).
#[must_use]
pub fn geocode_grain_radius_m(place_type: &str) -> Option<f64> {
    let radius = match place_type.trim().to_ascii_lowercase().as_str() {
        "country" => 300_000.0,
        "state" | "province" | "region" => 100_000.0,
        "state_district" | "county" | "district" => 30_000.0,
        "city" | "municipality" | "administrative" => 8_000.0,
        "postcode" | "postal_code" => 4_000.0,
        "town" | "island" => 4_000.0,
        "borough" | "suburb" | "village" | "quarter" | "neighbourhood" | "hamlet" | "locality" => {
            1_500.0
        }
        // A street's representative point, not a building on it: Photon's
        // `street` type, Nominatim's highway classes.
        "street" | "road" | "residential" | "tertiary" | "secondary" | "primary" => 300.0,
        _ => return None,
    };
    debug_assert!(
        radius > precision_radius_m(GeoSourceClass::Geocode),
        "this table may only coarsen"
    );
    Some(radius)
}

/// The radius a GeoNames `feature_code` (Open-Meteo's geocoder) implies: a
/// populated place (`PPL*`) is a town or city; a first-order division
/// (`ADM1`) a state; lower divisions (`ADM2`–`ADM5`, `ADMD`) a district; a
/// political entity (`PCL*`) a country; anything else — a mountain, a
/// headland, a bay — is at least a locality, never a point: GeoNames places
/// every feature at one representative coordinate.
fn feature_code_radius_m(code: &str) -> f64 {
    let code = code.trim().to_ascii_uppercase();
    let by_type = |t: &str| geocode_grain_radius_m(t).unwrap_or(f64::INFINITY);
    if code == "ADM1" {
        by_type("state")
    } else if code.starts_with("ADM") {
        by_type("district")
    } else if code.starts_with("PCL") {
        by_type("country")
    } else {
        by_type("city")
    }
}

/// The forward geocoders: a record from one of these carrying `input_address`
/// is a geocode of that string, capped at the grain the string names.
const FORWARD_GEOCODERS: &[&str] = &["geocode", "photon", "open_meteo_geo"];

/// Photon `osm_key`s whose features ARE address components (a place, a road,
/// a building, an address point). A `house`-typed hit under any other key is a
/// point of interest — "Ian Thorpe Aquatic Centre" is `leisure/sports_centre`
/// — whose name is the feature's, not an address anyone reported.
const ADDRESS_OSM_KEYS: &[&str] = &["place", "highway", "building", "addr"];

/// The grain an input names at its finest, as a cap on the geocode of it.
fn named_cap(street: Option<StreetGrain>, admin: Option<AdminGrain>) -> FixGrain {
    match (street, admin) {
        (Some(StreetGrain::House), _) => FixGrain::Point,
        (Some(StreetGrain::Street), _) => FixGrain::Street,
        (None, Some(AdminGrain::Postcode)) => FixGrain::Suburb,
        (None, Some(AdminGrain::Locality) | None) => FixGrain::Locality,
        (None, Some(AdminGrain::Region)) => FixGrain::Region,
        (None, Some(AdminGrain::Country)) => FixGrain::Country,
    }
}

/// One originating record's account of the point.
#[derive(Debug, Clone)]
struct Account {
    radius_m: f64,
    basis: FixBasis,
    positive: bool,
    stands_for: Option<StandsFor>,
    /// Whether this account explains the VALUE — why the point sits exactly
    /// where it does — and so sets a country signal on the same point aside
    /// ([`assess`], step 2). False only for a country signal itself and for
    /// the attribute-less copy of one ([`is_stripped_country_signal`]).
    explains: bool,
}

impl Account {
    fn new(radius_m: f64, basis: FixBasis, positive: bool) -> Self {
        Self {
            radius_m,
            basis,
            positive,
            stands_for: None,
            explains: basis != FixBasis::CountrySignal,
        }
    }
}

/// A radius attribute's value, when it is a finite positive number.
fn positive_number(v: &str) -> Option<f64> {
    v.trim()
        .parse::<f64>()
        .ok()
        .filter(|r| r.is_finite() && *r > 0.0)
}

/// The evidence source `wikidata_geo` (and the `wikidata` module) record under.
const WIKIDATA_CORPUS_SOURCE: &str = "wikidata";

/// The default basis of a record from `source`, by its role and its
/// `GeoSourceClass`.
fn basis_of(source: &str, class: GeoSourceClass) -> FixBasis {
    match role_of(source) {
        Some(CoordinateTargetRole::Measures | CoordinateTargetRole::AnnotatesAndMeasures) => {
            return FixBasis::Measured;
        }
        Some(CoordinateTargetRole::MapsFeatures | CoordinateTargetRole::AnnotatesAndMaps) => {
            return FixBasis::MappedFeature;
        }
        _ => {}
    }
    // `wikidata_geo` writes its nearby-place records under the corpus's own
    // name, `wikidata` (one Wikidata item must not count as two sources), so
    // its role in [`COORDINATE_TARGET_MODULES`] never matches a record's
    // source. A `wikidata` coordinate is always an item's own mapped position
    // — a place, a building, a landmark — never a sighting of anyone.
    if source == WIKIDATA_CORPUS_SOURCE {
        return FixBasis::MappedFeature;
    }
    if class_locates_subject_directly(class) {
        FixBasis::Measured
    } else if class == GeoSourceClass::Geocode || source == "open_meteo_geo" {
        FixBasis::ForwardGeocode
    } else if class == GeoSourceClass::Other {
        FixBasis::Unknown
    } else {
        FixBasis::Provider
    }
}

/// The radius a centroid of a tabulated kind is good to — read from the one
/// grain table, so a city centroid is 8 km here exactly as a geocoder's
/// declared city is.
fn tabulated_radius_m(c: &TabulatedCentroid) -> f64 {
    let place_type = match c {
        TabulatedCentroid::Postcode { .. } => "postcode",
        TabulatedCentroid::City { .. } => "city",
        TabulatedCentroid::PostcodeRegion { .. } => "region",
    };
    geocode_grain_radius_m(place_type).unwrap_or(f64::INFINITY)
}

/// The modules that mint country-signal points ([`is_country_signal`]):
/// `email_locale` (every coordinate it mints) and `geo_intel` (its
/// `method=e164-prefix` points).
const COUNTRY_SIGNAL_SOURCES: &[&str] = &["email_locale", "geo_intel"];

/// Whether a record is a country-signal emitter's record with NO attributes —
/// the shape HSE's CSV importer rebuilds every record in (it keeps source and
/// summary, never attributes). `geo_intel`'s prefix record loses the `method`
/// that made it a country signal ([`is_country_signal`]) and becomes an
/// unclassified record indistinguishable from any other; it is still only the
/// signal's own copy, so it explains nothing about the value, and the point's
/// tags ([`COUNTRY_SIGNAL_TAGS`]) decide. A LIVE record of either module
/// always carries attributes, so its unclassified non-signal records (an IP
/// geolocation) are not mistaken for one.
fn is_stripped_country_signal(ev: &Evidence) -> bool {
    COUNTRY_SIGNAL_SOURCES.contains(&ev.source.as_str()) && ev.attributes.is_empty()
}

/// The tags the country-grain inference modules stamp on the point they mint:
/// `geo_intel`'s dialling-prefix country (`phone-prefix`) and `email_locale`'s
/// ccTLD and name-pattern locales (`cctld-inferred`, `locale-inferred`). Read
/// by [`assess`] exactly as the record rule ([`is_country_signal`]) is read, so
/// a copy of the point whose records lost their attributes (a CSV re-import
/// keeps tags, not attributes) is still read as the country it is — and
/// yields exactly when the record would (see [`assess`], step 2).
const COUNTRY_SIGNAL_TAGS: &[&str] = &["phone-prefix", "cctld-inferred", "locale-inferred"];

/// The radius of a country signal: unbounded. The signal says "somewhere in
/// New Zealand" and nothing about where; its point is a stand-in (Wellington's
/// row for `+64`, Sydney's for a `.au` domain, the continent's centre for
/// `+61`), not the middle of anything the signal measured. A finite radius —
/// it was the geocoder table's 300 km "country" — drew a disc around the
/// stand-in that most of the country lies outside: a `.au` email at Sydney
/// ±300 km excluded Melbourne, Brisbane and Perth, and `+64` at Wellington
/// ±300 km excluded Auckland. So no disc is claimed at all: the label names
/// the country with no `±`, the JSON radius is `null` and the CSV cell empty.
const COUNTRY_SIGNAL_RADIUS_M: f64 = f64::INFINITY;

/// Whether a record is a COUNTRY-grain inference: a phone number's E.164
/// dialling prefix (`method=e164-prefix`, `geo_intel`) or an email's ccTLD or
/// name-pattern locale (every coordinate `email_locale` mints).
///
/// Each says only "New Zealand" or "Australia", and places the point at a
/// stand-in for the whole country — `+64` at Wellington's row, a `.au` domain
/// at Sydney's, `+61` at the continent's centre. Their sources are
/// unclassified (`GeoSourceClass::Other`), so without this rule they graded at
/// the 30 km unknown default, a gazetteer coincidence then named the city, and
/// the label read "Wellington (city centroid — not a street location)" or
/// "remote NT — nearest centre Alice Springs (locality-level fix, ±30 km)" for
/// a signal that names a country and nothing finer.
///
/// The stand-in is a real city's row, so a genuine finding of that city — a
/// `+64 4` landline's area code resolved through `city_coords` to Wellington,
/// a Sydney ABN address, a GitLab profile's "Sydney", a NumVerify line's
/// "Wellington, New Zealand" — lands on the very same value and merges into
/// the same entity. The signal then explains nothing about that value: the
/// city finding does. [`assess`] therefore reads a country signal only when
/// no other record on the point accounts for it (step 2 there).
fn is_country_signal(ev: &Evidence) -> bool {
    ev.source == "email_locale"
        || ev
            .attributes
            .get("method")
            .is_some_and(|m| m.trim() == "e164-prefix")
}

/// The place a point's country-signal records NAME, for the label of a point
/// graded [`FixBasis::CountrySignal`] — `None` when no such record names one
/// (a CSV copy keeps no attributes).
///
/// A signal is not always one country. `+1` is "United States/Canada", `+7`
/// "Russia/Kazakhstan", and `email_locale`'s name patterns name regions
/// ("Eastern Europe (Ukraine/Russia/Serbia)", "Iberia/Latin America"). Its
/// stand-in, though, sits in ONE country — the US centroid, Moscow, Lisbon —
/// so naming the point by its stored `country_code` or the country box the
/// stand-in falls in labelled a Toronto `+1 416` number "United States" and
/// `ivan.shevchenko@…` "Russia", a country the evidence never stated. The
/// signal's own words are read instead: its `country` attribute, else its
/// `region`. Several signals on one stand-in naming different places are all
/// named, sorted, so the pick never depends on record order.
///
/// Read over every signal record, not only the originating ones:
/// `email_locale` is a derivation module, so its records are engine-side
/// ([`is_annotator_row`]) and its grade travels by its tags — but its record
/// is still the one that says which place it meant.
#[must_use]
pub(crate) fn country_signal_place(e: &Entity) -> Option<String> {
    let mut named: Vec<&str> = e
        .evidence
        .iter()
        .filter(|ev| !ev.is_annotation && is_country_signal(ev))
        .filter_map(|ev| {
            ["country", "region"].into_iter().find_map(|k| {
                ev.attributes
                    .get(k)
                    .map(|v| v.trim())
                    .filter(|v| !v.is_empty())
            })
        })
        .collect();
    named.sort_unstable();
    named.dedup();
    (!named.is_empty()).then(|| named.join(" or "))
}

/// One originating record's account of the point, or `None` for an annotator
/// ([`is_annotator_row`]). The first rule that applies decides:
///
/// 1. the operator's seed — radius 0 (the quantisation floor in [`assess`]
///    then grades it by the decimals the operator typed);
/// 2. a centroid `address_to_coords_pass` carried from an Address
///    (`addr_entity_uid`) — the grain the pass declared (`place_type`), a city
///    for a record written before it declared one; a `search_engines`
///    known-city lookup — a city;
/// 3. a register's postcode-grain record (`qld_unclaimed` / `au_unclaimed` with
///    `postcode`) — a postcode centroid; a country-grain inference
///    ([`is_country_signal`]) — the country, with no radius
///    ([`COUNTRY_SIGNAL_RADIUS_M`]);
/// 4. a stated error bar (`accuracy_m`, `gps_accuracy_m`, `range_m`) — that
///    radius, as a measurement;
/// 5. a GeoNames `feature_code`, else a declared `place_type` / `osm_value`
///    ([`geocode_grain_radius_m`]), else the source class's default radius —
///    and for a forward geocode, capped at the grain its `input_address` names
///    (see [`forward_geocode_account`]).
fn account_of(ev: &Evidence) -> Option<Account> {
    if is_annotator_row(ev) {
        return None;
    }
    let src = ev.source.as_str();
    let attr = |k: &str| {
        ev.attributes
            .get(k)
            .map(|v| v.trim())
            .filter(|v| !v.is_empty())
    };
    if src == SEED_SOURCE {
        return Some(Account::new(0.0, FixBasis::Operator, false));
    }
    let city = || geocode_grain_radius_m("city").unwrap_or(f64::INFINITY);
    if attr(crate::core::engine::ADDR_ENTITY_UID_ATTR).is_some() {
        let r = attr("place_type")
            .and_then(geocode_grain_radius_m)
            .unwrap_or_else(city);
        return Some(Account::new(r, FixBasis::Centroid, true));
    }
    if attr("method") == Some("known-city-lookup") {
        return Some(Account::new(city(), FixBasis::Centroid, true));
    }
    if matches!(src, "qld_unclaimed" | "au_unclaimed")
        && let Some(code) = attr("postcode")
    {
        let mut a = Account::new(
            geocode_grain_radius_m("postcode").unwrap_or(f64::INFINITY),
            FixBasis::Centroid,
            true,
        );
        a.stands_for = Some(StandsFor::Postcode {
            code: code.to_string(),
            state: crate::util::address_au::state_code(code).map(str::to_string),
        });
        return Some(a);
    }
    if is_country_signal(ev) {
        return Some(Account::new(
            COUNTRY_SIGNAL_RADIUS_M,
            FixBasis::CountrySignal,
            true,
        ));
    }
    if let Some(r) = ["accuracy_m", "gps_accuracy_m", "range_m"]
        .into_iter()
        .find_map(|k| attr(k).and_then(positive_number))
    {
        return Some(Account::new(r, FixBasis::Measured, false));
    }
    let class = geo_source_class(src);
    let declared = attr("feature_code").map(feature_code_radius_m).or_else(|| {
        attr("place_type")
            .and_then(geocode_grain_radius_m)
            .or_else(|| attr("osm_value").and_then(geocode_grain_radius_m))
    });
    // A declared grain is positive evidence of an AREA only when it is one: a
    // geocoder that said "street" located a street, not a suburb.
    let mut hit = Account::new(
        declared.unwrap_or_else(|| precision_radius_m(class)),
        basis_of(src, class),
        declared.is_some_and(|r| FixGrain::from_radius_m(r) >= FixGrain::Suburb),
    );
    hit.explains = !is_stripped_country_signal(ev);
    match attr("input_address") {
        Some(input) if FORWARD_GEOCODERS.contains(&src) => {
            Some(forward_geocode_account(ev, input, hit))
        }
        _ => Some(hit),
    }
}

/// Cap a forward geocode's `hit` at the grain its `input` names.
///
/// A geocode can be no finer than the question: "Brisbane" answered with a
/// point is the Brisbane centroid, and "Ian Thorpe, North Carolina" answered
/// with "Thorpe-Abbotts Lane" is a state-grain guess whatever street it landed
/// on. So:
///
/// * the cap is the finest component the input names
///   (`util::place_grain::place_naming`): a numbered street a point, a street a
///   street, a postcode a suburb, a locality a locality, a state a region, a
///   country a country — and an input naming nothing recognisable a locality
///   at best (an unrecognised word is not evidence of a street);
/// * an AMBIGUOUS hit (`ambiguity_detected`, or `candidates_count` > 1) is one
///   rung coarser than it claims — the geocoder itself was not sure which;
/// * a hit whose name — the road it lies on (`road`, Nominatim) or its own
///   name (`place_name`, Photon and Open-Meteo) — is not the place an input
///   naming no NUMBERED street asked about
///   (`util::place_grain::is_name_of_queried_place`) is a FRAGMENT match, and
///   only the input's administrative grain stands. For an input naming no
///   street at all that is the cap anyway ("Ian Thorpe, North Carolina" →
///   "Thorpe-Abbotts Lane"); it bites on an UNNUMBERED street, because a
///   street-type word also ends real locality names and a leading one starts
///   given names and towns — "Kelvin Grove, QLD" (a Brisbane suburb) reads as
///   the street "Kelvin Grove", "Kiệt Nguyễn, Hà Nội" (a person) as the alley
///   "Kiệt Nguyễn" — and a hit on "Kelvin Grove Road" or on any "Nguyễn …"
///   street is then an answer to a question nobody asked. A hit that IS the
///   named street ("Smith Street" for "Smith St") keeps the street cap. A
///   numbered street is specific enough to stand on its own;
/// * a Photon `house` hit under a non-address `osm_key` is a point of interest
///   ([`ADDRESS_OSM_KEYS`]): a mapped feature, capped at the input's
///   administrative grain, never a street address.
fn forward_geocode_account(ev: &Evidence, input: &str, mut hit: Account) -> Account {
    let attr = |k: &str| {
        ev.attributes
            .get(k)
            .map(|v| v.trim())
            .filter(|v| !v.is_empty())
    };
    let naming = place_naming(input);
    let ambiguous = attr("ambiguity_detected") == Some("true")
        || attr("candidates_count")
            .and_then(|c| c.parse::<u32>().ok())
            .is_some_and(|n| n > 1);
    if ambiguous {
        let rung = FixGrain::from_radius_m(hit.radius_m).coarser();
        hit.radius_m = hit.radius_m.max(rung.floor_m());
    }
    let poi = ev.source == "photon"
        && attr("place_type").is_some_and(|t| t.eq_ignore_ascii_case("house"))
        && attr("osm_key").is_some_and(|k| !ADDRESS_OSM_KEYS.contains(&k));
    let hit_names: Vec<&str> = ["road", "place_name"]
        .into_iter()
        .filter_map(attr)
        .collect();
    let fragment = naming.street != Some(StreetGrain::House)
        && !hit_names.is_empty()
        && !hit_names
            .iter()
            .any(|name| is_name_of_queried_place(name, input));
    let cap = if poi || fragment {
        named_cap(None, naming.admin)
    } else {
        named_cap(naming.street, naming.admin)
    };
    if poi {
        hit.basis = FixBasis::MappedFeature;
    }
    if cap.floor_m() > hit.radius_m {
        hit.radius_m = cap.floor_m();
        if cap >= FixGrain::Suburb {
            hit.stands_for = Some(StandsFor::Input(input.to_string()));
        }
    }
    hit.positive |= cap >= FixGrain::Suburb;
    hit
}

/// A `"lat,lon"` string's two components, when both parse as numbers — the
/// shape the two printed-width readers below accept.
fn numeric_pair(s: &str) -> Option<(&str, &str)> {
    let (lat, lon) = s.split_once(',')?;
    let (lat, lon) = (lat.trim(), lon.trim());
    (lat.parse::<f64>().is_ok() && lon.parse::<f64>().is_ok()).then_some((lat, lon))
}

/// The digits a component PRINTS after its decimal point (`"-33.80"` → 2).
fn printed_decimals(part: &str) -> usize {
    part.split_once('.').map_or(0, |(_, frac)| frac.len())
}

/// The form of the value its emitter actually PRINTED: `raw_value` when it is
/// a coordinate pair, else `value`.
///
/// `Entity::new` normalises every `Coordinates` value to six decimals and
/// keeps what it was given only in `raw_value`, so `value` is never evidence
/// of how wide the emitter printed — `-33.800000,151.000000` is equally the
/// six-decimal Parramatta REGIONS row a module minted and the normalisation
/// of a redacted `-33.8,151.0` that HSE's own CSV importer rebuilt through
/// `Entity::new`. Only `raw_value` tells the two apart. `value` is read only
/// when `raw_value` is not a pair (a legacy row, or a raw form in another
/// notation), and for a value that was never normalised (the redactor rewrites
/// both fields in place).
fn printed_form(e: &Entity) -> &str {
    if numeric_pair(&e.raw_value).is_some() {
        &e.raw_value
    } else {
        &e.value
    }
}

/// The radius the value's own printed decimals can support: a value quoted to
/// `d` decimals is uncertain by half its last digit, `0.5 × 10^-d` degrees
/// (≈ `55.66 km × 10^-d`). `None` when neither the value nor the raw value
/// parses as a coordinate pair.
///
/// The decimals are counted on the PRINTED form ([`printed_form`]): what the
/// module or the redactor wrote, never the six-decimal normalisation, whose
/// pad says nothing. Reading `min(value, raw_value)` instead let the
/// normalisation win: a redacted `-28.0,153.0` re-imported through
/// `Entity::new` became `-28.000000,153.000000`, stripped to 0 decimals, and
/// graded a region (±55.7 km) beside `-27.9,153.2` at a locality (±5.6 km) —
/// the parity split REQ-GEOLABEL-013 removed, back on the import surface. The
/// count is capped by the value's own printed width, so a raw value printed
/// wider than the six decimals kept can never grade the point finer than the
/// value it is.
///
/// Trailing zeros of a WIDER component are not precision: `-33.900000` may be
/// the six-decimal print of `-33.9`, and the pad cannot be told from a real
/// zero, so it is stripped — the direction that never manufactures precision.
/// A component printed with EXACTLY one decimal is read as one decimal even
/// when that digit is `0`: only a one-decimal formatter prints that shape (the
/// redactor's `{v:.1}`, `util::redact::coarsen_coordinates`), so the zero is a
/// digit it chose to print. Stripping it graded `-28.0,153.0` at 0 decimals
/// (±55.7 km, region) and `-27.9,153.0` at 1 (±5.6 km, locality) — two
/// redactions of identical precision labelled a grain apart by the parity of
/// their digits.
pub(crate) fn quantisation_radius_m(e: &Entity) -> Option<f64> {
    /// Metres per degree of latitude, the scale of the half-digit bound.
    const METRES_PER_DEGREE: f64 = 111_320.0;
    let significant = |part: &str| -> usize {
        let frac = part.split_once('.').map_or("", |(_, f)| f);
        if frac.len() == 1 {
            1
        } else {
            frac.trim_end_matches('0').len()
        }
    };
    let (lat, lon) = numeric_pair(printed_form(e))?;
    let mut d = significant(lat).max(significant(lon));
    if let Some((vlat, vlon)) = numeric_pair(&e.value) {
        d = d.min(printed_decimals(vlat).max(printed_decimals(vlon)));
    }
    let d = i32::try_from(d).ok()?;
    Some(0.5 * 10f64.powi(-d) * METRES_PER_DEGREE)
}

/// The decimals the gazetteer tables are keyed at
/// (`util::city_coords::tabulated_centroid_at` compares at 4 decimals).
const TABLE_KEY_DECIMALS: usize = 4;

/// Whether the point was CUT to fewer printed decimals than the gazetteer key
/// — a redacted `"-33.8,151.0"` — read on its value AND its printed form
/// ([`printed_form`]).
///
/// Such a value cannot be identified as a table row: the rounding that
/// produced it maps a whole ~11 km cell of real points onto whichever row is
/// aligned to one decimal. Nineteen REGIONS rows are (`"21"` is
/// `-33.8,151.0`), and so is the Footscray anchor, so a redacted geocode in
/// Parramatta read as "New South Wales (region-level fix, ±100 km)" and a
/// redacted inner-west Melbourne point as "Footscray (city centroid)". Its
/// printed width, not its significant digits, is the test — a six-decimal
/// `-33.800000,151.000000` that a module PRINTED at that width IS the row, and
/// keeps its coincidence; the cut value is graded by its quantisation alone.
///
/// Both fields, because `Entity::new` hides the cut in `raw_value`: HSE's CSV
/// importer rebuilds a redacted `-33.8,151.0` row into value
/// `-33.800000,151.000000`, and a gate on `value` alone read that as the
/// REGIONS row again — the Parramatta point re-imported as "New South Wales
/// (region-level fix)", stamped `coarse` and withheld from pivots. A value
/// the redactor rewrote in place is cut in `value` itself.
fn cut_below_table_key(e: &Entity) -> bool {
    let cut = |s: &str| {
        numeric_pair(s).is_some_and(|(lat, lon)| {
            printed_decimals(lat).min(printed_decimals(lon)) < TABLE_KEY_DECIMALS
        })
    };
    cut(&e.value) || cut(printed_form(e))
}

/// Grade how precisely a `Coordinates` entity locates anything.
///
/// 1. Each originating record gives an account ([`account_of`]); annotators
///    give none ([`is_annotator_row`]). So does an `accuracy:<n>m` tag (a
///    device fix's error bar).
/// 2. The COARSEST account wins — identical values from different origins are
///    one datum, and a centroid explanation proves it (module docs). On an
///    exact tie the more explanatory basis names it ([`FixBasis`]'s order).
///    When a MEASURED account good to a street or better is present, only the
///    measured accounts are combined (the measurement exemption, module docs).
///    A country signal ([`is_country_signal`], or its [`COUNTRY_SIGNAL_TAGS`])
///    is read only when no other account explains the value — every other
///    account is a country signal or a signal's attribute-less CSV copy
///    ([`is_stripped_country_signal`]), and the point carries no grade a
///    scan wrote for it (a `fix-grain:` or `fix-radius:` tag, neither ever
///    written for a country signal). Its point is a stand-in on a real
///    city's row, so a real finding of that city — from any source,
///    classified or not — lands on the same value; that finding is the
///    reading of the point, and the signal is set aside like an annotator.
///    Read, it grades the point at country grain with NO radius
///    ([`COUNTRY_SIGNAL_RADIUS_M`]).
/// 3. With no account at all the basis is [`FixBasis::Unknown`], graded at the
///    unclassified-source default (30 km, a locality at best) and never
///    positive evidence of an area.
/// 4. Floors from the entity's tags: a `fix-grain:` stamp, `coarse` (suburb),
///    `postcode-centroid` (suburb), the country-signal tags (step 2), and the
///    legacy signatures of the paths that minted city centroids before the
///    `coarse` tag — `search-geocoded`, and the `recycled` + `addr-derived`
///    pair (locality).
/// 5. Gazetteer coincidence: a value equal at 4 decimals to a tabulated
///    centroid (`util::city_coords::tabulated_centroid_at`) is graded at the
///    grain of what it stands for, and says what that is — unless a MEASURED
///    account good to a street or better sits on the same entity, a country
///    signal grades the point (the row is its stand-in), or the value was
///    printed below the table's 4 decimals ([`cut_below_table_key`]).
/// 6. The quantisation floor ([`quantisation_radius_m`]), and a re-import's
///    carried grade ([`FIX_RADIUS_TAG_PREFIX`]).
///
/// Pure and order-independent: every combination is a `max` or an `||`, ties
/// break on a total order, and nothing reads the clock or the network.
/// Invariant: the radius is never finer than any originating account's — of
/// the measured accounts alone, under the measurement exemption, and of the
/// explaining accounts alone when a country signal is set aside.
#[must_use]
pub fn assess(e: &Entity) -> FixPrecision {
    let mut accounts: Vec<Account> = e.evidence.iter().filter_map(account_of).collect();
    accounts.extend(e.tags.iter().filter_map(|t| {
        let r = t
            .strip_prefix("accuracy:")?
            .strip_suffix('m')
            .and_then(positive_number)?;
        Some(Account::new(r, FixBasis::Measured, false))
    }));
    let measured_fine = accounts.iter().any(|a| {
        a.basis == FixBasis::Measured && FixGrain::from_radius_m(a.radius_m) <= FixGrain::Street
    });
    if measured_fine {
        accounts.retain(|a| a.basis == FixBasis::Measured);
    }
    // A country signal's point is a stand-in on a real city's row, so a real
    // finding of that city merges onto it. Any other account explains the
    // value and is the reading of the point; the signal (record and tags
    // alike) then says nothing about it and is set aside, as an annotator is.
    // Before, the coarsest-wins rule let the signal erase the finding: a
    // Sydney ABN address merged with a `.au` email's point read "Australia",
    // and a Wellington area-code point merged with `+64`'s read "New
    // Zealand".
    //
    // "Any other" includes an UNCLASSIFIED source. Excluding those (round 2)
    // left every `profile_kit` location emitter (GitLab, Stack Overflow,
    // Codeberg, Steam, …), NumVerify and the other `city_coords` callers
    // erased by the signal: a GitLab "Sydney" merged with a `.au` point read
    // "Australia", though it read "Sydney" alone. Such a record reached six
    // decimals of a city's row only by looking that city up, which the
    // gazetteer coincidence below then names. The one unclassified record
    // that explains nothing is the signal's own CSV copy
    // ([`is_stripped_country_signal`]).
    //
    // A carried grade explains the value too: the engine never stamps a
    // `fix-grain:` on a country-signal grade, and the CSV export writes no
    // `fix_radius_m` for one, so either tag says the exporting scan read the
    // point as something finer than the country. A re-import strips the
    // attributes that made the explaining record explain (an Address
    // centroid's `addr_entity_uid`), and without this the round trip turned
    // "Sydney (city centroid)" back into "Australia".
    let has = |t: &str| e.has_tag(t);
    let carried_grade = e.tags.iter().any(|t| {
        t.strip_prefix(FIX_GRAIN_TAG_PREFIX)
            .and_then(FixGrain::parse)
            .is_some()
            || t.strip_prefix(FIX_RADIUS_TAG_PREFIX)
                .and_then(|r| r.strip_suffix('m'))
                .and_then(positive_number)
                .is_some()
    });
    let explained_otherwise = carried_grade || accounts.iter().any(|a| a.explains);
    if explained_otherwise {
        accounts.retain(|a| a.basis != FixBasis::CountrySignal);
    }
    let country_signal = !explained_otherwise
        && (accounts.iter().any(|a| a.basis == FixBasis::CountrySignal)
            || COUNTRY_SIGNAL_TAGS.iter().any(|t| has(t)));

    let mut best = Account::new(
        precision_radius_m(GeoSourceClass::Other),
        FixBasis::Unknown,
        false,
    );
    let mut first = true;
    let mut positive = false;
    for a in accounts {
        positive |= a.positive;
        if first {
            best = a;
            first = false;
        } else {
            raise(&mut best, a);
        }
    }

    let floor = |grain: FixGrain| Account::new(grain.floor_m(), FixBasis::Centroid, true);
    let mut floors: Vec<Account> = e
        .tags
        .iter()
        .filter_map(|t| {
            t.strip_prefix(FIX_GRAIN_TAG_PREFIX)
                .and_then(FixGrain::parse)
        })
        .map(floor)
        .collect();
    if has(crate::core::tags::COARSE) || has("postcode-centroid") {
        floors.push(floor(FixGrain::Suburb));
    }
    // The country-signal tags stand in for the record rule, so they yield
    // exactly when that record's account does (`explained_otherwise`, which a
    // fine measurement also is).
    if country_signal {
        floors.push(Account::new(
            COUNTRY_SIGNAL_RADIUS_M,
            FixBasis::CountrySignal,
            true,
        ));
    }
    if e.kind == EntityKind::Coordinates
        && (has(crate::core::tags::SEARCH_GEOCODED)
            || (has(crate::core::tags::RECYCLED) && has(crate::core::tags::ADDR_DERIVED)))
    {
        floors.push(Account::new(
            geocode_grain_radius_m("city").unwrap_or(f64::INFINITY),
            FixBasis::Centroid,
            true,
        ));
    }
    // Not on a country signal's point: the row it lands on is the stand-in the
    // signal was minted at, not a place anyone reported.
    if !measured_fine
        && !country_signal
        && !cut_below_table_key(e)
        && let Some((lat, lon)) = crate::util::geohash::parse_coords(&e.value)
        && let Some(centroid) = crate::util::city_coords::tabulated_centroid_at(lat, lon)
    {
        // The coincidence names the place even when a coarser account decides
        // the radius — it is the one reading that knows what the value IS.
        let mut a = Account::new(tabulated_radius_m(&centroid), FixBasis::Centroid, true);
        let stands_for = StandsFor::from_tabulated(centroid);
        a.stands_for = Some(stands_for.clone());
        floors.push(a);
        best.stands_for = Some(stands_for);
        best.basis = FixBasis::Centroid;
    }
    for f in floors {
        positive |= f.positive;
        raise(&mut best, f);
    }
    if let Some(q) = quantisation_radius_m(e) {
        best.radius_m = best.radius_m.max(q);
    }
    // A re-import carries the exporting scan's grade as a radius floor. It
    // raises the radius only: the basis the surviving records name still says
    // what KIND of fix the point is.
    if let Some(r) = e
        .tags
        .iter()
        .filter_map(|t| {
            t.strip_prefix(FIX_RADIUS_TAG_PREFIX)?
                .strip_suffix('m')
                .and_then(positive_number)
        })
        .reduce(f64::max)
    {
        best.radius_m = best.radius_m.max(r);
    }
    FixPrecision {
        grain: FixGrain::from_radius_m(best.radius_m),
        radius_m: best.radius_m,
        basis: best.basis,
        stands_for: best.stands_for,
        positive_coarse: positive,
    }
}

/// Fold `incoming` into `held`, keeping the coarser account: a larger radius
/// replaces it; an equal one keeps the larger [`FixBasis`] and the larger
/// [`StandsFor`] (a total order, so the result never depends on the order the
/// records were merged in). A coarser account without a `stands_for` keeps the
/// one already held.
fn raise(held: &mut Account, incoming: Account) {
    if incoming.radius_m > held.radius_m {
        held.radius_m = incoming.radius_m;
        held.basis = incoming.basis;
        if incoming.stands_for.is_some() {
            held.stands_for = incoming.stands_for;
        }
    } else if (incoming.radius_m - held.radius_m).abs() <= f64::EPSILON {
        held.basis = held.basis.max(incoming.basis);
        held.stands_for = held.stands_for.take().max(incoming.stands_for);
    }
}

/// Whether `e` is a `Coordinates` that locates NO position at all — a point
/// [`assess`] grades a country signal ([`FixBasis::CountrySignal`], an
/// unbounded radius). Its value is a stand-in the signal was minted at, not
/// where anything is, so the correlator's person-anchor gate
/// (`correlator::is_infrastructure_geo`) keeps it out of every footprint,
/// fusion and best-location rung: fed in, its infinite radius reached the
/// best-location estimate as `radius_km = inf`, which report.json wrote as
/// `null`, the debug bundle as "± 0.0 km" and the CLI dossier as "± inf km".
///
/// Cheap for every other point: [`assess`] runs only when a record or tag
/// could make the point a country signal at all.
#[must_use]
pub(crate) fn claims_no_position(e: &Entity) -> bool {
    e.kind == EntityKind::Coordinates
        && (e.evidence.iter().any(is_country_signal)
            || COUNTRY_SIGNAL_TAGS.iter().any(|t| e.has_tag(t)))
        && assess(e).basis == FixBasis::CountrySignal
}

/// The finest precision radius (metres) the correlator's fusion may weigh `e`
/// at — its finest person-anchoring source's class radius, never finer than
/// [`assess`] grades the point.
///
/// The class radius is the correlator's ("a GPS fix is ~10 m, a registry office
/// ~500 m"); the `max` with [`assess`] is coarsen-only, so a centroid carried
/// under `geocode` by `address_to_coords_pass` is weighed as the city it is,
/// not a 40 m rooftop (the tabulated Brisbane centroid read 40 m before), and a
/// geocode of a city-only address as that city. `None` when the entity carries
/// no anchoring source, exactly as before (REQ-GEOLABEL-007).
///
/// Always FINITE: a point graded with no radius (a country signal) returns
/// `None` rather than infinity. The person-anchor gate already keeps such a
/// point out of every rule that reads this ([`claims_no_position`]); this is
/// the contract that makes a radius from here safe to print and to fold.
#[must_use]
pub(crate) fn best_precision_radius_m(e: &Entity) -> Option<f64> {
    let finest = e
        .corroborating_sources()
        .into_iter()
        .filter(|s| is_anchoring_geo_source(s))
        .map(|s| precision_radius_m(geo_source_class(s)))
        .fold(None, |acc: Option<f64>, r| {
            Some(acc.map_or(r, |a| a.min(r)))
        })?;
    if e.kind == EntityKind::Coordinates {
        Some(finest.max(assess(e).radius_m)).filter(|r| r.is_finite())
    } else {
        Some(finest)
    }
}
