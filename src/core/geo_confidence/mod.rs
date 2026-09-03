//! `core::geo_confidence` — a geolocation fix with its uncertainty, and the
//! rules for combining fixes without inventing precision.
//!
//! # Why this module exists
//!
//! A coordinate without an uncertainty is a lie of precision. "Sydney" and "the
//! doorway of 14 Smith St" are both expressible as a lat/lon pair to six
//! decimal places, and once stored that way nothing downstream can tell them
//! apart: they rank the same, cluster the same, and appear on a map the same.
//! The engine attempts geolocation for every materially geolocatable entity, so
//! it produces a great many weak fixes — and a weak fix is only safe to keep if
//! its weakness travels with it.
//!
//! A [`GeoFix`] therefore carries three things a bare coordinate does not: the
//! **radius** inside which the subject actually is, the **method** that produced
//! it (which bounds how much the radius can ever be believed), and the
//! **provenance** of the observation behind it.
//!
//! # What this module refuses to do
//!
//! * **Average two fixes.** The midpoint of two cities is a field neither
//!   subject was ever in. [`GeoFix::intersect`] narrows only when the fixes
//!   genuinely overlap, and returns a conflict otherwise.
//! * **Shrink an uncertainty by agreement.** Two independent city-level fixes
//!   agreeing is corroboration of the CITY, not evidence of a street address.
//!   The combined radius is never smaller than the better input's radius.
//! * **Let geolocation outrank stronger evidence.** Nothing here promotes a
//!   claim; a fix is evidence like any other, and [`crate::core::claim`] governs
//!   what may be concluded from it.

use serde::{Deserialize, Serialize};

#[cfg(test)]
mod tests;

/// Mean Earth radius in kilometres (IUGG), for the haversine below.
const EARTH_RADIUS_KM: f64 = 6371.0088;

/// How a fix was derived. The method sets a FLOOR on the uncertainty: no
/// amount of corroboration lets a country-level method yield a street-level
/// radius, because the method never had that resolution to give.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GeoMethod {
    /// EXIF GPS, a device fix, or a survey coordinate — metres.
    Instrument,
    /// A postal address resolved by a gazetteer — hundreds of metres.
    Address,
    /// A named suburb/locality.
    Locality,
    /// Wi-Fi BSSID / cell-tower triangulation against a public database.
    RadioSurvey,
    /// A city, from a profile field or a registry.
    City,
    /// IP geolocation. Notoriously coarse and frequently wrong about the
    /// SUBJECT even when right about the address — a VPN egress is a real place
    /// that is not the subject's place.
    IpInference,
    /// A country, from a dialling code, TLD, jurisdiction, or language.
    Country,
}

impl GeoMethod {
    /// The smallest uncertainty radius (km) this method can honestly claim.
    /// A supplied radius is raised to this floor rather than trusted below it.
    #[must_use]
    pub fn floor_km(self) -> f64 {
        match self {
            Self::Instrument => 0.05,
            Self::Address => 0.25,
            Self::Locality => 3.0,
            Self::RadioSurvey => 5.0,
            Self::City => 25.0,
            Self::IpInference => 50.0,
            Self::Country => 500.0,
        }
    }

    /// Whether the method observes the SUBJECT's location or merely a location
    /// ASSOCIATED with the subject. An IP egress, a registry's service address
    /// and a country of citizenship are all real places that need not be where
    /// the subject is — a distinction that must survive into any conclusion.
    #[must_use]
    pub fn locates_subject_directly(self) -> bool {
        matches!(self, Self::Instrument | Self::RadioSurvey)
    }

    /// Canonical wire spelling.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Instrument => "instrument",
            Self::Address => "address",
            Self::Locality => "locality",
            Self::RadioSurvey => "radio_survey",
            Self::City => "city",
            Self::IpInference => "ip_inference",
            Self::Country => "country",
        }
    }
}

/// A geolocation with its uncertainty — the only shape a coordinate may take
/// once it leaves the module that produced it.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct GeoFix {
    pub lat: f64,
    pub lon: f64,
    /// Radius in km within which the subject is believed to be. Never below
    /// [`GeoMethod::floor_km`].
    pub radius_km: f64,
    pub method: GeoMethod,
    /// The lineage that observed it, so a fix carries its provenance the same
    /// way any other evidence does.
    pub lineage: crate::core::claim::SourceLineage,
    /// When the observation was made (unix seconds), if known. A five-year-old
    /// city fix is not a current one, and combining fixes across time silently
    /// is how a subject appears to be in two places at once.
    pub observed_at: Option<u64>,
}

/// The outcome of combining two fixes.
#[derive(Debug, Clone, PartialEq)]
pub enum GeoCombination {
    /// The fixes overlap; the result is the tighter constraint.
    Narrowed(GeoFix),
    /// The fixes do not overlap. NOT an error and NOT resolved by averaging:
    /// the subject was plausibly in both places at different times, or one
    /// source is wrong, and only discriminating evidence can say which.
    Conflict {
        left: GeoFix,
        right: GeoFix,
        separation_km: f64,
    },
}

impl GeoFix {
    /// A fix, with its radius raised to the method's floor.
    ///
    /// Coordinates are validated: a non-finite or out-of-range pair is refused
    /// rather than clamped, because a clamped coordinate is a fabricated
    /// observation — silently relocating a subject to the nearest valid point
    /// on Earth is exactly the kind of invented finding the contract forbids.
    #[must_use]
    pub fn new(
        lat: f64,
        lon: f64,
        radius_km: f64,
        method: GeoMethod,
        lineage: crate::core::claim::SourceLineage,
    ) -> Option<Self> {
        if !lat.is_finite() || !lon.is_finite() || !(-90.0..=90.0).contains(&lat) {
            return None;
        }
        if !(-180.0..=180.0).contains(&lon) {
            return None;
        }
        let radius_km = if radius_km.is_finite() {
            radius_km.max(method.floor_km())
        } else {
            method.floor_km()
        };
        Some(Self {
            lat,
            lon,
            radius_km,
            method,
            lineage,
            observed_at: None,
        })
    }

    /// Stamp the observation time (builder).
    #[must_use]
    pub fn observed_at(mut self, ts: u64) -> Self {
        self.observed_at = Some(ts);
        self
    }

    /// Great-circle distance to another fix, in km.
    #[must_use]
    pub fn separation_km(&self, other: &Self) -> f64 {
        let (lat1, lon1) = (self.lat.to_radians(), self.lon.to_radians());
        let (lat2, lon2) = (other.lat.to_radians(), other.lon.to_radians());
        let (dlat, dlon) = (lat2 - lat1, lon2 - lon1);
        let a = (dlat / 2.0).sin().powi(2) + lat1.cos() * lat2.cos() * (dlon / 2.0).sin().powi(2);
        2.0 * EARTH_RADIUS_KM * a.sqrt().clamp(0.0, 1.0).asin()
    }

    /// Whether the two uncertainty discs overlap at all.
    #[must_use]
    pub fn overlaps(&self, other: &Self) -> bool {
        self.separation_km(other) <= self.radius_km + other.radius_km
    }

    /// Combine two fixes of the SAME subject.
    ///
    /// Overlapping fixes narrow to the tighter one — its centre and its radius,
    /// never a midpoint and never a smaller radius than either input allows.
    /// Two agreeing city fixes corroborate the city; they do not synthesise a
    /// street. Non-overlapping fixes return [`GeoCombination::Conflict`] with
    /// both preserved.
    #[must_use]
    pub fn intersect(&self, other: &Self) -> GeoCombination {
        let separation_km = self.separation_km(other);
        if separation_km > self.radius_km + other.radius_km {
            return GeoCombination::Conflict {
                left: self.clone(),
                right: other.clone(),
                separation_km,
            };
        }
        // The tighter fix wins outright. Its radius is already at or above its
        // own method floor, so the result can never claim resolution that no
        // input method possessed.
        let tighter = if self.radius_km <= other.radius_km {
            self
        } else {
            other
        };
        GeoCombination::Narrowed(tighter.clone())
    }

    /// A short operator-facing rendering that always shows the uncertainty, so
    /// a coordinate can never be read as more precise than it is.
    #[must_use]
    pub fn describe(&self) -> String {
        format!(
            "{:.5}, {:.5} ±{:.2} km ({}{})",
            self.lat,
            self.lon,
            self.radius_km,
            self.method.as_str(),
            if self.method.locates_subject_directly() {
                ""
            } else {
                ", associated-location"
            }
        )
    }
}
