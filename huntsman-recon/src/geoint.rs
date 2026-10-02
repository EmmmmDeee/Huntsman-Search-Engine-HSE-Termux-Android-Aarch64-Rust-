//! GEOINT on operator-supplied fixes. WGS84 sphere. No live geolocation.

use crate::error::Error;

const EARTH_M: f64 = 6_371_000.0;

#[derive(Debug, Clone, PartialEq)]
pub struct Fix {
    pub id: String,
    pub lat: f64,
    pub lon: f64,
    pub at_unix: i64,
}

#[derive(Debug, Clone, PartialEq)]
pub struct CoLocation {
    pub left: String,
    pub right: String,
    pub meters: f64,
    pub delta_secs: i64,
}

pub fn parse_latlon(raw: &str) -> Result<(f64, f64), Error> {
    let (a, b) = raw.split_once(',').ok_or_else(|| Error::Invalid("expected lat,lon".into()))?;
    let lat: f64 = a.trim().parse().map_err(|_| Error::Invalid("lat".into()))?;
    let lon: f64 = b.trim().parse().map_err(|_| Error::Invalid("lon".into()))?;
    if !(-90.0..=90.0).contains(&lat) || !(-180.0..=180.0).contains(&lon) {
        return Err(Error::Invalid("coordinate out of range".into()));
    }
    Ok((lat, lon))
}

#[must_use]
pub fn haversine_m(lat1: f64, lon1: f64, lat2: f64, lon2: f64) -> f64 {
    let p1 = lat1.to_radians();
    let p2 = lat2.to_radians();
    let dp = (lat2 - lat1).to_radians();
    let dl = (lon2 - lon1).to_radians();
    let h = (dp / 2.0).sin().powi(2) + p1.cos() * p2.cos() * (dl / 2.0).sin().powi(2);
    2.0 * EARTH_M * h.sqrt().asin()
}

#[must_use]
pub fn colocated(fixes: &[Fix], radius_m: f64, window_secs: i64) -> Vec<CoLocation> {
    let mut out = Vec::new();
    for i in 0..fixes.len() {
        for j in (i + 1)..fixes.len() {
            let meters = haversine_m(fixes[i].lat, fixes[i].lon, fixes[j].lat, fixes[j].lon);
            let delta = (fixes[i].at_unix - fixes[j].at_unix).abs();
            if meters <= radius_m && delta <= window_secs {
                out.push(CoLocation {
                    left: fixes[i].id.clone(),
                    right: fixes[j].id.clone(),
                    meters,
                    delta_secs: delta,
                });
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn brisbane_sydney_band() {
        // Published city centroids, not a survey. Band is the acceptance, not a claim of survey grade.
        let (blat, blon) = parse_latlon("-27.4698,153.0251").unwrap();
        let (slat, slon) = parse_latlon("-33.8688,151.2093").unwrap();
        let m = haversine_m(blat, blon, slat, slon);
        assert!(m > 700_000.0 && m < 760_000.0, "{m}");
    }

    #[test]
    fn outside_radius_or_window_is_not_colocation() {
        let fixes = vec![
            Fix { id: "a".into(), lat: -27.47, lon: 153.02, at_unix: 1_000 },
            Fix { id: "b".into(), lat: -27.47, lon: 153.03, at_unix: 1_100 },
            Fix { id: "c".into(), lat: -33.87, lon: 151.21, at_unix: 1_050 },
        ];
        let near = colocated(&fixes, 2_000.0, 200);
        assert!(near.iter().any(|c| c.left == "a" && c.right == "b"));
        assert!(near.iter().all(|c| c.right != "c" && c.left != "c"));
        let stale = colocated(&fixes, 2_000.0, 10);
        assert!(stale.is_empty());
    }

    #[test]
    fn rejects_out_of_range() {
        assert!(parse_latlon("91,0").is_err());
    }
}
