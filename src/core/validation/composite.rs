use super::{
    coordinates::validate_coordinates, domain::validate_domain_shape,
    email::validate_email_syntax, phone::validate_phone_e164, report::ValidationReport,
};

/// Apply every validator that is relevant to the given entity-kind
/// string and return the first failure (or `ok` if all pass). The
/// kind set is intentionally narrow; callers with unusual kinds
/// should call the individual validators.
pub fn validate_for_kind(kind: &str, value: &str) -> ValidationReport {
    match kind {
        "phone" => validate_phone_e164(value),
        "email" => validate_email_syntax(value),
        "domain" => validate_domain_shape(value),
        "coordinates" => {
            // Accept "lat,lon" only.
            match value.split_once(',') {
                Some((a, b)) => {
                    let lat: f64 = a.trim().parse().unwrap_or(f64::NAN);
                    let lon: f64 = b.trim().parse().unwrap_or(f64::NAN);
                    validate_coordinates(lat, lon)
                }
                None => ValidationReport::fail("coord.shape", "expected 'lat,lon'"),
            }
        }
        _ => ValidationReport::ok(),
    }
}
