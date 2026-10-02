//! Canonical forms for entity values and provenance labels.

use crate::evidence_ancestry::canonical_family;
use crate::validation;

const TRACKING_PARAMS: &[&str] = &[
    "gclid",
    "gclsrc",
    "dclid",
    "gbraid",
    "wbraid",
    "_ga",
    "_gl",
    "fbclid",
    "igshid",
    "igsh",
    "mibextid",
    "msclkid",
    "twclid",
    "ref_src",
    "ref_url",
    "yclid",
    "mc_cid",
    "mc_eid",
    "mkt_tok",
    "_hsenc",
    "_hsmi",
    "hsctatracking",
    "vero_id",
    "vero_conv",
    "oly_anon_id",
    "oly_enc_id",
    "wickedid",
    "spm",
    "scm",
    "s_kwcid",
    "_openstat",
    "icid",
];

#[must_use]
pub fn canonical_whitespace(raw: &str) -> String {
    raw.split_whitespace()
        .map(str::to_ascii_lowercase)
        .collect::<Vec<_>>()
        .join(" ")
}

#[must_use]
pub fn canonical_name(raw: &str) -> String {
    canonical_whitespace(raw)
}

#[must_use]
pub fn canonical_handle(raw: &str) -> Option<String> {
    let trimmed = raw
        .trim()
        .trim_start_matches('@')
        .chars()
        .filter(|c| !matches!(c, '.' | '_' | '-'))
        .map(|c| c.to_ascii_lowercase())
        .collect::<String>();
    if trimmed.is_empty()
        || trimmed.len() > 40
        || !trimmed.chars().all(|c| c.is_ascii_alphanumeric())
    {
        return None;
    }
    Some(trimmed)
}

fn valid_domain_label(label: &str) -> bool {
    !label.is_empty()
        && label.len() <= 63
        && !label.starts_with('-')
        && !label.ends_with('-')
        && label.chars().all(|c| c.is_ascii_alphanumeric() || c == '-')
}

#[must_use]
pub fn canonical_domain(raw: &str) -> Option<String> {
    let domain = raw.trim().trim_matches('.').to_ascii_lowercase();
    if domain.is_empty() || domain.len() > 253 {
        return None;
    }
    let labels: Vec<&str> = domain.split('.').collect();
    if labels.len() < 2 || !labels.iter().all(|label| valid_domain_label(label)) {
        return None;
    }
    Some(domain)
}

#[must_use]
pub fn canonical_domain_host(raw: &str) -> Option<String> {
    let domain = raw.trim().trim_matches('.').to_ascii_lowercase();
    let stripped = domain.strip_prefix("www.").unwrap_or(domain.as_str());
    canonical_domain(stripped)
}

#[must_use]
pub fn canonical_email(raw: &str) -> Option<String> {
    let trimmed = raw.trim().to_ascii_lowercase();
    let (local, domain) = trimmed.split_once('@')?;
    if local.is_empty()
        || !local
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '+' | '-'))
    {
        return None;
    }
    Some(format!("{local}@{}", canonical_domain(domain)?))
}

#[must_use]
pub fn canonical_phone(raw: &str) -> Option<String> {
    validation::to_e164_au(raw)
}

#[must_use]
pub fn canonical_coordinates(raw: &str) -> Option<String> {
    let (lat, lon) = raw.split_once(',')?;
    let lat: f64 = lat.trim().parse().ok()?;
    let lon: f64 = lon.trim().parse().ok()?;
    if !((-90.0)..=90.0).contains(&lat) || !((-180.0)..=180.0).contains(&lon) {
        return None;
    }
    Some(format!("{lat:.6},{lon:.6}"))
}

#[must_use]
pub fn canonical_provenance_family(raw: &str) -> String {
    canonical_family(raw)
}

#[must_use]
pub fn is_tracking_param_key(key: &str) -> bool {
    if key
        .get(..4)
        .is_some_and(|prefix| prefix.eq_ignore_ascii_case("utm_"))
    {
        return true;
    }
    TRACKING_PARAMS
        .iter()
        .any(|known| key.eq_ignore_ascii_case(known))
}

#[must_use]
pub fn canonical_query(raw: &str) -> String {
    let mut pairs: Vec<(String, String)> = raw
        .split('&')
        .filter(|part| !part.is_empty())
        .filter_map(|part| {
            let (key, value) = part.split_once('=').unwrap_or((part, ""));
            if is_tracking_param_key(key) {
                None
            } else {
                Some((key.to_ascii_lowercase(), value.to_owned()))
            }
        })
        .collect();
    pairs.sort_unstable();
    pairs
        .into_iter()
        .map(|(key, value)| {
            if value.is_empty() {
                key
            } else {
                format!("{key}={value}")
            }
        })
        .collect::<Vec<_>>()
        .join("&")
}

#[must_use]
pub fn canonical_url(raw: &str) -> Option<String> {
    let trimmed = raw.trim();
    let (scheme, rest) = trimmed.split_once("://")?;
    if !matches!(scheme.to_ascii_lowercase().as_str(), "http" | "https") {
        return None;
    }
    let (before_fragment, _) = rest.split_once('#').unwrap_or((rest, ""));
    let split = before_fragment
        .find(['/', '?'])
        .unwrap_or(before_fragment.len());
    let authority = &before_fragment[..split];
    let tail = &before_fragment[split..];
    let (host, port) = authority.split_once(':').unwrap_or((authority, ""));
    let host = canonical_domain(host)?;
    let port = if port.is_empty()
        || (scheme.eq_ignore_ascii_case("http") && port == "80")
        || (scheme.eq_ignore_ascii_case("https") && port == "443")
    {
        String::new()
    } else {
        format!(":{port}")
    };
    let (path, query) = tail.split_once('?').unwrap_or((tail, ""));
    let path = if path.is_empty() { "/" } else { path };
    let query = canonical_query(query);
    let rendered_path = if path == "/" { "" } else { path };
    let mut out = format!(
        "{}://{}{port}{rendered_path}",
        scheme.to_ascii_lowercase(),
        host
    );
    if !query.is_empty() {
        out.push('?');
        out.push_str(&query);
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn handle_collapses_separators() {
        assert_eq!(
            canonical_handle("@Ada.Lovelace"),
            Some("adalovelace".into())
        );
        assert_eq!(canonical_handle(""), None);
    }

    #[test]
    fn email_and_domain_are_validated() {
        assert_eq!(
            canonical_email(" Ada@Test.EXAMPLE.com "),
            Some("ada@test.example.com".into())
        );
        assert_eq!(canonical_email("x@."), None);
        assert_eq!(canonical_domain("ExAmPlE.COM."), Some("example.com".into()));
        assert_eq!(
            canonical_domain_host(" WWW.Example.COM. "),
            Some("example.com".into())
        );
    }

    #[test]
    fn url_drops_tracking_query() {
        assert_eq!(
            canonical_url("https://Example.com/?utm_source=x&b=2&a=1"),
            Some("https://example.com?a=1&b=2".into())
        );
    }

    #[test]
    fn coordinates_and_phone_normalise() {
        assert_eq!(
            canonical_coordinates(" -27.4698 , 153.0251 "),
            Some("-27.469800,153.025100".into())
        );
        assert_eq!(
            canonical_phone("+61 412 345 678"),
            Some("+61412345678".into())
        );
        assert_eq!(canonical_phone("abc"), None);
    }
}
