//! Vietnamese `.vn` domain-registrant semantics — the VN analogue of the
//! `.au` registrant classifier in [`crate::util::address_au::au_domain_registrant`].
//!
//! Vietnam operates a structured second-level-domain namespace under `.vn`,
//! administered by VNNIC (the Vietnam Internet Network Information Center). Each
//! generic second-level domain encodes the registrant's *type* — `gov.vn` a
//! government body, `edu.vn` an education/training institution, `com.vn` a
//! commercial entity, `name.vn` a natural person, and so on — exactly the way a
//! `.au` second-level domain encodes its registrant under the auDA licensing
//! rules. That type is a people-vs-organisation and jurisdiction signal the
//! engine can read straight off the domain string, with no network call.
//!
//! ## Authoritative source
//!
//! The second-level-domain list below is the published VNNIC namespace, defined
//! in Circular No. 24/2015/TT-BTTTT of Vietnam's Ministry of Information and
//! Communications and mirrored, entry for entry, in the Mozilla Public Suffix
//! List's `vn` section (<https://publicsuffix.org/list/public_suffix_list.dat>).
//! Both are public, verifiable registry documents — this is a classification of
//! a *published domain hierarchy*, never an inference from observed private
//! data (RULE 1). Only the second-level domains whose registrant *category* is
//! unambiguous in that source are categorised here; the ambiguous ones
//! (`pro.vn`, `info.vn`, `health.vn`, `int.vn`) still classify to Vietnam at
//! country grain via the classifier's ccTLD table, they simply carry no
//! registrant-type tag.

/// Classify a Vietnamese `.vn` domain by the registrant *type* its second-level
/// domain encodes, returning `(category, human-readable label)`.
///
/// The `category` vocabulary is deliberately shared with
/// [`crate::util::address_au::au_domain_registrant`] — `government`,
/// `education`, `commercial`, `non-profit`, `individual` — so a downstream
/// consumer that already reasons over AU registrant categories (e.g. the
/// people-vs-organisation correlation rules) reads a VN domain with the same
/// vocabulary. Matching is on the registrable suffix, case-insensitively, so a
/// subdomain (`mail.mps.gov.vn`) classifies identically to its parent.
///
/// Returns `None` for a domain that is not `.vn`, or a `.vn` domain registered
/// directly under a geographic or ambiguous second-level domain that carries no
/// registrant-type signal (e.g. a bare `example.vn` or `foo.hanoi.vn`).
#[must_use]
pub fn vn_domain_registrant(domain: &str) -> Option<(&'static str, &'static str)> {
    let d = domain.trim().trim_end_matches('.').to_ascii_lowercase();
    if !d.ends_with(".vn") {
        return None;
    }
    // Ordered most-specific-first; the suffixes are disjoint, so `ends_with`
    // order is not load-bearing — only the longest-suffix intent is.
    const REGISTRANTS: &[(&str, &str, &str)] = &[
        (
            ".gov.vn",
            "government",
            "a Vietnamese government body (gov.vn)",
        ),
        (
            ".edu.vn",
            "education",
            "a Vietnamese education/training institution (edu.vn)",
        ),
        (
            ".ac.vn",
            "education",
            "a Vietnamese research/academic institution (ac.vn)",
        ),
        (
            ".org.vn",
            "non-profit",
            "a Vietnamese political/social/professional organisation (org.vn)",
        ),
        (
            ".com.vn",
            "commercial",
            "a Vietnamese commercial registrant (com.vn)",
        ),
        (
            ".biz.vn",
            "commercial",
            "a Vietnamese business registrant (biz.vn)",
        ),
        (
            ".net.vn",
            "commercial",
            "a Vietnamese network-service registrant (net.vn)",
        ),
        (
            ".name.vn",
            "individual",
            "a natural-person Vietnamese registrant (name.vn)",
        ),
    ];
    REGISTRANTS
        .iter()
        .find(|(suffix, _, _)| d.ends_with(suffix))
        .map(|&(_, tag, label)| (tag, label))
}

#[cfg(test)]
mod tests {
    include!("tests.rs");
}
