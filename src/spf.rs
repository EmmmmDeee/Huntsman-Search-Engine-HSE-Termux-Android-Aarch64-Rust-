//! SPF (RFC 7208) parsing and analysis.

use crate::netblock::{Ipv4Cidr, Ipv6Cidr};
use crate::value_syntax::record_tag;

/// RFC 7208 section 4.5: the version must be exactly `v=spf1`, followed
/// by an ASCII space or the end of the TXT record (not `v=spf10`).
#[must_use]
pub fn is_spf(txt: &str) -> bool {
    let bytes = txt.as_bytes();
    bytes.get(..6).is_some_and(|version| version.eq_ignore_ascii_case(b"v=spf1"))
        && bytes.get(6).is_none_or(|next| *next == b' ')
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Qualifier {
    Pass,
    Fail,
    SoftFail,
    Neutral,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Mechanism {
    All,
    Include(String),
    A(Option<String>),
    Mx(Option<String>),
    Ptr(Option<String>),
    Exists(String),
    Ip4(Ipv4Cidr),
    Ip6(Ipv6Cidr),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AllPolicy {
    HardFail,
    SoftFail,
    Neutral,
    Pass,
    Redirect,
    ImplicitNeutral,
}

impl AllPolicy {
    #[must_use]
    pub fn tag(self) -> &'static str {
        match self {
            Self::HardFail => "spf:hardfail",
            Self::SoftFail => "spf:softfail",
            Self::Neutral => "spf:neutral",
            Self::Pass => "spf:pass-all",
            Self::Redirect => "spf:redirect-policy",
            Self::ImplicitNeutral => "spf:implicit-neutral",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SpfIssue {
    OpenPolicy,
    WeakPolicy,
    ExceedsLookupLimit(usize),
    DeprecatedPtr,
    MacrosPresent,
    UnreachableMechanisms(usize),
    SyntaxErrors(usize),
}

impl SpfIssue {
    #[must_use]
    pub fn tag(&self) -> &'static str {
        match self {
            Self::OpenPolicy => "spf:open-policy",
            Self::WeakPolicy => "spf:weak-policy",
            Self::ExceedsLookupLimit(_) => "spf:too-many-lookups",
            Self::DeprecatedPtr => "spf:deprecated-ptr",
            Self::MacrosPresent => "spf:macros",
            Self::UnreachableMechanisms(_) => "spf:unreachable-mechanisms",
            Self::SyntaxErrors(_) => "spf:syntax-error",
        }
    }
}

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct SpfRecord {
    pub directives: Vec<(Qualifier, Mechanism)>,
    pub redirect: Option<String>,
    pub exp: Option<String>,
    pub has_macros: bool,
    pub unknown_modifiers: usize,
    pub invalid_terms: Vec<String>,
}

#[must_use]
pub fn parse(txt: &str) -> Option<SpfRecord> {
    if !is_spf(txt) {
        return None;
    }
    let mut record = SpfRecord::default();
    for term in txt.split_whitespace().skip(1) {
        if let Some((name, value)) = record_tag(term) {
            let is_modifier_name = !name.is_empty()
                && name
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_');
            if is_modifier_name {
                if value.contains('%') {
                    record.has_macros = true;
                }
                match name.to_ascii_lowercase().as_str() {
                    "redirect" => record.redirect = Some(value.to_string()),
                    "exp" => record.exp = Some(value.to_string()),
                    _ => record.unknown_modifiers += 1,
                }
                continue;
            }
        }

        let (qualifier, mechanism_text) = match term.as_bytes().first().copied() {
            Some(b'+') => (Qualifier::Pass, &term[1..]),
            Some(b'-') => (Qualifier::Fail, &term[1..]),
            Some(b'~') => (Qualifier::SoftFail, &term[1..]),
            Some(b'?') => (Qualifier::Neutral, &term[1..]),
            _ => (Qualifier::Pass, term),
        };
        if mechanism_text.contains('%') {
            record.has_macros = true;
        }
        match parse_mechanism(mechanism_text) {
            Some(mechanism) => record.directives.push((qualifier, mechanism)),
            None => record.invalid_terms.push(term.to_string()),
        }
    }
    Some(record)
}

fn ci_strip<'a>(value: &'a str, prefix: &str) -> Option<&'a str> {
    if value.len() >= prefix.len()
        && value.as_bytes()[..prefix.len()].eq_ignore_ascii_case(prefix.as_bytes())
    {
        Some(&value[prefix.len()..])
    } else {
        None
    }
}

fn tail_domain(rest: &str) -> Option<String> {
    let domain = rest.strip_prefix(':')?;
    let domain = domain.split('/').next().unwrap_or(domain);
    if domain.is_empty() {
        None
    } else {
        Some(domain.to_string())
    }
}

fn parse_mechanism(raw: &str) -> Option<Mechanism> {
    if raw.eq_ignore_ascii_case("all") {
        return Some(Mechanism::All);
    }
    if let Some(value) = ci_strip(raw, "include:") {
        return (!value.is_empty()).then(|| Mechanism::Include(value.to_string()));
    }
    if let Some(value) = ci_strip(raw, "exists:") {
        return (!value.is_empty()).then(|| Mechanism::Exists(value.to_string()));
    }
    if let Some(value) = ci_strip(raw, "ip4:") {
        return Ipv4Cidr::parse(value).map(Mechanism::Ip4);
    }
    if let Some(value) = ci_strip(raw, "ip6:") {
        return Ipv6Cidr::parse(value).map(Mechanism::Ip6);
    }
    if let Some(rest) = ci_strip(raw, "mx") {
        if rest.is_empty() || rest.starts_with(':') || rest.starts_with('/') {
            return Some(Mechanism::Mx(tail_domain(rest)));
        }
    }
    if let Some(rest) = ci_strip(raw, "ptr") {
        if rest.is_empty() || rest.starts_with(':') {
            return Some(Mechanism::Ptr(tail_domain(rest)));
        }
    }
    if let Some(rest) = ci_strip(raw, "a") {
        if rest.is_empty() || rest.starts_with(':') || rest.starts_with('/') {
            return Some(Mechanism::A(tail_domain(rest)));
        }
    }
    None
}

impl SpfRecord {
    #[must_use]
    pub fn all_policy(&self) -> AllPolicy {
        for (qualifier, mechanism) in &self.directives {
            if matches!(mechanism, Mechanism::All) {
                return match qualifier {
                    Qualifier::Pass => AllPolicy::Pass,
                    Qualifier::Fail => AllPolicy::HardFail,
                    Qualifier::SoftFail => AllPolicy::SoftFail,
                    Qualifier::Neutral => AllPolicy::Neutral,
                };
            }
        }
        if self.redirect.is_some() {
            AllPolicy::Redirect
        } else {
            AllPolicy::ImplicitNeutral
        }
    }

    #[must_use]
    pub fn dns_lookup_count(&self) -> usize {
        let lookups = self
            .directives
            .iter()
            .filter(|(_, mechanism)| {
                matches!(
                    mechanism,
                    Mechanism::Include(_)
                        | Mechanism::A(_)
                        | Mechanism::Mx(_)
                        | Mechanism::Ptr(_)
                        | Mechanism::Exists(_)
                )
            })
            .count();
        lookups + usize::from(self.redirect.is_some())
    }

    #[must_use]
    pub fn issues(&self) -> Vec<SpfIssue> {
        let mut issues = Vec::new();
        match self.all_policy() {
            AllPolicy::Pass => issues.push(SpfIssue::OpenPolicy),
            AllPolicy::Neutral | AllPolicy::ImplicitNeutral => issues.push(SpfIssue::WeakPolicy),
            _ => {}
        }
        let lookups = self.dns_lookup_count();
        if lookups > 10 {
            issues.push(SpfIssue::ExceedsLookupLimit(lookups));
        }
        if self
            .directives
            .iter()
            .any(|(_, mechanism)| matches!(mechanism, Mechanism::Ptr(_)))
        {
            issues.push(SpfIssue::DeprecatedPtr);
        }
        if self.has_macros {
            issues.push(SpfIssue::MacrosPresent);
        }
        if let Some(index) = self
            .directives
            .iter()
            .position(|(_, mechanism)| matches!(mechanism, Mechanism::All))
        {
            let after = self.directives.len().saturating_sub(index + 1);
            if after > 0 {
                issues.push(SpfIssue::UnreachableMechanisms(after));
            }
        }
        if !self.invalid_terms.is_empty() {
            issues.push(SpfIssue::SyntaxErrors(self.invalid_terms.len()));
        }
        issues
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fmt::Write as _;

    #[test]
    fn version_token_requires_an_exact_spf1_with_a_space_or_end() {
        // RFC 7208 section 4.5 gives v=spf10 as an explicit non-match.
        for raw in [
            "v=spf10 -all",
            "v=spf1extra +all",
            "v=spf1\t-all",
            "v=spf1\n-all",
            "v=spf1; -all",
        ] {
            assert!(!is_spf(raw), "accepted unsupported SPF version: {raw:?}");
            assert!(parse(raw).is_none(), "parsed unsupported SPF version: {raw:?}");
        }
        // Retain case-insensitive recognition and existing valid records.
        for raw in ["v=spf1", "v=spf1 -all", "V=SPF1 +mx -all"] {
            assert!(is_spf(raw), "refused supported SPF version: {raw:?}");
            assert!(parse(raw).is_some(), "failed to parse SPF record: {raw:?}");
        }
    }

    #[test]
    fn extracts_policies() {
        let record =
            parse("v=spf1 ip4:198.51.100.0/24 include:_spf.example.com -all").expect("SPF record");
        assert_eq!(record.all_policy(), AllPolicy::HardFail);
        assert_eq!(record.dns_lookup_count(), 1);
        let issues = record.issues();
        assert!(issues.is_empty(), "{issues:?}");
    }

    #[test]
    fn modifier_names_ignore_case_but_not_spaces() {
        let record =
            parse("v=spf1 Redirect=_spf.example.com EXP=explain.example.com").expect("record");
        assert_eq!(record.redirect.as_deref(), Some("_spf.example.com"));
        assert_eq!(record.exp.as_deref(), Some("explain.example.com"));
        assert_eq!(record.unknown_modifiers, 0);
        assert_eq!(record.all_policy(), AllPolicy::Redirect);

        // Terms are separated by spaces, so `name = value` is three terms and none a modifier.
        let spaced = parse("v=spf1 redirect = _spf.example.com").expect("record");
        assert_eq!(spaced.redirect, None);
        assert_eq!(spaced.invalid_terms, ["redirect", "=", "_spf.example.com"]);
    }

    #[test]
    fn flags_open_weak_and_broken_records() {
        assert!(
            parse("v=spf1 +all")
                .expect("record")
                .issues()
                .contains(&SpfIssue::OpenPolicy)
        );
        assert!(
            parse("v=spf1 ip4:203.0.113.1")
                .expect("record")
                .issues()
                .contains(&SpfIssue::WeakPolicy)
        );

        let mut record = String::from("v=spf1");
        for index in 0..11 {
            let _ = write!(record, " include:_spf{index}.example.com");
        }
        record.push_str(" -all");
        let parsed = parse(&record).expect("record");
        assert!(parsed.issues().contains(&SpfIssue::ExceedsLookupLimit(11)));
    }

    #[test]
    fn detects_macros_ptr_and_unreachable_terms() {
        let record = parse("v=spf1 ptr include:%{i}.x.test -all ip4:1.2.3.4").expect("record");
        let issues = record.issues();
        assert!(issues.contains(&SpfIssue::DeprecatedPtr));
        assert!(issues.contains(&SpfIssue::MacrosPresent));
        assert!(issues.contains(&SpfIssue::UnreachableMechanisms(1)));
    }
}
