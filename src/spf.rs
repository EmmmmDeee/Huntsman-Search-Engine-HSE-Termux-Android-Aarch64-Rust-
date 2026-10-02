//! SPF (RFC 7208) parsing and analysis.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use crate::signals::record_tag;

#[must_use]
pub fn is_spf(txt: &str) -> bool {
    let bytes = txt.as_bytes();
    bytes.len() >= 6 && bytes[..6].eq_ignore_ascii_case(b"v=spf1")
}

#[derive(Debug, PartialEq, Eq)]
pub enum Member<'a> {
    Ip(&'a str),
    Include(&'a str),
    Redirect(&'a str),
    A(&'a str),
    Mx(&'a str),
}

pub fn members(txt: &str) -> impl Iterator<Item = Member<'_>> {
    fn usable_domain(value: &str) -> bool {
        value.contains('.') && !value.contains('%')
    }

    txt.split_whitespace().filter_map(|part| {
        let mech = part.strip_prefix(['+', '-', '~', '?']).unwrap_or(part);
        if let Some(ip) = mech
            .strip_prefix("ip4:")
            .or_else(|| mech.strip_prefix("ip6:"))
        {
            let ip = ip.split('/').next().unwrap_or(ip);
            if ip.is_empty() {
                None
            } else {
                Some(Member::Ip(ip))
            }
        } else if let Some(include) = mech.strip_prefix("include:") {
            usable_domain(include).then_some(Member::Include(include))
        } else if let Some(redirect) = part.strip_prefix("redirect=") {
            usable_domain(redirect).then_some(Member::Redirect(redirect))
        } else if let Some(domain) = mech.strip_prefix("a:") {
            usable_domain(domain).then_some(Member::A(domain))
        } else if let Some(domain) = mech.strip_prefix("mx:") {
            usable_domain(domain).then_some(Member::Mx(domain))
        } else {
            None
        }
    })
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

    #[must_use]
    pub fn lists_ip(&self, ip: IpAddr) -> Option<Qualifier> {
        for (qualifier, mechanism) in &self.directives {
            match (mechanism, ip) {
                (Mechanism::Ip4(cidr), IpAddr::V4(addr)) if cidr.contains(addr) => {
                    return Some(*qualifier);
                }
                (Mechanism::Ip6(cidr), IpAddr::V6(addr)) if cidr.contains(addr) => {
                    return Some(*qualifier);
                }
                _ => {}
            }
        }
        None
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Ipv4Cidr {
    addr: Ipv4Addr,
    prefix: u8,
}

impl Ipv4Cidr {
    #[must_use]
    pub fn parse(raw: &str) -> Option<Self> {
        let (addr_raw, prefix_raw) = raw.split_once('/').unwrap_or((raw, "32"));
        let addr: Ipv4Addr = addr_raw.trim().parse().ok()?;
        let prefix: u8 = prefix_raw.trim().parse().ok()?;
        (prefix <= 32).then_some(Self { addr, prefix })
    }

    fn mask(self) -> u32 {
        if self.prefix == 0 {
            0
        } else {
            u32::MAX << (32 - self.prefix)
        }
    }

    #[must_use]
    pub fn contains(self, ip: Ipv4Addr) -> bool {
        let mask = self.mask();
        (u32::from(ip) & mask) == (u32::from(self.addr) & mask)
    }

    #[must_use]
    pub fn prefix_len(self) -> u8 {
        self.prefix
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Ipv6Cidr {
    addr: Ipv6Addr,
    prefix: u8,
}

impl Ipv6Cidr {
    #[must_use]
    pub fn parse(raw: &str) -> Option<Self> {
        let (addr_raw, prefix_raw) = raw.split_once('/').unwrap_or((raw, "128"));
        let addr: Ipv6Addr = addr_raw.trim().parse().ok()?;
        let prefix: u8 = prefix_raw.trim().parse().ok()?;
        (prefix <= 128).then_some(Self { addr, prefix })
    }

    fn mask(self) -> u128 {
        if self.prefix == 0 {
            0
        } else {
            u128::MAX << (128 - self.prefix)
        }
    }

    #[must_use]
    pub fn contains(self, ip: Ipv6Addr) -> bool {
        let mask = self.mask();
        (u128::from(ip) & mask) == (u128::from(self.addr) & mask)
    }

    #[must_use]
    pub fn prefix_len(self) -> u8 {
        self.prefix
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fmt::Write as _;

    #[test]
    fn extracts_members_and_policies() {
        let members_found: Vec<Member<'_>> = members(
            "v=spf1 +ip4:198.51.100.1 -ip6:2001:db8::1 include:_spf.example.com a:mail.example.com mx:relay.example.net redirect=_spf.redirect.test -all",
        )
        .collect();
        assert_eq!(
            members_found,
            vec![
                Member::Ip("198.51.100.1"),
                Member::Ip("2001:db8::1"),
                Member::Include("_spf.example.com"),
                Member::A("mail.example.com"),
                Member::Mx("relay.example.net"),
                Member::Redirect("_spf.redirect.test"),
            ]
        );

        let record =
            parse("v=spf1 ip4:198.51.100.0/24 include:_spf.example.com -all").expect("SPF record");
        assert_eq!(record.all_policy(), AllPolicy::HardFail);
        assert_eq!(record.dns_lookup_count(), 1);
        let issues = record.issues();
        assert!(issues.is_empty(), "{issues:?}");
        assert_eq!(
            record.lists_ip("198.51.100.17".parse().expect("ip")),
            Some(Qualifier::Pass)
        );
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

    #[test]
    fn cidr_math_is_safe() {
        assert!(
            Ipv4Cidr::parse("0.0.0.0/0")
                .expect("cidr")
                .contains("1.2.3.4".parse().expect("ip"))
        );
        assert!(
            Ipv6Cidr::parse("::/0")
                .expect("cidr")
                .contains("2001:db8::1".parse().expect("ip"))
        );
        assert!(Ipv4Cidr::parse("10.0.0.0/33").is_none());
    }
}
