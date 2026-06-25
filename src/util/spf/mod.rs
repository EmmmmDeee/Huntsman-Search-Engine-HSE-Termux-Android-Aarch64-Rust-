//! SPF (RFC 7208) parsing, sender extraction, and **security analysis**.
//!
//! Two layers:
//!
//! * [`is_spf`] + [`members`] — the lean, zero-copy member extractor the DNS
//!   modules share so `dns_intel` and `doh_resolver` can't drift in what they
//!   pull out of a `v=spf1` record (they had: one case-sensitive version check,
//!   one case-insensitive; both silently dropping `ip6:`).
//! * [`parse`] → [`SpfRecord`] — a full structural parse plus the analysis an
//!   OSINT/email-security pass actually wants: the effective catch-all
//!   [`AllPolicy`] (`-all`/`~all`/`?all`/`+all`), the **DNS-lookup budget**
//!   ([`SpfRecord::dns_lookup_count`], RFC 7208 §4.6.4 caps it at 10 — the most
//!   common real-world SPF break), a list of [`SpfIssue`] misconfigurations, and
//!   a no-DNS literal-range membership test ([`SpfRecord::lists_ip`]).
//!
//! Unknown modifiers are ignored, not errored (RFC 7208 §6); CIDR maths is
//! overflow-safe (a `/0` never shifts by the word width); parsing is total and
//! never panics. Macro expansion and the live recursive `include`/`a`/`mx`
//! evaluation are out of scope here — they require live DNS and a macro engine;
//! this layer is the pure, statically-decidable core.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// True if `txt` is an SPF record. Per RFC 7208 §4.5 the `v=spf1` version
/// tag is matched case-insensitively.
#[must_use]
pub fn is_spf(txt: &str) -> bool {
    let b = txt.as_bytes();
    b.len() >= 6 && b[..6].eq_ignore_ascii_case(b"v=spf1")
}

/// An authorising member of an SPF record that resolves to an entity.
#[derive(Debug, PartialEq, Eq)]
pub enum Member<'a> {
    /// An `ip4:` / `ip6:` address with any CIDR suffix stripped — never empty.
    Ip(&'a str),
    /// An `include:` domain — guaranteed non-empty and dotted.
    Include(&'a str),
    /// The `redirect=` modifier's target domain — guaranteed non-empty and
    /// dotted. Delegates the whole SPF policy to another domain (RFC 7208 §6),
    /// so for OSINT it is a related-domain pivot just like an `include:`.
    Redirect(&'a str),
    /// An `a:domain` mechanism target — whose A records authorise sending.
    /// Bare `a` (no colon) is skipped; only explicit cross-domain references
    /// are surfaced as new OSINT pivots.
    A(&'a str),
    /// An `mx:domain` mechanism target — whose MX records authorise sending.
    /// Bare `mx` (no colon) is skipped for the same reason as bare `a`.
    Mx(&'a str),
}

/// Iterate the `ip4:`/`ip6:`/`include:`/`redirect=`/`a:`/`mx:` members of an
/// SPF record. Bare/blank IP mechanisms and empty/dotless or macro-bearing
/// domain targets are skipped (they would only normalise to junk entities).
/// Bare `a` and `mx` (no explicit domain target), `ptr`, `exists`, `all`, and
/// the `exp=` modifier are not interpreted — callers tag the domain itself.
pub fn members(txt: &str) -> impl Iterator<Item = Member<'_>> {
    // A usable include/redirect/a/mx target is non-empty, dotted, and free of
    // SPF macros (`%{…}`) which don't resolve to a literal domain.
    fn usable_domain(d: &str) -> bool {
        d.contains('.') && !d.contains('%')
    }
    txt.split_whitespace().filter_map(|part| {
        // A *mechanism* (ip4/ip6/include/a/mx) may carry an optional leading
        // qualifier — `+`/`-`/`~`/`?` (RFC 7208 §4.6.1) — e.g. `-ip4:…` or
        // `?include:…`. Strip it before matching, or a qualified member is
        // silently dropped. A *modifier* (`redirect=`) takes no qualifier, so
        // it is matched on the original token.
        let mech = part.strip_prefix(['+', '-', '~', '?']).unwrap_or(part);
        if let Some(ip) = mech
            .strip_prefix("ip4:")
            .or_else(|| mech.strip_prefix("ip6:"))
        {
            let ip = ip.split('/').next().unwrap_or(ip);
            (!ip.is_empty()).then_some(Member::Ip(ip))
        } else if let Some(inc) = mech.strip_prefix("include:") {
            usable_domain(inc).then_some(Member::Include(inc))
        } else if let Some(red) = part.strip_prefix("redirect=") {
            usable_domain(red).then_some(Member::Redirect(red))
        } else if let Some(a_dom) = mech.strip_prefix("a:") {
            usable_domain(a_dom).then_some(Member::A(a_dom))
        } else if let Some(mx_dom) = mech.strip_prefix("mx:") {
            usable_domain(mx_dom).then_some(Member::Mx(mx_dom))
        } else {
            None
        }
    })
}

// ── Structural parse + analysis ─────────────────────────────────────────────

/// A mechanism qualifier (RFC 7208 §4.6.2). The default when omitted is `Pass`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Qualifier {
    /// `+` — authorise.
    Pass,
    /// `-` — reject.
    Fail,
    /// `~` — accept but mark (soft fail).
    SoftFail,
    /// `?` — no assertion.
    Neutral,
}

/// An SPF mechanism (RFC 7208 §5). `a`/`mx`/`ptr` retain only their optional
/// target domain — the OSINT pivot; their CIDR suffixes affect only live
/// A/AAAA evaluation, which this static layer does not perform.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Mechanism {
    /// `all` — the catch-all.
    All,
    /// `include:<domain>`.
    Include(String),
    /// `a` / `a:<domain>`.
    A(Option<String>),
    /// `mx` / `mx:<domain>`.
    Mx(Option<String>),
    /// `ptr` / `ptr:<domain>` (deprecated, RFC 7208 §5.5).
    Ptr(Option<String>),
    /// `exists:<domain>`.
    Exists(String),
    /// `ip4:<cidr>`.
    Ip4(Ipv4Cidr),
    /// `ip6:<cidr>`.
    Ip6(Ipv6Cidr),
}

/// The effective policy a record asserts for senders that match no mechanism.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AllPolicy {
    /// `-all` — reject everything else (the strict, recommended posture).
    HardFail,
    /// `~all` — soft-fail everything else (common, lenient).
    SoftFail,
    /// `?all` — neutral; asserts nothing (weak).
    Neutral,
    /// `+all` — authorise *every* sender. An open policy: anyone may spoof.
    Pass,
    /// No `all`, but a `redirect=` delegates the whole policy elsewhere.
    Redirect,
    /// No `all` and no `redirect` — the default result is Neutral (weak).
    ImplicitNeutral,
}

impl AllPolicy {
    /// Short stable tag for the posture, e.g. `"spf:hardfail"`.
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

/// A flagged SPF misconfiguration or weakness.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SpfIssue {
    /// `+all` — authorises any sender (spoofable). The most serious.
    OpenPolicy,
    /// `?all` / no catch-all — the record asserts no real protection.
    WeakPolicy,
    /// More than 10 DNS-lookup terms in this record alone (RFC 7208 §4.6.4):
    /// evaluators MUST return `permerror`, so the SPF is effectively broken.
    ExceedsLookupLimit(usize),
    /// A `ptr` mechanism — deprecated and discouraged (RFC 7208 §5.5).
    DeprecatedPtr,
    /// Macros (`%{…}`) are present — not statically resolvable.
    MacrosPresent,
    /// Mechanisms appear after the catch-all `all` and can never be reached.
    UnreachableMechanisms(usize),
    /// Terms that failed to parse (a syntax error is itself a `permerror`).
    SyntaxErrors(usize),
}

impl SpfIssue {
    /// Short stable tag for the issue (`waf:`-style), e.g. `"spf:open-policy"`.
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

/// A parsed SPF record: its ordered directives plus the modifiers and signals an
/// analysis needs.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct SpfRecord {
    /// Mechanisms in evaluation order, each with its qualifier.
    pub directives: Vec<(Qualifier, Mechanism)>,
    /// The `redirect=` target, if any (a policy-delegation pivot).
    pub redirect: Option<String>,
    /// The `exp=` explanation target, if any.
    pub exp: Option<String>,
    /// Any `%{…}` macro appeared in a domain/value.
    pub has_macros: bool,
    /// Count of unknown modifiers (ignored per RFC 7208 §6, but surfaced).
    pub unknown_modifiers: usize,
    /// Raw terms that failed to parse.
    pub invalid_terms: Vec<String>,
}

/// Parse a `v=spf1` record into an [`SpfRecord`]. Returns `None` only when `txt`
/// is not an SPF record at all; otherwise it is lenient — a malformed term is
/// collected into [`SpfRecord::invalid_terms`] rather than failing the whole
/// record, so an OSINT pass still gets everything that did parse. Total and
/// panic-free.
#[must_use]
pub fn parse(txt: &str) -> Option<SpfRecord> {
    if !is_spf(txt) {
        return None;
    }
    let mut rec = SpfRecord::default();
    for term in txt.split_whitespace().skip(1) {
        // A modifier is `name=value` where `name` is a bare LDH token (no
        // qualifier, no `:`). Anything else is a directive.
        if let Some((name, value)) = term.split_once('=')
            && !name.is_empty()
            && name
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
        {
            if value.contains('%') {
                rec.has_macros = true;
            }
            match name.to_ascii_lowercase().as_str() {
                "redirect" => rec.redirect = Some(value.to_string()),
                "exp" => rec.exp = Some(value.to_string()),
                _ => rec.unknown_modifiers += 1, // RFC 7208 §6: ignore unknown
            }
            continue;
        }

        let (qual, mech_str) = match term.as_bytes().first() {
            Some(b'+') => (Qualifier::Pass, &term[1..]),
            Some(b'-') => (Qualifier::Fail, &term[1..]),
            Some(b'~') => (Qualifier::SoftFail, &term[1..]),
            Some(b'?') => (Qualifier::Neutral, &term[1..]),
            _ => (Qualifier::Pass, term),
        };
        if mech_str.contains('%') {
            rec.has_macros = true;
        }
        match parse_mechanism(mech_str) {
            Some(m) => rec.directives.push((qual, m)),
            None => rec.invalid_terms.push(term.to_string()),
        }
    }
    Some(rec)
}

/// Case-insensitive `strip_prefix`.
fn ci_strip<'a>(s: &'a str, prefix: &str) -> Option<&'a str> {
    (s.len() >= prefix.len()
        && s.as_bytes()[..prefix.len()].eq_ignore_ascii_case(prefix.as_bytes()))
    .then(|| &s[prefix.len()..])
}

/// The optional `:<domain>` of an `a`/`mx`/`ptr` tail (`""`, `":d"`, `"/24"`,
/// `":d/24//64"` → the domain, CIDR stripped).
fn tail_domain(rest: &str) -> Option<String> {
    let d = rest.strip_prefix(':')?;
    let d = d.split('/').next().unwrap_or(d);
    (!d.is_empty()).then(|| d.to_string())
}

fn parse_mechanism(s: &str) -> Option<Mechanism> {
    if s.eq_ignore_ascii_case("all") {
        return Some(Mechanism::All);
    }
    if let Some(v) = ci_strip(s, "include:") {
        return (!v.is_empty()).then(|| Mechanism::Include(v.to_string()));
    }
    if let Some(v) = ci_strip(s, "exists:") {
        return (!v.is_empty()).then(|| Mechanism::Exists(v.to_string()));
    }
    if let Some(v) = ci_strip(s, "ip4:") {
        return Ipv4Cidr::parse(v).map(Mechanism::Ip4);
    }
    if let Some(v) = ci_strip(s, "ip6:") {
        return Ipv6Cidr::parse(v).map(Mechanism::Ip6);
    }
    // a / mx / ptr: a bare name, optionally `:<domain>` and/or `/<cidr>`.
    if let Some(rest) = ci_strip(s, "mx")
        && (rest.is_empty() || rest.starts_with([':', '/']))
    {
        return Some(Mechanism::Mx(tail_domain(rest)));
    }
    if let Some(rest) = ci_strip(s, "ptr")
        && (rest.is_empty() || rest.starts_with(':'))
    {
        return Some(Mechanism::Ptr(tail_domain(rest)));
    }
    if let Some(rest) = ci_strip(s, "a")
        && (rest.is_empty() || rest.starts_with([':', '/']))
    {
        return Some(Mechanism::A(tail_domain(rest)));
    }
    None
}

impl SpfRecord {
    /// The effective catch-all [`AllPolicy`].
    #[must_use]
    pub fn all_policy(&self) -> AllPolicy {
        if let Some((q, _)) = self
            .directives
            .iter()
            .find(|(_, m)| matches!(m, Mechanism::All))
        {
            match q {
                Qualifier::Pass => AllPolicy::Pass,
                Qualifier::Fail => AllPolicy::HardFail,
                Qualifier::SoftFail => AllPolicy::SoftFail,
                Qualifier::Neutral => AllPolicy::Neutral,
            }
        } else if self.redirect.is_some() {
            AllPolicy::Redirect
        } else {
            AllPolicy::ImplicitNeutral
        }
    }

    /// Number of DNS-lookup-incurring terms in **this** record: `include`, `a`,
    /// `mx`, `ptr`, `exists`, plus the `redirect` modifier (RFC 7208 §4.6.4).
    /// `ip4`/`ip6`/`all`/`exp` incur no lookup. A return value > 10 means an
    /// evaluator must `permerror` — the SPF is broken on its own.
    #[must_use]
    pub fn dns_lookup_count(&self) -> usize {
        let mechs = self
            .directives
            .iter()
            .filter(|(_, m)| {
                matches!(
                    m,
                    Mechanism::Include(_)
                        | Mechanism::A(_)
                        | Mechanism::Mx(_)
                        | Mechanism::Ptr(_)
                        | Mechanism::Exists(_)
                )
            })
            .count();
        mechs + usize::from(self.redirect.is_some())
    }

    /// Every [`SpfIssue`] the record exhibits, worst-first-ish.
    #[must_use]
    pub fn issues(&self) -> Vec<SpfIssue> {
        let mut out = Vec::new();
        match self.all_policy() {
            AllPolicy::Pass => out.push(SpfIssue::OpenPolicy),
            AllPolicy::Neutral | AllPolicy::ImplicitNeutral => out.push(SpfIssue::WeakPolicy),
            _ => {}
        }
        let lookups = self.dns_lookup_count();
        if lookups > 10 {
            out.push(SpfIssue::ExceedsLookupLimit(lookups));
        }
        if self
            .directives
            .iter()
            .any(|(_, m)| matches!(m, Mechanism::Ptr(_)))
        {
            out.push(SpfIssue::DeprecatedPtr);
        }
        if self.has_macros {
            out.push(SpfIssue::MacrosPresent);
        }
        if let Some(i) = self
            .directives
            .iter()
            .position(|(_, m)| matches!(m, Mechanism::All))
        {
            let after = self.directives.len() - 1 - i;
            if after > 0 {
                out.push(SpfIssue::UnreachableMechanisms(after));
            }
        }
        if !self.invalid_terms.is_empty() {
            out.push(SpfIssue::SyntaxErrors(self.invalid_terms.len()));
        }
        out
    }

    /// The qualifier of the first `ip4:`/`ip6:` mechanism whose CIDR literally
    /// contains `ip`, or `None`. A no-DNS membership test — it does **not**
    /// perform full SPF evaluation (it ignores `a`/`mx`/`include`/order vs DNS
    /// mechanisms), so it answers only "is this IP in a published literal range,
    /// and under what qualifier".
    #[must_use]
    pub fn lists_ip(&self, ip: IpAddr) -> Option<Qualifier> {
        for (q, m) in &self.directives {
            match (m, ip) {
                (Mechanism::Ip4(c), IpAddr::V4(v4)) if c.contains(v4) => return Some(*q),
                (Mechanism::Ip6(c), IpAddr::V6(v6)) if c.contains(v6) => return Some(*q),
                _ => {}
            }
        }
        None
    }
}

// ── Overflow-safe CIDR maths ─────────────────────────────────────────────────

/// An IPv4 network: address + prefix length, with containment. A `/0` masks to
/// zero rather than shifting by the word width (which would be UB/panic).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Ipv4Cidr {
    addr: Ipv4Addr,
    prefix: u8,
}

impl Ipv4Cidr {
    /// Parse `a.b.c.d[/prefix]` (a missing prefix is `/32`). `None` on a bad
    /// address or a prefix > 32.
    #[must_use]
    pub fn parse(s: &str) -> Option<Self> {
        let (a, p) = s.split_once('/').unwrap_or((s, "32"));
        let addr: Ipv4Addr = a.trim().parse().ok()?;
        let prefix: u8 = p.trim().parse().ok()?;
        (prefix <= 32).then_some(Self { addr, prefix })
    }
    fn mask(self) -> u32 {
        if self.prefix == 0 {
            0
        } else {
            u32::MAX << (32 - self.prefix)
        }
    }
    /// True if `ip` falls within this network.
    #[must_use]
    pub fn contains(self, ip: Ipv4Addr) -> bool {
        let m = self.mask();
        (u32::from(ip) & m) == (u32::from(self.addr) & m)
    }
}

/// An IPv6 network: address + prefix length, with containment.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Ipv6Cidr {
    addr: Ipv6Addr,
    prefix: u8,
}

impl Ipv6Cidr {
    /// Parse `addr[/prefix]` (a missing prefix is `/128`). `None` on a bad
    /// address or a prefix > 128.
    #[must_use]
    pub fn parse(s: &str) -> Option<Self> {
        let (a, p) = s.split_once('/').unwrap_or((s, "128"));
        let addr: Ipv6Addr = a.trim().parse().ok()?;
        let prefix: u8 = p.trim().parse().ok()?;
        (prefix <= 128).then_some(Self { addr, prefix })
    }
    fn mask(self) -> u128 {
        if self.prefix == 0 {
            0
        } else {
            u128::MAX << (128 - self.prefix)
        }
    }
    /// True if `ip` falls within this network.
    #[must_use]
    pub fn contains(self, ip: Ipv6Addr) -> bool {
        let m = self.mask();
        (u128::from(ip) & m) == (u128::from(self.addr) & m)
    }
}

#[cfg(test)]
mod tests {
    include!("tests.rs");
}
