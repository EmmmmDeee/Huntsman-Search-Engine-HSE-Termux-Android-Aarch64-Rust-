//! DMARC (RFC 7489) parsing and security analysis.
//!
//! Two layers:
//!
//! * [`is_dmarc`] — quick version-tag check before committing to a full parse.
//! * [`parse`] → [`DmarcRecord`] — structural parse plus the analysis an
//!   email-security OSINT pass needs: the effective disposition policy
//!   ([`DmarcPolicy`]), subdomain override ([`DmarcRecord::sp`]), the coverage
//!   percentage ([`DmarcRecord::pct`]), DKIM/SPF alignment modes
//!   ([`AlignmentMode`]), and the `rua`/`ruf` report-destination addresses.
//!
//! DMARC records live at `_dmarc.{domain}` (RFC 7489 §6.6.3), never at the
//! domain apex — callers are responsible for looking up the correct name.
//!
//! Parsing is total and never panics. Unknown tags are ignored (RFC 7489 §6.3
//! requires forward-compatibility). A tag that appears more than once uses the
//! first value (left-to-right, RFC 7489 §6.3).

/// True if `txt` is a DMARC record. `v=DMARC1` is matched case-insensitively
/// as required by RFC 7489 §6.3 (the version tag is case-insensitive).
#[must_use]
pub fn is_dmarc(txt: &str) -> bool {
    let b = txt.as_bytes();
    b.len() >= 8 && b[..8].eq_ignore_ascii_case(b"v=DMARC1")
}

/// The disposition policy a DMARC record requests for messages that fail
/// authentication (RFC 7489 §6.3 `p=` tag).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DmarcPolicy {
    /// `p=none` — monitoring only; no enforcement. The weakest posture.
    None,
    /// `p=quarantine` — route failing mail to junk/spam.
    Quarantine,
    /// `p=reject` — reject failing mail outright. The strongest posture.
    Reject,
}

impl DmarcPolicy {
    /// Short stable tag, e.g. `"dmarc:none"`.
    #[must_use]
    pub fn tag(self) -> &'static str {
        match self {
            Self::None => "dmarc:none",
            Self::Quarantine => "dmarc:quarantine",
            Self::Reject => "dmarc:reject",
        }
    }

    fn parse(s: &str) -> Option<Self> {
        match s.to_ascii_lowercase().as_str() {
            "none" => Some(Self::None),
            "quarantine" => Some(Self::Quarantine),
            "reject" => Some(Self::Reject),
            _ => None,
        }
    }
}

/// DKIM/SPF identifier-alignment mode (RFC 7489 §3.1 `adkim=`/`aspf=` tags).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AlignmentMode {
    /// `r` — relaxed: organisational domain match (the default).
    Relaxed,
    /// `s` — strict: exact domain match required.
    Strict,
}

impl AlignmentMode {
    fn parse(s: &str) -> Option<Self> {
        match s.to_ascii_lowercase().as_str() {
            "r" => Some(Self::Relaxed),
            "s" => Some(Self::Strict),
            _ => None,
        }
    }
}

/// A flagged DMARC misconfiguration or weakness.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DmarcIssue {
    /// `p=none` — no enforcement; the record is monitoring-only.
    NoEnforcement,
    /// `pct=` is present and less than 100 — partial enforcement.
    PartialCoverage(u8),
    /// `sp=none` or `sp=` not set while `p=none` — subdomain unprotected.
    SubdomainUnprotected,
    /// No `rua=` address — aggregate reports won't be received; failures are
    /// silent and the domain owner can't detect abuse.
    NoAggregateReports,
    /// The `p=` tag is absent or unparseable — the record is effectively a no-op
    /// (RFC 7489 §6.6.1 says `p=` MUST be present; absent means treat as none).
    MissingPolicy,
}

impl DmarcIssue {
    /// Short stable tag, e.g. `"dmarc:no-enforcement"`.
    #[must_use]
    pub fn tag(&self) -> &'static str {
        match self {
            Self::NoEnforcement => "dmarc:no-enforcement",
            Self::PartialCoverage(_) => "dmarc:partial-coverage",
            Self::SubdomainUnprotected => "dmarc:subdomain-unprotected",
            Self::NoAggregateReports => "dmarc:no-aggregate-reports",
            Self::MissingPolicy => "dmarc:missing-policy",
        }
    }
}

/// A parsed DMARC record (`v=DMARC1; …`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DmarcRecord {
    /// The required `p=` disposition policy. `None` means the tag was absent or
    /// unparseable (the record is effectively a no-op per RFC 7489 §6.6.1).
    pub policy: Option<DmarcPolicy>,
    /// `sp=` — subdomain policy override. When absent the parent `p=` applies.
    pub sp: Option<DmarcPolicy>,
    /// `pct=` — percentage of failing mail to apply policy to (0–100). When
    /// absent the default is 100.
    pub pct: u8,
    /// `adkim=` — DKIM alignment mode. Default: `Relaxed`.
    pub adkim: AlignmentMode,
    /// `aspf=` — SPF alignment mode. Default: `Relaxed`.
    pub aspf: AlignmentMode,
    /// `rua=` aggregate-report destinations (parsed `mailto:` URIs, size suffix
    /// stripped). May be empty if the tag is absent.
    pub rua: Vec<String>,
    /// `ruf=` forensic-report destinations (parsed `mailto:` URIs, size suffix
    /// stripped). May be empty if the tag is absent.
    pub ruf: Vec<String>,
    /// `fo=` — failure-reporting options string, kept verbatim.
    pub fo: Option<String>,
    /// `ri=` — aggregate-report interval in seconds. Default: 86400.
    pub ri: u32,
    /// `rf=` — report format. Default: `"afrf"`.
    pub rf: Option<String>,
}

impl Default for DmarcRecord {
    fn default() -> Self {
        Self {
            policy: None,
            sp: None,
            pct: 100,
            adkim: AlignmentMode::Relaxed,
            aspf: AlignmentMode::Relaxed,
            rua: Vec::new(),
            ruf: Vec::new(),
            fo: None,
            ri: 86_400,
            rf: None,
        }
    }
}

/// Parse a `v=DMARC1` TXT record. Returns `None` only when `txt` is not a
/// DMARC record at all. Otherwise, all tags that successfully parse are filled
/// in; unknown/malformed tags are skipped without failing the whole parse.
/// Tag order is preserved; first occurrence wins for duplicate tags (RFC 7489
/// §6.3: "leftmost value used"). Total and panic-free.
#[must_use]
pub fn parse(txt: &str) -> Option<DmarcRecord> {
    if !is_dmarc(txt) {
        return None;
    }
    let mut rec = DmarcRecord::default();
    let mut policy_set = false;
    let mut sp_set = false;
    let mut pct_set = false;
    let mut adkim_set = false;
    let mut aspf_set = false;
    let mut rua_set = false;
    let mut ruf_set = false;
    let mut fo_set = false;
    let mut ri_set = false;
    let mut rf_set = false;

    for tag in txt.split(';') {
        let tag = tag.trim();
        if tag.is_empty() {
            continue;
        }
        let Some((name, value)) = tag.split_once('=') else {
            continue;
        };
        let name = name.trim().to_ascii_lowercase();
        let value = value.trim();
        match name.as_str() {
            "v" => {} // version tag, already validated
            "p" if !policy_set => {
                rec.policy = DmarcPolicy::parse(value);
                policy_set = true;
            }
            "sp" if !sp_set => {
                rec.sp = DmarcPolicy::parse(value);
                sp_set = true;
            }
            "pct" if !pct_set => {
                if let Ok(n) = value.parse::<u8>()
                    && n <= 100
                {
                    rec.pct = n;
                    pct_set = true;
                }
            }
            "adkim" if !adkim_set => {
                if let Some(m) = AlignmentMode::parse(value) {
                    rec.adkim = m;
                    adkim_set = true;
                }
            }
            "aspf" if !aspf_set => {
                if let Some(m) = AlignmentMode::parse(value) {
                    rec.aspf = m;
                    aspf_set = true;
                }
            }
            "rua" if !rua_set => {
                rec.rua = parse_mailto_list(value);
                rua_set = true;
            }
            "ruf" if !ruf_set => {
                rec.ruf = parse_mailto_list(value);
                ruf_set = true;
            }
            "fo" if !fo_set => {
                rec.fo = Some(value.to_string());
                fo_set = true;
            }
            "ri" if !ri_set => {
                if let Ok(n) = value.parse::<u32>() {
                    rec.ri = n;
                    ri_set = true;
                }
            }
            "rf" if !rf_set => {
                rec.rf = Some(value.to_string());
                rf_set = true;
            }
            _ => {}
        }
    }

    Some(rec)
}

/// Parse a DMARC URI list (`rua=`/`ruf=` value). Each entry is a
/// `mailto:addr[!size]` URI; non-`mailto:` URIs (e.g. `https:`) are skipped.
/// The optional `!<size>` report-size suffix is stripped (RFC 7489 §6.2).
/// Only syntactically plausible addresses (contain `@`, length ≥ 5) survive.
fn parse_mailto_list(s: &str) -> Vec<String> {
    s.split(',')
        .filter_map(|entry| {
            let addr = entry.trim().strip_prefix("mailto:")?;
            let addr = addr.split('!').next().unwrap_or(addr).trim();
            (addr.contains('@') && addr.len() >= 5).then(|| addr.to_string())
        })
        .collect()
}

impl DmarcRecord {
    /// Every [`DmarcIssue`] the record exhibits, most severe first.
    #[must_use]
    pub fn issues(&self) -> Vec<DmarcIssue> {
        let mut out = Vec::new();
        match self.policy {
            None => out.push(DmarcIssue::MissingPolicy),
            Some(DmarcPolicy::None) => {
                out.push(DmarcIssue::NoEnforcement);
                // If `sp=` is also absent or none, subdomains are unprotected.
                let sp_enforced = self
                    .sp
                    .is_some_and(|s| !matches!(s, DmarcPolicy::None));
                if !sp_enforced {
                    out.push(DmarcIssue::SubdomainUnprotected);
                }
            }
            Some(DmarcPolicy::Quarantine | DmarcPolicy::Reject) => {
                // Check if subdomain protection was explicitly weakened.
                if self.sp == Some(DmarcPolicy::None) {
                    out.push(DmarcIssue::SubdomainUnprotected);
                }
            }
        }
        if self.pct < 100 {
            out.push(DmarcIssue::PartialCoverage(self.pct));
        }
        if self.rua.is_empty() {
            out.push(DmarcIssue::NoAggregateReports);
        }
        out
    }

    /// Returns all unique email addresses from both `rua` and `ruf` report
    /// destinations — the OSINT-valuable pivot: these reveal where the
    /// organization receives failure reports, often internal infrastructure.
    #[must_use]
    pub fn report_addresses(&self) -> Vec<&str> {
        let mut addrs: Vec<&str> = self
            .rua
            .iter()
            .chain(self.ruf.iter())
            .map(String::as_str)
            .collect();
        addrs.sort_unstable();
        addrs.dedup();
        addrs
    }
}

#[cfg(test)]
mod tests {
    include!("tests.rs");
}
