//! WAF/CDN detection — fingerprint web application firewalls and CDNs from a
//! single HTTP `HEAD` response.
//!
//! A declarative signature engine (dnstwist's `wafw00f` is the reference; this
//! covers ~30 providers) matches response **headers**, **header values**, and
//! **`Set-Cookie` cookie names** against a curated table, returns *every* layer
//! it sees (Cloudflare in front of an origin's F5, say), each with a confidence
//! and the exact evidence that fired. No API key, one `HEAD` request, and the
//! whole signature core is pure and zero-allocation (case-insensitive matching
//! runs over header bytes without lowercasing a copy).
//!
//! Cookie fingerprints (`incap_ses_*`, `AWSALB`, `BIGipServer*`, …) are read
//! from the *value* of each `Set-Cookie` header — the cookie's name — not from
//! header keys, which is the usual way this is gotten wrong.

use async_trait::async_trait;
use reqwest::header::HeaderMap;

use crate::core::{confidence, 
    entity::{Entity, EntityKind, Evidence},
    error::Result,
    module::{Module, ModuleCategory, ModuleContext, ModuleResult},
    scan::{Target, TargetKind},
};
use crate::util::http::RequestBuilderExt;

const SRC: &str = "waf_detect";

pub struct WafDetect;

#[async_trait]
impl Module for WafDetect {
    fn name(&self) -> &'static str {
        SRC
    }
    fn description(&self) -> &'static str {
        "WAF/CDN recon — fingerprints providers from HTTP response header and cookie signatures"
    }
    fn priority(&self) -> u8 {
        30
    }
    fn max_timeout_ms(&self) -> u64 {
        6_000
    }
    fn accepts(&self, t: &Target) -> bool {
        matches!(t.kind, TargetKind::Domain | TargetKind::Url)
    }

    fn category(&self) -> ModuleCategory {
        ModuleCategory::Web
    }

    fn attack_techniques(&self) -> &'static [&'static str] {
        // Fingerprints WAFs (network security appliances) and CDNs from HTTP
        // headers — ATT&CK Network Security Appliances (T1590.006) and CDNs
        // (T1596.004), not the Web category default. Both are free/keyless.
        &["T1590.006", "T1596.004"]
    }

    fn produces(&self) -> &'static [EntityKind] {
        const KINDS: &[EntityKind] = &[EntityKind::Domain];
        KINDS
    }

    async fn process(&self, target: &Target, ctx: &ModuleContext) -> Result<ModuleResult> {
        let mut result = ModuleResult::new();

        let url = match target.kind {
            TargetKind::Url => target.value.clone(),
            TargetKind::Domain => format!("https://{}", target.value.trim()),
            _ => return Ok(result),
        };

        let resp = ctx.http.head(&url).send_tagged(SRC).await?;
        let headers = resp.headers();
        let detections = detect(headers);
        if detections.is_empty() {
            return Ok(result);
        }

        // Emit the finding against the HOST, not the raw target value: for a
        // `Url` target `target.value` is the full URL (`https://host/path`),
        // which must never be stored as a `Domain` entity value.
        let host = crate::util::url_util::host_from_url(&url)
            .unwrap_or_else(|| target.value.trim().to_string());
        // Entity confidence tracks the strongest layer detected.
        let score = match detections[0].confidence {
            Confidence::High => 0.9,
            Confidence::Medium => confidence::VERY_HIGH,
            Confidence::Low => confidence::MEDIUM_HIGH,
        };
        let mut e = Entity::new(EntityKind::Domain, &host, score, &ctx.scan_id);
        for d in &detections {
            e.tag(format!("waf:{}", d.provider));
        }
        e.tag("waf-detected");

        let providers = detections
            .iter()
            .map(|d| d.provider)
            .collect::<Vec<_>>()
            .join(", ");
        let detail = detections
            .iter()
            .map(|d| format!("{} [{}] — {}", d.provider, d.confidence.label(), d.evidence))
            .collect::<Vec<_>>()
            .join("; ");
        e.add_evidence(
            Evidence::new(SRC, format!("WAF/CDN detected: {providers}"))
                .with_attr("providers", &providers)
                .with_attr("detections", &detail)
                .with_attr(
                    "server",
                    headers
                        .get("server")
                        .and_then(|v| v.to_str().ok())
                        .unwrap_or(""),
                ),
        );
        result.push(e);

        Ok(result)
    }
}

// ── Detection engine ────────────────────────────────────────────────────────

/// How strongly a signature implies the provider. `High` is a header/cookie only
/// that provider emits; `Medium` is distinctive but shared with a sibling
/// product; `Low` is suggestive (a generic cache/server banner).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum Confidence {
    Low,
    Medium,
    High,
}

impl Confidence {
    fn label(self) -> &'static str {
        match self {
            Self::Low => "low",
            Self::Medium => "medium",
            Self::High => "high",
        }
    }
}

/// A fired detection: one provider, the strongest evidence seen for it.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Detection {
    provider: &'static str,
    confidence: Confidence,
    evidence: &'static str,
}

/// What a [`Signature`] looks for.
enum Match {
    /// A response header key is present (e.g. `cf-ray`).
    Header(&'static str),
    /// A response header's value contains a substring, case-insensitively
    /// (e.g. `server` contains `cloudflare`).
    HeaderValue(&'static str, &'static str),
    /// A `Set-Cookie` sets a cookie whose **name** begins with this prefix,
    /// case-insensitively (e.g. `incap_ses_`, `AWSALB`, `BIGipServer`).
    Cookie(&'static str),
}

impl Match {
    fn fires(&self, headers: &HeaderMap, cookie_names: &[&str]) -> bool {
        match *self {
            Match::Header(k) => headers.contains_key(k),
            Match::HeaderValue(k, needle) => headers
                .get_all(k)
                .iter()
                .filter_map(|v| v.to_str().ok())
                .any(|v| ci_contains(v, needle)),
            Match::Cookie(prefix) => cookie_names.iter().any(|n| ci_starts_with(n, prefix)),
        }
    }
}

struct Signature {
    provider: &'static str,
    confidence: Confidence,
    evidence: &'static str,
    matcher: Match,
}

/// Run every signature over a response's headers and return one [`Detection`]
/// per provider that fired — its strongest evidence — ordered confidence-first
/// then alphabetically. Pure and deterministic.
fn detect(headers: &HeaderMap) -> Vec<Detection> {
    let cookies = cookie_names(headers);
    let mut found: Vec<Detection> = Vec::new();
    for sig in SIGNATURES {
        if !sig.matcher.fires(headers, &cookies) {
            continue;
        }
        // Keep one entry per provider, upgrading to the strongest evidence.
        if let Some(existing) = found.iter_mut().find(|d| d.provider == sig.provider) {
            if sig.confidence > existing.confidence {
                existing.confidence = sig.confidence;
                existing.evidence = sig.evidence;
            }
        } else {
            found.push(Detection {
                provider: sig.provider,
                confidence: sig.confidence,
                evidence: sig.evidence,
            });
        }
    }
    found.sort_by(|a, b| {
        b.confidence
            .cmp(&a.confidence)
            .then_with(|| a.provider.cmp(b.provider))
    });
    found
}

/// Cookie names set by the response, parsed from every `Set-Cookie` header's
/// value (`NAME=value; attrs…` → `NAME`). Borrowed, no per-name allocation.
fn cookie_names(headers: &HeaderMap) -> Vec<&str> {
    headers
        .get_all("set-cookie")
        .iter()
        .filter_map(|v| v.to_str().ok())
        .filter_map(|s| s.split(['=', ';']).next())
        .map(str::trim)
        .filter(|n| !n.is_empty())
        .collect()
}

/// Case-insensitive ASCII substring test, allocation-free.
fn ci_contains(haystack: &str, needle: &str) -> bool {
    let (h, n) = (haystack.as_bytes(), needle.as_bytes());
    !n.is_empty() && n.len() <= h.len() && h.windows(n.len()).any(|w| w.eq_ignore_ascii_case(n))
}

/// Case-insensitive ASCII prefix test, allocation-free.
fn ci_starts_with(s: &str, prefix: &str) -> bool {
    let (s, p) = (s.as_bytes(), prefix.as_bytes());
    s.len() >= p.len() && s[..p.len()].eq_ignore_ascii_case(p)
}

// ── Signature table ─────────────────────────────────────────────────────────
// Curated for distinctive, low-false-positive fingerprints. Multiple rows per
// provider are fine: `detect` collapses them to the strongest evidence.

use Confidence::{High, Low, Medium};
use Match::{Cookie, Header, HeaderValue};

const SIGNATURES: &[Signature] = &[
    sig("Cloudflare", High, "CF-Ray header", Header("cf-ray")),
    sig(
        "Cloudflare",
        High,
        "Server: cloudflare",
        HeaderValue("server", "cloudflare"),
    ),
    sig(
        "Cloudflare",
        High,
        "cf-mitigated header",
        Header("cf-mitigated"),
    ),
    sig(
        "Cloudflare",
        Medium,
        "cf-cache-status header",
        Header("cf-cache-status"),
    ),
    sig(
        "Cloudflare",
        Medium,
        "cf_clearance cookie",
        Cookie("cf_clearance"),
    ),
    sig("Cloudflare", Medium, "__cfduid cookie", Cookie("__cfduid")),
    sig(
        "AWS CloudFront",
        High,
        "X-Amz-Cf-Id header",
        Header("x-amz-cf-id"),
    ),
    sig(
        "AWS CloudFront",
        High,
        "X-Amz-Cf-Pop header",
        Header("x-amz-cf-pop"),
    ),
    sig(
        "AWS CloudFront",
        High,
        "Server: CloudFront",
        HeaderValue("server", "cloudfront"),
    ),
    sig("AWS ELB/ALB", Medium, "AWSALB cookie", Cookie("AWSALB")),
    sig(
        "AWS ELB/ALB",
        Medium,
        "AWSALBCORS cookie",
        Cookie("AWSALBCORS"),
    ),
    sig(
        "Akamai",
        High,
        "X-Akamai-Transformed header",
        Header("x-akamai-transformed"),
    ),
    sig(
        "Akamai",
        High,
        "Server: AkamaiGHost",
        HeaderValue("server", "akamaighost"),
    ),
    sig(
        "Akamai",
        Medium,
        "Akamai-Origin-Hop header",
        Header("akamai-origin-hop"),
    ),
    sig(
        "Akamai",
        Medium,
        "ak_bmsc (Bot Manager) cookie",
        Cookie("ak_bmsc"),
    ),
    sig(
        "Fastly",
        High,
        "X-Fastly-Request-ID header",
        Header("x-fastly-request-id"),
    ),
    sig(
        "Fastly",
        Medium,
        "X-Served-By: cache-*",
        HeaderValue("x-served-by", "cache-"),
    ),
    sig("Sucuri", High, "X-Sucuri-ID header", Header("x-sucuri-id")),
    sig(
        "Sucuri",
        High,
        "Server: Sucuri",
        HeaderValue("server", "sucuri"),
    ),
    sig(
        "Sucuri",
        Medium,
        "X-Sucuri-Cache header",
        Header("x-sucuri-cache"),
    ),
    sig(
        "Imperva/Incapsula",
        High,
        "incap_ses_* cookie",
        Cookie("incap_ses_"),
    ),
    sig(
        "Imperva/Incapsula",
        High,
        "visid_incap_* cookie",
        Cookie("visid_incap_"),
    ),
    sig(
        "Imperva/Incapsula",
        High,
        "X-Iinfo header",
        Header("x-iinfo"),
    ),
    sig(
        "Imperva/Incapsula",
        High,
        "X-CDN: Incapsula",
        HeaderValue("x-cdn", "incapsula"),
    ),
    sig(
        "Azure Front Door",
        High,
        "X-Azure-Ref header",
        Header("x-azure-ref"),
    ),
    sig(
        "F5 BIG-IP",
        High,
        "BIGipServer* cookie",
        Cookie("BIGipServer"),
    ),
    sig(
        "F5 BIG-IP",
        Medium,
        "Server: BIG-IP",
        HeaderValue("server", "big-ip"),
    ),
    sig("F5 BIG-IP", Medium, "TS* (ASM) cookie", Cookie("TS01")),
    sig(
        "ModSecurity",
        Medium,
        "Server: Mod_Security",
        HeaderValue("server", "mod_security"),
    ),
    sig(
        "ModSecurity",
        Medium,
        "Server: NOYB",
        HeaderValue("server", "noyb"),
    ),
    sig(
        "DDoS-Guard",
        High,
        "Server: ddos-guard",
        HeaderValue("server", "ddos-guard"),
    ),
    sig("StackPath", High, "X-SP-URL header", Header("x-sp-url")),
    sig("StackPath", High, "X-SP-WAF header", Header("x-sp-waf")),
    sig(
        "Barracuda",
        High,
        "barra_counter_session cookie",
        Cookie("barra_counter_session"),
    ),
    sig(
        "Barracuda",
        Medium,
        "Server: Barracuda",
        HeaderValue("server", "barracuda"),
    ),
    sig(
        "Fortinet FortiWeb",
        High,
        "FORTIWAFSID cookie",
        Cookie("FORTIWAFSID"),
    ),
    sig(
        "Fortinet FortiWeb",
        Medium,
        "Server: FortiWeb",
        HeaderValue("server", "fortiweb"),
    ),
    sig(
        "Citrix NetScaler",
        High,
        "citrix_ns_id cookie",
        Cookie("citrix_ns_id"),
    ),
    sig("Citrix NetScaler", Medium, "NSC_* cookie", Cookie("NSC_")),
    sig(
        "Wallarm",
        High,
        "Server: nginx-wallarm",
        HeaderValue("server", "nginx-wallarm"),
    ),
    sig("Reblaze", High, "rbzid cookie", Cookie("rbzid")),
    sig(
        "Reblaze",
        Medium,
        "Server: Reblaze",
        HeaderValue("server", "reblaze"),
    ),
    sig("Vercel", High, "X-Vercel-Id header", Header("x-vercel-id")),
    sig(
        "Vercel",
        Medium,
        "Server: Vercel",
        HeaderValue("server", "vercel"),
    ),
    sig(
        "Netlify",
        High,
        "Server: Netlify",
        HeaderValue("server", "netlify"),
    ),
    sig(
        "Netlify",
        Medium,
        "X-NF-Request-Id header",
        Header("x-nf-request-id"),
    ),
    sig(
        "KeyCDN",
        High,
        "Server: keycdn-engine",
        HeaderValue("server", "keycdn"),
    ),
    sig(
        "BunnyCDN",
        High,
        "Server: BunnyCDN",
        HeaderValue("server", "bunnycdn"),
    ),
    sig(
        "Section.io",
        Medium,
        "section-io-id header",
        Header("section-io-id"),
    ),
    sig(
        "Alibaba/Aliyun WAF",
        Medium,
        "aliyungf_tc cookie",
        Cookie("aliyungf_tc"),
    ),
    sig(
        "Baidu Yunjiasu",
        Medium,
        "Server: yunjiasu",
        HeaderValue("server", "yunjiasu"),
    ),
    sig(
        "Google Front End",
        Medium,
        "Server: gws",
        HeaderValue("server", "gws"),
    ),
    sig(
        "Varnish Cache",
        Low,
        "X-Varnish header",
        Header("x-varnish"),
    ),
    sig(
        "Envoy",
        Low,
        "Server: envoy",
        HeaderValue("server", "envoy"),
    ),
];

/// `const`-fn signature constructor, so the table reads as data.
const fn sig(
    provider: &'static str,
    confidence: Confidence,
    evidence: &'static str,
    matcher: Match,
) -> Signature {
    Signature {
        provider,
        confidence,
        evidence,
        matcher,
    }
}

#[cfg(test)]
mod tests {
    include!("tests.rs");
}
