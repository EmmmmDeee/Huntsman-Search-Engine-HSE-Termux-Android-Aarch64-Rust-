use serde_json::Value;
use std::collections::HashSet;

use crate::core::{
    entity::{Entity, EntityKind, Evidence},
    module::ModuleResult,
};
use crate::util::oathnet::val_str;

use super::SRC;

mod crypto;
mod osint_keys;
mod patterns;
mod service_domains;
use crypto::*;
mod emit;
use emit::{emit_key, emit_key_with};
pub use emit::{store_api_credential, store_api_credential_from_item};
use osint_keys::match_osint_provider;
use patterns::KEY_PATTERNS;
use service_domains::identify_service_from_url;

/// Entropy-based credential detection — finds credentials that don't match known patterns.
/// Uses the credential_likelihood scoring from the entropy analyzer.
/// Returns confidence_score if entropy analysis found a credential.
fn try_entropy_detect(field: &str, value: &str) -> Option<f64> {
    // Skip field names that are unlikely to contain credentials
    let field_lower = field.to_lowercase();
    if !field_lower.contains("key")
        && !field_lower.contains("secret")
        && !field_lower.contains("token")
        && !field_lower.contains("password")
        && !field_lower.contains("credential")
        && !field_lower.contains("auth")
    {
        return None;
    }

    // Skip base64-encoded values — they're handled by try_decode_through_scan
    // (a base64 string has its own entropy profile, different from the decoded value).
    if is_likely_base64(value) {
        return None;
    }

    // Score the value using entropy analysis
    let score = crate::modules::credential_entropy_analyzer::credential_likelihood(value);

    // High confidence: entropy analysis flagged this as a credential
    // Threshold is conservative (75%+) to avoid false positives
    if score > 0.75 {
        return Some(score);
    }

    None
}

/// Check if a value looks like it might be base64 (mostly base64 charset, no spaces).
fn is_likely_base64(value: &str) -> bool {
    if value.len() < 16 {
        return false;
    }
    // Base64 alphabet: A-Z, a-z, 0-9, +, /, =
    let base64_chars = value
        .chars()
        .filter(|c| c.is_ascii_alphanumeric() || *c == '+' || *c == '/' || *c == '=')
        .count();
    // If >90% of chars are base64 alphabet, it might be base64
    (base64_chars as f64 / value.len() as f64) > 0.9
}

/// Public, serializable view of one entry in the `KEY_PATTERNS` table.
/// Exposed by `pattern_catalogue()` so the HTTP API can surface the
/// detector's coverage at `/api/v1/keys/patterns`.
#[derive(Debug, Clone, serde::Serialize)]
pub struct PatternEntry {
    pub prefix: &'static str,
    pub service: &'static str,
    pub min_len: usize,
}

/// Snapshot of the prefix-match table that drives `identify_api_key`.
/// Returns one entry per declared pattern in declaration order
/// (specific-before-generic), so callers can reason about override
/// priority. ~167 entries today; cheap to build (no allocations beyond
/// the Vec).
pub fn pattern_catalogue() -> Vec<PatternEntry> {
    KEY_PATTERNS
        .iter()
        .map(|p| PatternEntry {
            prefix: p.prefix,
            service: p.service,
            min_len: p.min_len,
        })
        .collect()
}

/// Operational value of a harvested foreign API key — its blast radius if the
/// leaked credential is live. Drives the confidence and the `high-value` tag on
/// the `ApiKey` entities drained from [`crate::util::found_keys`], so the
/// persisted key set is a *ranked* database: a leaked AWS secret or a private
/// key is not filed alongside a publishable Stripe key or a webhook URL.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
pub enum KeyValue {
    /// Full infrastructure / data / money compromise, or an irrevocable secret:
    /// cloud root creds, DB connection URIs, secret managers, payment *live*
    /// secrets, private keys, package-registry publish tokens.
    Critical,
    /// Send-as-victim (email/SMS/chat), source-control, billable compute (AI),
    /// or deploy/hosting control.
    High,
    /// Scoped / test / restricted keys, monitoring, and SaaS-data tokens.
    Medium,
    /// Public/publishable identifiers, webhook URLs, geocoding — low blast radius.
    Low,
}

impl KeyValue {
    /// Stable lower-case identifier (entity tag / evidence attr / API).
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Critical => "critical",
            Self::High => "high",
            Self::Medium => "medium",
            Self::Low => "low",
        }
    }

    /// Confidence to stamp on the drained `ApiKey` entity. Higher-value keys
    /// rank above the flat baseline so the graph/dossier/export surfaces them
    /// first; low-value identifiers sink below it.
    #[must_use]
    pub fn confidence(self) -> f64 {
        match self {
            Self::Critical => 0.95,
            Self::High => 0.90,
            Self::Medium => 0.80,
            Self::Low => 0.65,
        }
    }

    /// Whether to flag the key `high-value` for filtering — Critical/High only.
    #[must_use]
    pub fn is_high_value(self) -> bool {
        matches!(self, Self::Critical | Self::High)
    }
}

/// Classify a harvested key's [`KeyValue`] from its identified `service` (the
/// string returned by [`identify_vendor_api_key`]). **Pure.** Unknown but
/// vendor-recognised services default to [`KeyValue::Medium`] — a real foreign
/// key of unproven impact should never silently rank as throwaway.
#[must_use]
pub fn key_value_tier(service: &str) -> KeyValue {
    // PEM private keys → always Critical (irrevocable host/identity secret).
    if service.starts_with("pem_") || service == "age_encryption" {
        return KeyValue::Critical;
    }
    match service {
        // ── Critical: cloud root/secret, secret managers, DB URIs, payment
        //    live secrets, supply-chain publish. ──
        "aws"
        | "aws_sts"
        | "gcp_service"
        | "google_service"
        | "azure"
        | "azure_devops"
        | "alibaba_cloud"
        | "digitalocean"
        | "cloudflare"
        | "cloudflare_acct"
        | "cloudflare_worker"
        | "vault_batch"
        | "vault_service"
        | "doppler_cli"
        | "doppler_personal"
        | "doppler_service_acct"
        | "doppler_service_token"
        | "1password"
        | "pulumi"
        | "mongodb_uri"
        | "mongodb_atlas"
        | "mysql_uri"
        | "postgres_uri"
        | "redis_uri"
        | "rabbitmq_uri"
        | "supabase"
        | "planetscale_password"
        | "planetscale_token"
        | "stripe"
        | "razorpay_live"
        | "square"
        | "paystack"
        | "npm"
        | "pypi"
        | "docker_hub_pat"
        | "clojars_deploy" => KeyValue::Critical,

        // ── High: send-as-victim, source control, billable AI, deploy/hosting. ──
        "sendgrid"
        | "mailgun"
        | "mailchimp"
        | "twilio"
        | "twilio_api_sid"
        | "brevo"
        | "mailersend"
        | "resend"
        | "postmark"
        | "telegram_bot"
        | "discord_bot"
        | "slack_bot"
        | "slack_app"
        | "slack_user"
        | "slack_enterprise"
        | "slack_refresh"
        | "github"
        | "github_app"
        | "github_oauth"
        | "github_refresh"
        | "github_user_server"
        | "gitlab_pat"
        | "gitlab_oauth"
        | "gitlab_deploy"
        | "gitlab_runner"
        | "bitbucket_app_password"
        | "bitbucket_oauth"
        | "anthropic"
        | "openai"
        | "openai_svc"
        | "openai_admin"
        | "openai_or_stripe"
        | "openai_session"
        | "openrouter"
        | "cohere"
        | "mistral"
        | "groq"
        | "huggingface"
        | "replicate"
        | "together_ai"
        | "xai_grok"
        | "nvidia"
        | "perplexity"
        | "fal_ai"
        | "langsmith"
        | "wandb"
        | "lightning_ai"
        | "tavily"
        | "shopify"
        | "shopify_custom_app"
        | "shopify_partner"
        | "shopify_shared_secret"
        | "vercel_account"
        | "vercel_integration"
        | "vercel_kv"
        | "vercel_project"
        | "vercel_runtime"
        | "vercel_v2"
        | "netlify"
        | "render"
        | "railway"
        | "flyio"
        | "databricks"
        | "aptible"
        | "tailscale"
        | "digitalocean_oauth"
        | "google_oauth_secret" => KeyValue::High,

        // ── Low: public/publishable identifiers, webhook URLs, geocoding. ──
        "discord_webhook_url"
        | "slack_webhook_url"
        | "stripe_webhook"
        | "stripe_pub"
        | "clerk_pub"
        | "newrelic_browser"
        | "mapbox"
        | "sentry_dsn"
        | "geocodio"
        | "facebook"
        | "google"
        | "google_oauth"
        | "jwt_token" => KeyValue::Low,

        // ── Everything else (test/restricted/scoped, monitoring, SaaS data, and
        //    any unlisted vendor key) → Medium. ──
        _ => KeyValue::Medium,
    }
}

/// How *certain* the detector is that a harvested string is the key it was
/// labelled — a provenance axis **orthogonal** to [`KeyValue`]'s blast-radius.
/// One asks "how sure are we this is real and is what we said", the other "how
/// bad if it is". Surfaced as a `detection:` tag and evidence attribute so triage
/// can separate "we saw the provider's name beside this key" from "this merely
/// has a high-entropy shape". (A JWT is `Probable` detection yet `Low` impact;
/// a context-attributed Shodan key is `Proven` detection yet `Medium` impact —
/// the two axes genuinely differ.)
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
pub enum DetectionConfidence {
    /// An objective vendor schema **corroborated by context**: a prefix-less
    /// OSINT/threat-intel key whose surrounding identifier or URL named its
    /// provider (a `<32 alnum>` blob under `shodan_api_key=`). Assigned only by
    /// the context-attribution path ([`identify_with_context`]); the strongest
    /// signal, since the value matched a known shape *and* the provider was named.
    Proven,
    /// An objective vendor schema **alone**: a distinctive prefix (`AKIA…`,
    /// `sk-ant-…`), a JWT's `eyJ` structure, a PEM private-key block, or a crypto
    /// address. The format itself is provider-specific, so no surrounding context
    /// is needed to trust it.
    Probable,
    /// A structural/entropy match with **no** vendor identity — a `generic_hex`
    /// blob or a bare URL-parameter value. Plausibly a real key of an unknown
    /// vendor (or a stray hash the gates let through); the weakest signal.
    Potential,
}

impl DetectionConfidence {
    /// Stable lower-case label (entity tag / evidence attr / API).
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Proven => "proven",
            Self::Probable => "probable",
            Self::Potential => "potential",
        }
    }

    /// The **baseline** provenance for a key identified *without* context
    /// corroboration — i.e. straight off [`identify_api_key`]'s prefix/shape
    /// result. **Pure**, mirroring how [`key_value_tier`] reads everything from
    /// the service tag. Identity-less results (`generic_hex`, `url_param_key`) are
    /// [`Self::Potential`]; every concrete vendor/PEM/crypto schema is
    /// [`Self::Probable`]. It never returns [`Self::Proven`] — that requires the
    /// extra context signal that only [`identify_with_context`] holds, so a key
    /// matched by a *prefix* (even a Shodan/Censys one, which also has a prefix
    /// entry) is correctly `Probable`, not over-claimed as `Proven`.
    #[must_use]
    pub fn for_service(service: &str) -> Self {
        match service {
            "generic_hex" | "url_param_key" => Self::Potential,
            _ => Self::Probable,
        }
    }
}

/// High-confidence, CHEAP key identification: recognised **vendor prefixes**,
/// **PEM** private-key blocks, and **crypto** addresses only. Deliberately
/// excludes the generic-hex / URL-param / `user:pass` heuristics.
///
/// For a token that matches none of these the cost is just prefix comparisons —
/// no Shannon-entropy pass, no lowercase allocation. That matters because the
/// universal response scanner (`util::found_keys`) runs key identification on
/// EVERY response body across every module: profiling showed the full
// Compiled aho-corasick automaton over the KEY_PATTERNS prefix table.
// LeftmostFirst preserves declaration order (specific-before-generic): when
// two patterns both anchor at position 0, the one declared first wins.
// Avoids the O(N) starts_with scan for the common case of no prefix match.
static PREFIX_MATCHER: std::sync::LazyLock<crate::util::scan::PrefixMatcher> =
    std::sync::LazyLock::new(|| {
        crate::util::scan::PrefixMatcher::new(KEY_PATTERNS.iter().map(|p| p.prefix))
    });

// Pre-grouped indices: prefix → [idx, …] in declaration order.
// A handful of prefixes appear more than once (phc_, pplx-, pk_live_) — they
// represent either multiple token shapes for the same service or provider
// overlaps (Stripe + Clerk both issue pk_live_). After aho-corasick identifies
// WHICH prefix matches, iterate only the K entries for that prefix (K ≤ 2).
static PREFIX_GROUPS: std::sync::LazyLock<std::collections::HashMap<&'static str, Vec<usize>>> =
    std::sync::LazyLock::new(|| {
        let mut map: std::collections::HashMap<&'static str, Vec<usize>> =
            std::collections::HashMap::new();
        for (i, pat) in KEY_PATTERNS.iter().enumerate() {
            map.entry(pat.prefix).or_default().push(i);
        }
        map
    });

/// [`identify_api_key`] at ~2.8 MB/s, dominated by `is_likely_real_key`
/// (entropy + context exclusion) triggering on every 32/64-char hex token — and
/// breach corpora are *full* of hex password hashes. Those hashes are already
/// captured as `Password` entities by the breach modules, so re-deriving them
/// here as "generic-hex API keys" was both slow and noisy. This function keeps
/// the universal scan fast and precise (real vendor keys only).
#[must_use]
pub fn identify_vendor_api_key(value: &str) -> Option<(&'static str, &str)> {
    let trimmed = value.trim();
    if trimmed.len() < 16 {
        return None;
    }
    // False-positive gate (entropy + context exclusion + UUID suppression) runs
    // only on an actual prefix MATCH — rare, so the common no-match token pays
    // nothing for it.
    //
    // aho-corasick identifies the FIRST-declared prefix that anchors at
    // position 0 (LeftmostFirst = declaration order wins). Then we iterate
    // the K entries for that prefix (usually 1, at most 2) to find one that
    // also satisfies min_len. A token whose most-specific prefix fails
    // min_len returns None rather than cascading to a shorter generic prefix
    // (which would misclassify it — e.g. a short `sk-svcacct-` token should
    // not be attributed to the generic `sk-` "openai_or_stripe" service).
    if let Some(first_idx) = PREFIX_MATCHER.find_prefix(trimmed) {
        let matched_prefix = KEY_PATTERNS[first_idx].prefix;
        if let Some(group) = PREFIX_GROUPS.get(matched_prefix) {
            for &idx in group {
                let pat = &KEY_PATTERNS[idx];
                if trimmed.len() >= pat.min_len {
                    if !is_likely_real_key(trimmed) {
                        return None;
                    }
                    return Some((pat.service, trimmed));
                }
            }
        }
    }
    // PEM private-key blocks (id_rsa / id_ed25519 / OpenVPN configs in stealer
    // logs). Multi-line; checked separately from the single-token prefix table.
    if let Some(service) = identify_pem_private_key(trimmed) {
        return Some((service, trimmed));
    }
    // Cryptocurrency wallet addresses (clipboard-hijacker stealer logs carry
    // these in volume; lookup modules pivot from the emitted entities).
    if let Some(service) = identify_crypto_address(trimmed) {
        return Some((service, trimmed));
    }
    None
}

pub fn identify_api_key(value: &str) -> Option<(&'static str, &str)> {
    let trimmed = value.trim();
    if trimmed.len() < 16 {
        return None;
    }
    // High-confidence structured forms first (vendor prefix / PEM / crypto).
    if let Some(hit) = identify_vendor_api_key(trimmed) {
        return Some(hit);
    }
    // Generic hex key detection (32 or 64 char hex = potential API key). The
    // entropy/exclusion gate below is the expensive path — see
    // [`identify_vendor_api_key`] for why the universal scanner skips it.
    if (trimmed.len() == 32 || trimmed.len() == 64)
        && trimmed.chars().all(|c| c.is_ascii_hexdigit())
    {
        if !is_likely_real_key(trimmed) {
            return None;
        }
        return Some(("generic_hex", trimmed));
    }

    // URL-embedded key extraction: ?key=VALUE, ?api_key=VALUE, ?token=VALUE
    for param in [
        "key=",
        "api_key=",
        "apikey=",
        "token=",
        "access_token=",
        "secret=",
    ] {
        if let Some(pos) = trimmed.find(param) {
            let start = pos + param.len();
            let rest = &trimmed[start..];
            let end = rest.find(['&', ' ', '"']).unwrap_or(rest.len());
            // Hard-cap the extracted value length. Without this, a
            // malicious stealer-log record with `?key=` followed by
            // hundreds of MB of base64-with-no-`&`-terminator would
            // cascade through `contains_excluded_context` (full-string
            // lowercase allocation) and `shannon_entropy` (full-string
            // iteration) per item — a cheap DoS surface. 4 KiB is well
            // above any real-world API-key length (longest known is
            // GitLab's ~256 chars).
            let end = end.min(EXTRACTED_VALUE_MAX);
            // Snap to a char boundary: `rest` is untrusted stealer data, so a
            // multi-byte UTF-8 char straddling the 4 KiB cap would panic a raw
            // byte slice (caught by the dispatch guard, but it silently voids the
            // whole harvest for the scan).
            let val = crate::util::str_util::truncate_safe(rest, end);
            if val.len() >= 16 {
                if let Some(hit) = identify_api_key(val) {
                    return Some(hit);
                }
                if val.len() >= 20
                    && val
                        .chars()
                        .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
                {
                    return Some(("url_param_key", val));
                }
            }
        }
    }

    // user:password format — extract the password portion. `split_once`
    // avoids the per-call `Vec` allocation the prior `splitn(2).collect()`
    // paid on every `user:pass`-shaped candidate.
    if !trimmed.starts_with("http")
        && let Some((_, pass)) = trimmed.split_once(':')
        && pass.len() >= 16
    {
        // Same DoS cap as above — recurse on at most 4 KiB (char-boundary safe).
        let pw = crate::util::str_util::truncate_safe(pass, EXTRACTED_VALUE_MAX);
        if let Some(hit) = identify_api_key(pw) {
            return Some(hit);
        }
    }
    None
}

/// Hard cap for the extracted `val` / `password` substring length
/// in [`identify_api_key`]'s URL-param and user:pass fallbacks.
/// Bounds the recursive cost on hostile or malformed inputs without
/// rejecting any plausible real-world credential (longest known
/// vendor key is ~256 chars; even base64-wrapped variants stay
/// well under 4 KiB).
const EXTRACTED_VALUE_MAX: usize = 4096;

/// Identify a key `value` given the `context` it was found under (an env-var
/// name, a JSON object key, or the URL it was passed to). Layers
/// context-attribution on top of the prefix/shape detector:
///
/// * a vendor-prefixed key (`sk-…`, `AKIA…`) is returned as-is — context is not
///   needed and never overrides a concrete prefix match;
/// * a bare hex blob the shape detector can only call `generic_hex` is **upgraded**
///   to the specific OSINT/threat-intel provider when `context` names one
///   (`api.virustotal.com/?apikey=<64 hex>` ⇒ `virustotal`, not `generic_hex`);
/// * a prefix-less, non-hex key the shape detector cannot see at all (Shodan's
///   32-char alphanumeric key) is **rescued** purely from context — and since this
///   path never went through the `generic_hex` gate, the shared
///   [`is_likely_real_key`] false-positive filter is re-applied here so a
///   placeholder / UUID / low-entropy value under a provider-named field is
///   dropped.
///
/// Returns the resolved service tag, the (trimmed) key slice, and the
/// [`DetectionConfidence`]: [`DetectionConfidence::Proven`] whenever the result
/// came from context attribution (the two `match_osint_provider` arms), otherwise
/// the schema/shape baseline from [`DetectionConfidence::for_service`].
fn identify_with_context<'a>(
    context: &str,
    value: &'a str,
) -> Option<(&'static str, &'a str, DetectionConfidence)> {
    let v = value.trim();
    match identify_api_key(v) {
        // A bare hex blob the context names as a specific provider is that
        // provider's key, not an anonymous `generic_hex` finding. The value
        // already cleared the FP gate inside `identify_api_key`'s hex path.
        // Attribution is `Proven` (shape + named provider); the plain fallback
        // keeps the `generic_hex` baseline (`Potential`).
        Some(("generic_hex", hit)) => Some(match match_osint_provider(context, v) {
            Some(svc) => (svc, hit, DetectionConfidence::Proven),
            None => ("generic_hex", hit, DetectionConfidence::Potential),
        }),
        // A concrete prefix/shape match (`Probable` baseline). When the context
        // ALSO names this provider, two independent objective signals — the key's
        // format and its surrounding identifier/host — agree, so the detection is
        // corroborated → `Proven`. An *uncorroborated* prefix match (incl. a
        // Shodan/Censys key matched by its prefix under a neutral field) stays
        // `Probable`, never over-claimed.
        Some((svc, hit)) => {
            let base = DetectionConfidence::for_service(svc);
            let conf =
                if base == DetectionConfidence::Probable && context_corroborates(context, svc) {
                    DetectionConfidence::Proven
                } else {
                    base
                };
            Some((svc, hit, conf))
        }
        // Prefix-less, non-hex OSINT keys are invisible to the shape table;
        // context is the only signal, so re-apply the FP gate before trusting it.
        // A hit here is necessarily context-attributed → `Proven`.
        None => match_osint_provider(context, v)
            .filter(|_| is_likely_real_key(v))
            .map(|svc| (svc, v, DetectionConfidence::Proven)),
    }
}

/// The authoritative host of a URL-shaped context, else the context unchanged.
///
/// Provider attribution from a URL must key off the **host** (`api.shodan.io`),
/// not text anywhere in the URL: otherwise a provider name dropped into a path or
/// query — `https://evil.example/?ref=shodan&key=…` — would spoof a `Proven`
/// attribution to a key served by an unrelated host. Identifier contexts (env-var
/// and object-key names carry no `://`) pass through untouched, so this is a
/// no-op for every non-URL caller.
fn context_host(context: &str) -> &str {
    match context.split_once("://") {
        Some((_, rest)) => {
            let end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
            &rest[..end]
        }
        None => context,
    }
}

/// True if `word` occurs in `haystack` as a whole word — bounded on both sides by
/// a non-alphanumeric character or a string edge. Precision over recall: a missed
/// boundary (e.g. camelCase `awsKey`) merely leaves a finding at its baseline
/// provenance, whereas a loose substring (`aws` inside `lawsuit`) would
/// over-claim. `haystack` is assumed already lowercased.
fn contains_word(haystack: &str, word: &str) -> bool {
    if word.is_empty() {
        return false;
    }
    haystack.match_indices(word).any(|(i, m)| {
        let before_ok = haystack[..i]
            .chars()
            .next_back()
            .is_none_or(|c| !c.is_ascii_alphanumeric());
        let after_ok = haystack[i + m.len()..]
            .chars()
            .next()
            .is_none_or(|c| !c.is_ascii_alphanumeric());
        before_ok && after_ok
    })
}

/// True if `context` independently names the provider behind `service` — the
/// service tag's provider stem (`github_app` → `github`, `shodan` → `shodan`)
/// occurs in the lowercased context as a whole word. Corroborates a prefix/schema
/// match: when the key's format AND its surrounding identifier/host agree on the
/// provider, the detection rests on two independent objective signals. The stem
/// must be ≥ 3 chars so a tiny token can't corroborate on noise.
fn context_corroborates(context: &str, service: &str) -> bool {
    let stem = service.split('_').next().unwrap_or(service);
    stem.len() >= 3 && contains_word(&context.to_ascii_lowercase(), stem)
}

/// Structurally validate a JWS/JWT compact token **offline** and return its
/// `alg`, or `None` if it is not a real JWT.
///
/// Practical, objective validation with no network and no secret: the first
/// dot-separated segment must base64url-decode to a JSON object carrying a string
/// `alg`. It separates a genuine token from an `eyJ`-shaped high-entropy blob, and
/// surfaces the algorithm — notably `alg: "none"`, an unsigned token that is the
/// classic JWT authentication-bypass. The signature is **not** verified (that
/// needs the issuer's secret); this is structure + header inspection only.
fn validate_jwt_alg(token: &str) -> Option<String> {
    use base64::Engine as _;
    let header_b64 = token.split('.').next()?;
    // A real JWT header (`{"alg":…}`) is at least a handful of base64url chars;
    // the gate keeps a stray short segment from reaching the JSON parser.
    if header_b64.len() < 8 {
        return None;
    }
    // JWT segments are base64url; tokens in the wild appear with and without
    // padding, so try the unpadded alphabet first, then the padded one.
    let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(header_b64)
        .or_else(|_| base64::engine::general_purpose::URL_SAFE.decode(header_b64))
        .ok()?;
    let header: serde_json::Value = serde_json::from_slice(&bytes).ok()?;
    header.get("alg")?.as_str().map(str::to_string)
}

/// Scan a JSON record for API key patterns in password / URL-param / extra
/// fields. Public so peer modules like `see_know` can use the same harvest
/// pipeline against their own response schemas.
/// Breach/stealer fields whose contents are a user password — so a bare hex
/// value in them is a password *hash*, not an API key. Used to suppress the
/// `generic_hex` ApiKey fallback for these fields (the value is still harvested
/// as a credential elsewhere).
fn is_password_field(field: &str) -> bool {
    matches!(
        field,
        "password" | "password_hash" | "pass" | "pwd" | "passwd" | "hash"
    )
}

/// The provider context a stealer/breach record carries **about itself**: the
/// host of its `url`/`url_str` field, else its `domain` field, lowercased. Empty
/// when the record names no host — then [`identify_with_context`] degrades to
/// plain shape/prefix detection, so this never weakens existing attribution.
///
/// Only the HOST is used (scheme + path stripped), so a provider name dropped in
/// a path/query can't spoof attribution — the same discipline as the URL-param
/// scanner. This is what lets the per-field harvest attribute a *prefix-less*
/// OSINT key (a 32-alnum Shodan / 64-hex VirusTotal key) sitting in an
/// `api_key` / `password` field of a record whose URL is that provider, instead
/// of dropping it as anonymous `generic_hex` — making the stealer-log sweep
/// exhaustive for OSINT-practitioner keys.
fn record_provider_context(item: &Value) -> String {
    for f in ["url", "url_str"] {
        if let Some(u) = val_str(item, f) {
            let host = context_host(&u);
            // Strip a leading path/query for scheme-less URLs (`context_host`
            // only trims when a `://` scheme is present).
            let host = host.split(['/', '?', '#']).next().unwrap_or(host);
            if !host.is_empty() {
                return host.to_ascii_lowercase();
            }
        }
    }
    val_str(item, "domain")
        .map(|d| d.to_ascii_lowercase())
        .unwrap_or_default()
}

pub fn extract_api_keys_from_item(
    item: &Value,
    scan_id: &str,
    seen: &mut HashSet<String>,
    result: &mut ModuleResult,
) {
    let fields = [
        // Core credential fields (breach + stealer common)
        "password",
        "password_hash",
        "pass",
        "pwd",
        "passwd",
        "hash",
        "api_key",
        "apikey",
        "key",
        "token",
        "secret",
        "access_key",
        "auth_token",
        "api_token",
        "credential",
        "private_key",
        "secret_key",
        "access_token",
        "refresh_token",
        "bearer",
        // Stealer-log-specific fields (RedLine / Vidar / Raccoon /
        // StealC dumps). Catches modern OAuth / PAT / Discord / app-
        // password tokens that don't land in the `password` field.
        "bearer_token",
        "client_secret",
        "oauth_token",
        "personal_access_token",
        "pat",
        "webhook_secret",
        "app_password",
        "discord_token",
        "telegram_session",
        "cookie",
        "session_token",
        "note",
        "notes",
        "app_data",
        // `.env` dumps from desktop file-grabbers — handled by the
        // multi-line parser below; included here so a single-line
        // env file still routes through the same scan.
        "env_content",
        "env",
        "dotenv",
    ];

    // The record's own URL host / domain is provider context for every credential
    // field below, so a prefix-less OSINT key in an `api_key` / `password` field
    // of an OSINT-provider record is attributed (and banked + flagged
    // `osint-practitioner`) rather than missed. Empty context degrades to plain
    // shape/prefix detection — identical to the prior behaviour.
    let record_context = record_provider_context(item);

    for field in &fields {
        if let Some(val) = val_str(item, field) {
            if let Some((service, key_val, detection)) =
                identify_with_context(&record_context, &val)
            {
                // A bare 32/64-hex value in a password/hash field is a leaked
                // password *hash* (MD5/SHA), not an API key — the shape alone is
                // the `generic_hex` fallback. Emitting it as a VERIFIED ApiKey is a
                // double error (wrong kind + inflated confidence); the value is
                // already captured as a credential by `store_api_credential`. A
                // *vendor-prefixed* key (sk-…, AKIA…) — or one the record's own
                // host attributes to a named provider — stored in a password field
                // is still a genuine leaked key, so only the anonymous generic
                // fallback is suppressed here. (Live email scan flooded with hex.)
                if !(service == "generic_hex" && is_password_field(field)) {
                    let db = val_str(item, "dbname").unwrap_or_default();
                    let source = if db.is_empty() {
                        format!("{field} field")
                    } else {
                        format!("breach ({db})")
                    };
                    emit_key_with(service, key_val, &source, detection, scan_id, seen, result);
                }
            }
            // Decode-through pass: same field, treat the value as
            // base64 of a key and recurse through `identify_api_key`.
            // Catches stealer-log entries that wrap the secret to
            // sneak it past lazy regex scanners, plus genuine
            // base64-encoded-credential field schemas.
            if let Some((service, decoded_key, depth)) = try_decode_through_scan(&val) {
                let pre = result.entities.len();
                let source = format!("{field} (base64-decoded, depth={depth})");
                emit_key(service, &decoded_key, &source, scan_id, seen, result);
                if result.entities.len() > pre
                    && let Some(last) = result.entities.last_mut()
                {
                    last.tag("via-base64");
                    last.tag(format!("base64_depth:{depth}"));
                }
            }

            // ENTROPY-BASED FALLBACK: if pattern matching didn't find anything,
            // use behavioral analysis (entropy, composition, length) to detect
            // credentials that don't match known prefixes.
            // This adds "proactive" + "creative" detection beyond pattern matching.
            if identify_with_context(&record_context, &val).is_none()
                && let Some(score) = try_entropy_detect(field, &val)
            {
                let pre = result.entities.len();
                let source =
                    format!("{field} (entropy-based, confidence={:.0}%)", score * 100.0);
                emit_key(
                    "behavioral_credential",
                    &val,
                    &source,
                    scan_id,
                    seen,
                    result,
                );
                if result.entities.len() > pre
                    && let Some(last) = result.entities.last_mut()
                {
                    last.tag("entropy-detected");
                    last.tag(format!("entropy-score:{score:.2}"));
                }
            }
        }
    }

    // Multi-line `.env` parser — stealer logs commonly dump entire
    // `.env` files into a single string field. Split on newlines,
    // extract `KEY=VALUE` pairs, and scan each value through the
    // same `identify_api_key` pipeline.
    for env_field in ["env_content", "env", "dotenv", "note", "notes"] {
        if let Some(blob) = val_str(item, env_field)
            && blob.contains('\n')
        {
            for line in blob.lines() {
                let trimmed = line.trim().trim_start_matches("export ");
                if let Some((raw_key, raw_val)) = trimmed.split_once('=') {
                    let val = raw_val
                        .trim()
                        .trim_matches('"')
                        .trim_matches('\'')
                        .trim_matches('`');
                    // The `KEY` half is provider context: `SHODAN_API_KEY=<32
                    // alnum>` is a prefix-less Shodan key the shape detector alone
                    // would miss, attributed via `identify_with_context`.
                    if val.len() >= 16
                        && let Some((service, key_val, detection)) =
                            identify_with_context(raw_key, val)
                    {
                        emit_key_with(
                            service,
                            key_val,
                            "dotenv line",
                            detection,
                            scan_id,
                            seen,
                            result,
                        );
                    }
                }
            }
        }
    }

    // Scan username field — some stealer logs store API keys as usernames
    if let Some(user) = val_str(item, "username")
        && let Some((service, key_val)) = identify_api_key(&user)
    {
        emit_key(service, key_val, "username field", scan_id, seen, result);
    }

    // Scan URL query parameters — stealer URLs often embed API keys:
    // https://api.shodan.io/host/1.1.1.1?key=ACTUAL_KEY
    for url_field in ["url", "url_str"] {
        if let Some(url) = val_str(item, url_field)
            && let Some(qmark) = url.find('?')
        {
            for param in url[qmark + 1..].split('&') {
                // The URL *host* is the provider context: a bare `?key=<32 alnum>`
                // on `api.shodan.io` is attributed to Shodan rather than missed,
                // and a 64-hex key on an OSINT host is upgraded from `generic_hex`
                // to the named provider. Only the host counts (`context_host`), so
                // a provider name in the path/query cannot spoof the attribution.
                if let Some((_, pval)) = param.split_once('=')
                    && pval.len() >= 16
                    && let Some((service, key_val, detection)) =
                        identify_with_context(context_host(&url), pval)
                {
                    emit_key_with(
                        service,
                        key_val,
                        "URL query parameter",
                        detection,
                        scan_id,
                        seen,
                        result,
                    );
                }
            }
        }
    }

    if let Some(extra) = item.get("extra").and_then(|v| v.as_object()) {
        for (ekey, eval) in extra {
            // The object key names the secret (`{"securitytrails_key": "<32
            // alnum>"}`), so it is provider context for `identify_with_context`.
            if let Some(s) = eval.as_str()
                && s.len() >= 16
                && let Some((service, key_val, detection)) = identify_with_context(ekey, s)
            {
                emit_key_with(
                    service,
                    key_val,
                    "extra field",
                    detection,
                    scan_id,
                    seen,
                    result,
                );
            }
        }
    }

    // Cookie arrays — stealer logs export browser cookies as
    // `[{ name, value, domain, expires, ... }, ...]`. Cookie values
    // sized like JWT / OAuth tokens get routed through the same
    // pipeline; the domain field gives us the service-tag context.
    if let Some(cookies) = item.get("cookies").and_then(|v| v.as_array()) {
        for cookie in cookies {
            let Some(obj) = cookie.as_object() else {
                continue;
            };
            // Read the cookie fields straight off the object map. The prior code
            // built `Value::Object(obj.clone())` — a full deep clone of every
            // cookie's key/value map — twice per cookie just to call `val_str`;
            // stealer logs export hundreds of cookies per record, so that was a
            // large per-cookie allocation for nothing. `val_str`'s empty-string
            // filter is preserved by the explicit `is_empty` / `< 16` guards.
            let name = obj
                .get("name")
                .and_then(|v| v.as_str())
                .filter(|s| !s.is_empty())
                .unwrap_or_default();
            let Some(value) = obj.get("value").and_then(|v| v.as_str()) else {
                continue;
            };
            if value.len() < 16 {
                continue;
            }
            if let Some((service, key_val)) = identify_api_key(value) {
                let source = if name.is_empty() {
                    "cookie".to_string()
                } else {
                    format!("cookie:{name}")
                };
                emit_key(service, key_val, &source, scan_id, seen, result);
            }
        }
    }
}

// ── False-positive filtering (APIKeyScanner port) ──────────────────────
//
// Three independent gates a candidate string must pass before
// `identify_api_key` considers it a real key:
//
//   1. **Context exclusion** — a substring (case-insensitive) from
//      [`CONTEXT_EXCLUSIONS`] anywhere in the string. Catches
//      `your_api_key_here`, `example_token_xxx`, `placeholder`,
//      and ~40 sibling patterns from APIKeyScanner.
//   2. **UUID suppression** — strict 8-4-4-4-12 hex layout rejects
//      formatted GUIDs that otherwise look credential-like.
//   3. **Shannon entropy** — threshold 3.5 bits/char rejects
//      strings whose character distribution is too regular to be
//      a high-randomness secret.
//
// The gate is OPT-IN-OUT: if any of the three trips, the candidate
// is dropped. Real keys (high entropy, no context flags, not a
// UUID) sail through.

/// Substrings whose appearance anywhere in a candidate string
/// disqualifies it as a real key. Case-insensitive comparison.
/// Sourced from APIKeyScanner's 40+ exclusion list plus a handful
/// of empirical additions from HSE's breach corpus.
const CONTEXT_EXCLUSIONS: &[&str] = &[
    // Documentation placeholders
    "example",
    "your_",
    "your-",
    "yourkey",
    "yourtoken",
    "yoursecret",
    "yourapi",
    "placeholder",
    "dummy",
    "fake",
    "sample",
    "changeme",
    "todo",
    "xxxx",
    "test_key",
    "test-key",
    "test_token",
    "demo_key",
    "demo-key",
    // Documentation field names
    "public_key",
    "public_token",
    "api_version",
    "secret_name",
    "key_name",
    "token_name",
    "primary_key",
    "foreign_key",
    "schema_key",
    "sequence_key",
    "key_code",
    "key_alias",
    "key_id_name",
    // Common English-word collisions with key-like substrings
    "keyboard",
    "monkey",
    "donkey",
    "keystone",
    "keystore",
    "keyword",
    "keymap",
    "keypress",
    "keyup",
    "keydown",
    "tokenize",
    "tokenizer",
];

/// True if the candidate value is plausibly a real credential.
/// Wraps the three FP gates so callers stay clean.
fn is_likely_real_key(value: &str) -> bool {
    !contains_excluded_context(value) && !is_uuid(value) && shannon_entropy(value) >= 3.5
}

/// True if `value` contains any [`CONTEXT_EXCLUSIONS`] substring
/// (ASCII-case-insensitive). One cached `aho-corasick` pass via `util::scan`
/// (SOL-F1) — byte-for-byte equivalent to the old
/// `value.to_ascii_lowercase().contains(pat)` loop (the patterns are lowercase
/// and `ascii_case_insensitive` ASCII-folds both sides exactly as
/// `to_ascii_lowercase` did), but it scans the *original* `value` so it also drops
/// the per-call lowercase allocation on this hot key-gate path.
fn contains_excluded_context(value: &str) -> bool {
    static EXCLUDED: std::sync::LazyLock<crate::util::scan::MatchSet> =
        std::sync::LazyLock::new(|| crate::util::scan::MatchSet::new_ascii_ci(CONTEXT_EXCLUSIONS));
    EXCLUDED.is_match(value)
}

/// True if `value` matches the canonical UUID v1-v5 layout
/// `XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX` (8-4-4-4-12 hex,
/// 36 chars total including the four dashes). UUIDs are
/// suppressed by default because they collide with several
/// vendor key formats (Heroku, Pinecone, etc.) without being
/// real credentials — the vendor-specific prefix check is
/// where those should land.
fn is_uuid(value: &str) -> bool {
    if value.len() != 36 {
        return false;
    }
    let bytes = value.as_bytes();
    bytes[8] == b'-'
        && bytes[13] == b'-'
        && bytes[18] == b'-'
        && bytes[23] == b'-'
        && value
            .chars()
            .filter(|c| *c != '-')
            .all(|c| c.is_ascii_hexdigit())
}

// ── PEM private-key block classifier (KeyFinder port) ─────────────
//
// Stealer logs that dump `id_rsa`, `id_ed25519`, OpenVPN configs,
// PGP keychains, or Bitcoin wallet WIF backups deliver these
// verbatim into the `app_data` / `notes` / `extras` payloads.
// Detection is shape-anchored on the BEGIN header — strict enough
// that a base64 blob in the body alone won't false-positive.

/// Every canonical service name the harvester can emit into `FoundKey.service`,
/// unioned across the three vendor tables (prefix-based `KEY_PATTERNS`,
/// shape-based `OSINT_PROVIDERS`, domain-based `API_SERVICE_DOMAINS`). Exposed
/// for the cross-registry drift-guard below, which asserts downstream ROI
/// classification only names services that can actually be produced.
#[cfg(test)]
fn emitted_service_names() -> std::collections::BTreeSet<&'static str> {
    let mut out = std::collections::BTreeSet::new();
    out.extend(KEY_PATTERNS.iter().map(|p| p.service));
    out.extend(
        service_domains::API_SERVICE_DOMAINS
            .iter()
            .map(|(_, svc)| *svc),
    );
    out.extend(osint_keys::OSINT_PROVIDERS.iter().map(|p| p.service));
    out
}

#[cfg(test)]
mod tests;
