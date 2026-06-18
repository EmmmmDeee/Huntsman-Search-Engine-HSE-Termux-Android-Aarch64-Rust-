//! Key registry: known keys, signup hints, embedded defaults, and pure resolvers.

/// Names of HUNTSMAN_* keys recognised by current/planned modules. Drives
/// the Settings UI so users see a populated grid before they've configured
/// anything. Matches the template comments in `install.sh`.
pub const KNOWN_KEYS: &[&str] = &[
    // Identity / breach
    "HUNTSMAN_OATHNET_KEY",
    "HUNTSMAN_HIBP_KEY",
    "HUNTSMAN_DEHASHED_KEY",
    "HUNTSMAN_HUNTER_KEY",
    "HUNTSMAN_INTELX_KEY",
    // Infrastructure / threat intel
    "HUNTSMAN_SHODAN_KEY",
    "HUNTSMAN_SECTRAILS_KEY",
    "HUNTSMAN_LEAKIX_KEY",
    "HUNTSMAN_CRIMINALIP_KEY",
    "HUNTSMAN_IPQS_KEY",
    "HUNTSMAN_VIRUSTOTAL_KEY",
    "HUNTSMAN_THREATFOX_KEY",
    // Expanded services (api_key_probe compatible)
    "HUNTSMAN_ABUSEIPDB_KEY",
    "HUNTSMAN_CENSYS_ID",
    "HUNTSMAN_CENSYS_SECRET",
    "HUNTSMAN_BINARYEDGE_KEY",
    "HUNTSMAN_GREYNOISE_KEY",
    "HUNTSMAN_FULLHUNT_KEY",
    "HUNTSMAN_URLSCAN_KEY",
    "HUNTSMAN_PASSIVETOTAL_KEY",
    "HUNTSMAN_ONYPHE_KEY",
    "HUNTSMAN_ZOOMEYE_KEY",
    "HUNTSMAN_FOFA_KEY",
    "HUNTSMAN_NETLAS_KEY",
    "HUNTSMAN_PULSEDIVE_KEY",
    "HUNTSMAN_BUILTWITH_KEY",
    "HUNTSMAN_EMAILREP_KEY",
    "HUNTSMAN_WHOISXML_KEY",
    "HUNTSMAN_BREACHDIR_KEY",
    "HUNTSMAN_C99_KEY",
    // Validation / enrichment
    "HUNTSMAN_NUMVERIFY_KEY",
    "HUNTSMAN_HLR_KEY",
    "HUNTSMAN_OPENCNAM_KEY",
    "HUNTSMAN_WIGLE_USER",
    "HUNTSMAN_WIGLE_TOKEN",
    "HUNTSMAN_ABR_GUID",
    "HUNTSMAN_OPENCELLID_KEY",
    // Australian archives
    "HUNTSMAN_TROVE_KEY",
    // OSINT orchestration APIs
    "HUNTSMAN_SEON_KEY",
    "HUNTSMAN_EPIEOS_KEY",
    "HUNTSMAN_PROXYCURL_KEY",
    "HUNTSMAN_OPENCORP_KEY",
    // Breach / search multipliers — high-leverage paid pools the Settings
    // grid must surface so the operator can paste/rotate them in the UI.
    "HUNTSMAN_SEEKNOW_KEY",
    "HUNTSMAN_EXA_KEY",
];

/// Human-readable provider + free-signup hint for a `HUNTSMAN_*` key, surfaced
/// in the engine's "module skipped — needs key" notice (and `hse doctor`) so an
/// unconfigured optional module tells the operator exactly where to get a key.
/// `None` for keys without a known signup page. Most listed providers have a
/// free tier; the few paid-only ones say so.
pub fn signup_hint(env: &str) -> Option<&'static str> {
    Some(match env {
        "HUNTSMAN_ABUSECH_KEY" | "HUNTSMAN_THREATFOX_KEY" => {
            "abuse.ch — free key at https://auth.abuse.ch (powers urlhaus + threatfox + malwarebazaar)"
        }
        "HUNTSMAN_VIRUSTOTAL_KEY" => {
            "VirusTotal — free key at https://www.virustotal.com/gui/join-us"
        }
        "HUNTSMAN_ABUSEIPDB_KEY" => "AbuseIPDB — free key at https://www.abuseipdb.com/register",
        "HUNTSMAN_SHODAN_KEY" => "Shodan — free key at https://account.shodan.io/register",
        "HUNTSMAN_SECTRAILS_KEY" => {
            "SecurityTrails — free tier at https://securitytrails.com/app/signup"
        }
        "HUNTSMAN_HUNTER_KEY" => "Hunter.io — free tier at https://hunter.io/users/sign_up",
        "HUNTSMAN_GREYNOISE_KEY" => "GreyNoise — free key at https://viz.greynoise.io/signup",
        "HUNTSMAN_URLSCAN_KEY" => "urlscan.io — free key at https://urlscan.io/user/signup",
        "HUNTSMAN_LEAKIX_KEY" => "LeakIX — free key at https://leakix.net/auth/register",
        "HUNTSMAN_INTELX_KEY" => "Intelligence X — free tier at https://intelx.io/signup",
        "HUNTSMAN_EMAILREP_KEY" => "EmailRep — free key at https://emailrep.io/key",
        "HUNTSMAN_CRIMINALIP_KEY" => {
            "Criminal IP — free tier at https://www.criminalip.io/register"
        }
        "HUNTSMAN_IPQS_KEY" => {
            "IPQualityScore — free tier at https://www.ipqualityscore.com/create-account"
        }
        "HUNTSMAN_CENSYS_ID" | "HUNTSMAN_CENSYS_SECRET" => {
            "Censys — free tier at https://accounts.censys.io/register"
        }
        "HUNTSMAN_WHOISXML_KEY" => "WhoisXML — free tier at https://whois.whoisxmlapi.com",
        "HUNTSMAN_ONYPHE_KEY" => "ONYPHE — free tier at https://www.onyphe.io/login/#register",
        "HUNTSMAN_NETLAS_KEY" => "Netlas — free tier at https://app.netlas.io/registration",
        "HUNTSMAN_PULSEDIVE_KEY" => "Pulsedive — free key at https://pulsedive.com/about/api",
        "HUNTSMAN_OPENCORP_KEY" => "OpenCorporates — https://opencorporates.com/api_accounts/new",
        "HUNTSMAN_NUMVERIFY_KEY" => "numverify — free tier at https://numverify.com/product",
        "HUNTSMAN_HLR_KEY" => "HLR Lookups — free trial at https://hlrlookups.com",
        "HUNTSMAN_OPENCNAM_KEY" => "OpenCNAM — free tier at https://www.opencnam.com/register",
        "HUNTSMAN_TROVE_KEY" => "National Library of Australia Trove — free key at https://trove.nla.gov.au/about/create-something/using-our-apis/api-technical-guide",
        "HUNTSMAN_OPENCELLID_KEY" => "OpenCelliD — free key at https://opencellid.org/register.php",
        "HUNTSMAN_EXA_KEY" => "Exa AI — free tier at https://dashboard.exa.ai/api-keys",
        "HUNTSMAN_WIGLE_TOKEN" | "HUNTSMAN_WIGLE_USER" => {
            "WiGLE — free account at https://wigle.net/account"
        }
        // Paid-only / invite providers.
        "HUNTSMAN_HIBP_KEY" => "Have I Been Pwned — paid key at https://haveibeenpwned.com/API/Key",
        "HUNTSMAN_DEHASHED_KEY" => {
            "DeHashed — paid (v2 API, key-only); needs an active search subscription at https://dehashed.com"
        }
        "HUNTSMAN_PROXYCURL_KEY" => "Proxycurl — paid, https://nubela.co/proxycurl",
        "HUNTSMAN_SEON_KEY" => "SEON — free trial at https://seon.io",
        "HUNTSMAN_EPIEOS_KEY" => "Epieos — https://epieos.com",
        "HUNTSMAN_SEEKNOW_KEY" => "SeekNow (see-know.eu) — https://see-know.eu",
        "HUNTSMAN_OATHNET_KEY" => "OathNet — https://oathnet.org",
        _ => return None,
    })
}

/// Env var an operator may set — in their local `$HOME/.huntsman.env` (chmod
/// 0600) or the shell — to a default scan seed, so `hse scan` / `hse live` can
/// run without retyping `--value`.
///
/// This is deliberately **operator-local**: it is never shipped with a value.
/// The public installer and repo only document the key (commented-out); the
/// operator fills in *their own* target on *their own* device. That keeps a
/// real target out of the public tool — installing HSE never silently points
/// it at someone. An explicit `--value` always overrides it.
pub const DEFAULT_SEED_ENV: &str = "HUNTSMAN_DEFAULT_SEED";

// ─── Embedded default keys — SINGLE SOURCE OF TRUTH ──────────────────────────
//
// Every key baked into the build lives here as exactly one constant. Modules
// that need a zero-config fallback (`hibp`, `wigle`/`wifi_intel`, `see_know`,
// `oathnet_pro`) reference these instead of re-declaring the literal, so a key
// can never drift between copies. To ROTATE a key: change the constant here and
// move its previous value into `SEEKNOW_SUPERSEDED_KEY` (or the relevant
// superseded slot) so old env files upgrade in place. "Only the latest" is thus
// enforced structurally — there is one place to edit.

/// OathNet Pro upstream key.
pub const OATHNET_DEFAULT_KEY: &str =
    "1f8097bdbf7dc68619857861adbc4343ddb490a1d72ae890551409e4b47116f2";
/// Have I Been Pwned key.
pub const HIBP_DEFAULT_KEY: &str = "42587552dce6424a87312941c8a2c3c5";
/// WiGLE API name (HTTP Basic user).
pub const WIGLE_DEFAULT_USER: &str = "AID4493a33e2df9d07ab9666a27c8aead17";
/// WiGLE API token (HTTP Basic password).
pub const WIGLE_DEFAULT_TOKEN: &str = "1aedb7ad0171ff3d6be5a844cca5d977";
/// SeekNow (see-know.eu) key — the current embedded default. Enterprise plan,
/// 5,000 daily credits. Live-verified (POST /api/v1/search → HTTP 200).
pub const SEEKNOW_DEFAULT_KEY: &str = "seek-62650f9a36e446fc3b1c1bcdf32a825048e608160e0fd0a4";
/// SeekNow key that has been ROTATED OUT — kept only so a stale env file written
/// by a previous build upgrades to [`SEEKNOW_DEFAULT_KEY`]. Never used as a live
/// default. Verified DEAD (HTTP 401 invalid_api_key).
pub const SEEKNOW_SUPERSEDED_KEY: &str = "seek-f419aa7ab831864149892e5145f6bc65dbb336e6ca94b4bc";
/// Earlier retired SeekNow key — also upgraded in place to the current default.
pub(super) const SEEKNOW_SUPERSEDED_KEY_2: &str =
    "seek-4b33b63d408dd7149765da4e76384ce91fd9f6df518f9a25";
/// Prior embedded default (free-tier `seek-b4a9…`), rotated out in favour of the
/// enterprise key above.
pub(super) const SEEKNOW_SUPERSEDED_KEY_3: &str =
    "seek-b4a9cd56f7e95bc6ea30b17925f482514a07a52e7ab0961a";

/// API keys embedded in the build so a fresh install works zero-config.
/// `ensure_hardcoded_keys` writes any that are absent from the env file.
/// Values come from the single-source-of-truth constants above.
pub(super) const HARDCODED: &[(&str, &str)] = &[
    ("HUNTSMAN_OATHNET_KEY", OATHNET_DEFAULT_KEY),
    ("HUNTSMAN_HIBP_KEY", HIBP_DEFAULT_KEY),
    ("HUNTSMAN_WIGLE_USER", WIGLE_DEFAULT_USER),
    ("HUNTSMAN_WIGLE_TOKEN", WIGLE_DEFAULT_TOKEN),
    ("HUNTSMAN_SEEKNOW_KEY", SEEKNOW_DEFAULT_KEY),
];

/// Embedded defaults that have been ROTATED. If the env file still carries an
/// old embedded value (written by a previous build's `ensure_hardcoded_keys`),
/// upgrade it in place to the current default so a rebuild picks up the new key
/// without the operator re-entering it. Scoped to EXACT prior embedded values —
/// a user's own custom key never matches one of these, so an intentional
/// override is never clobbered.
pub(super) const SUPERSEDED: &[(&str, &str)] = &[
    ("HUNTSMAN_SEEKNOW_KEY", SEEKNOW_SUPERSEDED_KEY),
    ("HUNTSMAN_SEEKNOW_KEY", SEEKNOW_SUPERSEDED_KEY_2),
    ("HUNTSMAN_SEEKNOW_KEY", SEEKNOW_SUPERSEDED_KEY_3),
];

/// Resolve an API key: the context-supplied key when present and non-empty,
/// otherwise the embedded `default`. The single definition of the "an explicit
/// non-empty key wins, else fall back to the embedded default" policy shared by
/// every zero-config keyed module (hibp, oathnet, see_know), so the rule can't
/// drift between them.
#[must_use]
pub fn resolve_or_default<'a>(ctx_key: Option<&'a str>, default: &'a str) -> &'a str {
    match ctx_key {
        Some(k) if !k.is_empty() => k,
        _ => default,
    }
}

/// Resolve the WiGLE HTTP-Basic credentials (API name + token) from the module
/// context, each falling back to the embedded default via [`resolve_or_default`].
/// Single-sources the WiGLE credential env-var names and defaults that the
/// `wigle` and `wifi_intel` modules both need — they authenticate against the
/// same WiGLE API, so this resolution previously lived in two places.
#[must_use]
pub fn wigle_credentials(ctx: &crate::core::module::ModuleContext) -> (&str, &str) {
    let user = resolve_or_default(ctx.key_opt("HUNTSMAN_WIGLE_USER"), WIGLE_DEFAULT_USER);
    let token = resolve_or_default(ctx.key_opt("HUNTSMAN_WIGLE_TOKEN"), WIGLE_DEFAULT_TOKEN);
    (user, token)
}

/// Every API-key/token value HSE uses to authenticate its OWN queries: the
/// embedded defaults, every superseded default (so a rotated-out auth key is
/// never reported as a finding), and every live `HUNTSMAN_*_KEY` / `*_TOKEN` /
/// `*_USER` value in the process environment. Used by `util::found_keys` to
/// EXCLUDE our own credentials when identifying keys leaked in endpoint data —
/// the operator already has these; only third-party keys in the data are
/// findings. Values are returned verbatim (lower-cased copies are added too, so
/// a case-shifted echo of our own key still matches).
#[must_use]
pub fn own_api_keys() -> std::collections::HashSet<String> {
    let mut set = std::collections::HashSet::new();
    let mut add = |v: &str| {
        // A value may be a comma-separated LIST (the multi-key round-robin
        // rotation `load()` supports). Exclude EACH key, not the joined string —
        // otherwise an individual rotation key leaked in a response would slip
        // past the exclusion and be mis-reported as a foreign finding.
        for part in v.split(',') {
            let part = part.trim();
            if part.len() >= 8 {
                set.insert(part.to_string());
                set.insert(part.to_lowercase());
            }
        }
    };
    for (_, v) in HARDCODED {
        add(v);
    }
    for (_, v) in SUPERSEDED {
        add(v);
    }
    // Live overrides: any HUNTSMAN_* secret the operator configured (env or
    // ~/.huntsman.env, which `populate_and_load` has already exported).
    for (k, v) in std::env::vars() {
        if k.starts_with("HUNTSMAN_")
            && (k.ends_with("_KEY") || k.ends_with("_TOKEN") || k.ends_with("_USER"))
        {
            add(&v);
        }
    }
    set
}
