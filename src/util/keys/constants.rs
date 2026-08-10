//! Key registry: known keys, signup hints, embedded defaults, and pure resolvers.

/// Names of HUNTSMAN_* keys recognised by current/planned modules. Drives
/// the Settings UI so users see a populated grid before they've configured
/// anything. Matches the template comments in `install.sh`.
pub const KNOWN_KEYS: &[&str] = &[
    // Identity / breach
    "HUNTSMAN_OATHNET_KEY",
    "HUNTSMAN_NIAMONX_KEY",
    "HUNTSMAN_OSINTCAT_KEY",
    "HUNTSMAN_HIBP_KEY",
    "HUNTSMAN_DEHASHED_KEY",
    "HUNTSMAN_HUNTER_KEY",
    "HUNTSMAN_PROXYCURL_KEY",
    "HUNTSMAN_INTELX_KEY",
    // Infrastructure / threat intel
    "HUNTSMAN_SHODAN_KEY",
    "HUNTSMAN_SECTRAILS_KEY",
    "HUNTSMAN_LEAKIX_KEY",
    "HUNTSMAN_CRIMINALIP_KEY",
    "HUNTSMAN_IPQS_KEY",
    "HUNTSMAN_VIRUSTOTAL_KEY",
    "HUNTSMAN_ABUSECH_KEY",
    "HUNTSMAN_THREATFOX_KEY",
    "HUNTSMAN_ALIENVAULT_KEY",
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
    "HUNTSMAN_DOMAINSDB_KEY",
    // Validation / enrichment
    "HUNTSMAN_FULLCONTACT_KEY",
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
    "HUNTSMAN_OPENSANCTIONS_KEY",
    "HUNTSMAN_EPIEOS_KEY",
    "HUNTSMAN_OPENCORP_KEY",
    // Read inline (`ctx.key_opt("HUNTSMAN_GITHUB_TOKEN")`) by github_user,
    // github_code_search and github_commits rather than via an `_ENV` const,
    // which is exactly why it went unregistered here for so long.
    "HUNTSMAN_GITHUB_TOKEN",
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
        "HUNTSMAN_ALIENVAULT_KEY" => "AlienVault OTX — free key at https://otx.alienvault.com/api",
        "HUNTSMAN_SHODAN_KEY" => "Shodan — free key at https://account.shodan.io/register",
        "HUNTSMAN_SECTRAILS_KEY" => {
            "SecurityTrails — free tier at https://securitytrails.com/app/signup"
        }
        "HUNTSMAN_HUNTER_KEY" => "Hunter.io — free tier at https://hunter.io/users/sign_up",
        // No free tier, unlike most of this list: proxycurl is `ModuleCost::Paid`
        // and bills per credit, so the hint points at pricing rather than a
        // signup that would imply the key costs nothing.
        "HUNTSMAN_PROXYCURL_KEY" => {
            "Proxycurl — paid, per-credit; see https://nubela.co/proxycurl/pricing"
        }
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
        "HUNTSMAN_DOMAINSDB_KEY" => {
            "domainsDB — key required (anonymous access disabled); obtain one at https://domainsdb.info"
        }
        "HUNTSMAN_ONYPHE_KEY" => "ONYPHE — free tier at https://www.onyphe.io/login/#register",
        "HUNTSMAN_NETLAS_KEY" => "Netlas — free tier at https://app.netlas.io/registration",
        "HUNTSMAN_PULSEDIVE_KEY" => "Pulsedive — free key at https://pulsedive.com/about/api",
        "HUNTSMAN_OPENCORP_KEY" => "OpenCorporates — https://opencorporates.com/api_accounts/new",
        "HUNTSMAN_GITHUB_TOKEN" => {
            "GitHub — optional; the github_* modules run key-free but share GitHub's 60 req/hour unauthenticated limit. A no-scope personal access token from https://github.com/settings/tokens raises it."
        }
        "HUNTSMAN_NUMVERIFY_KEY" => "numverify — free tier at https://numverify.com/product",
        "HUNTSMAN_HLR_KEY" => "HLR Lookups — free trial at https://hlrlookups.com",
        "HUNTSMAN_OPENCNAM_KEY" => "OpenCNAM — free tier at https://www.opencnam.com/register",
        "HUNTSMAN_TROVE_KEY" => {
            "National Library of Australia Trove — free key at https://trove.nla.gov.au/about/create-something/using-our-apis/api-technical-guide"
        }
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
        "HUNTSMAN_SEON_KEY" => "SEON — free trial at https://seon.io",
        "HUNTSMAN_OPENSANCTIONS_KEY" => {
            "OpenSanctions — free trial/nonprofit key at https://www.opensanctions.org/api/"
        }
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

// ─── Embedded default keys — DELIBERATELY NONE ───────────────────────────────
//
// This build ships with NO provider credentials. Earlier revisions embedded live
// OathNet / HIBP / WiGLE / SeekNow credentials here so a fresh install worked
// zero-config. That is not viable in a public repository: anything compiled into
// a published binary — and committed to a public tree — is disclosed to everyone
// who can read either. Those values are considered COMPROMISED, have been removed
// from source, and must be revoked and reissued at each provider.
//
// Keyed modules now require the operator to supply their own key via the
// environment or `~/.huntsman.env`, and report an actionable "key required"
// notice (with the provider's signup URL, see [`signup_hint`]) when one is
// absent. There is no fallback path that silently authenticates as someone else.

/// SHA-256 digests (lowercase hex) of the credential values that shipped as
/// embedded defaults in previous builds, paired with the env var each occupied.
///
/// Stored as digests, not values: the point of this list is to RECOGNISE a
/// compromised credential still sitting in an operator's `~/.huntsman.env` —
/// written there by a previous build's key-provisioning step — so it can be
/// purged on upgrade. A digest identifies the value without redisclosing it, so
/// the remediation itself does not re-commit the secret. Each source value has
/// ≥128 bits of entropy, so publishing its digest does not expose it.
///
/// This list only ever grows: an entry must survive for as long as any install
/// might still carry that value. Never add a credential the operator chose —
/// only values this project itself shipped.
pub(super) const COMPROMISED_EMBEDDED_DIGESTS: &[(&str, &str)] = &[
    (
        "HUNTSMAN_OATHNET_KEY",
        "a2003bc8452ab3a70522bba2d02bb6ab974d19a392b415964f1f8f6911d5d177",
    ),
    (
        "HUNTSMAN_HIBP_KEY",
        "339ba734d77919ed6ab3118bd740e7f9a319bc7a8923d377dacd7cf68afefcfb",
    ),
    (
        "HUNTSMAN_WIGLE_USER",
        "35cc89cf9aa6b6350e1f65893eaffce1a3e885b66ff9aa6fa61153ac87b3cef0",
    ),
    (
        "HUNTSMAN_WIGLE_TOKEN",
        "9b9b7a9eb784e9cc7a6e725795233713e9e3571335d860e527e2ba37e2f4a424",
    ),
    (
        "HUNTSMAN_SEEKNOW_KEY",
        "c55fde64d83c6990a6277a7215eb5805a945e45b8dafedbbff0136bdff265fac",
    ),
    (
        "HUNTSMAN_SEEKNOW_KEY",
        "e6f4ce25ae9e719b86cb5a209a64080245c9bca273b43cdf8603d7365a25b6b2",
    ),
    (
        "HUNTSMAN_SEEKNOW_KEY",
        "5a9c6485a690b95e4604666678ffdf0edfa0d380b6e3a1fa3a2f51c4fab7696b",
    ),
    (
        "HUNTSMAN_SEEKNOW_KEY",
        "3a5f5e829481607833d4f4cfbea995486ac879d1064737d5b24c7c668bac4b78",
    ),
    (
        "HUNTSMAN_SEEKNOW_KEY",
        "ed445fc4cb4f8bbcf874b1d6be1a2146bb4b652d23d38db2a42a8b794c60ec68",
    ),
    (
        "HUNTSMAN_SEEKNOW_KEY",
        "2b2fc2d5c3b4262ef29788c1298d50dca103b82108d4d1a4998b2ee637c771c7",
    ),
    // Never an embedded default — this one was published as a copy-pasteable
    // "Example ~/.huntsman.env" in docs/SEEKNOW_SETUP.md, so any operator who
    // followed that guide literally has it in their env file today. Same
    // exposure, same remedy.
    (
        "HUNTSMAN_SEEKNOW_KEY",
        "751b3d29dd00f20e244941eab563ee002ca41de8b5bb616571c5325a165c02aa",
    ),
];

/// Lowercase-hex SHA-256 of `value`. Used to match an env-file value against
/// [`COMPROMISED_EMBEDDED_DIGESTS`] without holding the plaintext to compare to.
#[must_use]
pub(super) fn digest(value: &str) -> String {
    use sha2::Digest as _;
    let mut h = sha2::Sha256::new();
    h.update(value.as_bytes());
    hex::encode(h.finalize())
}

/// Whether `value` sitting in `env_var` digests to one of `digests`.
///
/// The list is a parameter so the purge policy can be tested positively against
/// a synthetic list: the real [`COMPROMISED_EMBEDDED_DIGESTS`] can only be
/// matched by holding the very plaintext this change exists to delete, so a test
/// asserting "a known-compromised value IS purged" would have to re-commit one.
pub(super) fn is_compromised_against(digests: &[(&str, &str)], env_var: &str, value: &str) -> bool {
    let d = digest(value);
    digests.iter().any(|(k, want)| *k == env_var && *want == d)
}

/// Whether `value` sitting in `env_var` is a credential this project previously
/// shipped as an embedded default, and which is therefore compromised.
///
/// Scoped to the exact (variable, value) pairs HSE itself wrote, so a key the
/// operator chose is never mistaken for one of ours — the digest of an operator
/// key will not appear in the list.
#[must_use]
pub fn is_compromised_embedded(env_var: &str, value: &str) -> bool {
    is_compromised_against(COMPROMISED_EMBEDDED_DIGESTS, env_var, value)
}

/// Bracketing of the `insert_<service>_key_here` placeholders that
/// `src/cli/env_template.txt` ships for every documented key.
const PLACEHOLDER_PREFIX: &str = "insert_";
const PLACEHOLDER_SUFFIX: &str = "_here";

/// Whether an env-file value is an unedited template placeholder
/// (`insert_..._here`) rather than a real credential.
///
/// Single-sourced here because two subsystems must agree on it: `hse provision`
/// (which must not preserve a placeholder as if it were a user value) and key
/// resolution (which must treat one as unconfigured). They disagreed before —
/// only provision knew the rule — which was harmless while an embedded default
/// existed to fall back on. With nothing embedded, a divergence would mean a
/// module sending the literal string `insert_haveibeenpwned_key_here` as its
/// credential and reporting the resulting 401 as a rejected key, instead of
/// telling the operator they never filled the slot in.
#[must_use]
pub fn is_template_placeholder(value: &str) -> bool {
    let v = value.trim();
    v.starts_with(PLACEHOLDER_PREFIX) && v.ends_with(PLACEHOLDER_SUFFIX)
}

/// Resolve an API key from the module context: `Some` when the operator supplied
/// a real key, `None` when the slot is absent, blank, or still holding the
/// template placeholder.
///
/// The single definition of the key-resolution policy shared by every keyed
/// module (hibp, oathnet, see_know, wigle), so the rule cannot drift between
/// them. There is deliberately no `default` parameter any more: a keyed module
/// with no configured key must report "key required" rather than fall back to a
/// credential belonging to whoever built the binary.
#[must_use]
pub fn resolve_key(ctx_key: Option<&str>) -> Option<&str> {
    ctx_key.filter(|k| !k.trim().is_empty() && !is_template_placeholder(k))
}

/// Resolve the WiGLE HTTP-Basic credentials (API name + token) from the module
/// context. `None` unless BOTH are configured — WiGLE authenticates with the
/// pair, so a half-configured account cannot make a request and must surface as
/// "key required" rather than as a 401 at the provider.
///
/// Single-sources the WiGLE credential env-var names that the `wigle` and
/// `wifi_intel` modules both need — they authenticate against the same WiGLE
/// API, so this resolution previously lived in two places.
#[must_use]
pub fn wigle_credentials(ctx: &crate::core::module::ModuleContext) -> Option<(&str, &str)> {
    let user = resolve_key(ctx.key_opt("HUNTSMAN_WIGLE_USER"))?;
    let token = resolve_key(ctx.key_opt("HUNTSMAN_WIGLE_TOKEN"))?;
    Some((user, token))
}

/// Every API-key/token value HSE uses to authenticate its OWN queries: every
/// live credential-bearing `HUNTSMAN_*` value in the process environment
/// (suffixes `_KEY` / `_TOKEN` / `_USER` / `_SECRET` / `_ID` / `_GUID` — the last
/// three cover the Censys ID+secret pair and the ABR GUID, which are auth
/// credentials too). Used by `util::found_keys` to EXCLUDE our own credentials
/// when identifying keys leaked in endpoint data — the operator already has
/// these; only third-party keys in the data are findings. Values are returned
/// verbatim (lower-cased copies are added too, so a case-shifted echo of our own
/// key still matches).
///
/// The process environment is now the ONLY source: with no embedded defaults
/// left, every key HSE authenticates with is one the operator configured.
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
    // Live keys: any HUNTSMAN_* secret the operator configured (env or
    // ~/.huntsman.env, which `populate_and_load` has already exported).
    for (k, v) in std::env::vars() {
        // Credential-bearing suffixes. `_SECRET`/`_ID`/`_GUID` are NOT optional:
        // HUNTSMAN_CENSYS_SECRET (a real secret) and HUNTSMAN_CENSYS_ID together
        // are Censys's HTTP-Basic credentials, and HUNTSMAN_ABR_GUID authenticates
        // the ABR lookup — without these suffixes our own Censys secret / ABR GUID
        // could be echoed by an upstream and mis-reported as a foreign finding.
        // Excluding a non-key HUNTSMAN_* var is harmless (it is never a foreign
        // key), so erring inclusive here is strictly safer than missing one.
        if k.starts_with("HUNTSMAN_")
            && (k.ends_with("_KEY")
                || k.ends_with("_TOKEN")
                || k.ends_with("_USER")
                || k.ends_with("_SECRET")
                || k.ends_with("_ID")
                || k.ends_with("_GUID"))
        {
            add(&v);
        }
    }
    set
}
