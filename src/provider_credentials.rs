//! Non-secret catalogue of operator-owned provider credential slots.
//!
//! Values are resolved by the existing `keys` module at runtime. This module
//! never stores, serializes, logs, or returns credential values.

use crate::clock;
use crate::credential_origin::{AuthenticationAuthority, OperatorCredentialRef};
use crate::fetch::{AuthStyle, Credential, FetchOptions, fetch};
use crate::http::{Request, Transport};
use crate::keys::{Keys, Secret};
use crate::service_defs::{ProbeVerdict, probe_service, service_for_env};

/// The only origin `WiGLE` credentials are ever sent to.
pub const WIGLE_ORIGIN: &str = "https://api.wigle.net:443";
/// `WiGLE`'s own-profile endpoint: it checks the credentials without spending a search query.
pub const WIGLE_PROFILE_URL: &str = "https://api.wigle.net/api/v2/profile/user";

/// The operator's `WiGLE` API name and token as one HTTP Basic credential pinned to
/// [`WIGLE_ORIGIN`], with every form of the secret a diagnostic must not show.
pub struct WigleCredential {
    pub credential: Credential,
    secrets: [Secret; 3],
}

impl WigleCredential {
    /// The API name, the token and the joined pair, for scrubbing provider text.
    #[must_use]
    pub fn secrets(&self) -> [&str; 3] {
        self.secrets.each_ref().map(Secret::expose)
    }
}

/// Why no `WiGLE` credential could be built. Neither variant carries a value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WigleCredentialError {
    /// One or both slots are empty.
    Missing,
    /// The values cannot be sent as Basic credentials.
    Refused(String),
}

/// The one place the `WiGLE` slots become a credential, for searches and for the probe.
///
/// # Errors
/// [`WigleCredentialError::Missing`] when either slot is empty;
/// [`WigleCredentialError::Refused`] when the API name holds a `:`, which Basic auth cannot
/// carry in a user name.
pub fn wigle_credential(
    keys: &Keys,
    now_unix: u64,
) -> Result<WigleCredential, WigleCredentialError> {
    use crate::environment::{WIGLE_TOKEN_ENV, WIGLE_USER_ENV};
    let (Some(user), Some(token)) = (keys.get(WIGLE_USER_ENV), keys.get(WIGLE_TOKEN_ENV)) else {
        return Err(WigleCredentialError::Missing);
    };
    if user.expose().contains(':') {
        return Err(WigleCredentialError::Refused(format!(
            "{WIGLE_USER_ENV} must be the API Name alone; a ':' cannot be sent as a Basic-auth user"
        )));
    }
    let refused = |e: crate::error::Error| WigleCredentialError::Refused(e.to_string());
    // Joined with a char, not `format!("{}:{}")`: that format leaves a lone ":" literal in
    // rodata, which the release key scan reads joined to the slot name before it as
    // `HUNTSMAN_WIGLE_TOKEN:...` and refuses the binary.
    let mut joined = String::with_capacity(user.expose().len() + 1 + token.expose().len());
    joined.push_str(user.expose());
    joined.push(':');
    joined.push_str(token.expose());
    let pair = Secret::new(joined).map_err(refused)?;
    let authority = AuthenticationAuthority::operator_approved(OperatorCredentialRef {
        provider_id: "wigle.net".into(),
        credential_slot: WIGLE_TOKEN_ENV.into(),
        approved_at_unix: now_unix,
        approval_provenance: format!("operator configured {WIGLE_USER_ENV} and {WIGLE_TOKEN_ENV}"),
    })
    .map_err(refused)?;
    let credential = Credential::new(authority, pair.clone(), AuthStyle::Basic)
        .map_err(refused)?
        .only_for_origin(WIGLE_ORIGIN);
    Ok(WigleCredential {
        credential,
        secrets: [user, token, pair],
    })
}

/// Check the `WiGLE` credentials against the profile endpoint, which spends no search query.
/// A 200 JSON answer that does not say `success: false` is valid; 401 is rejected; 429 is rate
/// limited. Nothing from the profile is kept: it names the account holder.
fn wigle_probe<T: Transport + ?Sized>(keys: &Keys, transport: &T) -> ProbeState {
    let now = clock::unix_now();
    let Ok(wigle) = wigle_credential(keys, now) else {
        return ProbeState::NotConfigured;
    };
    let request = Request::get(WIGLE_PROFILE_URL).header("Accept", "application/json");
    let Ok(fetched) = fetch(
        transport,
        request,
        Some(&wigle.credential),
        &FetchOptions::no_redirects(),
        "wigle",
        now,
    ) else {
        return ProbeState::Unavailable;
    };
    let Some(response) = fetched.response else {
        return ProbeState::Unavailable;
    };
    match response.status {
        200 => {
            let answer: Option<serde_json::Value> = serde_json::from_slice(&response.body).ok();
            match answer {
                Some(value) if value.get("success") != Some(&serde_json::Value::Bool(false)) => {
                    ProbeState::Valid
                }
                _ => ProbeState::Indeterminate,
            }
        }
        401 | 403 => ProbeState::Rejected,
        429 => ProbeState::RateLimited,
        _ => ProbeState::Indeterminate,
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Provider {
    pub name: &'static str,
    pub slots: &'static [&'static str],
    /// Where an operator obtains this key. A stable provider page, never a
    /// value. Empty only for a provider with no public signup.
    pub get_key_url: &'static str,
    /// One line on the free tier or cost, as of this catalogue. Terms drift, so
    /// it is guidance, not a guarantee.
    pub free_tier: &'static str,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProviderStatus {
    pub name: &'static str,
    pub slots: Vec<SlotStatus>,
    pub configured: bool,
    pub get_key_url: &'static str,
    pub free_tier: &'static str,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SlotStatus {
    pub slot: &'static str,
    pub configured: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProbeState {
    NotConfigured,
    Unsupported,
    Valid,
    Rejected,
    RateLimited,
    Indeterminate,
    Unavailable,
}

impl ProbeState {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::NotConfigured => "not_configured",
            Self::Unsupported => "unsupported",
            Self::Valid => "valid",
            Self::Rejected => "rejected",
            Self::RateLimited => "rate_limited",
            Self::Indeterminate => "indeterminate",
            Self::Unavailable => "unavailable",
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProviderProbeStatus {
    pub provider: ProviderStatus,
    pub probe: ProbeState,
    pub evidence: Vec<(String, String)>,
}

pub const PROVIDERS: &[Provider] = &[
    Provider {
        name: "WiGLE",
        get_key_url: "https://wigle.net/account",
        free_tier: "free; USER is the API Name, TOKEN the API Token (not the encoded value); daily search limit",
        slots: &[
            crate::environment::WIGLE_USER_ENV,
            crate::environment::WIGLE_TOKEN_ENV,
        ],
    },
    Provider {
        name: "Brave Search",
        get_key_url: "https://api-dashboard.search.brave.com/app/keys",
        free_tier: "free tier; prepaid credit since 2026-09",
        slots: &[crate::environment::BRAVE_KEY_ENV],
    },
    Provider {
        name: "Shodan",
        get_key_url: "https://account.shodan.io",
        free_tier: "one-time membership unlocks query credits",
        slots: &[crate::environment::SHODAN_KEY_ENV],
    },
    Provider {
        name: "Whoxy",
        get_key_url: "https://www.whoxy.com/pricing.php",
        free_tier: "pay-as-you-go, ~$2 minimum balance",
        slots: &[crate::environment::WHOXY_KEY_ENV],
    },
    Provider {
        name: "HIBP",
        get_key_url: "https://haveibeenpwned.com/API/Key",
        free_tier: "US$3.50/mo, key required",
        slots: &[crate::environment::HUNTSMAN_HIBP_KEY_ENV],
    },
    Provider {
        name: "SeekNow",
        get_key_url: "",
        free_tier: "invite/paid; no public signup",
        slots: &[crate::environment::SEEKNOW_KEY_ENV],
    },
    Provider {
        name: "OathNet",
        get_key_url: "https://oathnet.org",
        free_tier: "paid API",
        slots: &[crate::environment::OATHNET_KEY_ENV],
    },
    Provider {
        name: "DeHashed",
        get_key_url: "https://dehashed.com",
        free_tier: "paid API",
        slots: &[crate::environment::DEHASHED_KEY_ENV],
    },
    Provider {
        name: "stolen.tax",
        get_key_url: "https://stolen.tax",
        free_tier: "paid API",
        slots: &[crate::environment::STOLEN_TAX_KEY_ENV],
    },
    Provider {
        name: "Exa",
        get_key_url: "https://dashboard.exa.ai/api-keys",
        free_tier: "free tier with signup credits",
        slots: &[crate::environment::EXA_KEY_ENV],
    },
    Provider {
        name: "OpenRouter",
        get_key_url: "https://openrouter.ai/keys",
        free_tier: "free tier; pay-as-you-go models",
        slots: &[crate::environment::OPENROUTER_KEY_ENV],
    },
    Provider {
        name: "Google Gemini",
        get_key_url: "https://aistudio.google.com/apikey",
        free_tier: "free tier via AI Studio",
        slots: &[crate::environment::GEMINI_KEY_ENV],
    },
    Provider {
        name: "GitHub",
        get_key_url: "https://github.com/settings/tokens",
        free_tier: "free; raises the API rate limit",
        slots: &[crate::environment::GITHUB_TOKEN_ENV],
    },
    Provider {
        name: "VirusTotal",
        get_key_url: "https://www.virustotal.com/gui/user/apikey",
        free_tier: "free: 4 req/min, 500/day",
        slots: &[crate::environment::VIRUSTOTAL_KEY_ENV],
    },
    Provider {
        name: "AbuseIPDB",
        get_key_url: "https://www.abuseipdb.com/account/api",
        free_tier: "free: 1,000 checks/day",
        slots: &[crate::environment::ABUSEIPDB_KEY_ENV],
    },
    Provider {
        name: "GreyNoise",
        get_key_url: "https://viz.greynoise.io/account/api-key",
        free_tier: "free Community key; works keyless at a lower limit",
        slots: &[crate::environment::GREYNOISE_KEY_ENV],
    },
    Provider {
        name: "Hunter.io",
        get_key_url: "https://hunter.io/api-keys",
        free_tier: "free: 25 searches/month",
        slots: &[crate::environment::HUNTER_KEY_ENV],
    },
    Provider {
        name: "Numverify (APILayer)",
        get_key_url: "https://apilayer.com/marketplace/number_verification-api",
        free_tier: "free: 100 lookups/month",
        slots: &[crate::environment::NUMVERIFY_KEY_ENV],
    },
    Provider {
        name: "LeakIX",
        get_key_url: "https://leakix.net/settings/api",
        free_tier: "free account key",
        slots: &[crate::environment::LEAKIX_KEY_ENV],
    },
    Provider {
        name: "Pulsedive",
        get_key_url: "https://pulsedive.com/account/",
        free_tier: "free key; works keyless at a lower limit",
        slots: &[crate::environment::PULSEDIVE_KEY_ENV],
    },
    Provider {
        name: "IPQualityScore",
        get_key_url: "https://www.ipqualityscore.com/user/settings",
        free_tier: "free: 1,000 lookups/month",
        slots: &[crate::environment::IPQS_KEY_ENV],
    },
    Provider {
        name: "ThreatFox (abuse.ch)",
        get_key_url: "https://auth.abuse.ch/",
        free_tier: "free abuse.ch Auth-Key",
        slots: &[crate::environment::THREATFOX_KEY_ENV],
    },
    Provider {
        name: "Cert Spotter (SSLMate)",
        get_key_url: "https://sslmate.com/account/api_credentials",
        free_tier: "free key; works keyless at a lower limit",
        slots: &[crate::environment::CERTSPOTTER_KEY_ENV],
    },
    Provider {
        name: "Netlas",
        get_key_url: "https://app.netlas.io/profile/",
        free_tier: "free Community key; works keyless at a lower limit",
        slots: &[crate::environment::NETLAS_KEY_ENV],
    },
    Provider {
        name: "SecurityTrails",
        get_key_url: "https://securitytrails.com/app/account/credentials",
        free_tier: "free: 50 queries/month",
        slots: &[crate::environment::SECTRAILS_KEY_ENV],
    },
    Provider {
        name: "URLhaus (abuse.ch)",
        get_key_url: "https://auth.abuse.ch/",
        free_tier: "free abuse.ch Auth-Key (the same key as ThreatFox)",
        slots: &[crate::environment::ABUSECH_KEY_ENV],
    },
    Provider {
        name: "AlienVault OTX",
        get_key_url: "https://otx.alienvault.com/settings",
        free_tier: "free key; works keyless at a lower limit",
        slots: &[crate::environment::OTX_KEY_ENV],
    },
    Provider {
        name: "urlscan.io",
        get_key_url: "https://urlscan.io/user/profile/",
        free_tier: "free key; searches work keyless at a lower quota",
        slots: &[crate::environment::URLSCAN_KEY_ENV],
    },
    Provider {
        name: "HackerTarget",
        get_key_url: "https://hackertarget.com/scan-membership/",
        free_tier: "membership key; works keyless at 50 queries/day",
        slots: &[crate::environment::HACKERTARGET_KEY_ENV],
    },
    Provider {
        name: "IPinfo",
        get_key_url: "https://ipinfo.io/account/token",
        free_tier: "free token: 50,000 lookups/month; works keyless at a lower limit",
        slots: &[crate::environment::IPINFO_KEY_ENV],
    },
    Provider {
        name: "Censys",
        get_key_url: "https://platform.censys.io/account/api",
        free_tier: "free: 250 req/month",
        slots: &[
            crate::environment::CENSYS_ID_ENV,
            crate::environment::CENSYS_SECRET_ENV,
        ],
    },
];

/// The slots that read a second name, as `(slot, alias)`: `HUNTSMAN_HIBP_KEY` falls back to a
/// `HIBP_API_KEY` entry, HIBP's own name for the same key. A slot reads its alias only when the
/// slot itself is unset.
pub(crate) const SLOT_FALLBACKS: &[(&str, &str)] = &[(
    crate::environment::HUNTSMAN_HIBP_KEY_ENV,
    crate::environment::HIBP_API_KEY_ENV,
)];

/// The secret `keys` holds for `slot`: the one rule from a slot to its key, which
/// `credential-status` reports with and a lookup must use. `HUNTSMAN_HIBP_KEY` falls back to a
/// `HIBP_API_KEY` entry, HIBP's own name for the same key.
#[must_use]
pub fn secret_for_slot(keys: &Keys, slot: &str) -> Option<Secret> {
    keys.get(slot).or_else(|| {
        SLOT_FALLBACKS
            .iter()
            .find(|(fallback, _)| *fallback == slot)
            .and_then(|(_, alias)| keys.get(alias))
    })
}

#[must_use]
pub fn status(keys: &Keys) -> Vec<ProviderStatus> {
    PROVIDERS
        .iter()
        .map(|provider| {
            let slots: Vec<_> = provider
                .slots
                .iter()
                .map(|&slot| SlotStatus {
                    slot,
                    configured: secret_for_slot(keys, slot).is_some(),
                })
                .collect();
            let configured = slots.iter().all(|slot| slot.configured);
            ProviderStatus {
                name: provider.name,
                slots,
                configured,
                get_key_url: provider.get_key_url,
                free_tier: provider.free_tier,
            }
        })
        .collect()
}

/// Keys-file slot names that match no provider slot and no other variable `huntsman-recon`
/// reads (see [`crate::environment::is_known_variable`]). Such a slot is stored in the keys file
/// and counted by `doctor`, yet no provider reads it, so the keyed source it was meant to
/// configure silently never runs. Surfacing it turns a misnamed key into an observable warning.
/// Names only, never values. Deterministic order (the keys file is a sorted map).
#[must_use]
pub fn unrecognised_slots(keys: &Keys) -> Vec<&str> {
    keys.slots()
        .into_iter()
        .filter(|slot| !crate::environment::is_known_variable(slot))
        .collect()
}

/// Append one line per [`unrecognised_slots`] entry, after the provider rows, so a misnamed key
/// is visible in `credential-status`. Never prints a value.
fn write_unrecognised(out: &mut String, keys: &Keys) {
    for slot in unrecognised_slots(keys) {
        out.push_str("unrecognised_slot=");
        out.push_str(slot);
        out.push_str("\tstate=unread\tnote=");
        if slot == crate::environment::LEGACY_INSTALL_DIR_ENV {
            out.push_str(
                "obsolete installer setting, not a provider key; remove with huntsman-recon keys remove ",
            );
            out.push_str(crate::environment::LEGACY_INSTALL_DIR_ENV);
            out.push_str(" (installer uses ");
            out.push_str(crate::environment::INSTALL_ROOT_ENV);
            out.push_str(" only when invoked)");
        } else if slot == crate::environment::RETIRED_MOZILLA_LOCATION_KEY_ENV {
            out.push_str(
                "Mozilla retired the Location Service API on 2024-06-12 and nothing reads this key; remove with huntsman-recon keys remove ",
            );
            out.push_str(crate::environment::RETIRED_MOZILLA_LOCATION_KEY_ENV);
        } else {
            out.push_str("matches no provider; rename it to the exact slot or remove it");
        }
        out.push('\n');
    }
}

/// Probe every configured single-slot provider that has a canonical
/// `service_defs` probe, and `WiGLE` through its own-profile endpoint. Unsupported providers remain explicit rather than
/// being guessed healthy. Probe errors are reduced to `Unavailable`; raw
/// transport text is deliberately not carried into this status surface.
#[must_use]
pub fn probe<T: Transport + ?Sized>(keys: &Keys, transport: &T) -> Vec<ProviderProbeStatus> {
    status(keys)
        .into_iter()
        .map(|provider| {
            if !provider.configured {
                return ProviderProbeStatus {
                    provider,
                    probe: ProbeState::NotConfigured,
                    evidence: Vec::new(),
                };
            }
            if provider.name == "WiGLE" {
                return ProviderProbeStatus {
                    probe: wigle_probe(keys, transport),
                    provider,
                    evidence: Vec::new(),
                };
            }
            let Some(slot) = provider.slots.first().filter(|_| provider.slots.len() == 1) else {
                return ProviderProbeStatus {
                    provider,
                    probe: ProbeState::Unsupported,
                    evidence: Vec::new(),
                };
            };
            let Some(service) = service_for_env(slot.slot) else {
                return ProviderProbeStatus {
                    provider,
                    probe: ProbeState::Unsupported,
                    evidence: Vec::new(),
                };
            };
            let Some(secret) = secret_for_slot(keys, slot.slot) else {
                return ProviderProbeStatus {
                    provider,
                    probe: ProbeState::NotConfigured,
                    evidence: Vec::new(),
                };
            };
            match probe_service(transport, service.name, &secret) {
                Ok(result) => {
                    let probe = match result.verdict {
                        ProbeVerdict::Valid => ProbeState::Valid,
                        ProbeVerdict::Rejected => ProbeState::Rejected,
                        ProbeVerdict::RateLimited => ProbeState::RateLimited,
                        ProbeVerdict::Indeterminate => ProbeState::Indeterminate,
                    };
                    ProviderProbeStatus {
                        provider,
                        probe,
                        evidence: result.evidence,
                    }
                }
                Err(_) => ProviderProbeStatus {
                    provider,
                    probe: ProbeState::Unavailable,
                    evidence: Vec::new(),
                },
            }
        })
        .collect()
}

#[must_use]
pub fn render(keys: &Keys) -> String {
    let mut out = String::new();
    for provider in status(keys) {
        write_status(&mut out, &provider, None, &[]);
    }
    write_unrecognised(&mut out, keys);
    out
}

#[must_use]
pub fn render_probed<T: Transport + ?Sized>(keys: &Keys, transport: &T) -> String {
    let mut out = String::new();
    for probed in probe(keys, transport) {
        write_status(
            &mut out,
            &probed.provider,
            Some(probed.probe),
            &probed.evidence,
        );
    }
    write_unrecognised(&mut out, keys);
    out
}

fn write_status(
    out: &mut String,
    provider: &ProviderStatus,
    probe: Option<ProbeState>,
    evidence: &[(String, String)],
) {
    let state = if provider.configured {
        "configured"
    } else {
        "incomplete"
    };
    out.push_str("provider=");
    out.push_str(provider.name);
    out.push_str("\tstate=");
    out.push_str(state);
    if let Some(probe) = probe {
        out.push_str("\tprobe=");
        out.push_str(probe.as_str());
    }
    for slot in &provider.slots {
        out.push('\t');
        out.push_str(slot.slot);
        out.push('=');
        out.push_str(if slot.configured { "set" } else { "unset" });
    }
    if !provider.configured {
        if !provider.get_key_url.is_empty() {
            out.push_str("\tget_key=");
            out.push_str(provider.get_key_url);
        }
        if !provider.free_tier.is_empty() {
            out.push_str("\tfree_tier=");
            out.push_str(&one_line(provider.free_tier, 80));
        }
    }
    for (key, value) in evidence {
        out.push_str("\tprobe.");
        out.push_str(&one_line(key, 64));
        out.push('=');
        out.push_str(&one_line(value, 160));
    }
    out.push('\n');
}

fn one_line(value: &str, max_chars: usize) -> String {
    value
        .chars()
        .filter(|c| !c.is_control())
        .take(max_chars)
        .collect()
}

#[cfg(test)]
mod tests {
    use std::cell::RefCell;

    use super::*;
    use crate::http::{Request, Response, TransportFailure};

    struct FakeTransport {
        response: Response,
        seen: RefCell<Vec<Request>>,
    }

    impl Transport for FakeTransport {
        fn send(&self, request: &Request) -> Result<Response, TransportFailure> {
            self.seen.borrow_mut().push(request.clone());
            Ok(self.response.clone())
        }
    }

    #[test]
    fn wigle_probe_checks_the_profile_with_basic_auth_and_keeps_nothing() {
        let keys = Keys::parse(
            "HUNTSMAN_WIGLE_USER=AIDprobe0123456789\nHUNTSMAN_WIGLE_TOKEN=probe-token-0123456789abcdef\n",
        )
        .expect("keys");
        for (status, body, expected) in [
            (200, r#"{"success":true,"userid":"Ada"}"#, ProbeState::Valid),
            (200, r#"{"success":false}"#, ProbeState::Indeterminate),
            (200, "<html>", ProbeState::Indeterminate),
            (401, "Not Authorized (WiGLE.net)", ProbeState::Rejected),
            (429, "{}", ProbeState::RateLimited),
            (500, "{}", ProbeState::Indeterminate),
        ] {
            let transport = FakeTransport {
                response: Response {
                    status,
                    headers: Vec::new(),
                    body: body.as_bytes().to_vec(),
                    truncated: false,
                },
                seen: RefCell::new(Vec::new()),
            };
            let wigle = probe(&keys, &transport)
                .into_iter()
                .find(|p| p.provider.name == "WiGLE")
                .expect("WiGLE");
            assert_eq!(wigle.probe, expected, "HTTP {status} {body}");
            assert!(
                wigle.evidence.is_empty(),
                "the profile names the account holder"
            );
            let seen = transport.seen.borrow();
            assert_eq!(seen.len(), 1, "one request, and only for WiGLE");
            assert_eq!(seen[0].url, WIGLE_PROFILE_URL);
            assert_eq!(
                seen[0].header_value("authorization"),
                Some("Basic QUlEcHJvYmUwMTIzNDU2Nzg5OnByb2JlLXRva2VuLTAxMjM0NTY3ODlhYmNkZWY=")
            );
        }
        let half = Keys::parse("HUNTSMAN_WIGLE_USER=AIDprobe0123456789\n").expect("keys");
        let transport = FakeTransport {
            response: Response {
                status: 200,
                headers: Vec::new(),
                body: Vec::new(),
                truncated: false,
            },
            seen: RefCell::new(Vec::new()),
        };
        let wigle = probe(&half, &transport)
            .into_iter()
            .find(|p| p.provider.name == "WiGLE")
            .expect("WiGLE");
        assert_eq!(wigle.probe, ProbeState::NotConfigured);
        assert!(transport.seen.borrow().is_empty());
    }

    #[test]
    fn every_provider_names_where_to_get_the_key_and_its_tier() {
        for provider in PROVIDERS {
            assert!(!provider.free_tier.is_empty(), "{}", provider.name);
            // A provider either has a signup URL or explains why it has none.
            if provider.get_key_url.is_empty() {
                assert!(
                    provider.free_tier.contains("offline")
                        || provider.free_tier.contains("no public signup"),
                    "{} has no URL and no reason",
                    provider.name
                );
            } else {
                assert!(
                    provider.get_key_url.starts_with("https://"),
                    "{}",
                    provider.name
                );
            }
        }
    }

    #[test]
    fn an_unconfigured_provider_shows_where_to_get_the_key() {
        let out = render(&Keys::default());
        assert!(
            out.contains(
                "provider=HIBP\tstate=incomplete\tHUNTSMAN_HIBP_KEY=unset\t\
                 get_key=https://haveibeenpwned.com/API/Key\tfree_tier=US$3.50/mo, key required\n"
            ),
            "{out}"
        );
        // A configured provider does not repeat the signup guidance.
        let keys = Keys::parse("HUNTSMAN_HIBP_KEY=abcdef0123456789abcdef0123456789").expect("keys");
        let configured = render(&keys);
        let hibp = configured
            .lines()
            .find(|line| line.starts_with("provider=HIBP\t"))
            .expect("HIBP line");
        assert!(hibp.contains("state=configured"), "{hibp}");
        assert!(!hibp.contains("get_key="), "{hibp}");
    }

    #[test]
    fn catalogue_is_unique_and_uses_huntsman_slots() {
        let mut names = std::collections::BTreeSet::new();
        let mut slots = std::collections::BTreeSet::new();
        for provider in PROVIDERS {
            assert!(names.insert(provider.name));
            assert!(!provider.slots.is_empty());
            for slot in provider.slots {
                assert!(slot.starts_with("HUNTSMAN_"), "{slot}");
                assert!(slots.insert(*slot), "duplicate slot {slot}");
            }
        }
    }

    #[test]
    fn status_requires_every_slot_for_multi_slot_provider() {
        let keys = Keys::parse("HUNTSMAN_WIGLE_USER=user-123\n").expect("keys");
        let wigle = status(&keys)
            .into_iter()
            .find(|p| p.name == "WiGLE")
            .expect("WiGLE");
        assert!(!wigle.configured);
        assert!(wigle.slots[0].configured);
        assert!(!wigle.slots[1].configured);
    }

    #[test]
    fn hibp_standard_api_key_alias_counts_as_configured() {
        let keys = Keys::parse("HIBP_API_KEY=0123456789abcdef0123456789abcdef\n").expect("keys");
        let hibp = status(&keys)
            .into_iter()
            .find(|provider| provider.name == "HIBP")
            .expect("HIBP");
        assert!(hibp.configured);
        assert!(hibp.slots[0].configured);
        let secret = secret_for_slot(&keys, crate::environment::HUNTSMAN_HIBP_KEY_ENV)
            .expect("HIBP_API_KEY entry fills the HUNTSMAN_HIBP_KEY slot");
        assert_eq!(secret.expose(), "0123456789abcdef0123456789abcdef");
    }

    #[test]
    fn rendering_never_contains_values() {
        let secret = "TEST-ONLY-SUPER-SECRET-WIGLE-TOKEN";
        let keys = Keys::parse(&format!(
            "HUNTSMAN_WIGLE_USER=test-user\nHUNTSMAN_WIGLE_TOKEN={secret}\nHUNTSMAN_BRAVE_KEY=brave-test-secret\n"
        ))
        .expect("keys");
        let rendered = render(&keys);
        assert!(!rendered.contains(secret));
        assert!(!rendered.contains("test-user"));
        assert!(!rendered.contains("brave-test-secret"));
        assert!(rendered.contains("HUNTSMAN_WIGLE_TOKEN=set"));
        assert!(rendered.contains("provider=WiGLE\tstate=configured"));
    }

    #[test]
    fn hibp_probe_uses_registered_status_endpoint_and_returns_plan_metadata() {
        let key = "fake-hibp-key-never-render";
        let keys = Keys::parse(&format!("HUNTSMAN_HIBP_KEY={key}\n")).expect("keys");
        let transport = FakeTransport {
            response: Response {
                status: 200,
                headers: Vec::new(),
                body: br#"{"SubscriptionName":"Core 1","Rpm":10,"IncludesStealerLogs":false,"IncludesKAnon":false}"#.to_vec(),
                truncated: false,
            },
            seen: RefCell::new(Vec::new()),
        };

        let statuses = probe(&keys, &transport);
        let hibp = statuses
            .iter()
            .find(|status| status.provider.name == "HIBP")
            .expect("HIBP status");
        assert_eq!(hibp.probe, ProbeState::Valid);
        assert!(
            hibp.evidence
                .iter()
                .any(|item| item == &("subscription_name".into(), "Core 1".into()))
        );
        let request = transport.seen.borrow()[0].clone();
        assert_eq!(
            request.url,
            "https://haveibeenpwned.com/api/v3/subscription/status"
        );
        assert_eq!(request.header_value("hibp-api-key"), Some(key));
        assert!(request.header_value("User-Agent").is_some());

        let rendered = render_probed(&keys, &transport);
        assert!(!rendered.contains(key));
        assert!(rendered.contains("provider=HIBP\tstate=configured\tprobe=valid"));
        assert!(rendered.contains("probe.subscription_name=Core 1"));
        assert!(rendered.contains("probe.rpm=10"));
    }

    #[test]
    fn a_challenge_page_leaves_the_hibp_key_unchecked() {
        // HIBP is behind Cloudflare. Its interstitial, served with 403 or with 200, never reached
        // HIBP, so the key is neither rejected nor valid.
        let keys = Keys::parse("HUNTSMAN_HIBP_KEY=fake-hibp-key-never-render\n").expect("keys");
        let page = "<!DOCTYPE html><html><head><title>Just a moment...</title></head><body>cloudflare <script src=\"/cdn-cgi/challenge-platform/h/b/orchestrate/jsch/v1\"></script></body></html>";
        for status in [403, 200] {
            let transport = FakeTransport {
                response: Response {
                    status,
                    headers: Vec::new(),
                    body: page.as_bytes().to_vec(),
                    truncated: false,
                },
                seen: RefCell::new(Vec::new()),
            };
            let rendered = render_probed(&keys, &transport);
            assert!(
                rendered.contains("provider=HIBP\tstate=configured\tprobe=indeterminate"),
                "HTTP {status}: {rendered}"
            );
        }
    }

    #[test]
    fn a_plain_401_renders_the_hibp_key_rejected() {
        // Without a challenge page a 401 is a rejected key, which `doctor --probe` fails on.
        let keys = Keys::parse("HUNTSMAN_HIBP_KEY=fake-hibp-key-never-render\n").expect("keys");
        let transport = FakeTransport {
            response: Response {
                status: 401,
                headers: Vec::new(),
                body: Vec::new(),
                truncated: false,
            },
            seen: RefCell::new(Vec::new()),
        };
        let rendered = render_probed(&keys, &transport);
        assert!(
            rendered.contains("provider=HIBP\tstate=configured\tprobe=rejected"),
            "{rendered}"
        );
    }

    #[test]
    fn unconfigured_and_unregistered_probes_stay_explicit() {
        let keys = Keys::parse("HUNTSMAN_BRAVE_KEY=brave-key\n").expect("keys");
        let transport = FakeTransport {
            response: Response {
                status: 200,
                headers: Vec::new(),
                body: Vec::new(),
                truncated: false,
            },
            seen: RefCell::new(Vec::new()),
        };
        let statuses = probe(&keys, &transport);
        let brave = statuses
            .iter()
            .find(|status| status.provider.name == "Brave Search")
            .expect("Brave");
        let hibp = statuses
            .iter()
            .find(|status| status.provider.name == "HIBP")
            .expect("HIBP");
        assert_eq!(brave.probe, ProbeState::Unsupported);
        assert_eq!(hibp.probe, ProbeState::NotConfigured);
        assert!(transport.seen.borrow().is_empty());
    }

    #[test]
    fn every_provider_slot_is_a_known_variable() {
        // No configured provider key may ever be flagged as unrecognised, now or as providers are
        // added: every slot a provider reads must be in environment::KNOWN_VARIABLES.
        for provider in PROVIDERS {
            for slot in provider.slots {
                assert!(
                    crate::environment::is_known_variable(slot),
                    "provider {} slot {slot} is not a known variable",
                    provider.name
                );
            }
        }
    }

    #[test]
    fn known_settings_and_cost_variables_are_not_flagged() {
        for name in [
            crate::environment::SERVE_TOKEN_ENV,
            crate::environment::SERVE_BIND_ENV,
            crate::environment::HIBP_API_KEY_ENV,
            crate::environment::HIBP_RATE_LIMIT_ENV,
            crate::environment::HUNTSMAN_HOME_ENV,
            crate::environment::HUNTSMAN_ENV_FILE_ENV,
            crate::environment::CA_BUNDLE_ENV,
            "HSE_PROVIDER_COST_SHODAN",
        ] {
            assert!(
                crate::environment::is_known_variable(name),
                "{name} should be recognised"
            );
        }
        for name in [
            "HUNTSMAN_SHODAN",
            "SHODAN_KEY",
            "HUNTSMAN_BOGUS_KEY",
            "NOTAKEY",
        ] {
            assert!(
                !crate::environment::is_known_variable(name),
                "{name} should be unrecognised"
            );
        }
    }

    /// A key for the retired Mozilla Location Service is read by nothing; it is named as retired,
    /// with the command that removes it, and its value is never shown.
    #[test]
    fn a_retired_mozilla_location_key_is_named_as_retired() {
        let slot = crate::environment::RETIRED_MOZILLA_LOCATION_KEY_ENV;
        let keys = Keys::parse(&format!("{slot}=mls-private-value\n")).expect("keys");
        assert_eq!(unrecognised_slots(&keys), vec![slot]);
        let rendered = render(&keys);
        assert!(
            rendered.contains(&format!("unrecognised_slot={slot}")),
            "{rendered}"
        );
        assert!(rendered.contains("retired"), "{rendered}");
        assert!(
            rendered.contains(&format!("huntsman-recon keys remove {slot}")),
            "{rendered}"
        );
        assert!(!rendered.contains("mls-private-value"), "{rendered}");
    }

    #[test]
    fn obsolete_install_dir_is_not_mistaken_for_a_credential() {
        let slot = crate::environment::LEGACY_INSTALL_DIR_ENV;
        let keys = Keys::parse(&format!("{slot}=/tmp/private-install-value\n")).expect("keys");
        assert_eq!(unrecognised_slots(&keys), vec![slot]);
        let rendered = render(&keys);
        assert!(
            rendered.contains(&format!("unrecognised_slot={slot}")),
            "{rendered}"
        );
        assert!(
            rendered.contains("huntsman-recon keys remove"),
            "{rendered}"
        );
        assert!(
            rendered.contains(crate::environment::INSTALL_ROOT_ENV),
            "{rendered}"
        );
        assert!(
            !rendered.contains("/tmp/private-install-value"),
            "{rendered}"
        );
    }

    #[test]
    fn unrecognised_slots_names_only_the_misnamed_key() {
        // A real provider key, a legitimate non-provider setting, and a misnamed key together.
        let keys = Keys::parse(
            "HUNTSMAN_SHODAN_KEY=shodan-secret-value-012345\nHSE_AUTH_TOKEN=serve-token-value-012345\nHUNTSMAN_SHODAN=misnamed-secret-value-012345\n",
        )
        .expect("keys");
        assert_eq!(unrecognised_slots(&keys), vec!["HUNTSMAN_SHODAN"]);

        let rendered = render(&keys);
        assert!(
            rendered.contains("unrecognised_slot=HUNTSMAN_SHODAN"),
            "credential-status must surface the misnamed slot: {rendered}"
        );
        assert!(
            !rendered.contains("misnamed-secret-value"),
            "it must never print the value"
        );

        // A keys file of only recognised names yields nothing.
        let clean = Keys::parse("HUNTSMAN_SHODAN_KEY=shodan-secret-value-012345\n").expect("keys");
        assert!(unrecognised_slots(&clean).is_empty());
    }
}
