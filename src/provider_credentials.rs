//! Non-secret catalogue of operator-owned provider credential slots.
//!
//! Values are resolved by the existing `keys` module at runtime. This module
//! never stores, serializes, logs, or returns credential values.

use crate::http::Transport;
use crate::keys::{Keys, Secret};
use crate::service_defs::{ProbeVerdict, probe_service, service_for_env};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Provider {
    pub name: &'static str,
    pub slots: &'static [&'static str],
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProviderStatus {
    pub name: &'static str,
    pub slots: Vec<SlotStatus>,
    pub configured: bool,
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
        slots: &["HUNTSMAN_WIGLE_USER", "HUNTSMAN_WIGLE_TOKEN"],
    },
    Provider {
        name: "Brave Search",
        slots: &["HUNTSMAN_BRAVE_KEY"],
    },
    Provider {
        name: "Shodan",
        slots: &["HUNTSMAN_SHODAN_KEY"],
    },
    Provider {
        name: "Whoxy",
        slots: &["HUNTSMAN_WHOXY_KEY"],
    },
    Provider {
        name: "Citadel",
        slots: &["HUNTSMAN_CITADEL_KEY"],
    },
    Provider {
        name: "HIBP",
        slots: &["HUNTSMAN_HIBP_KEY"],
    },
    Provider {
        name: "SeekNow",
        slots: &["HUNTSMAN_SEEKNOW_KEY"],
    },
    Provider {
        name: "OathNet",
        slots: &["HUNTSMAN_OATHNET_KEY"],
    },
    Provider {
        name: "Exa",
        slots: &["HUNTSMAN_EXA_KEY"],
    },
    Provider {
        name: "OpenRouter",
        slots: &["HUNTSMAN_OPENROUTER_KEY"],
    },
    Provider {
        name: "Google Gemini",
        slots: &["HUNTSMAN_GEMINI_KEY"],
    },
    Provider {
        name: "GitHub",
        slots: &["HUNTSMAN_GITHUB_TOKEN"],
    },
    Provider {
        name: "VirusTotal",
        slots: &["HUNTSMAN_VIRUSTOTAL_KEY"],
    },
    Provider {
        name: "Censys",
        slots: &["HUNTSMAN_CENSYS_ID", "HUNTSMAN_CENSYS_SECRET"],
    },
];

fn secret_for_slot(keys: &Keys, slot: &str) -> Option<Secret> {
    keys.get(slot).or_else(|| match slot {
        "HUNTSMAN_HIBP_KEY" => keys.get("HIBP_API_KEY"),
        _ => None,
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
            }
        })
        .collect()
}

/// Probe every configured single-slot provider that has a canonical
/// `service_defs` probe. Unsupported providers remain explicit rather than
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
            match probe_service(transport, service.name, secret.expose()) {
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
}
