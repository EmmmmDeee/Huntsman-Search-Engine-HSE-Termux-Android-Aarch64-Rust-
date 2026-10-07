//! Non-secret catalogue of operator-owned provider credential slots.
//!
//! Values are resolved by the existing `keys` module at runtime. This module
//! never stores, serializes, logs, or returns credential values.

use crate::keys::Keys;

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
                    configured: keys.get(slot).is_some(),
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

#[must_use]
pub fn render(keys: &Keys) -> String {
    let mut out = String::new();
    for provider in status(keys) {
        let state = if provider.configured {
            "configured"
        } else {
            "incomplete"
        };
        out.push_str("provider=");
        out.push_str(provider.name);
        out.push_str("\tstate=");
        out.push_str(state);
        for slot in provider.slots {
            out.push('\t');
            out.push_str(slot.slot);
            out.push('=');
            out.push_str(if slot.configured { "set" } else { "unset" });
        }
        out.push('\n');
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

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
    fn rendering_never_contains_values() {
        let secret = "TEST-ONLY-SUPER-SECRET-WIGLE-TOKEN";
        let keys = Keys::parse(&format!(
            "HUNTSMAN_WIGLE_USER=test-user\nHUNTSMAN_WIGLE_TOKEN={secret}\nHUNTSMAN_BRAVE_KEY=brave-test-secret\n"
        )).expect("keys");
        let rendered = render(&keys);
        assert!(!rendered.contains(secret));
        assert!(!rendered.contains("test-user"));
        assert!(!rendered.contains("brave-test-secret"));
        assert!(rendered.contains("HUNTSMAN_WIGLE_TOKEN=set"));
        assert!(rendered.contains("provider=WiGLE\tstate=configured"));
    }
}
