//! Keys from a file another tool wrote, for the keys file. It reads Spiderfoot 4.0's settings
//! export (`SpiderFoot.cfg`, which Settings → Export API Keys writes as `sfp_module:option=value`
//! lines) and keys files (`HUNTSMAN_…=value` lines, as `~/.huntsman.env` holds them). [`plan`]
//! names the provider catalogue slot each line sets. Values stay in [`Secret`]s, and the rest of
//! the plan carries option names and line numbers, never a value.

use crate::base64;
use crate::environment::{
    ABUSEIPDB_KEY_ENV, CENSYS_ID_ENV, CENSYS_SECRET_ENV, CERTSPOTTER_KEY_ENV, DEHASHED_KEY_ENV,
    GREYNOISE_KEY_ENV, HUNTER_KEY_ENV, HUNTSMAN_HIBP_KEY_ENV, IPINFO_KEY_ENV, IPQS_KEY_ENV,
    LEAKIX_KEY_ENV, NUMVERIFY_KEY_ENV, OTX_KEY_ENV, PULSEDIVE_KEY_ENV, SECTRAILS_KEY_ENV,
    SHODAN_KEY_ENV, VIRUSTOTAL_KEY_ENV, WHOXY_KEY_ENV, WIGLE_TOKEN_ENV, WIGLE_USER_ENV,
};
use crate::keys::{Keys, MAX_KEY_BYTES, Secret};
use crate::provider_credentials::{PROVIDERS, SLOT_FALLBACKS};

/// The Spiderfoot 4.0 module options whose key a Huntsman source takes, by the name
/// `SpiderFoot.cfg` gives each (`module:option`), with the slot it fills. `sfp_greynoise` and
/// `sfp_greynoise_community` both fill the one `GreyNoise` slot. Huntsman asks the Community API,
/// which takes either key.
pub const SPIDERFOOT_OPTIONS: &[(&str, &str)] = &[
    ("sfp_abuseipdb:api_key", ABUSEIPDB_KEY_ENV),
    ("sfp_alienvault:api_key", OTX_KEY_ENV),
    ("sfp_censys:censys_api_key_uid", CENSYS_ID_ENV),
    ("sfp_censys:censys_api_key_secret", CENSYS_SECRET_ENV),
    ("sfp_certspotter:api_key", CERTSPOTTER_KEY_ENV),
    ("sfp_dehashed:api_key", DEHASHED_KEY_ENV),
    ("sfp_greynoise:api_key", GREYNOISE_KEY_ENV),
    ("sfp_greynoise_community:api_key", GREYNOISE_KEY_ENV),
    ("sfp_haveibeenpwned:api_key", HUNTSMAN_HIBP_KEY_ENV),
    ("sfp_hunter:api_key", HUNTER_KEY_ENV),
    ("sfp_ipinfo:api_key", IPINFO_KEY_ENV),
    ("sfp_ipqualityscore:api_key", IPQS_KEY_ENV),
    ("sfp_leakix:api_key", LEAKIX_KEY_ENV),
    ("sfp_numverify:api_key", NUMVERIFY_KEY_ENV),
    ("sfp_pulsedive:api_key", PULSEDIVE_KEY_ENV),
    ("sfp_securitytrails:api_key", SECTRAILS_KEY_ENV),
    ("sfp_shodan:api_key", SHODAN_KEY_ENV),
    ("sfp_virustotal:api_key", VIRUSTOTAL_KEY_ENV),
    ("sfp_whoxy:api_key", WHOXY_KEY_ENV),
];

/// `sfp_wigle`'s one key option: the base64 of `NAME:TOKEN`, which Spiderfoot sends as HTTP Basic
/// credentials. Huntsman keeps the API name and token in two slots, so the import decodes it.
pub const SPIDERFOOT_WIGLE_OPTION: &str = "sfp_wigle:api_key_encoded";

/// What importing a file would save.
#[derive(Debug, Default)]
pub struct Plan {
    /// Each slot once, at the line that first set it, with the value of the last line that set it.
    /// A `HIBP_API_KEY` line fills `HUNTSMAN_HIBP_KEY` only when no `HUNTSMAN_HIBP_KEY` or
    /// `sfp_haveibeenpwned:api_key` line sets it.
    pub saves: Vec<(&'static str, Secret)>,
    /// Keys the file sets that no Huntsman source takes: Spiderfoot `api_key` options and
    /// keys-file slots outside the catalogue, by name, each once.
    pub unused: Vec<String>,
    /// How many Spiderfoot options are settings, not keys. Spiderfoot's own test is that an
    /// option's name holds `api_key`.
    pub settings: usize,
    /// The lines that cannot be read, each as its number and why, never with a value.
    pub refused: Vec<String>,
    /// The slots in `saves` that only an alias line has set so far.
    fallback_only: Vec<&'static str>,
}

impl Plan {
    fn save(&mut self, slot: &'static str, secret: Secret) {
        self.fallback_only.retain(|known| *known != slot);
        match self.saves.iter_mut().find(|(known, _)| *known == slot) {
            Some(save) => save.1 = secret,
            None => self.saves.push((slot, secret)),
        }
    }

    /// A save from an alias line, which a line naming the slot itself outranks wherever it is,
    /// as [`secret_for_slot`](crate::provider_credentials::secret_for_slot) reads a keys file.
    /// Unlike a keys file, a placeholder line naming the slot is skipped, not read as unsetting
    /// it, so it does not let an alias line through.
    fn save_fallback(&mut self, slot: &'static str, secret: Secret) {
        if self.saves.iter().any(|(known, _)| *known == slot) && !self.fallback_only.contains(&slot)
        {
            return;
        }
        self.save(slot, secret);
        self.fallback_only.push(slot);
    }

    fn unused(&mut self, name: &str) {
        if !self.unused.iter().any(|known| known == name) {
            self.unused.push(name.to_owned());
        }
    }
}

/// The plan for importing `text`: a `SpiderFoot.cfg` export or a keys file, or a mix of their
/// lines. A Spiderfoot option with an empty value is skipped, since Spiderfoot exports every key
/// option whether set or not, and so is a placeholder value, which a keys file reads as not set.
/// Blank lines and `#` comments are skipped too. A later line that
/// sets a slot replaces an earlier one, as in a keys file, except that a `HIBP_API_KEY` line fills
/// `HUNTSMAN_HIBP_KEY` only when no `HUNTSMAN_HIBP_KEY` or `sfp_haveibeenpwned:api_key` line sets
/// it, as [`secret_for_slot`](crate::provider_credentials::secret_for_slot) reads a keys file.
/// A placeholder line is skipped there too, where a keys file would read it as unsetting the slot.
/// **Pure.**
#[must_use]
pub fn plan(text: &str) -> Plan {
    let mut plan = Plan::default();
    for (index, raw) in text.lines().enumerate() {
        let number = index + 1;
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        match line.split_once('=') {
            Some((name, value)) if spiderfoot_option(name) => {
                spiderfoot_line(&mut plan, number, name, value.trim());
            }
            _ => keys_file_line(&mut plan, number, line),
        }
    }
    plan
}

/// A Spiderfoot module option's name: `sfp_module:option`.
fn spiderfoot_option(name: &str) -> bool {
    name.strip_prefix("sfp_")
        .and_then(|rest| rest.split_once(':'))
        .is_some_and(|(module, option)| {
            [module, option].iter().all(|part| {
                !part.is_empty()
                    && part
                        .bytes()
                        .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
            })
        })
}

fn spiderfoot_line(plan: &mut Plan, number: usize, name: &str, value: &str) {
    if value.is_empty() {
        return;
    }
    if name == SPIDERFOOT_WIGLE_OPTION {
        let pair = base64::decode_standard(value)
            .and_then(|bytes| String::from_utf8(bytes).ok())
            .and_then(|pair| {
                let (user, token) = pair.split_once(':')?;
                Some((Secret::new(user).ok()?, Secret::new(token).ok()?))
            });
        match pair {
            Some((user, token)) => {
                if !(too_long(plan, number, name, user.expose())
                    || too_long(plan, number, name, token.expose()))
                {
                    plan.save(WIGLE_USER_ENV, user);
                    plan.save(WIGLE_TOKEN_ENV, token);
                }
            }
            None => plan.refused.push(format!(
                "line {number}: {name} is not the base64 of an API name and token joined by ':'"
            )),
        }
        return;
    }
    let Some(&(_, slot)) = SPIDERFOOT_OPTIONS
        .iter()
        .find(|(option, _)| *option == name)
    else {
        if name
            .split_once(':')
            .is_some_and(|(_, option)| option.contains("api_key"))
        {
            plan.unused(name);
        } else {
            plan.settings += 1;
        }
        return;
    };
    // A placeholder reads as not set, as it does in a keys file.
    let Ok(secret) = Secret::new(value) else {
        return;
    };
    if !too_long(plan, number, name, secret.expose()) {
        plan.save(slot, secret);
    }
}

/// Refuses line `number` when `value` is longer than [`MAX_KEY_BYTES`], by `name` and never with
/// the value.
fn too_long(plan: &mut Plan, number: usize, name: &str, value: &str) -> bool {
    let long = value.len() > MAX_KEY_BYTES;
    if long {
        plan.refused.push(format!(
            "line {number}: {name} is longer than {MAX_KEY_BYTES} bytes"
        ));
    }
    long
}

fn keys_file_line(plan: &mut Plan, number: usize, line: &str) {
    let Ok(keys) = Keys::parse(line) else {
        plan.refused.push(format!(
            "line {number}: neither a Spiderfoot option (sfp_module:option=value) nor a keys-file line (NAME=value)"
        ));
        return;
    };
    // A placeholder reads as no slot at all; it is skipped as an empty Spiderfoot option is.
    for name in keys.slots() {
        let Some(secret) = keys.get(name) else {
            continue;
        };
        if let Some(&(slot, _)) = SLOT_FALLBACKS.iter().find(|(_, alias)| *alias == name) {
            if !too_long(plan, number, name, secret.expose()) {
                plan.save_fallback(slot, secret);
            }
            continue;
        }
        let slot = PROVIDERS
            .iter()
            .flat_map(|provider| provider.slots.iter().copied())
            .find(|slot| *slot == name);
        match slot {
            Some(slot) => {
                if !too_long(plan, number, name, secret.expose()) {
                    plan.save(slot, secret);
                }
            }
            None => plan.unused(name),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::environment::HIBP_API_KEY_ENV;

    const SHODAN: &str = "TEST_ONLY_IMPORT_SHODAN_51c2";

    fn saved(plan: &Plan) -> Vec<(&str, &str)> {
        plan.saves
            .iter()
            .map(|(slot, secret)| (*slot, secret.expose()))
            .collect()
    }

    #[test]
    fn a_spiderfoot_export_fills_the_slots_its_keys_belong_to() {
        // As Settings → Export API Keys writes it: sorted, every key option, set or not.
        let export = format!(
            "sfp_abstractapi:companyenrichment_api_key=\n\
             sfp_censys:censys_api_key_secret=TEST_ONLY_CENSYS_SECRET\n\
             sfp_censys:censys_api_key_uid=TEST_ONLY_CENSYS_ID\n\
             sfp_fullhunt:api_key=TEST_ONLY_UNUSED_7e1\n\
             sfp_greynoise:api_key=TEST_ONLY_GN_ENTERPRISE\n\
             sfp_greynoise_community:api_key=TEST_ONLY_GN_COMMUNITY\n\
             sfp_haveibeenpwned:api_key=TEST_ONLY_HIBP\n\
             sfp_shodan:api_key={SHODAN}\r\n\
             sfp_spider:maxpages=100\n\
             sfp_virustotal:api_key=\n"
        );
        let plan = super::plan(&export);
        assert!(plan.refused.is_empty(), "{:?}", plan.refused);
        assert_eq!(
            saved(&plan),
            [
                (CENSYS_SECRET_ENV, "TEST_ONLY_CENSYS_SECRET"),
                (CENSYS_ID_ENV, "TEST_ONLY_CENSYS_ID"),
                (GREYNOISE_KEY_ENV, "TEST_ONLY_GN_COMMUNITY"),
                (HUNTSMAN_HIBP_KEY_ENV, "TEST_ONLY_HIBP"),
                (SHODAN_KEY_ENV, SHODAN),
            ]
        );
        assert_eq!(plan.unused, ["sfp_fullhunt:api_key"]);
        assert_eq!(plan.settings, 1);
    }

    #[test]
    fn a_wigle_pair_is_decoded_into_its_name_and_token() {
        let encoded = base64::standard(b"TEST_ONLY_AID:TEST_ONLY_TOKEN=x");
        let plan = super::plan(&format!("{SPIDERFOOT_WIGLE_OPTION}={encoded}"));
        assert_eq!(
            saved(&plan),
            [
                (WIGLE_USER_ENV, "TEST_ONLY_AID"),
                (WIGLE_TOKEN_ENV, "TEST_ONLY_TOKEN=x")
            ]
        );
        for bad in [
            "not*base64",
            &base64::standard(b"no-colon"),
            &base64::standard(b":token"),
        ] {
            let plan = super::plan(&format!("\n{SPIDERFOOT_WIGLE_OPTION}={bad}"));
            assert!(plan.saves.is_empty(), "{bad}");
            assert_eq!(plan.refused.len(), 1, "{bad}");
            assert!(plan.refused[0].starts_with("line 2: sfp_wigle"), "{plan:?}");
            assert!(!plan.refused[0].contains(bad));
        }
    }

    #[test]
    fn a_keys_file_imports_its_catalogue_slots_and_names_the_rest() {
        let file = format!(
            "# mine\nexport {SHODAN_KEY_ENV}='{SHODAN}'\n{HIBP_API_KEY_ENV}=TEST_ONLY_OLD_HIBP\n\
             HUNTSMAN_NOT_A_SOURCE_KEY=TEST_ONLY_X\n{WHOXY_KEY_ENV}=changeme\n\
             {SHODAN_KEY_ENV}=TEST_ONLY_LATER\n"
        );
        let plan = super::plan(&file);
        assert!(plan.refused.is_empty(), "{:?}", plan.refused);
        assert_eq!(
            saved(&plan),
            [
                (SHODAN_KEY_ENV, "TEST_ONLY_LATER"),
                (HUNTSMAN_HIBP_KEY_ENV, "TEST_ONLY_OLD_HIBP"),
            ]
        );
        assert_eq!(plan.unused, ["HUNTSMAN_NOT_A_SOURCE_KEY"]);
    }

    #[test]
    fn a_hibp_api_key_line_fills_the_hibp_slot_only_when_no_line_names_the_slot() {
        let named = format!("{HUNTSMAN_HIBP_KEY_ENV}=TEST_ONLY_NAMED_HIBP");
        let alias = format!("{HIBP_API_KEY_ENV}=TEST_ONLY_ALIAS_HIBP");
        let spiderfoot = "sfp_haveibeenpwned:api_key=TEST_ONLY_NAMED_HIBP";
        for text in [
            format!("{named}\n{alias}\n"),
            format!("{alias}\n{named}\n"),
            format!("{spiderfoot}\n{alias}\n"),
            format!("{alias}\n{spiderfoot}\n"),
            format!("{alias}\n{named}\n{alias}\n"),
            format!("{alias}\n{spiderfoot}\n{alias}\n"),
        ] {
            let plan = super::plan(&text);
            assert!(plan.refused.is_empty(), "{:?}", plan.refused);
            assert_eq!(
                saved(&plan),
                [(HUNTSMAN_HIBP_KEY_ENV, "TEST_ONLY_NAMED_HIBP")],
                "{text}"
            );
            let keys = Keys::parse(&text.replace(spiderfoot, &named)).expect("keys");
            let read = crate::provider_credentials::secret_for_slot(&keys, HUNTSMAN_HIBP_KEY_ENV);
            assert_eq!(
                read.as_ref().map(Secret::expose),
                Some("TEST_ONLY_NAMED_HIBP"),
                "the import saves what the keys file reads as when no line is a placeholder: {text}"
            );
        }
        let plan = super::plan(&format!(
            "{alias}\n{HIBP_API_KEY_ENV}=TEST_ONLY_LATER_ALIAS\n"
        ));
        assert_eq!(
            saved(&plan),
            [(HUNTSMAN_HIBP_KEY_ENV, "TEST_ONLY_LATER_ALIAS")]
        );
        // A placeholder line is skipped, not read as unsetting the slot as a keys file reads it.
        let plan = super::plan(&format!(
            "{named}\n{HUNTSMAN_HIBP_KEY_ENV}=changeme\n{alias}\n"
        ));
        assert_eq!(
            saved(&plan),
            [(HUNTSMAN_HIBP_KEY_ENV, "TEST_ONLY_NAMED_HIBP")]
        );
    }

    #[test]
    fn an_unreadable_line_is_refused_by_number_without_its_value() {
        let long = "k".repeat(MAX_KEY_BYTES + 1);
        let plan = super::plan(&format!(
            "sfp_shodan:api_key={SHODAN}\nShodan key: TEST_ONLY_PASTED\nsfp_whoxy:api_key=changeme\n\
             sfp_hunter:api_key={long}\n"
        ));
        assert_eq!(plan.refused.len(), 2, "{:?}", plan.refused);
        assert!(plan.refused[0].starts_with("line 2: neither"));
        assert!(plan.refused[1].starts_with("line 4: sfp_hunter:api_key is longer"));
        // A keys-file line, a catalogue slot or the HIBP alias, is held to the same bound.
        for (line, name) in [
            (format!("{SHODAN_KEY_ENV}={long}"), SHODAN_KEY_ENV),
            (format!("{HIBP_API_KEY_ENV}={long}"), HIBP_API_KEY_ENV),
        ] {
            let plan = super::plan(&format!("\n{line}\n"));
            assert!(plan.saves.is_empty(), "{plan:?}");
            assert_eq!(plan.refused.len(), 1, "{:?}", plan.refused);
            assert!(
                plan.refused[0].starts_with(&format!("line 2: {name} is longer")),
                "{:?}",
                plan.refused
            );
            assert!(!plan.refused[0].contains(&long));
        }
        assert_eq!(
            saved(&plan),
            [(SHODAN_KEY_ENV, SHODAN)],
            "a placeholder reads as not set"
        );
        let text = plan.refused.join("\n");
        assert!(!text.contains("TEST_ONLY_PASTED") && !text.contains(&long));
        assert!(
            !format!("{plan:?}").contains(SHODAN),
            "a plan never shows a value"
        );
        // A decoded WiGLE pair is held to the same bound, and refused once for either part.
        for pair in [
            format!("TEST_ONLY_AID:{long}"),
            format!("{long}:TEST_ONLY_TOKEN"),
            format!("{long}:{long}"),
        ] {
            let encoded = base64::standard(pair.as_bytes());
            let plan = super::plan(&format!("\n{SPIDERFOOT_WIGLE_OPTION}={encoded}\n"));
            assert!(plan.saves.is_empty(), "{plan:?}");
            assert_eq!(plan.refused.len(), 1, "{:?}", plan.refused);
            assert!(
                plan.refused[0].starts_with("line 2: sfp_wigle:api_key_encoded is longer"),
                "{:?}",
                plan.refused
            );
            let text = plan.refused.join("\n");
            assert!(
                !text.contains(&long) && !text.contains(&encoded) && !text.contains("TEST_ONLY")
            );
        }
    }

    #[test]
    fn the_credential_manifest_lists_every_spiderfoot_option_with_its_slot() {
        let manifest = include_str!("../docs/PROVIDER_CREDENTIALS.md");
        for (option, slot) in SPIDERFOOT_OPTIONS {
            let row = format!("| `{option}` | `{slot}` |");
            assert!(manifest.contains(&row), "the manifest has no row {row}");
        }
        assert!(manifest.contains(&format!(
            "| `{SPIDERFOOT_WIGLE_OPTION}` | `{WIGLE_USER_ENV}` and `{WIGLE_TOKEN_ENV}`"
        )));
    }

    #[test]
    fn every_spiderfoot_option_fills_a_slot_of_the_catalogue_that_takes_it() {
        let catalogue: Vec<&str> = PROVIDERS
            .iter()
            .flat_map(|provider| provider.slots.iter().copied())
            .collect();
        for (option, slot) in SPIDERFOOT_OPTIONS {
            assert!(spiderfoot_option(option), "{option}");
            assert!(catalogue.contains(slot), "{option} -> {slot}");
        }
        assert!(spiderfoot_option(SPIDERFOOT_WIGLE_OPTION));
        for slot in [WIGLE_USER_ENV, WIGLE_TOKEN_ENV, HUNTSMAN_HIBP_KEY_ENV] {
            assert!(catalogue.contains(&slot), "{slot}");
        }
        for name in ["sfp_:api_key", "sfp_x:", "sfp_x", "sfp_x:a-b", "HUNTSMAN_A"] {
            assert!(!spiderfoot_option(name), "{name}");
        }
    }
}
