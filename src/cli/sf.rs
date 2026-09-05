//! `hse sf` — SpiderFoot 4.0's `sf.py` command line, on HSE's engine.
//!
//! The contract replicated here was read from SpiderFoot's own source at tag
//! `v4.0` (`sf.py`, `spiderfoot/helpers.py`, `modules/sfp__stor_stdout.py`,
//! `spiderfoot/db.py`): the flags and their help, the validation order and
//! error strings, the target-type detection rules in their precedence order
//! (including `sf.py`'s pre-quoting of the target), the tab/csv/json layouts
//! (the Type column is the human description, `Source` is padded to 30 and
//! `Type` to 45), `-M`/`-T` listings and the `-C` per-rule summary.
//!
//! What maps, and how — every mapping is visible in `-M` and `-T`:
//! - a use case selects HSE modules: `passive` → modules with no network
//!   contact (`Module::is_passive`), `footprint` → every module except the
//!   threat-intel category, `investigate` and `all` → every module;
//! - `-m` names HSE modules (validated against the registry, like `hse scan`);
//! - `-t` / `-F` filter printed rows by SpiderFoot type; with `-x`, `-t` also
//!   bounds the run to the seed itself (no expansion);
//! - HSE entity kinds print under their SpiderFoot type names where one
//!   exists and as `HSE_…` types where SpiderFoot has none.
//!
//! Two deliberate deviations from SpiderFoot's csv: its writer emits four
//! columns on every row while its header has three unless `-r` is given (here
//! rows and header always agree), and each cell is run through HSE's shared
//! spreadsheet formula guard so a provider-derived value cannot execute as a
//! formula when the csv is opened in a spreadsheet — safety over byte-for-byte
//! fidelity, the same guard the scan export uses.

use std::collections::BTreeSet;
use std::io::Write;

use crate::core::entity::{Entity, EntityKind};
use crate::core::error::{Error, Result};
use crate::core::module::ModuleCategory;
use crate::core::scan::{ScanOptions, Target, TargetKind};

/// Parsed `sf` arguments (mirrors the clap variant).
pub struct SfArgs {
    pub target: Option<String>,
    pub use_case: String,
    pub modules: Vec<String>,
    pub types: Vec<String>,
    pub format: String,
    pub no_header: bool,
    pub strip_newlines: bool,
    pub include_source: bool,
    pub max_len: Option<usize>,
    pub delimiter: Option<String>,
    pub filter_types: bool,
    pub show_types: Vec<String>,
    pub strict: bool,
    pub quiet: bool,
    pub list_modules: bool,
    pub list_types: bool,
    pub correlate: Option<String>,
    pub listen: Option<String>,
    pub version: bool,
}

// ── Target-type detection: sf.py + helpers.targetTypeFromString, in order ──

/// SpiderFoot type code of a seed string, after `sf.py`'s pre-quoting: a
/// value with a space, or one with no `.` that neither starts with `+` nor is
/// already quoted, is wrapped in quotes first — so `jsmith` is a USERNAME and
/// `John Smith` a HUMAN_NAME. `None` when no rule matches, as SpiderFoot.
#[must_use]
pub fn sf_target_type(raw: &str) -> Option<(&'static str, String)> {
    let mut target = raw.trim().to_string();
    if target.is_empty() {
        return None;
    }
    if target.contains(' ')
        || (!target.contains('.') && !target.starts_with('+') && !target.contains('"'))
    {
        target = format!("\"{target}\"");
    }
    let t = target.as_str();
    let lower = t.to_ascii_lowercase();
    let octets = |s: &str| {
        let parts: Vec<&str> = s.split('.').collect();
        parts.len() == 4
            && parts
                .iter()
                .all(|p| !p.is_empty() && p.len() <= 3 && p.bytes().all(|b| b.is_ascii_digit()))
    };
    let code = if octets(t) {
        "IP_ADDRESS"
    } else if t.split_once('/').is_some_and(|(ip, bits)| {
        octets(ip) && !bits.is_empty() && bits.bytes().all(|b| b.is_ascii_digit())
    }) {
        "NETBLOCK_OWNER"
    } else if t.contains('@') {
        "EMAILADDR"
    } else if t.len() > 1 && t.starts_with('+') && t[1..].bytes().all(|b| b.is_ascii_digit()) {
        "PHONE_NUMBER"
    } else if t.len() > 2
        && t.starts_with('"')
        && t.ends_with('"')
        && t[1..t.len() - 1].contains(char::is_whitespace)
    {
        "HUMAN_NAME"
    } else if t.len() > 2 && t.starts_with('"') && t.ends_with('"') {
        "USERNAME"
    } else if t.bytes().all(|b| b.is_ascii_digit()) {
        "BGP_AS_OWNER"
    } else if lower.bytes().all(|b| b.is_ascii_hexdigit() || b == b':') {
        "IPV6_ADDRESS"
    } else if lower.split_once("::/").is_some_and(|(a, b)| {
        a.bytes().all(|c| c.is_ascii_hexdigit() || c == b':')
            && b.bytes().all(|c| c.is_ascii_digit())
    }) {
        "NETBLOCKV6_OWNER"
    } else if is_internet_name(&lower) {
        "INTERNET_NAME"
    } else if is_bitcoin(t) {
        "BITCOIN_ADDRESS"
    } else {
        return None;
    };
    Some((code, target.trim_matches('"').to_string()))
}

fn is_internet_name(s: &str) -> bool {
    let labels: Vec<&str> = s.split('.').collect();
    labels.len() >= 2
        && labels.iter().all(|l| {
            !l.is_empty()
                && l.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
                && !l.starts_with('-')
                && !l.ends_with('-')
        })
}

fn is_bitcoin(s: &str) -> bool {
    let b58 = |c: char| c.is_ascii_alphanumeric() && !matches!(c, '0' | 'O' | 'I' | 'l');
    if let Some(rest) = s.strip_prefix("bc") {
        let ok = |c: char| {
            c.is_ascii_lowercase() && !matches!(c, 'b' | 'i' | 'o')
                || c.is_ascii_digit() && c != '1'
        };
        return rest.starts_with('0')
            && (rest.len() == 40 || rest.len() == 60)
            && rest[1..].chars().all(ok)
            || rest.starts_with('1')
                && (9..=88).contains(&rest.len())
                && rest[1..].chars().all(ok);
    }
    (s.starts_with('1') || s.starts_with('3')) && (26..=36).contains(&s.len()) && s.chars().all(b58)
}

/// The HSE seed kind a SpiderFoot target type runs as.
#[must_use]
pub fn kind_for_sf_target(code: &str) -> Option<TargetKind> {
    Some(match code {
        "IP_ADDRESS" | "IPV6_ADDRESS" => TargetKind::IpAddress,
        "NETBLOCK_OWNER" | "NETBLOCKV6_OWNER" => TargetKind::Cidr,
        "EMAILADDR" => TargetKind::Email,
        "PHONE_NUMBER" => TargetKind::Phone,
        "HUMAN_NAME" => TargetKind::FullName,
        "USERNAME" => TargetKind::Username,
        "BGP_AS_OWNER" => TargetKind::Asn,
        "INTERNET_NAME" => TargetKind::Domain,
        "BITCOIN_ADDRESS" => TargetKind::CryptoAddress,
        _ => return None,
    })
}

// ── Type names: HSE kinds ↔ SpiderFoot event types ────────────────────────

/// `(SpiderFoot type code, its human description)` for an HSE entity. Where
/// SpiderFoot has no type, an `HSE_…` code with its own description.
#[must_use]
pub fn sf_type_of(e: &Entity, seed_domain: Option<&str>) -> (&'static str, &'static str) {
    match &e.kind {
        EntityKind::Email => ("EMAILADDR", "Email Address"),
        EntityKind::Person => ("HUMAN_NAME", "Human Name"),
        EntityKind::Phone => ("PHONE_NUMBER", "Phone Number"),
        EntityKind::Username => ("USERNAME", "Username"),
        EntityKind::Credential | EntityKind::Password => {
            ("PASSWORD_COMPROMISED", "Compromised Password")
        }
        EntityKind::ApiKey => ("HSE_API_KEY", "API Key (HSE)"),
        EntityKind::IpAddress => {
            if e.value.contains(':') {
                ("IPV6_ADDRESS", "IPv6 Address")
            } else {
                ("IP_ADDRESS", "IP Address")
            }
        }
        EntityKind::Domain => {
            if e.value.matches('.').count() >= 2 {
                ("INTERNET_NAME", "Internet Name")
            } else {
                ("DOMAIN_NAME", "Domain Name")
            }
        }
        EntityKind::Url => {
            let internal = seed_domain.is_some_and(|d| {
                url::Url::parse(&e.value)
                    .ok()
                    .and_then(|u| u.host_str().map(str::to_ascii_lowercase))
                    .is_some_and(|h| h == d || h.ends_with(&format!(".{d}")))
            });
            if internal {
                ("LINKED_URL_INTERNAL", "Linked URL - Internal")
            } else {
                ("LINKED_URL_EXTERNAL", "Linked URL - External")
            }
        }
        EntityKind::Asn => ("BGP_AS_OWNER", "BGP AS Ownership"),
        EntityKind::Cidr => ("NETBLOCK_OWNER", "Netblock Ownership"),
        EntityKind::Address => ("PHYSICAL_ADDRESS", "Physical Address"),
        EntityKind::Coordinates => ("PHYSICAL_COORDINATES", "Physical Coordinates"),
        EntityKind::Organisation => ("COMPANY_NAME", "Company Name"),
        EntityKind::AbnAcn => (
            "HSE_COMPANY_REGISTRATION",
            "Company Registration Number (HSE)",
        ),
        EntityKind::MacAddress => ("HSE_MAC_ADDRESS", "MAC Address (HSE)"),
        EntityKind::DeviceId => ("HSE_DEVICE_ID", "Device Identifier (HSE)"),
        EntityKind::Ssid => ("HSE_WIFI_SSID", "Wi-Fi Network Name (HSE)"),
        EntityKind::TrackingId => ("WEB_ANALYTICS_ID", "Web Analytics"),
        EntityKind::CryptoAddress => {
            if e.value.starts_with("0x") {
                ("ETHEREUM_ADDRESS", "Ethereum Address")
            } else {
                ("BITCOIN_ADDRESS", "Bitcoin Address")
            }
        }
        EntityKind::Other(_) => ("HSE_OTHER", "Other (HSE)"),
    }
}

/// The `-T` table: every type this front end can print, with its description
/// and the HSE kind(s) behind it.
#[must_use]
pub fn type_table() -> Vec<(&'static str, &'static str, &'static str)> {
    vec![
        ("BGP_AS_OWNER", "BGP AS Ownership", "asn"),
        ("BITCOIN_ADDRESS", "Bitcoin Address", "crypto_address"),
        ("COMPANY_NAME", "Company Name", "organisation"),
        ("DOMAIN_NAME", "Domain Name", "domain (registrable)"),
        ("EMAILADDR", "Email Address", "email"),
        (
            "ETHEREUM_ADDRESS",
            "Ethereum Address",
            "crypto_address (0x…)",
        ),
        ("HSE_API_KEY", "API Key (HSE)", "api_key"),
        (
            "HSE_COMPANY_REGISTRATION",
            "Company Registration Number (HSE)",
            "abn_acn",
        ),
        ("HSE_DEVICE_ID", "Device Identifier (HSE)", "device_id"),
        ("HSE_MAC_ADDRESS", "MAC Address (HSE)", "mac_address"),
        ("HSE_OTHER", "Other (HSE)", "other"),
        ("HSE_WIFI_SSID", "Wi-Fi Network Name (HSE)", "ssid"),
        ("HUMAN_NAME", "Human Name", "person"),
        ("INTERNET_NAME", "Internet Name", "domain (host)"),
        ("IPV6_ADDRESS", "IPv6 Address", "ip_address"),
        ("IP_ADDRESS", "IP Address", "ip_address"),
        ("LINKED_URL_EXTERNAL", "Linked URL - External", "url"),
        (
            "LINKED_URL_INTERNAL",
            "Linked URL - Internal",
            "url (under the seed's domain)",
        ),
        ("NETBLOCK_OWNER", "Netblock Ownership", "cidr"),
        (
            "PASSWORD_COMPROMISED",
            "Compromised Password",
            "credential, password",
        ),
        ("PHONE_NUMBER", "Phone Number", "phone"),
        ("PHYSICAL_ADDRESS", "Physical Address", "address"),
        (
            "PHYSICAL_COORDINATES",
            "Physical Coordinates",
            "coordinates",
        ),
        ("USERNAME", "Username", "username"),
        ("WEB_ANALYTICS_ID", "Web Analytics", "tracking_id"),
    ]
}

fn known_type(code: &str) -> bool {
    type_table()
        .iter()
        .any(|(c, _, _)| c.eq_ignore_ascii_case(code))
}

// ── Use cases → HSE modules ───────────────────────────────────────────────

/// The use cases an HSE module belongs to, in SpiderFoot's vocabulary.
#[must_use]
pub fn use_cases_of(m: &dyn crate::core::module::Module) -> Vec<&'static str> {
    let mut out = vec!["Investigate"];
    if m.category() != ModuleCategory::Threat {
        out.push("Footprint");
    }
    if m.is_passive() {
        out.push("Passive");
    }
    out.sort_unstable();
    out
}

fn modules_for_use_case(case: &str) -> Result<Option<Vec<String>>> {
    let wanted = match case.to_ascii_lowercase().as_str() {
        "all" => return Ok(None),
        "footprint" => "Footprint",
        "investigate" => "Investigate",
        "passive" => "Passive",
        other => {
            return Err(Error::Other(format!(
                "argument -u: invalid choice: '{other}' (choose from 'all', 'footprint', 'investigate', 'passive')"
            )));
        }
    };
    Ok(Some(
        crate::modules::registry()
            .iter()
            .filter(|m| use_cases_of(m.as_ref()).contains(&wanted))
            .map(|m| m.name().to_string())
            .collect(),
    ))
}

// ── Output ────────────────────────────────────────────────────────────────

struct Row {
    module: String,
    type_descr: &'static str,
    type_code: &'static str,
    source_data: String,
    data: String,
    generated: u64,
}

fn prep(s: &str, strip_newlines: bool, max_len: Option<usize>) -> String {
    let mut v = if strip_newlines {
        s.replace('\n', " ").replace('\r', "")
    } else {
        s.to_string()
    };
    if let Some(n) = max_len {
        v = v.chars().take(n).collect();
    }
    v
}

fn print_rows(rows: &[Row], a: &SfArgs) -> Result<()> {
    let out = std::io::stdout();
    let mut w = out.lock();
    write_rows(&mut w, rows, a)
}

/// The body of [`print_rows`], generic over the sink so the row formatting —
/// especially the csv quoting — can be exercised against a buffer in tests.
fn write_rows<W: Write>(w: &mut W, rows: &[Row], a: &SfArgs) -> Result<()> {
    match a.format.as_str() {
        "tab" => {
            if !a.no_header {
                if a.include_source {
                    writeln!(w, "{:30}\t{:45}\tSource Data\tData", "Source", "Type")?;
                } else {
                    writeln!(w, "{:30}\t{:45}\tData", "Source", "Type")?;
                }
            }
            for r in rows {
                let data = prep(&r.data, a.strip_newlines, a.max_len);
                if a.include_source {
                    let src = prep(&r.source_data, a.strip_newlines, a.max_len);
                    writeln!(w, "{:30}\t{:45}\t{}\t{}", r.module, r.type_descr, src, data)?;
                } else {
                    writeln!(w, "{:30}\t{:45}\t{}", r.module, r.type_descr, data)?;
                }
            }
        }
        "csv" => {
            // RFC-4180 quoting via `csv::Writer` (like `hse ingest`), so a value
            // holding the delimiter, a quote or a newline stays one field instead
            // of corrupting the row — the same reason SpiderFoot writes csv with
            // Python's `csv.writer`. Each cell is also run through the shared
            // spreadsheet formula guard (as the scan export is): a
            // provider-derived value starting with `=`/`+`/`-`/`@` would
            // otherwise execute as a formula when the operator opens the csv in
            // Excel or LibreOffice. Safety wins over byte-for-byte SpiderFoot
            // fidelity here — the only visible effect is a leading `'` on a cell
            // that would have been a live formula. The delimiter is validated to
            // a single byte in `cmd_sf`.
            use crate::app::export::formula_guard;
            let delim = a.delimiter.as_deref().map_or(b',', |d| d.as_bytes()[0]);
            // Build into a buffer (as `hse ingest` does) so csv errors map to
            // one place; the finished bytes then go to stdout as an io write.
            let csv_err = |e: csv::Error| Error::Other(format!("sf: csv write failed: {e}"));
            let mut wtr = csv::WriterBuilder::new()
                .delimiter(delim)
                .terminator(csv::Terminator::Any(b'\n'))
                .from_writer(Vec::new());
            if !a.no_header {
                if a.include_source {
                    wtr.write_record(["Source", "Type", "Source Data", "Data"])
                        .map_err(csv_err)?;
                } else {
                    wtr.write_record(["Source", "Type", "Data"])
                        .map_err(csv_err)?;
                }
            }
            for r in rows {
                let data = prep(&r.data, a.strip_newlines, a.max_len);
                let module = formula_guard(&r.module);
                let descr = formula_guard(r.type_descr);
                let data_g = formula_guard(&data);
                if a.include_source {
                    let src = prep(&r.source_data, a.strip_newlines, a.max_len);
                    let src_g = formula_guard(&src);
                    wtr.write_record([
                        module.as_ref(),
                        descr.as_ref(),
                        src_g.as_ref(),
                        data_g.as_ref(),
                    ])
                    .map_err(csv_err)?;
                } else {
                    wtr.write_record([module.as_ref(), descr.as_ref(), data_g.as_ref()])
                        .map_err(csv_err)?;
                }
            }
            let bytes = wtr.into_inner().map_err(csv::IntoInnerError::into_error)?;
            w.write_all(&bytes)?;
        }
        "json" => {
            write!(w, "[")?;
            for (i, r) in rows.iter().enumerate() {
                if i > 0 {
                    writeln!(w, ",")?;
                }
                // Apply `-n` (strip newlines) and `-S` (max length) here too, so
                // the flags behave the same across tab/csv/json.
                let data = prep(&r.data, a.strip_newlines, a.max_len);
                let source = prep(&r.source_data, a.strip_newlines, a.max_len);
                write!(
                    w,
                    "{}",
                    serde_json::json!({
                        "generated": r.generated,
                        "type": r.type_descr,
                        "event_type": r.type_code,
                        "data": data,
                        "module": r.module,
                        "source": source,
                    })
                )?;
            }
            writeln!(w, "]")?;
        }
        _ => unreachable!("validated in cmd_sf"),
    }
    Ok(())
}

fn info(quiet: bool, msg: &str) {
    if !quiet {
        eprintln!("[INFO] {msg}");
    }
}

pub async fn cmd_sf(a: SfArgs) -> Result<()> {
    // sf.py's evaluation order: -V, then -C, -M, -T, -l, else scan.
    if a.version {
        println!(
            "HSE {} — SpiderFoot 4.0.0-compatible command line.",
            crate::VERSION
        );
        return Ok(());
    }
    if let Some(sid) = &a.correlate {
        return correlate(sid, a.quiet);
    }
    if a.list_modules {
        info(a.quiet, "Modules available:");
        let mut mods: Vec<_> = crate::modules::registry();
        mods.sort_by(|x, y| x.name().cmp(y.name()));
        for m in mods {
            println!(
                "{:25} {} [{}]",
                m.name(),
                m.description(),
                use_cases_of(m.as_ref()).join(", ")
            );
        }
        return Ok(());
    }
    if a.list_types {
        info(a.quiet, "Types available:");
        for (code, descr, kinds) in type_table() {
            println!("{code:45} {descr} (hse: {kinds})");
        }
        return Ok(());
    }
    if let Some(listen) = &a.listen {
        let Some((ip, port)) = listen.split_once(':') else {
            return Err(Error::Other("Invalid ip:port format.".into()));
        };
        if ip.is_empty() || port.parse::<u16>().is_err() {
            return Err(Error::Other("Invalid ip:port format.".into()));
        }
        return super::serve::cmd_serve(listen.clone(), true, None, false).await;
    }

    // Scan mode — sf.py's validations, in its order, with its messages.
    let Some(raw_target) = a.target.as_deref() else {
        return Err(Error::Other(
            "You must specify a target when running in scan mode. Try --help for guidance.".into(),
        ));
    };
    if a.strict && a.types.is_empty() {
        return Err(Error::Other(
            "-x can only be used with -t. Use --help for guidance.".into(),
        ));
    }
    if a.strict && !a.modules.is_empty() {
        return Err(Error::Other(
            "-x can only be used with -t and not with -m. Use --help for guidance.".into(),
        ));
    }
    if !matches!(a.format.as_str(), "tab" | "csv" | "json") {
        return Err(Error::Other(format!(
            "argument -o: invalid choice: '{}' (choose from 'tab', 'csv', 'json')",
            a.format
        )));
    }
    if a.include_source && a.format == "json" {
        return Err(Error::Other(
            "-r can only be used when your output format is tab or csv.".into(),
        ));
    }
    if a.no_header && a.format == "json" {
        return Err(Error::Other(
            "-H can only be used when your output format is tab or csv.".into(),
        ));
    }
    if a.delimiter.is_some() && a.format != "csv" {
        return Err(Error::Other(
            "-D can only be used when using the csv output format.".into(),
        ));
    }
    if let Some(d) = &a.delimiter
        && d.len() != 1
    {
        // The csv writer takes a single-byte delimiter (as Python's
        // `csv.writer` takes a 1-character string); reject anything else
        // rather than silently using only its first byte.
        return Err(Error::Other(
            "-D delimiter must be a single character.".into(),
        ));
    }
    let Some((sf_code, target_value)) = sf_target_type(raw_target) else {
        return Err(Error::Other(format!(
            "Could not determine target type. Invalid target: {raw_target}"
        )));
    };
    let Some(kind) = kind_for_sf_target(sf_code) else {
        return Err(Error::Other(format!(
            "Could not determine target type. Invalid target: {raw_target}"
        )));
    };
    if a.filter_types && a.types.is_empty() {
        return Err(Error::Other(
            "You can only use -f with -t. Use --help for guidance.".into(),
        ));
    }
    for t in a.types.iter().chain(a.show_types.iter()) {
        if !known_type(t) {
            return Err(Error::Other(format!(
                "Unknown type {t:?}. Use -T to list the types available."
            )));
        }
    }

    // Module selection: -t alone selects everything (HSE dispatches by seed
    // kind; type filtering is applied to the output), -m replaces, -u unions.
    let mut selected: Option<BTreeSet<String>> = None;
    if !a.modules.is_empty() {
        let unknown = crate::modules::unknown_module_names(&Some(a.modules.clone()), &[]);
        if !unknown.is_empty() {
            return Err(Error::Other(format!(
                "Invalid module(s): {}. Use -M to list the modules available.",
                unknown.join(", ")
            )));
        }
        selected = Some(a.modules.iter().cloned().collect());
    }
    if let Some(by_case) = modules_for_use_case(&a.use_case)? {
        let set = selected.get_or_insert_with(BTreeSet::new);
        set.extend(by_case);
    }
    if a.modules.is_empty() && a.types.is_empty() && a.use_case.eq_ignore_ascii_case("all") {
        info(
            a.quiet,
            "You didn't specify any modules, types or use case, so all modules will be enabled.",
        );
    }
    if let Some(set) = &selected
        && set.is_empty()
    {
        return Err(Error::Other(
            "Based on your criteria, no modules were enabled.".into(),
        ));
    }

    let options = ScanOptions {
        modules: selected.as_ref().map(|s| s.iter().cloned().collect()),
        passive_only: a.use_case.eq_ignore_ascii_case("passive"),
        depth: if a.strict {
            0
        } else {
            ScanOptions::default().depth
        },
        ..ScanOptions::default()
    };
    if let Some(set) = &selected {
        info(
            a.quiet,
            &format!(
                "Modules enabled ({}): {}",
                set.len(),
                set.iter().cloned().collect::<Vec<_>>().join(",")
            ),
        );
    }
    let target = Target::new(kind, target_value.clone());
    let seed_domain = match kind {
        TargetKind::Domain => Some(target.value.to_ascii_lowercase()),
        TargetKind::Email => target.value.rsplit('@').next().map(str::to_ascii_lowercase),
        _ => None,
    };
    let run = crate::app::scan_run::run_seed(target, options).await?;
    let status = match run.scan.status {
        crate::core::scan::ScanStatus::Complete => "FINISHED",
        crate::core::scan::ScanStatus::Aborted => "ABORTED",
        _ => "ERROR-FAILED",
    };
    let entities = run.store.entities_for_scan(&run.scan_id)?;

    // Output filter: -F (show only), and -t when -f or -x asked for it.
    let mut only: BTreeSet<String> = a
        .show_types
        .iter()
        .map(|t| t.to_ascii_uppercase())
        .collect();
    if a.filter_types || a.strict {
        only.extend(a.types.iter().map(|t| t.to_ascii_uppercase()));
    }
    let rows: Vec<Row> = entities
        .iter()
        .filter_map(|e| {
            let (code, descr) = sf_type_of(e, seed_domain.as_deref());
            if !only.is_empty() && !only.contains(code) {
                return None;
            }
            Some(Row {
                module: e
                    .evidence
                    .first()
                    .map_or_else(|| "hse".to_string(), |ev| ev.source.clone()),
                type_descr: descr,
                type_code: code,
                source_data: target_value.clone(),
                data: e.value.clone(),
                generated: e.observed_at,
            })
        })
        .collect();
    print_rows(&rows, &a)?;
    info(
        a.quiet,
        &format!(
            "Scan completed with status {status} ({} rows; scan ID {})",
            rows.len(),
            run.scan_id
        ),
    );
    Ok(())
}

/// `-C`: SpiderFoot runs its correlation rules over a stored scan and reports
/// each rule's result count. HSE's findings are the correlator's output,
/// stored with the scan; report them per rule id the same way.
fn correlate(raw: &str, quiet: bool) -> Result<()> {
    let (sid, per_rule) = crate::app::scan_run::rule_result_counts(raw)?;
    info(
        quiet,
        &format!(
            "Running {} correlation rules against scan, {sid}.",
            per_rule.len()
        ),
    );
    for (rule, n) in per_rule {
        println!("Rule {rule} returned {n} results.");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn target_detection_follows_spiderfoots_rules_and_pre_quoting() {
        // helpers.targetTypeFromString order, after sf.py's quoting of bare words.
        let t = sf_target_type;
        assert_eq!(t("192.0.2.1"), Some(("IP_ADDRESS", "192.0.2.1".into())));
        assert_eq!(
            t("192.0.2.0/24"),
            Some(("NETBLOCK_OWNER", "192.0.2.0/24".into()))
        );
        assert_eq!(
            t("jane@example.com"),
            Some(("EMAILADDR", "jane@example.com".into()))
        );
        assert_eq!(
            t("+61412345678"),
            Some(("PHONE_NUMBER", "+61412345678".into()))
        );
        assert_eq!(t("John Smith"), Some(("HUMAN_NAME", "John Smith".into())));
        assert_eq!(
            t("\"John Smith\""),
            Some(("HUMAN_NAME", "John Smith".into()))
        );
        assert_eq!(
            t("jsmith"),
            Some(("USERNAME", "jsmith".into())),
            "a bare word is quoted, then USERNAME"
        );
        assert_eq!(
            t("12345"),
            Some(("USERNAME", "12345".into())),
            "sf.py quotes a bare number before detection"
        );
        assert_eq!(
            t("example.com"),
            Some(("INTERNET_NAME", "example.com".into()))
        );
        assert_eq!(
            t("sub.example.co.uk"),
            Some(("INTERNET_NAME", "sub.example.co.uk".into()))
        );
        assert_eq!(t(""), None);
        // A dotted, unquoted string that is no valid host (trailing `!`) matches
        // no rule — sf.py does not quote it (it has a `.`), so it stays None. A
        // string with a space would instead be quoted into a HUMAN_NAME, so the
        // unclassifiable case must itself be space-free.
        assert_eq!(t("not.a.valid.target!"), None);
    }

    #[test]
    fn every_sf_target_type_runs_as_an_hse_kind() {
        for code in [
            "IP_ADDRESS",
            "NETBLOCK_OWNER",
            "EMAILADDR",
            "PHONE_NUMBER",
            "HUMAN_NAME",
            "USERNAME",
            "BGP_AS_OWNER",
            "IPV6_ADDRESS",
            "NETBLOCKV6_OWNER",
            "INTERNET_NAME",
            "BITCOIN_ADDRESS",
        ] {
            assert!(
                kind_for_sf_target(code).is_some(),
                "{code} must map to a seed kind"
            );
        }
    }

    #[test]
    fn type_table_is_sorted_unique_and_covers_every_entity_kind() {
        let table = type_table();
        let codes: Vec<&str> = table.iter().map(|(c, _, _)| *c).collect();
        let mut sorted = codes.clone();
        sorted.sort_unstable();
        sorted.dedup();
        assert_eq!(
            codes, sorted,
            "-T prints types sorted by name, as sf.py does"
        );
        let mk = |k: EntityKind, v: &str| Entity::new(k, v, 0.5, "s");
        for (kind, value) in [
            (EntityKind::Person, "Jane Doe"),
            (EntityKind::Email, "a@b.c"),
            (EntityKind::Phone, "+61400000000"),
            (EntityKind::Username, "jane"),
            (EntityKind::Credential, "x"),
            (EntityKind::ApiKey, "k"),
            (EntityKind::Password, "p"),
            (EntityKind::IpAddress, "203.0.113.7"),
            (EntityKind::IpAddress, "2001:db8::1"),
            (EntityKind::Domain, "example.com"),
            (EntityKind::Domain, "www.example.com"),
            (EntityKind::Url, "https://x.example/"),
            (EntityKind::Asn, "AS13335"),
            (EntityKind::Cidr, "203.0.113.0/24"),
            (EntityKind::Address, "1 Main St"),
            (EntityKind::Coordinates, "-33.8,151.2"),
            (EntityKind::Organisation, "Acme"),
            (EntityKind::AbnAcn, "51824753556"),
            (EntityKind::MacAddress, "aa:bb:cc:dd:ee:ff"),
            (EntityKind::DeviceId, "d"),
            (EntityKind::Ssid, "wifi"),
            (EntityKind::TrackingId, "UA-1"),
            (
                EntityKind::CryptoAddress,
                "1BoatSLRHtKNngkdXEeobR76b53LETtpyT",
            ),
            (EntityKind::CryptoAddress, "0xabc"),
            (EntityKind::Other("x".into()), "o"),
        ] {
            let (code, _) = sf_type_of(&mk(kind, value), Some("example.com"));
            assert!(
                known_type(code),
                "{code} for {value} must be in the -T table"
            );
        }
    }

    #[test]
    fn a_url_under_the_seeds_domain_is_internal() {
        let e = Entity::new(EntityKind::Url, "https://www.example.com/a", 0.5, "s");
        assert_eq!(sf_type_of(&e, Some("example.com")).0, "LINKED_URL_INTERNAL");
        assert_eq!(sf_type_of(&e, Some("other.org")).0, "LINKED_URL_EXTERNAL");
        assert_eq!(sf_type_of(&e, None).0, "LINKED_URL_EXTERNAL");
    }

    #[test]
    fn use_cases_select_modules_the_documented_way() {
        let all = modules_for_use_case("all").unwrap();
        assert!(all.is_none(), "`all` places no allowlist");
        let passive = modules_for_use_case("passive").unwrap().unwrap();
        let footprint = modules_for_use_case("footprint").unwrap().unwrap();
        let investigate = modules_for_use_case("investigate").unwrap().unwrap();
        let registry = crate::modules::registry();
        assert_eq!(
            investigate.len(),
            registry.len(),
            "investigate is every module"
        );
        assert!(
            footprint.len() < investigate.len(),
            "footprint drops the threat-intel category"
        );
        assert!(!passive.is_empty() && passive.len() < footprint.len());
        for name in &passive {
            let m = registry.iter().find(|m| m.name() == name).unwrap();
            assert!(
                m.is_passive(),
                "{name} in the passive use case must be passive"
            );
        }
        assert!(modules_for_use_case("bogus").is_err());
    }

    fn sf_args(format: &str, delimiter: Option<&str>) -> SfArgs {
        SfArgs {
            target: None,
            use_case: "all".into(),
            modules: vec![],
            types: vec![],
            format: format.into(),
            no_header: false,
            strip_newlines: false,
            include_source: false,
            max_len: None,
            delimiter: delimiter.map(str::to_string),
            filter_types: false,
            show_types: vec![],
            strict: false,
            quiet: true,
            list_modules: false,
            list_types: false,
            correlate: None,
            listen: None,
            version: false,
        }
    }

    fn row(module: &str, descr: &'static str, code: &'static str, data: &str) -> Row {
        Row {
            module: module.into(),
            type_descr: descr,
            type_code: code,
            source_data: "seed".into(),
            data: data.into(),
            generated: 0,
        }
    }

    #[test]
    fn csv_output_rfc4180_quotes_fields_holding_the_delimiter_or_a_quote() {
        // A raw string join would corrupt these rows: the coordinates carry the
        // comma delimiter, the name carries embedded quotes. RFC-4180 quoting
        // keeps each row exactly three fields.
        let rows = vec![
            row(
                "corpus_a",
                "Physical Coordinates",
                "PHYSICAL_COORDINATES",
                "-33.8,151.2",
            ),
            row("corpus_b", "Human Name", "HUMAN_NAME", "Ab \"Ace\" Cee"),
        ];
        let mut buf = Vec::new();
        write_rows(&mut buf, &rows, &sf_args("csv", None)).unwrap();
        let out = String::from_utf8(buf).unwrap();
        // The coordinates start with `-`, so the formula guard prepends `'`
        // before the field is quoted for the embedded comma.
        assert_eq!(
            out,
            "Source,Type,Data\n\
             corpus_a,Physical Coordinates,\"'-33.8,151.2\"\n\
             corpus_b,Human Name,\"Ab \"\"Ace\"\" Cee\"\n"
        );
    }

    #[test]
    fn csv_output_defangs_a_spreadsheet_formula_cell() {
        // A provider-derived value that would execute as a formula in a
        // spreadsheet is guarded with a leading `'` before it reaches the file.
        let rows = vec![row("m", "Other (HSE)", "HSE_OTHER", "=SUM(A1:A9)")];
        let mut buf = Vec::new();
        write_rows(&mut buf, &rows, &sf_args("csv", None)).unwrap();
        let out = String::from_utf8(buf).unwrap();
        assert_eq!(out, "Source,Type,Data\nm,Other (HSE),'=SUM(A1:A9)\n");
    }

    #[test]
    fn csv_output_honours_a_single_character_delimiter() {
        let rows = vec![row("m", "Email Address", "EMAILADDR", "a@b.c")];
        let mut buf = Vec::new();
        write_rows(&mut buf, &rows, &sf_args("csv", Some("|"))).unwrap();
        let out = String::from_utf8(buf).unwrap();
        assert_eq!(out, "Source|Type|Data\nm|Email Address|a@b.c\n");
    }
}
