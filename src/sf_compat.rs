//! Partial `SpiderFoot` 4.0 command-line compatibility over rebuilt Huntsman paths.
//!
//! The compatibility layer is deliberately narrow: it implements the legacy target
//! classifier, `-M` / `-T` / `-V`, use-case validation, tab/csv/json rows, type
//! filtering, and single-target execution for the people/email/username/phone
//! front-ends that are actually rebuilt. Unsupported target classes fail explicitly.

use std::fmt::Write as _;

use serde::Serialize;

use crate::email_cli::{self, EmailRun};
use crate::entity::{Entity, EntityKind};
use crate::error::Error;
use crate::http::Transport;
use crate::module::reachable_modules;
use crate::people_cli::{self, PeopleRun};
use crate::phone_cli::{self, PhoneRun};
use crate::username_cli::{self, UsernameRun};

pub const SF_USAGE: &str = "usage: huntsman-recon sf [-M|-T|-V] | -s TARGET [-u all|footprint|investigate|passive] [-o tab|csv|json] [-t TYPE[,TYPE...]] [-r] [-q]";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SfMode {
    Scan,
    ListModules,
    ListTypes,
    Version,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SfArgs {
    pub target: Option<String>,
    pub use_case: String,
    pub format: String,
    pub types: Vec<String>,
    pub include_source: bool,
    pub quiet: bool,
    pub mode: SfMode,
}

impl Default for SfArgs {
    fn default() -> Self {
        Self {
            target: None,
            use_case: "all".into(),
            format: "tab".into(),
            types: Vec::new(),
            include_source: false,
            quiet: false,
            mode: SfMode::Scan,
        }
    }
}

impl SfArgs {
    /// Parse the supported SpiderFoot-compatible flag subset.
    ///
    /// # Errors
    /// Unknown flags, missing values, incompatible listing/scan modes, invalid
    /// use cases, output formats, or event types.
    pub fn parse(args: &[String]) -> Result<Self, Error> {
        let mut parsed = Self::default();
        let mut index = 0;
        while index < args.len() {
            match args[index].as_str() {
                "-s" | "--target" => {
                    parsed.target = Some(value(args, index, "-s/--target")?.to_owned());
                    index += 2;
                }
                "-u" | "--use-case" => {
                    parsed.use_case = value(args, index, "-u/--use-case")?.to_ascii_lowercase();
                    index += 2;
                }
                "-o" | "--output" | "--format" => {
                    parsed.format = value(args, index, "-o/--output")?.to_ascii_lowercase();
                    index += 2;
                }
                "-t" | "-F" | "--types" => {
                    parsed.types.extend(
                        value(args, index, "-t/-F")?
                            .split(',')
                            .filter(|item| !item.is_empty())
                            .map(str::to_ascii_uppercase),
                    );
                    index += 2;
                }
                "-r" | "--include-source" => {
                    parsed.include_source = true;
                    index += 1;
                }
                "-q" | "--quiet" => {
                    parsed.quiet = true;
                    index += 1;
                }
                "-M" | "--list-modules" => {
                    set_mode(&mut parsed, SfMode::ListModules)?;
                    index += 1;
                }
                "-T" | "--list-types" => {
                    set_mode(&mut parsed, SfMode::ListTypes)?;
                    index += 1;
                }
                "-V" | "--sf-version" => {
                    set_mode(&mut parsed, SfMode::Version)?;
                    index += 1;
                }
                flag if flag.starts_with('-') => {
                    return Err(Error::Invalid(format!(
                        "unsupported sf option {flag}; supported subset: {SF_USAGE}"
                    )));
                }
                value => {
                    return Err(Error::Invalid(format!(
                        "unexpected sf argument {value:?}; target must follow -s"
                    )));
                }
            }
        }

        validate_use_case(&parsed.use_case)?;
        if !matches!(parsed.format.as_str(), "tab" | "csv" | "json") {
            return Err(Error::Invalid(format!(
                "invalid sf output format {:?}; choose tab, csv, or json",
                parsed.format
            )));
        }
        for kind in &parsed.types {
            if !known_type(kind) {
                return Err(Error::Invalid(format!("unknown sf event type {kind}")));
            }
        }

        if parsed.mode != SfMode::Scan && parsed.target.is_some() {
            return Err(Error::Invalid(
                "sf listing/version modes do not accept -s".into(),
            ));
        }
        if parsed.mode == SfMode::Scan && parsed.target.is_none() {
            return Err(Error::Invalid("sf needs -s TARGET, -M, -T, or -V".into()));
        }
        Ok(parsed)
    }
}

fn set_mode(args: &mut SfArgs, mode: SfMode) -> Result<(), Error> {
    if args.mode != SfMode::Scan {
        return Err(Error::Invalid(
            "sf accepts only one of -M, -T, or -V at a time".into(),
        ));
    }
    args.mode = mode;
    Ok(())
}

fn value<'a>(args: &'a [String], index: usize, flag: &str) -> Result<&'a str, Error> {
    args.get(index + 1)
        .map(String::as_str)
        .filter(|value| !value.starts_with('-') || *value == "-")
        .ok_or_else(|| Error::Invalid(format!("{flag} needs a value")))
}

fn validate_use_case(value: &str) -> Result<(), Error> {
    if matches!(value, "all" | "footprint" | "investigate" | "passive") {
        Ok(())
    } else {
        Err(Error::Invalid(format!(
            "argument -u: invalid choice: '{value}' (choose from 'all', 'footprint', 'investigate', 'passive')"
        )))
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SfAction {
    Text(String),
    Scan(SfScan),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SfScan {
    pub target: String,
    pub target_type: &'static str,
    pub use_case: String,
    pub format: String,
    pub types: Vec<String>,
    pub include_source: bool,
}

/// Resolve parsed flags to a metadata action or one supported scan.
pub fn action(args: &SfArgs) -> Result<SfAction, Error> {
    match args.mode {
        SfMode::Version => {
            return Ok(SfAction::Text(format!(
                "Huntsman Recon {} — SpiderFoot 4.0-compatible subset.\n",
                env!("CARGO_PKG_VERSION")
            )));
        }
        SfMode::ListModules => return Ok(SfAction::Text(module_listing(args.quiet))),
        SfMode::ListTypes => return Ok(SfAction::Text(type_listing(args.quiet))),
        SfMode::Scan => {}
    }
    let target = args.target.as_deref().unwrap_or_default();
    let (target_type, normalized) = sf_target_type(target).ok_or_else(|| {
        Error::Invalid(format!("sf: unable to detect target type for {target:?}"))
    })?;
    Ok(SfAction::Scan(SfScan {
        target: normalized,
        target_type,
        use_case: args.use_case.clone(),
        format: args.format.clone(),
        types: args.types.clone(),
        include_source: args.include_source,
    }))
}

#[must_use]
pub fn module_listing(quiet: bool) -> String {
    let mut out = String::new();
    if !quiet {
        out.push_str("[INFO] Modules available:\n");
    }
    for module in reachable_modules() {
        let cases = if module.network {
            "Footprint, Investigate"
        } else {
            "Footprint, Investigate, Passive"
        };
        writeln!(
            &mut out,
            "{:25} {} [{}]",
            module.name, module.description, cases
        )
        .expect("writing to String cannot fail");
    }
    out
}

#[must_use]
pub fn type_listing(quiet: bool) -> String {
    let mut out = String::new();
    if !quiet {
        out.push_str("[INFO] Types available:\n");
    }
    for (code, description, kinds) in type_table() {
        writeln!(&mut out, "{code:45} {description} (hse: {kinds})")
            .expect("writing to String cannot fail");
    }
    out
}

/// Execute one supported sf target over the already-rebuilt lookup front-ends.
pub fn run_scan<T: Transport + ?Sized>(
    transport: &T,
    scan: &SfScan,
    now_unix: u64,
) -> Result<String, Error> {
    if scan.use_case == "passive" && scan.target_type != "PHONE_NUMBER" {
        return Err(Error::Invalid(format!(
            "sf passive mode has no rebuilt offline collector for {} yet",
            scan.target_type
        )));
    }

    let entities = match scan.target_type {
        "EMAILADDR" => match email_cli::run(transport, &scan.target, now_unix) {
            EmailRun::Printed { report, .. } => report.entities,
            EmailRun::Network(message) => return Err(Error::Network(message)),
            EmailRun::Failed(message) => return Err(Error::Invalid(message)),
        },
        "USERNAME" => match username_cli::run(transport, &scan.target, now_unix) {
            UsernameRun::Printed { report, .. } => report.entities,
            UsernameRun::Failed(message) => return Err(Error::Invalid(message)),
        },
        "PHONE_NUMBER" => match phone_cli::run(&scan.target, now_unix) {
            PhoneRun::Printed { report, .. } => report.entities,
            PhoneRun::Failed(message) => return Err(Error::Invalid(message)),
        },
        "HUMAN_NAME" => match people_cli::run(transport, &scan.target, now_unix) {
            PeopleRun::Printed { report, .. } => report.entities,
            PeopleRun::Network(message) => return Err(Error::Network(message)),
            PeopleRun::Failed(message) => return Err(Error::Invalid(message)),
        },
        other => {
            return Err(Error::Invalid(format!(
                "sf target type {other} is detected but its rebuilt scan path is not available yet"
            )));
        }
    };

    let mut rows: Vec<Row> = entities.iter().map(Row::from_entity).collect();
    if !scan.types.is_empty() {
        rows.retain(|row| {
            scan.types
                .iter()
                .any(|wanted| wanted.eq_ignore_ascii_case(row.event_type))
        });
    }
    render_rows(&rows, &scan.format, scan.include_source)
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
struct Row {
    source: String,
    event_type: &'static str,
    type_description: &'static str,
    source_data: String,
    data: String,
}

impl Row {
    fn from_entity(entity: &Entity) -> Self {
        let (event_type, type_description) = sf_type(&entity.kind);
        let evidence = entity.evidence.first();
        Self {
            source: evidence
                .map(|item| item.provenance.source.clone())
                .filter(|value| !value.is_empty())
                .unwrap_or_else(|| "huntsman".into()),
            event_type,
            type_description,
            source_data: evidence
                .map(|item| item.summary.clone())
                .unwrap_or_default(),
            data: entity.raw_value.clone(),
        }
    }
}

fn render_rows(rows: &[Row], format: &str, include_source: bool) -> Result<String, Error> {
    match format {
        "tab" => Ok(render_tab(rows, include_source)),
        "csv" => Ok(render_csv(rows, include_source)),
        "json" => serde_json::to_string_pretty(rows)
            .map(|body| format!("{body}\n"))
            .map_err(|error| Error::Invalid(format!("sf json: {error}"))),
        _ => Err(Error::Invalid("invalid sf output format".into())),
    }
}

fn render_tab(rows: &[Row], include_source: bool) -> String {
    let mut out = String::new();
    if include_source {
        out.push_str("Source\tType\tSource Data\tData\n");
    } else {
        out.push_str("Source\tType\tData\n");
    }
    for row in rows {
        if include_source {
            writeln!(
                &mut out,
                "{}\t{}\t{}\t{}",
                one_line(&row.source),
                one_line(row.type_description),
                one_line(&row.source_data),
                one_line(&row.data)
            )
            .expect("writing to String cannot fail");
        } else {
            writeln!(
                &mut out,
                "{}\t{}\t{}",
                one_line(&row.source),
                one_line(row.type_description),
                one_line(&row.data)
            )
            .expect("writing to String cannot fail");
        }
    }
    out
}

fn render_csv(rows: &[Row], include_source: bool) -> String {
    let mut out = String::new();
    if include_source {
        out.push_str("Source,Type,Source Data,Data\n");
    } else {
        out.push_str("Source,Type,Data\n");
    }
    for row in rows {
        let fields: Vec<String> = if include_source {
            vec![
                csv_cell(&row.source),
                csv_cell(row.type_description),
                csv_cell(&row.source_data),
                csv_cell(&row.data),
            ]
        } else {
            vec![
                csv_cell(&row.source),
                csv_cell(row.type_description),
                csv_cell(&row.data),
            ]
        };
        out.push_str(&fields.join(","));
        out.push('\n');
    }
    out
}

fn one_line(value: &str) -> String {
    value.replace(['\r', '\n', '\t'], " ")
}

fn csv_cell(value: &str) -> String {
    let one_line = one_line(value);
    let guarded = if one_line
        .as_bytes()
        .first()
        .is_some_and(|first| matches!(first, b'=' | b'+' | b'-' | b'@'))
    {
        format!("'{one_line}")
    } else {
        one_line
    };
    if guarded
        .chars()
        .any(|character| matches!(character, ',' | '"' | '\n' | '\r'))
    {
        format!("\"{}\"", guarded.replace('"', "\"\""))
    } else {
        guarded
    }
}

#[must_use]
pub fn sf_target_type(raw: &str) -> Option<(&'static str, String)> {
    let mut target = raw.trim().to_owned();
    if target.is_empty() {
        return None;
    }
    if target.contains(char::is_whitespace)
        || (!target.contains('.')
            && !target.contains(':')
            && !target.starts_with('+')
            && !target.contains('"'))
    {
        target = format!("\"{target}\"");
    }
    let value = target.as_str();
    let lower = value.to_ascii_lowercase();

    let code = if is_ipv4(value) {
        "IP_ADDRESS"
    } else if value
        .split_once('/')
        .is_some_and(|(ip, bits)| is_ipv4(ip) && valid_prefix(bits, 32))
    {
        "NETBLOCK_OWNER"
    } else if value.contains('@') {
        "EMAILADDR"
    } else if value.strip_prefix('+').is_some_and(|digits| {
        !digits.is_empty() && digits.bytes().all(|byte| byte.is_ascii_digit())
    }) {
        "PHONE_NUMBER"
    } else if quoted(value) && value[1..value.len() - 1].contains(char::is_whitespace) {
        "HUMAN_NAME"
    } else if quoted(value) {
        "USERNAME"
    } else if !value.is_empty() && value.bytes().all(|byte| byte.is_ascii_digit()) {
        "BGP_AS_OWNER"
    } else if value.contains(':')
        && lower
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() || byte == b':')
    {
        "IPV6_ADDRESS"
    } else if lower.split_once('/').is_some_and(|(network, bits)| {
        network.contains(':')
            && network
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit() || byte == b':')
            && valid_prefix(bits, 128)
    }) {
        "NETBLOCKV6_OWNER"
    } else if is_internet_name(&lower) {
        "INTERNET_NAME"
    } else {
        return None;
    };
    Some((code, value.trim_matches('"').to_owned()))
}

fn quoted(value: &str) -> bool {
    value.len() > 2 && value.starts_with('"') && value.ends_with('"')
}

fn is_ipv4(value: &str) -> bool {
    let parts: Vec<&str> = value.split('.').collect();
    parts.len() == 4
        && parts.iter().all(|part| {
            !part.is_empty()
                && part.len() <= 3
                && part.bytes().all(|byte| byte.is_ascii_digit())
                && part.parse::<u8>().is_ok()
        })
}

fn valid_prefix(value: &str, max: u8) -> bool {
    value.parse::<u8>().is_ok_and(|prefix| prefix <= max)
}

fn is_internet_name(value: &str) -> bool {
    let labels: Vec<&str> = value.split('.').collect();
    labels.len() >= 2
        && labels.iter().all(|label| {
            !label.is_empty()
                && !label.starts_with('-')
                && !label.ends_with('-')
                && label
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        })
}

#[must_use]
pub fn type_table() -> &'static [(&'static str, &'static str, &'static str)] {
    &[
        ("BGP_AS_OWNER", "BGP AS Ownership", "asn"),
        ("COMPANY_NAME", "Company Name", "organisation"),
        ("DOMAIN_NAME", "Domain Name", "domain"),
        ("EMAILADDR", "Email Address", "email"),
        ("HUMAN_NAME", "Human Name", "person"),
        ("INTERNET_NAME", "Internet Name", "domain"),
        ("IPV6_ADDRESS", "IPv6 Address", "ip_address"),
        ("IP_ADDRESS", "IP Address", "ip_address"),
        ("LINKED_URL_EXTERNAL", "Linked URL - External", "url"),
        ("NETBLOCK_OWNER", "Netblock Ownership", "cidr"),
        ("NETBLOCKV6_OWNER", "IPv6 Netblock Ownership", "cidr"),
        ("PHONE_NUMBER", "Phone Number", "phone"),
        ("PHYSICAL_ADDRESS", "Physical Address", "address"),
        (
            "PHYSICAL_COORDINATES",
            "Physical Coordinates",
            "coordinates",
        ),
        ("USERNAME", "Username", "username"),
        ("WEB_ANALYTICS_ID", "Web Analytics", "tracking_id"),
        (
            "HSE_COMPANY_REGISTRATION",
            "Company Registration Number (HSE)",
            "abn_acn",
        ),
        (
            "HSE_CRYPTO_ADDRESS",
            "Crypto Address (HSE)",
            "crypto_address",
        ),
        ("HSE_DOCUMENT", "Document (HSE)", "document"),
        ("HSE_DEVICE_ID", "Device Identifier (HSE)", "device_id"),
        ("HSE_MAC_ADDRESS", "MAC Address (HSE)", "mac_address"),
        ("HSE_OTHER", "Other (HSE)", "other"),
        ("HSE_WIFI_SSID", "Wi-Fi Network Name (HSE)", "ssid"),
    ]
}

fn known_type(value: &str) -> bool {
    type_table()
        .iter()
        .any(|(code, _, _)| code.eq_ignore_ascii_case(value))
}

fn sf_type(kind: &EntityKind) -> (&'static str, &'static str) {
    match kind {
        EntityKind::Person => ("HUMAN_NAME", "Human Name"),
        EntityKind::Organisation => ("COMPANY_NAME", "Company Name"),
        EntityKind::Email => ("EMAILADDR", "Email Address"),
        EntityKind::Phone => ("PHONE_NUMBER", "Phone Number"),
        EntityKind::Username => ("USERNAME", "Username"),
        EntityKind::Domain => ("DOMAIN_NAME", "Domain Name"),
        EntityKind::Url => ("LINKED_URL_EXTERNAL", "Linked URL - External"),
        EntityKind::IpAddress => ("IP_ADDRESS", "IP Address"),
        EntityKind::Coordinates => ("PHYSICAL_COORDINATES", "Physical Coordinates"),
        EntityKind::Address => ("PHYSICAL_ADDRESS", "Physical Address"),
        EntityKind::Credential | EntityKind::ApiKey | EntityKind::Other => {
            ("HSE_OTHER", "Other (HSE)")
        }
        EntityKind::Document => ("HSE_DOCUMENT", "Document (HSE)"),
        EntityKind::CryptoAddress => ("HSE_CRYPTO_ADDRESS", "Crypto Address (HSE)"),
        EntityKind::DeviceId => ("HSE_DEVICE_ID", "Device Identifier (HSE)"),
        EntityKind::Ssid => ("HSE_WIFI_SSID", "Wi-Fi Network Name (HSE)"),
        EntityKind::TrackingId => ("WEB_ANALYTICS_ID", "Web Analytics"),
        EntityKind::AbnAcn => (
            "HSE_COMPANY_REGISTRATION",
            "Company Registration Number (HSE)",
        ),
        EntityKind::MacAddress => ("HSE_MAC_ADDRESS", "MAC Address (HSE)"),
        EntityKind::Asn => ("BGP_AS_OWNER", "BGP AS Ownership"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;
    use std::collections::VecDeque;

    use crate::http::{Request, Response, TransportFailure};

    struct Fake {
        responses: RefCell<VecDeque<Result<Response, TransportFailure>>>,
    }

    impl Fake {
        fn new(responses: Vec<Result<Response, TransportFailure>>) -> Self {
            Self {
                responses: RefCell::new(responses.into()),
            }
        }
    }

    impl Transport for Fake {
        fn send(&self, _request: &Request) -> Result<Response, TransportFailure> {
            self.responses
                .borrow_mut()
                .pop_front()
                .expect("unexpected request")
        }
    }

    #[test]
    fn target_detection_matches_rebuilt_legacy_shapes() {
        assert_eq!(
            sf_target_type("jdoe"),
            Some(("USERNAME", "jdoe".to_owned()))
        );
        assert_eq!(
            sf_target_type("Jane Doe"),
            Some(("HUMAN_NAME", "Jane Doe".to_owned()))
        );
        assert_eq!(
            sf_target_type("jane@example.org"),
            Some(("EMAILADDR", "jane@example.org".to_owned()))
        );
        assert_eq!(
            sf_target_type("+61412345678"),
            Some(("PHONE_NUMBER", "+61412345678".to_owned()))
        );
        assert_eq!(
            sf_target_type("example.org"),
            Some(("INTERNET_NAME", "example.org".to_owned()))
        );
    }

    #[test]
    fn metadata_modes_are_offline_and_complete() {
        let modules = module_listing(true);
        assert!(modules.contains("phone_intl"));
        assert!(modules.contains("github_user"));
        let types = type_listing(true);
        assert!(types.contains("EMAILADDR"));
        assert!(types.contains("HUMAN_NAME"));
    }

    #[test]
    fn phone_scan_formats_spiderfoot_rows_without_network() {
        let fake = Fake::new(Vec::new());
        let scan = SfScan {
            target: "+61412345678".into(),
            target_type: "PHONE_NUMBER",
            use_case: "passive".into(),
            format: "json".into(),
            types: Vec::new(),
            include_source: false,
        };
        let rendered = run_scan(&fake, &scan, 1).unwrap();
        let value: serde_json::Value = serde_json::from_str(&rendered).unwrap();
        assert_eq!(value.as_array().map(Vec::len), Some(1));
        assert_eq!(value[0]["event_type"], "PHONE_NUMBER");
        assert_eq!(value[0]["data"], "+61412345678");
    }

    #[test]
    fn passive_networked_target_fails_before_request() {
        let fake = Fake::new(Vec::new());
        let scan = SfScan {
            target: "jane@example.org".into(),
            target_type: "EMAILADDR",
            use_case: "passive".into(),
            format: "tab".into(),
            types: Vec::new(),
            include_source: false,
        };
        let error = run_scan(&fake, &scan, 1).unwrap_err();
        assert!(error.to_string().contains("passive"));
    }

    #[test]
    fn csv_rows_quote_and_guard_special_cells() {
        let rows = [Row {
            source: "=source".into(),
            event_type: "EMAILADDR",
            type_description: "Email Address",
            source_data: "a,b".into(),
            data: "jane@example.org".into(),
        }];
        let rendered = render_csv(&rows, true);
        assert!(rendered.contains("'=source"));
        assert!(rendered.contains("\"a,b\""));
    }
}
