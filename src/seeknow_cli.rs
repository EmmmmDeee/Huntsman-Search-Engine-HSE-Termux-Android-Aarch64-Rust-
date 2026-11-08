//! CLI-facing adapter for `huntsman-recon seeknow`.
//!
//! Parsing, credential authority, safe rendering, and exit-category decisions live
//! here so the binary reaches the L4 [`crate::seeknow`] client only through L5.

use std::collections::BTreeSet;
use std::ffi::OsStr;
use std::fmt::Write;
use std::path::{Path, PathBuf};

use crate::collector::{CollectionLimits, CollectionOutcome};
use crate::entity::{Entity, EntityKind};
use crate::error::Error;
use crate::fetch::Credential;
use crate::http::Transport;
use crate::keys::Keys;
use crate::lineage::Lineage;
use crate::seeknow::{KEY_SLOT, credits, status};
use crate::seeknow_collector::{SeekNowCollectionMode, collect_with_credential};
use crate::source_outcome::{SourceExecutionOutcome, SourceOutcomeKind};
use crate::textnorm::escape_controls;

pub const SEEKNOW_USAGE: &str = "usage: huntsman-recon seeknow [status | credits | search KIND VALUE [--deep | --fast-only]] [--keys FILE] | seeknow import EXPORT.json [--json]";
pub const SEEKNOW_HELP: &str = "\
seeknow status [--keys FILE]
seeknow credits [--keys FILE]
seeknow search KIND VALUE [--deep | --fast-only] [--keys FILE]
Use the operator-provided HUNTSMAN_SEEKNOW_KEY through the guarded HTTPS boundary.
KIND is one of email, username, phone, ip, domain, person, url, machine_id.
--deep is retained as the CLI name for SeekNow's current /api/v1/stealer endpoint.
Adaptive mode uses /search first when that endpoint supports the selector, and spends
a stealer request only when the selector is supported there and escalation is justified.
seeknow import EXPORT.json [--json]
Read a SeekNow bulk export offline (no key, no request). Every row is kept as a record with its
fields verbatim; a row is attributed to its target only when it carries the target in a field of
the target's kind. Credential values alone are masked, each field named in sensitive_fields.";

/// The largest bulk export `seeknow import` reads, the `/api/inspect` upload bound.
pub const MAX_EXPORT_BYTES: u64 = 64 * 1024 * 1024;

/// The report of one imported bulk export: rendered text, its entities and its outcomes.
///
/// # Errors
/// A message when the bytes are not a readable `SeekNow` bulk export.
pub fn import_export(
    bytes: &[u8],
    now_unix: u64,
) -> Result<crate::seeknow_collector::ExportImport, String> {
    let export = crate::seeknow::parse_bulk_export(bytes)?;
    Ok(crate::seeknow_collector::collect_from_export(
        &export,
        &CollectionLimits::default(),
        now_unix,
    ))
}

fn run_import(args: &[String], now_unix: u64) -> SeekNowCliRun {
    let (json, paths): (Vec<&String>, Vec<&String>) =
        args.iter().partition(|arg| arg.as_str() == "--json");
    let ([path], json) = (paths.as_slice(), json.len()) else {
        return SeekNowCliRun::Usage;
    };
    if json > 1 || path.starts_with('-') {
        return SeekNowCliRun::Usage;
    }
    match std::fs::metadata(path) {
        Ok(meta) if meta.len() > MAX_EXPORT_BYTES => {
            return SeekNowCliRun::BadData(format!(
                "{path} is {} bytes; at most {MAX_EXPORT_BYTES} are read",
                meta.len()
            ));
        }
        Ok(_) => {}
        Err(error) => return SeekNowCliRun::Input(format!("cannot read {path}: {error}")),
    }
    let bytes = match std::fs::read(path) {
        Ok(bytes) => bytes,
        Err(error) => return SeekNowCliRun::Input(format!("cannot read {path}: {error}")),
    };
    let import = match import_export(&bytes, now_unix) {
        Ok(import) => import,
        Err(message) => return SeekNowCliRun::BadData(message),
    };
    if json == 1 {
        return match serde_json::to_string_pretty(&serde_json::json!({
            "entities": import.entities,
            "outcomes": import.outcomes,
            "pivots": import.pivots.iter().map(|p| serde_json::json!({"kind": p.kind, "value": p.value})).collect::<Vec<_>>(),
            // The complete uploaded dataset: every row of every block, all fields verbatim,
            // credential values alone withheld (listed by name in each row's sensitive_fields).
            "records": import.records,
            "record_count": import.records.len(),
        })) {
            Ok(text) => SeekNowCliRun::Printed(text + "\n"),
            Err(error) => SeekNowCliRun::BadData(error.to_string()),
        };
    }
    match crate::lookup_report::render(&import.entities, &import.outcomes) {
        Ok(mut text) => {
            let _ = writeln!(
                text,
                "records_preserved={} (every row kept; use --json for the full dataset)",
                import.records.len()
            );
            SeekNowCliRun::Printed(text)
        }
        Err(message) => SeekNowCliRun::BadData(message),
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SeekNowCliRun {
    Usage,
    Printed(String),
    BadData(String),
    Input(String),
    NoPerm(String),
    Unavailable(String),
}

#[must_use]
pub fn run<T: Transport + ?Sized>(
    transport: &T,
    args: &[String],
    home: Option<&OsStr>,
    now_unix: u64,
) -> SeekNowCliRun {
    // An export is read offline: it needs no key and sends nothing.
    if args.first().map(String::as_str) == Some("import") {
        return run_import(&args[1..], now_unix);
    }
    let Ok((command_args, explicit_keys)) = split_keys_arg(args) else {
        return SeekNowCliRun::Usage;
    };
    let resolved = match Keys::resolve(explicit_keys.as_deref(), home) {
        Ok(resolved) => resolved,
        Err(error) => return SeekNowCliRun::Input(format!("cannot load SeekNow keys: {error}")),
    };
    let mut result = run_with_keys(transport, &command_args, &resolved.keys, now_unix);
    if let Some(warning) = resolved.warning {
        if let Some(text) = result_text_mut(&mut result) {
            text.push('\n');
            text.push_str(&warning);
        }
    }
    result
}

#[must_use]
pub fn run_with_keys<T: Transport + ?Sized>(
    transport: &T,
    args: &[String],
    keys: &Keys,
    now_unix: u64,
) -> SeekNowCliRun {
    let Some(command) = args.first().map(String::as_str) else {
        return SeekNowCliRun::Usage;
    };
    if !matches!(command, "status" | "credits" | "search") {
        return SeekNowCliRun::Usage;
    }

    // A missing key is missing input (exit 66), as `hibp` and `recon stolen-tax` treat it;
    // only a key that is present but cannot be approved is a permission failure (exit 77).
    if crate::provider_credentials::secret_for_slot(keys, KEY_SLOT).is_none() {
        return SeekNowCliRun::Input(format!("credential {KEY_SLOT} is not configured"));
    }
    let credential = match credential_from_keys(keys, now_unix) {
        Ok(credential) => credential,
        Err(message) => return SeekNowCliRun::NoPerm(message),
    };

    match command {
        "credits" if args.len() == 1 => match credits(transport, &credential, now_unix) {
            Ok(result) => {
                let mut text = format!("outcome={}\n", result.outcome.kind.as_str());
                if let Some(remaining) = result.remaining {
                    let _ = writeln!(text, "remaining={remaining}");
                }
                if let Some(limit) = result.limit {
                    let _ = writeln!(text, "limit={limit}");
                }
                finish_diagnostic(&result.outcome, text)
            }
            Err(error) => map_error(error),
        },
        "status" if args.len() == 1 => match status(transport, &credential, now_unix) {
            Ok(result) => {
                let mut text = format!("outcome={}\n", result.outcome.kind.as_str());
                for (key, value) in result.fields {
                    let _ = writeln!(
                        text,
                        "{}={}",
                        escape_controls(&key),
                        escape_controls(&value)
                    );
                }
                finish_diagnostic(&result.outcome, text)
            }
            Err(error) => map_error(error),
        },
        "search" => run_search(transport, &credential, &args[1..], now_unix),
        _ => SeekNowCliRun::Usage,
    }
}

fn split_keys_arg(args: &[String]) -> Result<(Vec<String>, Option<PathBuf>), ()> {
    let mut command = Vec::with_capacity(args.len());
    let mut explicit = None;
    let mut index = 0;
    while index < args.len() {
        if args[index] == "--keys" {
            let Some(path) = args.get(index + 1) else {
                return Err(());
            };
            if explicit.is_some() || path.starts_with("--") {
                return Err(());
            }
            explicit = Some(Path::new(path).to_path_buf());
            index += 2;
        } else {
            command.push(args[index].clone());
            index += 1;
        }
    }
    Ok((command, explicit))
}

fn credential_from_keys(keys: &Keys, now_unix: u64) -> Result<Credential, String> {
    crate::seeknow_collector::operator_credential(keys, now_unix, "huntsman-recon seeknow command")
}

fn run_search<T: Transport + ?Sized>(
    transport: &T,
    credential: &Credential,
    args: &[String],
    now_unix: u64,
) -> SeekNowCliRun {
    let Some(kind_token) = args.first() else {
        return SeekNowCliRun::Usage;
    };
    let Some(kind) = parse_kind(kind_token) else {
        return SeekNowCliRun::Usage;
    };

    let mut mode = SeekNowCollectionMode::Adaptive;
    let mut mode_seen = false;
    let mut value_parts = Vec::new();
    for arg in &args[1..] {
        match arg.as_str() {
            "--deep" if !mode_seen => {
                mode = SeekNowCollectionMode::DeepOnly;
                mode_seen = true;
            }
            "--fast-only" if !mode_seen => {
                mode = SeekNowCollectionMode::FastOnly;
                mode_seen = true;
            }
            "--deep" | "--fast-only" => return SeekNowCliRun::Usage,
            value if value.starts_with('-') => return SeekNowCliRun::Usage,
            value => value_parts.push(value.to_owned()),
        }
    }
    if value_parts.is_empty() {
        return SeekNowCliRun::Usage;
    }
    let value = value_parts.join(" ");
    let scan_id = crate::entity::scan_id(&kind.to_string(), &value);
    let selector = Entity::new(kind, value, 1.0, scan_id);
    let limits = CollectionLimits::default();
    let batch =
        match collect_with_credential(&selector, transport, credential, &limits, mode, now_unix) {
            Ok(batch) => batch,
            Err(crate::collector::CollectorError::InvalidSelector(message)) => {
                return SeekNowCliRun::BadData(message);
            }
            Err(crate::collector::CollectorError::UnsupportedSelector(_)) => {
                return SeekNowCliRun::Usage;
            }
            // A request refused before sending is a refusal (exit 77), not an unavailable source.
            Err(crate::collector::CollectorError::Refused(message)) => {
                return SeekNowCliRun::NoPerm(message);
            }
            Err(error) => return SeekNowCliRun::Unavailable(error.to_string()),
        };

    match batch.outcome {
        CollectionOutcome::Success | CollectionOutcome::ValidZero => {
            SeekNowCliRun::Printed(render_batch(&batch))
        }
        CollectionOutcome::Partial | CollectionOutcome::Failed => {
            let kind = batch.receipts.last().map(|receipt| receipt.outcome.kind);
            let message = kind.map_or_else(
                || "SeekNow collection did not produce a usable outcome".into(),
                |kind| format!("SeekNow collection outcome={}", kind.as_str()),
            );
            if kind.is_some_and(permission_outcome) {
                SeekNowCliRun::NoPerm(message)
            } else {
                SeekNowCliRun::Unavailable(message)
            }
        }
    }
}

fn parse_kind(value: &str) -> Option<EntityKind> {
    match value {
        "email" => Some(EntityKind::Email),
        "username" => Some(EntityKind::Username),
        "phone" => Some(EntityKind::Phone),
        "ip" => Some(EntityKind::IpAddress),
        "domain" => Some(EntityKind::Domain),
        "person" => Some(EntityKind::Person),
        "url" => Some(EntityKind::Url),
        "machine_id" => Some(EntityKind::DeviceId),
        _ => None,
    }
}

fn render_batch(batch: &crate::collector::CollectionBatch) -> String {
    let mut text = format!("outcome={}\n", collection_outcome_name(batch.outcome));
    let _ = writeln!(text, "entities={}", batch.entities.len());
    let mut families = BTreeSet::new();
    for entity in &batch.entities {
        let _ = writeln!(text, "{}\t{}", entity.kind, escape_controls(&entity.value));
        for evidence in &entity.evidence {
            match Lineage::of(evidence) {
                Lineage::Upstream { family, .. } => {
                    families.insert(family);
                }
                Lineage::Ambiguous { .. } | Lineage::Unattributed => {}
            }
        }
    }
    for family in families {
        let _ = writeln!(text, "lineage={}", escape_controls(&family));
    }
    for receipt in &batch.receipts {
        let _ = write!(
            text,
            "source={} outcome={} rows={} truncated={}",
            receipt.source,
            receipt.outcome.kind.as_str(),
            receipt.parsed_rows,
            receipt.truncated
        );
        if let Some(quota) = &receipt.quota {
            for (key, value) in [
                ("quota_remaining", quota.remaining.map(|n| n.to_string())),
                ("quota_limit", quota.limit.map(|n| n.to_string())),
                ("quota_reset", quota.reset.as_deref().map(escape_controls)),
            ] {
                if let Some(value) = value {
                    let _ = write!(text, " {key}={value}");
                }
            }
        }
        text.push('\n');
    }
    text
}

fn finish_diagnostic(outcome: &SourceExecutionOutcome, text: String) -> SeekNowCliRun {
    match outcome.kind {
        SourceOutcomeKind::Success | SourceOutcomeKind::ValidZero => SeekNowCliRun::Printed(text),
        kind if permission_outcome(kind) => {
            SeekNowCliRun::NoPerm(format!("SeekNow outcome={}", kind.as_str()))
        }
        kind => SeekNowCliRun::Unavailable(format!(
            "SeekNow outcome={}{}",
            kind.as_str(),
            outcome
                .detail
                .as_deref()
                .map_or_else(String::new, |detail| format!(" detail={detail}"))
        )),
    }
}

fn permission_outcome(kind: SourceOutcomeKind) -> bool {
    matches!(
        kind,
        SourceOutcomeKind::AuthRequired
            | SourceOutcomeKind::AuthRejected
            | SourceOutcomeKind::EntitlementDenied
    )
}

fn map_error(error: Error) -> SeekNowCliRun {
    match error {
        Error::Invalid(message)
        | Error::InvalidValue(message)
        | Error::MissingCredential(message)
        | Error::MissingField(message) => SeekNowCliRun::BadData(message),
        Error::Network(message) | Error::Store(message) | Error::TerminateRefused(message) => {
            SeekNowCliRun::Unavailable(message)
        }
    }
}

fn collection_outcome_name(outcome: CollectionOutcome) -> &'static str {
    match outcome {
        CollectionOutcome::Success => "success",
        CollectionOutcome::ValidZero => "valid_zero",
        CollectionOutcome::Partial => "partial",
        CollectionOutcome::Failed => "failed",
    }
}

fn result_text_mut(result: &mut SeekNowCliRun) -> Option<&mut String> {
    match result {
        SeekNowCliRun::Printed(text)
        | SeekNowCliRun::BadData(text)
        | SeekNowCliRun::Input(text)
        | SeekNowCliRun::NoPerm(text)
        | SeekNowCliRun::Unavailable(text) => Some(text),
        SeekNowCliRun::Usage => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every HTTP send is refused before leaving the host.
    struct Blocked;

    impl Transport for Blocked {
        fn send(
            &self,
            _: &crate::http::Request,
        ) -> Result<crate::http::Response, crate::http::TransportFailure> {
            Err(crate::http::TransportFailure {
                kind: SourceOutcomeKind::ConnectFailure,
                detail: "egress-policy: destination (0.0.0.0) is not publicly routable".into(),
                blocked: true,
            })
        }
    }

    /// A `seeknow search` the egress refuses before sending is a permission failure (exit 77),
    /// not the unavailable source (exit 69) it used to read as.
    #[test]
    fn a_search_refused_before_sending_is_a_permission_failure() {
        let keys = Keys::parse("HUNTSMAN_SEEKNOW_KEY=dummy-seeknow-key-for-tests\n")
            .unwrap_or_else(|error| panic!("fixture keys: {error}"));
        let credential =
            credential_from_keys(&keys, 1).unwrap_or_else(|error| panic!("credential: {error}"));
        let args = ["email".to_owned(), "ada@example.com".to_owned()];
        match run_search(&Blocked, &credential, &args, 1) {
            SeekNowCliRun::NoPerm(message) => {
                assert!(message.contains("egress-policy"), "{message}");
            }
            other => panic!("expected a refusal (NoPerm, exit 77), got {other:?}"),
        }
    }

    /// `SeekNow`'s own key file `~/.config/seeknow/api_key` supplies the key on a Termux install
    /// that has no persistent shell environment. The credential builder must read that file
    /// through the same slot rule as `DeHashed` and HIBP, so the key need not sit in an env var.
    /// The slot itself is unset here, so this would fail if the builder still read `keys.get`.
    #[test]
    fn seeknow_s_own_key_file_builds_the_operator_credential() {
        let keys = Keys::parse("")
            .unwrap_or_else(|error| panic!("fixture keys: {error}"))
            .with_provider_file(KEY_SLOT, "file-only-seeknow-key");
        assert!(
            keys.get(KEY_SLOT).is_none(),
            "the slot must be unset so the file is the only source under test"
        );
        credential_from_keys(&keys, 1)
            .unwrap_or_else(|error| panic!("file-supplied credential: {error}"));
    }

    /// The same file must let the CLI past its not-configured gate: a file-only key is a
    /// configured key, so `seeknow search` proceeds to build and send a request.
    #[test]
    fn a_file_only_key_passes_the_cli_configured_gate() {
        let keys = Keys::parse("")
            .unwrap_or_else(|error| panic!("fixture keys: {error}"))
            .with_provider_file(KEY_SLOT, "file-only-seeknow-key");
        let args = [
            "search".to_owned(),
            "email".to_owned(),
            "ada@example.com".to_owned(),
        ];
        match run_with_keys(&Blocked, &args, &keys, 1) {
            // The gate let it through; the egress refusal is the expected downstream outcome.
            SeekNowCliRun::NoPerm(_) => {}
            SeekNowCliRun::Input(message) => {
                panic!("file-only key read as not configured: {message}")
            }
            other => panic!("expected the request to be attempted, got {other:?}"),
        }
    }
}
