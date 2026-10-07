//! CLI-facing adapter for `huntsman-recon seeknow`.
//!
//! Parsing, credential authority, safe rendering, and exit-category decisions live
//! here so the binary reaches the L4 [`crate::seeknow`] client only through L5.

use std::collections::BTreeSet;
use std::ffi::OsStr;
use std::fmt::Write;
use std::path::{Path, PathBuf};

use crate::collector::{CollectionLimits, CollectionOutcome};
use crate::credential_origin::{AuthenticationAuthority, OperatorCredentialRef};
use crate::entity::{Entity, EntityKind};
use crate::error::Error;
use crate::fetch::{AuthStyle, Credential};
use crate::http::Transport;
use crate::keys::Keys;
use crate::lineage::Lineage;
use crate::seeknow::{KEY_SLOT, credits, status};
use crate::seeknow_collector::{SeekNowCollectionMode, collect_with_credential};
use crate::source_outcome::{SourceExecutionOutcome, SourceOutcomeKind};

pub const SEEKNOW_USAGE: &str = "usage: huntsman-recon seeknow [status | credits | search KIND VALUE [--deep | --fast-only]] [--keys FILE]";
pub const SEEKNOW_HELP: &str = "\
seeknow status [--keys FILE]
seeknow credits [--keys FILE]
seeknow search KIND VALUE [--deep | --fast-only] [--keys FILE]
Use the operator-provided HUNTSMAN_SEEKNOW_KEY through the guarded HTTPS boundary.
KIND is one of email, username, phone, ip, domain, person. Search defaults to fast
and spends a deep-search request only after a contract-validated fast zero.";

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

    let credential = match credential_from_keys(keys, now_unix) {
        Ok(credential) => credential,
        Err(message) => return SeekNowCliRun::NoPerm(message),
    };

    match command {
        "credits" if args.len() == 1 => match credits(transport, &credential, now_unix) {
            Ok(result) => {
                let mut text = format!("outcome={}\n", outcome_name(result.outcome.kind));
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
                let mut text = format!("outcome={}\n", outcome_name(result.outcome.kind));
                for (key, value) in result.fields {
                    let _ = writeln!(text, "{key}={value}");
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
    let secret = keys
        .get(KEY_SLOT)
        .ok_or_else(|| format!("credential {KEY_SLOT} is not configured"))?;
    let authority = AuthenticationAuthority::operator_approved(OperatorCredentialRef {
        provider_id: "seeknow".into(),
        credential_slot: KEY_SLOT.into(),
        approved_at_unix: now_unix,
        approval_provenance: "huntsman-recon seeknow command".into(),
    })
    .map_err(|error| error.to_string())?;
    Credential::new(authority, secret, AuthStyle::Header("X-API-Key".into()))
        .map_err(|error| error.to_string())
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
    let scan_id = entity::scan_id(&kind.to_string(), &value);
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
                |kind| format!("SeekNow collection outcome={}", outcome_name(kind)),
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
        _ => None,
    }
}

fn render_batch(batch: &crate::collector::CollectionBatch) -> String {
    let mut text = format!("outcome={}\n", collection_outcome_name(batch.outcome));
    let _ = writeln!(text, "entities={}", batch.entities.len());
    let mut families = BTreeSet::new();
    for entity in &batch.entities {
        let _ = writeln!(text, "{}\t{}", entity.kind, entity.value);
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
        let _ = writeln!(text, "lineage={family}");
    }
    for receipt in &batch.receipts {
        let _ = writeln!(
            text,
            "source={} outcome={} rows={} truncated={}",
            receipt.source,
            outcome_name(receipt.outcome.kind),
            receipt.parsed_rows,
            receipt.truncated
        );
    }
    text
}

fn finish_diagnostic(outcome: &SourceExecutionOutcome, text: String) -> SeekNowCliRun {
    match outcome.kind {
        SourceOutcomeKind::Success | SourceOutcomeKind::ValidZero => SeekNowCliRun::Printed(text),
        kind if permission_outcome(kind) => {
            SeekNowCliRun::NoPerm(format!("SeekNow outcome={}", outcome_name(kind)))
        }
        kind => SeekNowCliRun::Unavailable(format!(
            "SeekNow outcome={}{}",
            outcome_name(kind),
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
        Error::Invalid(message) | Error::MissingField(message) => SeekNowCliRun::BadData(message),
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

fn outcome_name(kind: SourceOutcomeKind) -> String {
    serde_json::to_value(kind)
        .ok()
        .and_then(|value| value.as_str().map(str::to_owned))
        .unwrap_or_else(|| "unknown".into())
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
