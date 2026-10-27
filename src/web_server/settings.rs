//! Provider key settings for the HTTP API: the `/api/settings/keys` page, key import, and the
//! bounded slot writer. Behaviour is unchanged from the handlers that lived in `web_server.rs`.

use std::collections::BTreeSet;
use std::path::Path;

use crate::error::Error;
use crate::key_import;
use crate::keys::{self, Keys};
use crate::provider_credentials::PROVIDERS;
use crate::value_syntax::form_pairs;

use super::{MAX_FORM_BYTES, Method, ParsedRequest, json_error, json_ok, page_refusal};

/// `GET` and `POST /api/settings/keys`: the provider keys the Settings page may save, and one save.
/// Spiderfoot keeps its modules' API keys in its settings. Here they live in the keys file every
/// lookup reads (`~/.huntsman.env`), so the next lookup uses a saved key without a restart. A save
/// sends `slot` and `value` as a form body, never in the URL, and an empty `value` removes the
/// slot. No answer carries a value: only whether each slot is set and whether the file sets it.
/// It changes what every lookup spends, so it is guarded as the scan API is: refused cross-site or
/// same-site, it needs the lookup header, and on a public bind the bearer token.
pub(super) fn keys_response(parsed: &ParsedRequest<'_>, home: Option<&Path>) -> String {
    let Some(home) = home else {
        return json_error(
            404,
            "this server keeps no keys file: start it with HOME set to an absolute directory",
        );
    };
    if let Some(refused) = page_refusal(parsed, "key request", true) {
        return refused;
    }
    // A URL is kept in history and logs, so a key must not reach this route in one, even beside
    // a form that would be saved.
    if !parsed.query.is_empty() {
        return json_error(
            400,
            "the key settings take no query string: send a form body",
        );
    }
    if parsed.method == Method::Post {
        return match save_key(parsed, &home.join(keys::DEFAULT_KEYS_FILE)) {
            Ok(imported) => key_slots(home, false, imported.as_ref()),
            Err(refused) => refused,
        };
    }
    if parsed.has_body {
        return json_error(400, "only a key save sends a body");
    }
    key_slots(home, parsed.method == Method::Head, None)
}

/// What a key import saved: the slots, and what it left out, by name.
struct Imported {
    slots: Vec<&'static str>,
    unused: Vec<String>,
    settings: usize,
}

/// One key save from the form in `parsed`'s body: `slot`, a slot of a provider in the credential
/// catalogue, and `value`, the key, or empty to remove the slot; or a key import, `import`, the
/// text of a file holding keys. The refusal is the answer to send.
fn save_key(parsed: &ParsedRequest<'_>, file: &Path) -> Result<Option<Imported>, String> {
    let Some(body) = parsed.body else {
        return Err(json_error(400, "the request ended before its head did"));
    };
    if parsed.content_length != Some(body.len()) {
        return Err(json_error(
            400,
            &format!("send the form as a body of at most {MAX_FORM_BYTES} bytes"),
        ));
    }
    let Some(form) = form_pairs(body) else {
        return Err(json_error(
            400,
            "the form is not valid percent-encoded UTF-8",
        ));
    };
    let field = |name: &str| {
        form.iter()
            .rev()
            .find(|(key, _)| key == name)
            .map(|(_, value)| value.as_str())
    };
    if let Some(text) = field("import") {
        if field("slot").is_some() || field("value").is_some() {
            return Err(json_error(
                400,
                "send either slot and value, or import, not both",
            ));
        }
        return import_keys(file, text).map(Some);
    }
    let slot = field("slot").unwrap_or_default();
    if !PROVIDERS
        .iter()
        .any(|provider| provider.slots.contains(&slot))
    {
        return Err(json_error(400, "slot is not a provider key slot"));
    }
    let value = field("value").filter(|value| !value.trim().is_empty());
    keys::store_slot(file, slot, value).map_err(store_refusal)?;
    Ok(None)
}

/// Every key `text` holds that a Huntsman source takes, saved in one rewrite of the keys file:
/// the text of a Spiderfoot settings export (`SpiderFoot.cfg`) or of a keys file. A line that
/// cannot be read saves nothing, and neither does a file that sets no key a source takes.
fn import_keys(file: &Path, text: &str) -> Result<Imported, String> {
    let plan = key_import::plan(text);
    if !plan.refused.is_empty() {
        return Err(json_error(
            422,
            &format!("nothing was imported: {}", plan.refused.join("; ")),
        ));
    }
    if plan.saves.is_empty() {
        let unused = if plan.unused.is_empty() {
            String::new()
        } else {
            format!(" (no Huntsman source takes {})", plan.unused.join(", "))
        };
        return Err(json_error(
            422,
            &format!("the file sets no key a Huntsman source takes{unused}"),
        ));
    }
    let changes: Vec<(&str, Option<&str>)> = plan
        .saves
        .iter()
        .map(|(slot, secret)| (*slot, Some(secret.expose())))
        .collect();
    keys::store_slots(file, &changes).map_err(store_refusal)?;
    Ok(Imported {
        slots: plan.saves.iter().map(|(slot, _)| *slot).collect(),
        unused: plan.unused,
        settings: plan.settings,
    })
}

/// The answer to a key save the keys file refused: 422 for a value or file it cannot hold, 500
/// for one it cannot read or write.
fn store_refusal(error: Error) -> String {
    match error {
        Error::Invalid(message) => json_error(422, &message),
        other => json_error(500, &other.to_string()),
    }
}

/// Every provider key slot in the credential catalogue: its provider, whether a lookup would find
/// it set (in the keys file or the environment), and whether the keys file sets it. With the file,
/// and the warning a lookup would print when it cannot read the file. After an import, what it
/// saved and left out.
fn key_slots(home: &Path, head: bool, imported: Option<&Imported>) -> String {
    let resolved = Keys::for_lookup(Some(home.as_os_str()));
    let saved: BTreeSet<&str> = resolved.keys.slots().into_iter().collect();
    let slots: Vec<serde_json::Value> = PROVIDERS
        .iter()
        .flat_map(|provider| {
            provider.slots.iter().map(|slot| {
                serde_json::json!({
                    "provider": provider.name,
                    "slot": slot,
                    "set": resolved.keys.get(slot).is_some(),
                    "saved": saved.contains(slot),
                })
            })
        })
        .collect();
    let mut body = serde_json::json!({
        "file": home.join(keys::DEFAULT_KEYS_FILE).display().to_string(),
        "warning": resolved.warning,
        "slots": slots,
    });
    if let Some(imported) = imported {
        body["imported"] = serde_json::json!({
            "slots": imported.slots,
            "unused": imported.unused,
            "settings": imported.settings,
        });
    }
    json_ok(&body.to_string(), head)
}
