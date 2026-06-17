//! Query generation: per-kind fanout functions and the public [`generate`] entry
//! point.

use std::collections::HashSet;

use crate::core::scan::TargetKind;
use crate::util::oathnet;
use crate::util::oathnet::{FIELD_DOMAIN, FIELD_EMAIL, FIELD_USERNAME};

use super::helpers::{
    ROLE_LOCALPARTS, SYNTH_EMAIL_PROVIDERS, handle_permutations, is_freemail, name_tokens,
    phone_formats,
};
use super::types::{BatchOptions, BatchQuery, Origin, Surface};

/// Push a breach query (and, for login-indexable fields, a stealer query) for
/// `value`. Blank values are dropped. Stealer-indexability is the shared
/// [`oathnet::stealer_indexable`] rule.
fn add(
    out: &mut Vec<BatchQuery>,
    opts: &BatchOptions,
    field: &'static str,
    value: &str,
    origin: Origin,
) {
    push_one(out, Surface::Breach, field, value, origin);
    if opts.include_stealer && oathnet::stealer_indexable(field) {
        push_one(out, Surface::Stealer, field, value, origin);
    }
}

/// Push a breach-only query for `value`.
fn add_breach(out: &mut Vec<BatchQuery>, field: &'static str, value: &str, origin: Origin) {
    push_one(out, Surface::Breach, field, value, origin);
}

fn push_one(
    out: &mut Vec<BatchQuery>,
    surface: Surface,
    field: &'static str,
    value: &str,
    origin: Origin,
) {
    let value = value.trim();
    if value.is_empty() {
        return;
    }
    out.push(BatchQuery {
        surface,
        field,
        value: value.to_string(),
        origin,
    });
}

fn gen_email(out: &mut Vec<BatchQuery>, opts: &BatchOptions, native: &'static str, v: &str) {
    add(out, opts, native, v, Origin::Seed);
    if let Some((local, domain)) = v.split_once('@') {
        let local = local.trim();
        let domain = domain.trim().to_ascii_lowercase();
        if local.len() >= 2 {
            add(out, opts, FIELD_USERNAME, local, Origin::EmailLocalPart);
            if opts.permute_handles {
                for h in handle_permutations(&name_tokens(local)) {
                    add(out, opts, FIELD_USERNAME, &h, Origin::Handle);
                }
            }
        }
        // Only pivot on a plausibly-real domain: a free provider is noise, and a
        // malformed host (no dot, or a stray `@` from a double-`@` address) is
        // not a domain worth a query. The dot check also subsumes "non-empty".
        if domain.contains('.') && !domain.contains('@') && !is_freemail(&domain) {
            add_breach(out, FIELD_DOMAIN, &domain, Origin::EmailDomain);
        }
    }
}

fn gen_username(out: &mut Vec<BatchQuery>, opts: &BatchOptions, native: &'static str, v: &str) {
    add(out, opts, native, v, Origin::Seed);
    if opts.permute_handles {
        for h in handle_permutations(&name_tokens(v)) {
            add(out, opts, native, &h, Origin::Handle);
        }
    }
    if opts.synthesize_emails {
        for d in SYNTH_EMAIL_PROVIDERS {
            add(
                out,
                opts,
                FIELD_EMAIL,
                &format!("{v}@{d}"),
                Origin::EmailCandidate,
            );
        }
    }
}

fn gen_name(out: &mut Vec<BatchQuery>, opts: &BatchOptions, native: &'static str, v: &str) {
    // Free-text name search is breach-only (the stealer corpus has no name index).
    add_breach(out, native, v, Origin::Seed);
    if !opts.permute_handles {
        return;
    }
    let handles = handle_permutations(&name_tokens(v));
    for h in &handles {
        add(out, opts, FIELD_USERNAME, h, Origin::Handle);
    }
    if opts.synthesize_emails {
        for h in &handles {
            for d in SYNTH_EMAIL_PROVIDERS {
                add(
                    out,
                    opts,
                    FIELD_EMAIL,
                    &format!("{h}@{d}"),
                    Origin::EmailCandidate,
                );
            }
        }
    }
}

fn gen_domain(out: &mut Vec<BatchQuery>, opts: &BatchOptions, native: &'static str, v: &str) {
    let d = v.trim().to_ascii_lowercase();
    add_breach(out, native, &d, Origin::Seed);
    if opts.synthesize_emails && !is_freemail(&d) {
        for role in ROLE_LOCALPARTS {
            add(
                out,
                opts,
                FIELD_EMAIL,
                &format!("{role}@{d}"),
                Origin::EmailCandidate,
            );
        }
    }
}

/// Generate the full, de-duplicated batch of OathNet queries for `value`
/// interpreted as `kind`.
///
/// Returns an empty vec for a blank `value`, or for a `kind` OathNet does not
/// index (per [`oathnet::selector_field`]). See the [module docs](crate::util::oathnet_batch)
/// for the full list of guarantees the returned vec upholds.
///
/// # Examples
///
/// An email seed fans out across surfaces, derived fields, and handle shapes:
///
/// ```
/// use huntsman_search_engine::util::oathnet_batch::{generate, BatchOptions, Surface};
/// use huntsman_search_engine::core::scan::TargetKind;
///
/// let plan = generate(TargetKind::Email, "jane.doe@example.com", &BatchOptions::default());
///
/// // The seed is searched first, on both corpora.
/// assert_eq!(plan[0].field, "email");
/// assert_eq!(plan[0].value, "jane.doe@example.com");
/// assert!(plan.iter().any(|q| q.surface == Surface::Stealer));
///
/// // The local part fans out into username handles — a "large array".
/// assert!(plan.iter().any(|q| q.field == "username" && q.value == "jdoe"));
/// assert!(plan.len() > 10);
/// ```
///
/// `max_queries` caps the plan, keeping the highest-priority queries:
///
/// ```
/// use huntsman_search_engine::util::oathnet_batch::{generate, BatchOptions};
/// use huntsman_search_engine::core::scan::TargetKind;
///
/// let opts = BatchOptions { max_queries: 3, ..BatchOptions::default() };
/// let plan = generate(TargetKind::Email, "jane.doe@example.com", &opts);
/// assert_eq!(plan.len(), 3);
/// ```
#[must_use]
pub fn generate(kind: TargetKind, value: &str, opts: &BatchOptions) -> Vec<BatchQuery> {
    let mut out = Vec::new();
    let v = value.trim();
    if v.is_empty() {
        return out;
    }
    // The seed's native selector field is the single-sourced kind→field mapping;
    // `None` means OathNet does not index this kind, so there is nothing to do.
    let Some(native) = oathnet::selector_field(kind) else {
        return out;
    };
    match kind {
        TargetKind::Email => gen_email(&mut out, opts, native, v),
        TargetKind::Username => gen_username(&mut out, opts, native, v),
        TargetKind::FullName => gen_name(&mut out, opts, native, v),
        TargetKind::Phone => {
            for (fmt, origin) in phone_formats(v) {
                add_breach(&mut out, native, &fmt, origin);
            }
        }
        TargetKind::IpAddress => add_breach(&mut out, native, v, Origin::Seed),
        TargetKind::Domain => gen_domain(&mut out, opts, native, v),
        // `native` is `Some` only for the kinds above, so reaching here means
        // `selector_field` learned a kind `generate` hasn't — a single-source
        // drift. Surface it in tests/debug; no-op (drop the kind) in release.
        _ => debug_assert!(
            false,
            "oathnet::selector_field returned Some for {kind:?} but \
             oathnet_batch::generate does not handle it",
        ),
    }

    // Collapse exact (surface, field, lowercased-value) duplicates, keeping the
    // first (highest-priority) occurrence.
    let mut seen = HashSet::new();
    out.retain(|q| seen.insert((q.surface, q.field, q.value.to_lowercase())));

    if opts.max_queries > 0 && out.len() > opts.max_queries {
        out.truncate(opts.max_queries);
    }
    out
}
