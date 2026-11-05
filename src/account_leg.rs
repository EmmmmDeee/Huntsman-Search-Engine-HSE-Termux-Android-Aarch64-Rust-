//! The shared path of the simple username legs: one keyless GET for a public account, read the
//! same way by each.
//!
//! A leg checks that its selector is a handle it can ask about, fetches the account document
//! without following redirects, and reads it in a fixed order:
//!
//! 1. A clean "no such account" is a zero, never drift: a plain 404 ([`Absent::NotFound`], which
//!    keeps a challenge page out because the fetch layer classes that as a wall, not
//!    `Upstream4xx`) or a JSON `null` body ([`Absent::NullBody`]).
//! 2. The whole response must be a document, decoded as the leg's own type.
//! 3. A document that names no account is schema drift; one that names another account is
//!    semantic drift, compared as the leg's site compares handles ([`Identity`]).
//!
//! Each leg keeps its own URL, request, handle rule, document type and entities, and states its
//! messages in full in its [`AccountLeg`], so every row reads as it always has.

use serde::de::DeserializeOwned;

use crate::entity::{Entity, merge_by_uid};
use crate::error::Error;
use crate::fetch::{FetchOptions, Fetched, answer, decode_json, fetch, whole_response};
use crate::http::{Request, Transport};
use crate::source_outcome::{SourceExecutionOutcome, SourceOutcomeKind};

/// What one account leg found: its entities and its row.
#[derive(Debug, Clone, PartialEq)]
pub struct Report {
    pub entities: Vec<Entity>,
    pub outcome: SourceExecutionOutcome,
}

impl Report {
    /// A leg that found nothing, with the row that says why.
    #[must_use]
    pub const fn miss(outcome: SourceExecutionOutcome) -> Self {
        Self {
            entities: Vec::new(),
            outcome,
        }
    }

    /// A confirmed account: its entities, merged by UID, and a success row with their count and
    /// the HTTP status that carried them.
    #[must_use]
    pub fn found(source: &str, mut entities: Vec<Entity>, status: u16, now_unix: u64) -> Self {
        merge_by_uid(&mut entities);
        Self {
            outcome: SourceExecutionOutcome::success(source, now_unix, entities.len())
                .with_http_status(status),
            entities,
        }
    }
}

/// How the site says an account does not exist.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Absent {
    /// A plain HTTP 404.
    NotFound,
    /// HTTP 200 with a JSON `null` body.
    NullBody,
}

/// How the site compares the account a document names with the handle asked about.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Identity {
    /// Handles are case-insensitive.
    IgnoreAsciiCase,
    /// Handles are case-sensitive.
    Exact,
}

/// How the selector becomes the handle the leg asks about, after trimming and dropping a
/// leading `@`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HandleCase {
    /// Lowercased: the site's canonical form, so a mixed-case caller still resolves.
    Lowered,
    /// As the operator typed it.
    AsTyped,
}

/// One account leg's rules and messages.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AccountLeg {
    /// The leg's source label, on every row and record.
    pub source: &'static str,
    /// What the document is, in the fetch layer's messages ("Lobsters user").
    pub document: &'static str,
    /// The row for a selector the leg cannot ask about.
    pub invalid: &'static str,
    /// The schema-drift detail for a document that names no account.
    pub no_identity: &'static str,
    /// The semantic-drift detail for a document that names another account.
    pub other_account: &'static str,
    pub handle_case: HandleCase,
    pub identity: Identity,
    pub absent: Absent,
}

impl AccountLeg {
    /// The handle this leg asks about, or the row for a selector `valid` refuses.
    ///
    /// # Errors
    /// The inconclusive row ([`AccountLeg::invalid`]) when `valid` refuses the handle.
    pub fn handle(
        &self,
        username: &str,
        valid: impl Fn(&str) -> bool,
        now_unix: u64,
    ) -> Result<String, SourceExecutionOutcome> {
        let handle = username.trim().trim_start_matches('@');
        let handle = match self.handle_case {
            HandleCase::Lowered => handle.to_ascii_lowercase(),
            HandleCase::AsTyped => handle.to_owned(),
        };
        if valid(&handle) {
            Ok(handle)
        } else {
            Err(SourceExecutionOutcome::inconclusive(
                self.source,
                now_unix,
                self.invalid,
            ))
        }
    }

    /// Send `request` without following redirects, paced, and read the account document it
    /// returns for `handle`; `identity` names the account a document is about.
    ///
    /// # Errors
    /// The outer error is the guarded fetch refusing the request. The inner one is the row of a
    /// lookup that confirmed no account: a clean zero, an unusable response, or drift.
    pub fn fetch<T, D>(
        &self,
        transport: &T,
        request: Request,
        handle: &str,
        identity: impl Fn(&D) -> &str,
        now_unix: u64,
    ) -> Result<Result<(D, u16), SourceExecutionOutcome>, Error>
    where
        T: Transport + ?Sized,
        D: DeserializeOwned,
    {
        let fetched = fetch(
            transport,
            request,
            None,
            &FetchOptions::no_redirects().paced(),
            self.source,
            now_unix,
        )?;
        Ok(self.read(&fetched, handle, identity, now_unix))
    }

    /// Read a fetched account document in the fixed order the module comment gives.
    fn read<D: DeserializeOwned>(
        &self,
        fetched: &Fetched,
        handle: &str,
        identity: impl Fn(&D) -> &str,
        now_unix: u64,
    ) -> Result<(D, u16), SourceExecutionOutcome> {
        if self.absent == Absent::NotFound {
            if let Some(response) = &fetched.response {
                if response.status == 404 && fetched.outcome.kind == SourceOutcomeKind::Upstream4xx
                {
                    return Err(SourceExecutionOutcome::valid_zero(self.source, now_unix)
                        .with_http_status(response.status));
                }
            }
        }
        let response = whole_response(fetched, self.document)?;
        answer(fetched, self.document)?;
        let document: D = match self.absent {
            Absent::NotFound => decode_json(response, self.source, now_unix, self.document)?,
            Absent::NullBody => {
                let parsed: Option<D> =
                    decode_json(response, self.source, now_unix, self.document)?;
                let Some(document) = parsed else {
                    return Err(SourceExecutionOutcome::valid_zero(self.source, now_unix)
                        .with_http_status(response.status));
                };
                document
            }
        };
        let named = identity(&document).trim();
        let drift = if named.is_empty() {
            Some((SourceOutcomeKind::SchemaDrift, self.no_identity))
        } else if !match self.identity {
            Identity::IgnoreAsciiCase => named.eq_ignore_ascii_case(handle),
            Identity::Exact => named == handle,
        } {
            Some((SourceOutcomeKind::SemanticDrift, self.other_account))
        } else {
            None
        };
        if let Some((kind, detail)) = drift {
            return Err(SourceExecutionOutcome::failed(
                self.source,
                now_unix,
                kind,
                Some(response.status),
                detail,
            ));
        }
        Ok((document, response.status))
    }
}
