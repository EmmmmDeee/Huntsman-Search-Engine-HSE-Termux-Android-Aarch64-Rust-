//! End-to-end front-end for `huntsman-recon domain` and the domain arm of `scan`.
//!
//! Runs crt.sh certificate transparency and DNS record lookups in sequence for a
//! single domain, combining both result sets into one entity list and rendered report.

use std::path::PathBuf;

use crate::canonical::canonical_domain;
use crate::crtsh::{self, CrtShError};
use crate::dns;
use crate::entity::Entity;
use crate::error::Error;
use crate::http::{Transport, UreqTransport};
use crate::lookup_args::LookupTokens;
use crate::lookup_report::entity_row;
use crate::recon::ReconTargetKind;
use crate::source_outcome::{SourceExecutionOutcome, SourceOutcomeKind};

pub const DOMAIN_USAGE: &str = "usage: huntsman-recon domain DOMAIN [--save FILE]";

#[derive(Debug, Clone, PartialEq, Default)]
pub struct Report {
    pub entities: Vec<Entity>,
    pub outcomes: Vec<SourceExecutionOutcome>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DomainArgs {
    pub domain: String,
    pub save: Option<PathBuf>,
}

impl DomainArgs {
    /// # Errors
    /// Invalid or missing domain, repeated `--save`, or an unknown option.
    pub fn parse(args: &[String]) -> Result<Self, Error> {
        let LookupTokens { positional, save } = LookupTokens::split(args)?;
        if positional.len() != 1 {
            return Err(Error::Invalid("domain needs exactly one DOMAIN".into()));
        }
        let domain = canonical_domain(&positional[0])
            .ok_or_else(|| Error::invalid_value("invalid domain"))?;
        Ok(Self { domain, save })
    }
}

pub enum DomainRun {
    Printed { text: String, report: Report },
    Network(String),
    Failed(String),
}

#[must_use]
pub fn run<T: Transport + ?Sized>(transport: &T, domain: &str, now_unix: u64) -> DomainRun {
    let Some(domain) = canonical_domain(domain) else {
        return DomainRun::Failed("invalid domain".into());
    };

    let mut entities = Vec::new();
    let mut outcomes = Vec::new();
    let mut sections = Vec::new();

    match crtsh::lookup(transport, ReconTargetKind::Domain, &domain, "domain_cli") {
        Ok(report) => {
            let count = report.entities.len();
            entities.extend(report.entities);
            outcomes.push(SourceExecutionOutcome::success("crtsh", now_unix, count));
            sections.push(format!("crtsh: {count} certificate-transparency entities"));
        }
        Err(CrtShError::Refused(reason)) => {
            outcomes.push(SourceExecutionOutcome::failed(
                "crtsh",
                now_unix,
                SourceOutcomeKind::EntitlementDenied,
                None,
                &reason,
            ));
            sections.push(format!("crtsh: refused ({reason})"));
        }
        Err(error) => {
            let message = error.to_string();
            outcomes.push(SourceExecutionOutcome::failed(
                "crtsh",
                now_unix,
                SourceOutcomeKind::Inconclusive,
                None,
                &message,
            ));
            sections.push(format!("crtsh: unavailable ({message})"));
        }
    }

    let dns_transport = UreqTransport::new(&dns::transport_config());
    match dns::lookup_domain(&dns_transport, &domain) {
        Some(report) => {
            let rendered = report.render();
            let answer_count = report.answers.len();
            outcomes.push(SourceExecutionOutcome::success(
                "dns",
                now_unix,
                answer_count,
            ));
            sections.push(rendered);
        }
        None => {
            outcomes.push(SourceExecutionOutcome::failed(
                "dns",
                now_unix,
                SourceOutcomeKind::Inconclusive,
                None,
                "bad domain",
            ));
        }
    }

    let any_results = !entities.is_empty()
        || outcomes
            .iter()
            .any(|o| o.kind.is_accepted() && o.found.unwrap_or(0) > 0);
    if !any_results {
        return DomainRun::Failed(format!("no results for domain {domain}"));
    }

    let mut text = String::new();
    use std::fmt::Write as _;
    let _ = writeln!(text, "domain: {domain}");
    for entity in &entities {
        text.push_str(&entity_row(entity, &entity.value));
        text.push('\n');
    }
    for section in &sections {
        text.push_str(section);
        if !section.ends_with('\n') {
            text.push('\n');
        }
    }

    DomainRun::Printed {
        text,
        report: Report { entities, outcomes },
    }
}
