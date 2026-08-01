#![allow(dead_code)]
//! Standardized entity builders for high-volume patterns.
//!
//! This module provides builder functions for common entity types that modules
//! frequently emit. Using these builders ensures consistency across the codebase,
//! reduces boilerplate in module implementations, and makes it easier to adjust
//! tagging strategy or evidence structure globally.

use crate::core::entity::{Entity, EntityKind, Evidence};

/// Build a breach entity with standard attributes.
///
/// # Arguments
/// * `breach_name` — the name of the breach or stealer record
/// * `source` — the module or source name (for evidence attribution)
/// * `confidence` — entity confidence level
/// * `attrs` — additional attributes to attach as evidence
/// * `scan_id` — the scan identifier for entity UID derivation
///
/// # Result
/// An entity tagged with `breach` and `source:<source>`, with evidence
/// linking the breach name and provided attributes.
pub fn build_breach_entity(
    breach_name: &str,
    source: &str,
    confidence: f64,
    attrs: &[(&str, String)],
    scan_id: &str,
) -> Entity {
    let mut e = Entity::new(EntityKind::Person, breach_name, confidence, scan_id);
    e.tag("breach");
    e.tag(format!("source:{source}"));
    let mut ev = Evidence::new(source, format!("Breach: {breach_name}"));
    for &(key, ref value) in attrs {
        ev = ev.with_attr(key, value.clone());
    }
    e.add_evidence(ev);
    e
}

/// Build an IP reputation entity with standard attributes.
///
/// # Arguments
/// * `ip` — the IP address as a string
/// * `reputation_score` — numeric reputation/abuse score (typically 0-100)
/// * `source` — the module or source name
/// * `confidence` — entity confidence level
/// * `attrs` — additional attributes to attach as evidence
/// * `scan_id` — the scan identifier
///
/// # Result
/// An entity of kind `IpAddress`, tagged with `reputation`, `source:<source>`,
/// and `score:<score>`, with evidence from the named source.
pub fn build_ip_reputation_entity(
    ip: &str,
    reputation_score: f64,
    source: &str,
    confidence: f64,
    attrs: &[(&str, String)],
    scan_id: &str,
) -> Entity {
    let mut e = Entity::new(EntityKind::IpAddress, ip, confidence, scan_id);
    e.tag("reputation");
    e.tag(format!("source:{source}"));
    e.tag(format!("score:{reputation_score:.2}"));
    let mut ev = Evidence::new(source, format!("IP reputation: {ip}"));
    for &(key, ref value) in attrs {
        ev = ev.with_attr(key, value.clone());
    }
    e.add_evidence(ev);
    e
}

/// Build an email entity with standard attributes.
///
/// # Arguments
/// * `email` — the email address
/// * `source` — the module or source name
/// * `confidence` — entity confidence level
/// * `attrs` — additional attributes to attach as evidence
/// * `scan_id` — the scan identifier
///
/// # Result
/// An entity of kind `Email`, tagged with `source:<source>`, with evidence
/// from the named source and provided attributes.
pub fn build_email_entity(
    email: &str,
    source: &str,
    confidence: f64,
    attrs: &[(&str, String)],
    scan_id: &str,
) -> Entity {
    let mut e = Entity::new(EntityKind::Email, email, confidence, scan_id);
    e.tag(format!("source:{source}"));
    let mut ev = Evidence::new(source, format!("Email found: {email}"));
    for &(key, ref value) in attrs {
        ev = ev.with_attr(key, value.clone());
    }
    e.add_evidence(ev);
    e
}

/// Build a domain entity with standard attributes.
///
/// # Arguments
/// * `domain` — the domain name
/// * `source` — the module or source name
/// * `confidence` — entity confidence level
/// * `attrs` — additional attributes to attach as evidence
/// * `scan_id` — the scan identifier
///
/// # Result
/// An entity of kind `Domain`, tagged with `source:<source>`, with evidence
/// from the named source and provided attributes.
pub fn build_domain_entity(
    domain: &str,
    source: &str,
    confidence: f64,
    attrs: &[(&str, String)],
    scan_id: &str,
) -> Entity {
    let mut e = Entity::new(EntityKind::Domain, domain, confidence, scan_id);
    e.tag(format!("source:{source}"));
    let mut ev = Evidence::new(source, format!("Domain found: {domain}"));
    for &(key, ref value) in attrs {
        ev = ev.with_attr(key, value.clone());
    }
    e.add_evidence(ev);
    e
}
