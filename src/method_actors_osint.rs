//! OSINT-specific method actors for Huntsman investigations.
//!
//! Provides pre-built actors for common OSINT operations like entity
//! classification, evidence extraction, and relationship identification.

use std::sync::Arc;

use crate::method_actor::{ActorMetadata, FunctionActor, MethodActor};

/// Create an actor that classifies entities by type (email, domain, IP, etc).
pub fn entity_classifier_actor() -> Arc<dyn MethodActor> {
    let metadata = ActorMetadata::new("entity_classifier", "Classify Entity Types")
        .with_cost_estimate(12);
    Arc::new(FunctionActor::new(metadata, Arc::new(|items| {
        Ok(items
            .into_iter()
            .map(|item| {
                let kind = if item.contains('@') && item.contains('.') {
                    "email"
                } else if item.contains('.') && !item.starts_with('.') && !item.ends_with('.') {
                    "domain"
                } else if item.chars().all(|c| c.is_numeric() || c == '.') {
                    "ip"
                } else if item.starts_with('+') || item.chars().all(|c| c.is_numeric()) {
                    "phone"
                } else {
                    "other"
                };
                format!("{}:{}", kind, item)
            })
            .collect())
    })))
}

/// Create an actor that extracts organization indicators from text.
pub fn organization_extractor_actor() -> Arc<dyn MethodActor> {
    let metadata = ActorMetadata::new("org_extractor", "Extract Organizations")
        .with_cost_estimate(15);
    Arc::new(FunctionActor::new(metadata, Arc::new(|items| {
        Ok(items
            .into_iter()
            .filter_map(|item| {
                if item.contains('.') && (item.ends_with(".com") || item.ends_with(".org") || item.ends_with(".net")) {
                    Some(item.clone())
                } else if item.contains('@') {
                    item.split('@').nth(1).map(|d| d.to_string())
                } else {
                    None
                }
            })
            .collect())
    })))
}

/// Create an actor that validates contact information.
pub fn contact_validator_actor() -> Arc<dyn MethodActor> {
    let metadata = ActorMetadata::new("contact_validator", "Validate Contact Info")
        .with_cost_estimate(10);
    Arc::new(FunctionActor::new(metadata, Arc::new(|items| {
        Ok(items
            .into_iter()
            .filter(|item| {
                let is_email = item.contains('@') && item.contains('.');
                let is_phone = item.starts_with('+') ||
                    (item.chars().filter(|c| c.is_numeric()).count() >= 7);
                let is_domain = item.contains('.') && !item.contains('@');

                is_email || is_phone || is_domain
            })
            .collect())
    })))
}

/// Create an actor that normalizes URLs to canonical form.
pub fn url_normalizer_actor() -> Arc<dyn MethodActor> {
    let metadata = ActorMetadata::new("url_normalizer", "Normalize URLs")
        .with_cost_estimate(12);
    Arc::new(FunctionActor::new(metadata, Arc::new(|items| {
        Ok(items
            .into_iter()
            .map(|url| {
                let normalized = if url.starts_with("http://") || url.starts_with("https://") {
                    url
                } else if url.contains("://") {
                    url
                } else {
                    format!("https://{}", url)
                };
                normalized.to_lowercase()
            })
            .collect())
    })))
}

/// Create an actor that extracts hostnames from URLs.
pub fn hostname_extractor_actor() -> Arc<dyn MethodActor> {
    let metadata = ActorMetadata::new("hostname_extractor", "Extract Hostnames")
        .with_cost_estimate(10);
    Arc::new(FunctionActor::new(metadata, Arc::new(|items| {
        Ok(items
            .into_iter()
            .filter_map(|item| {
                if item.contains("://") {
                    let after_protocol = item.split("://").nth(1)?;
                    let before_path = after_protocol.split('/').next()?;
                    let hostname = before_path.split(':').next()?.to_string();
                    Some(hostname)
                } else {
                    None
                }
            })
            .collect())
    })))
}

/// Create an actor that filters known false positives.
pub fn false_positive_filter_actor() -> Arc<dyn MethodActor> {
    let metadata = ActorMetadata::new("fp_filter", "Filter False Positives")
        .with_cost_estimate(8);
    Arc::new(FunctionActor::new(metadata, Arc::new(|items| {
        let fp_patterns = [
            "example.com",
            "localhost",
            "127.0.0.1",
            "0.0.0.0",
            "::1",
            "test@",
            "admin@",
            "noreply@",
            "no-reply@",
            "placeholder",
            "sample",
            "demo",
        ];

        Ok(items
            .into_iter()
            .filter(|item| {
                !fp_patterns.iter().any(|&fp| item.contains(fp))
            })
            .collect())
    })))
}

/// Create an actor that validates domain registries.
pub fn domain_registry_validator_actor() -> Arc<dyn MethodActor> {
    let metadata = ActorMetadata::new("domain_registry", "Validate Domain Registry")
        .with_cost_estimate(10);
    Arc::new(FunctionActor::new(metadata, Arc::new(|items| {
        let tlds = [
            ".com", ".org", ".net", ".io", ".co", ".uk", ".au", ".de", ".fr",
            ".jp", ".cn", ".ru", ".in", ".br", ".mx", ".edu", ".gov",
        ];

        Ok(items
            .into_iter()
            .filter(|item| {
                tlds.iter().any(|&tld| item.ends_with(tld))
            })
            .collect())
    })))
}

/// Create an actor that extracts evidence snippets (truncated for context).
pub fn evidence_snippet_actor(max_length: usize) -> Arc<dyn MethodActor> {
    let metadata = ActorMetadata::new("evidence_snippet", "Extract Evidence Snippets")
        .with_cost_estimate(6);
    Arc::new(FunctionActor::new(metadata, Arc::new(move |items| {
        Ok(items
            .into_iter()
            .map(|item| {
                if item.len() > max_length {
                    format!("{}...", &item[..max_length])
                } else {
                    item
                }
            })
            .collect())
    })))
}

/// Create an actor that resolves entity relationships (simple heuristic).
pub fn relationship_resolver_actor() -> Arc<dyn MethodActor> {
    let metadata = ActorMetadata::new("relationship_resolver", "Resolve Relationships")
        .with_cost_estimate(20);
    Arc::new(FunctionActor::new(metadata, Arc::new(|items| {
        Ok(items
            .into_iter()
            .flat_map(|item| {
                let mut relations = vec![item.clone()];

                if item.contains('@') {
                    if let Some(domain) = item.split('@').nth(1) {
                        relations.push(format!("domain:{}", domain));
                        relations.push(format!("email_of:{}", domain));
                    }
                }

                if item.contains('.') && !item.contains('@') {
                    relations.push(format!("hosted_on:{}", item));
                    if let Some(root) = item.split('.').nth(0) {
                        relations.push(format!("subdomain_of:{}", root));
                    }
                }

                relations
            })
            .collect())
    })))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::method_actor::PipelineBuilder;

    #[test]
    fn test_entity_classifier() {
        let actor = entity_classifier_actor();
        let result = actor
            .process(vec![
                "user@example.com".to_string(),
                "example.com".to_string(),
                "test123".to_string(),
            ])
            .unwrap();
        assert_eq!(result.len(), 3);
        assert!(result[0].contains("email:"));
        assert!(result[1].contains("domain:"));
        assert_eq!(result.len(), 3);
    }

    #[test]
    fn test_contact_validator() {
        let actor = contact_validator_actor();
        let result = actor
            .process(vec![
                "user@example.com".to_string(),
                "+1234567890".to_string(),
                "invalid".to_string(),
                "example.com".to_string(),
            ])
            .unwrap();
        assert_eq!(result.len(), 3);
    }

    #[test]
    fn test_false_positive_filter() {
        let actor = false_positive_filter_actor();
        let result = actor
            .process(vec![
                "john@realdomain.com".to_string(),
                "test@localhost".to_string(),
                "alice@legitimate.org".to_string(),
            ])
            .unwrap();
        assert!(result.len() >= 1);
    }

    #[test]
    fn test_osint_investigation_pipeline() {
        let pipeline = PipelineBuilder::new()
            .add_actor(entity_classifier_actor())
            .add_actor(false_positive_filter_actor())
            .add_actor(contact_validator_actor())
            .build()
            .unwrap();

        let result = pipeline
            .execute(vec![
                "user@legitimate.com".to_string(),
                "info@verified.io".to_string(),
                "contact@business.org".to_string(),
            ])
            .unwrap();

        assert!(!result.output.is_empty());
        assert_eq!(result.stages.len(), 3);
    }

    #[test]
    fn test_url_normalization_pipeline() {
        let pipeline = PipelineBuilder::new()
            .add_actor(url_normalizer_actor())
            .add_actor(hostname_extractor_actor())
            .build()
            .unwrap();

        let result = pipeline
            .execute(vec![
                "HTTP://EXAMPLE.COM/path".to_string(),
                "https://test.org:8080/api".to_string(),
            ])
            .unwrap();

        assert!(!result.output.is_empty());
    }
}
