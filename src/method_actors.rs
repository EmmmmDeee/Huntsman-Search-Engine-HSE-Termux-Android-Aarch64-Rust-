//! Concrete method actors for common Huntsman processing tasks.
//!
//! Provides pre-built actors for entity classification, normalization, validation,
//! and enrichment that can be composed into investigation pipelines.

use std::sync::Arc;

use crate::method_actor::{ActorMetadata, FunctionActor, MethodActor};

/// Create an actor that filters empty or whitespace-only strings.
pub fn whitespace_filter_actor() -> Arc<dyn MethodActor> {
    let metadata = ActorMetadata::new("whitespace_filter", "Filter Empty Values")
        .with_cost_estimate(5);
    Arc::new(FunctionActor::new(metadata, Arc::new(|items| {
        Ok(items.into_iter().filter(|s| !s.trim().is_empty()).collect())
    })))
}

/// Create an actor that normalizes values to lowercase.
pub fn lowercase_normalizer_actor() -> Arc<dyn MethodActor> {
    let metadata = ActorMetadata::new("lowercase_normalizer", "Normalize to Lowercase")
        .with_cost_estimate(8);
    Arc::new(FunctionActor::new(metadata, Arc::new(|items| {
        Ok(items.into_iter().map(|s| s.to_lowercase()).collect())
    })))
}

/// Create an actor that deduplicates consecutive identical values.
pub fn deduplication_actor() -> Arc<dyn MethodActor> {
    let metadata = ActorMetadata::new("deduplicator", "Deduplicate Values")
        .with_cost_estimate(15);
    Arc::new(FunctionActor::new(metadata, Arc::new(|items| {
        let mut seen = std::collections::HashSet::new();
        Ok(items
            .into_iter()
            .filter(|item| seen.insert(item.clone()))
            .collect())
    })))
}

/// Create an actor that validates email format.
pub fn email_validator_actor() -> Arc<dyn MethodActor> {
    let metadata = ActorMetadata::new("email_validator", "Validate Email Format")
        .with_cost_estimate(12);
    Arc::new(FunctionActor::new(metadata, Arc::new(|items| {
        Ok(items
            .into_iter()
            .filter(|email| {
                email.contains('@') && email.contains('.') && email.len() > 5
            })
            .collect())
    })))
}

/// Create an actor that validates domain format.
pub fn domain_validator_actor() -> Arc<dyn MethodActor> {
    let metadata = ActorMetadata::new("domain_validator", "Validate Domain Format")
        .with_cost_estimate(10);
    Arc::new(FunctionActor::new(metadata, Arc::new(|items| {
        Ok(items
            .into_iter()
            .filter(|domain| {
                domain.contains('.') && !domain.starts_with('.') && !domain.ends_with('.')
            })
            .collect())
    })))
}

/// Create an actor that extracts domains from email addresses.
pub fn email_domain_extractor_actor() -> Arc<dyn MethodActor> {
    let metadata = ActorMetadata::new("email_domain_extractor", "Extract Domain from Email")
        .with_cost_estimate(8);
    Arc::new(FunctionActor::new(metadata, Arc::new(|items| {
        Ok(items
            .into_iter()
            .filter_map(|email| {
                email.split('@').nth(1).map(|d| d.to_string())
            })
            .collect())
    })))
}

/// Create an actor that truncates values to a maximum length.
pub fn truncation_actor(max_length: usize) -> Arc<dyn MethodActor> {
    let metadata = ActorMetadata::new("truncator", "Truncate Values")
        .with_cost_estimate(6);
    Arc::new(FunctionActor::new(metadata, Arc::new(move |items| {
        Ok(items
            .into_iter()
            .map(|s| {
                if s.len() > max_length {
                    s.chars().take(max_length).collect()
                } else {
                    s
                }
            })
            .collect())
    })))
}

/// Create an actor that filters values by a length range.
pub fn length_filter_actor(min_length: usize, max_length: usize) -> Arc<dyn MethodActor> {
    let metadata = ActorMetadata::new("length_filter", "Filter by Length")
        .with_cost_estimate(5);
    Arc::new(FunctionActor::new(
        metadata,
        Arc::new(move |items| {
            Ok(items
                .into_iter()
                .filter(|s| s.len() >= min_length && s.len() <= max_length)
                .collect())
        }),
    ))
}

/// Create an actor that validates against a pattern (case-insensitive substring match).
pub fn pattern_filter_actor(pattern: String) -> Arc<dyn MethodActor> {
    let metadata = ActorMetadata::new("pattern_filter", "Filter by Pattern")
        .with_cost_estimate(15);
    let pattern_lower = pattern.to_lowercase();
    Arc::new(FunctionActor::new(metadata, Arc::new(move |items| {
        Ok(items
            .into_iter()
            .filter(|s| s.to_lowercase().contains(&pattern_lower))
            .collect())
    })))
}

/// Create an actor that removes common TLDs from domains.
pub fn tld_stripper_actor() -> Arc<dyn MethodActor> {
    let metadata = ActorMetadata::new("tld_stripper", "Strip Common TLDs")
        .with_cost_estimate(8);
    let tlds = [".com", ".org", ".net", ".io", ".co", ".edu", ".gov"];
    Arc::new(FunctionActor::new(metadata, Arc::new(move |items| {
        Ok(items
            .into_iter()
            .map(|domain| {
                let mut result = domain.clone();
                for tld in &tlds {
                    if result.ends_with(tld) {
                        result = result[..result.len() - tld.len()].to_string();
                        break;
                    }
                }
                result
            })
            .collect())
    })))
}

/// Create an actor that adds a prefix to each value.
pub fn prefix_actor(prefix: String) -> Arc<dyn MethodActor> {
    let metadata = ActorMetadata::new("prefix_actor", "Add Prefix")
        .with_cost_estimate(6);
    Arc::new(FunctionActor::new(metadata, Arc::new(move |items| {
        Ok(items
            .into_iter()
            .map(|s| format!("{}{}", prefix, s))
            .collect())
    })))
}

/// Create an actor that adds a suffix to each value.
pub fn suffix_actor(suffix: String) -> Arc<dyn MethodActor> {
    let metadata = ActorMetadata::new("suffix_actor", "Add Suffix")
        .with_cost_estimate(6);
    Arc::new(FunctionActor::new(metadata, Arc::new(move |items| {
        Ok(items
            .into_iter()
            .map(|s| format!("{}{}", s, suffix))
            .collect())
    })))
}

/// Create an actor that replaces whitespace with a separator.
pub fn whitespace_normalizer_actor(separator: String) -> Arc<dyn MethodActor> {
    let metadata = ActorMetadata::new("whitespace_normalizer", "Normalize Whitespace")
        .with_cost_estimate(10);
    Arc::new(FunctionActor::new(metadata, Arc::new(move |items| {
        Ok(items
            .into_iter()
            .map(|s| {
                s.split_whitespace()
                    .collect::<Vec<_>>()
                    .join(&separator)
            })
            .collect())
    })))
}

/// Create an actor that counts characters (represented as "length:value").
pub fn char_counter_actor() -> Arc<dyn MethodActor> {
    let metadata = ActorMetadata::new("char_counter", "Count Characters")
        .with_cost_estimate(5);
    Arc::new(FunctionActor::new(metadata, Arc::new(|items| {
        Ok(items
            .into_iter()
            .map(|s| format!("{}:{}", s.len(), s))
            .collect())
    })))
}

/// Create an actor that parses "length:value" format and recovers value.
pub fn char_counter_parser_actor() -> Arc<dyn MethodActor> {
    let metadata = ActorMetadata::new("char_counter_parser", "Parse Character Count")
        .with_cost_estimate(8);
    Arc::new(FunctionActor::new(metadata, Arc::new(|items| {
        Ok(items
            .into_iter()
            .filter_map(|s| s.split(':').nth(1).map(|v| v.to_string()))
            .collect())
    })))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::method_actor::PipelineBuilder;

    #[test]
    fn test_whitespace_filter() {
        let actor = whitespace_filter_actor();
        let result = actor
            .process(vec![
                "hello".to_string(),
                "   ".to_string(),
                "world".to_string(),
                "".to_string(),
            ])
            .unwrap();
        assert_eq!(result.len(), 2);
        assert_eq!(result, vec!["hello".to_string(), "world".to_string()]);
    }

    #[test]
    fn test_lowercase_normalizer() {
        let actor = lowercase_normalizer_actor();
        let result = actor
            .process(vec!["HELLO".to_string(), "World".to_string()])
            .unwrap();
        assert_eq!(result, vec!["hello".to_string(), "world".to_string()]);
    }

    #[test]
    fn test_deduplication() {
        let actor = deduplication_actor();
        let result = actor
            .process(vec![
                "a".to_string(),
                "b".to_string(),
                "a".to_string(),
                "c".to_string(),
                "b".to_string(),
            ])
            .unwrap();
        assert_eq!(result.len(), 3);
    }

    #[test]
    fn test_email_validator() {
        let actor = email_validator_actor();
        let result = actor
            .process(vec![
                "user@example.com".to_string(),
                "invalid".to_string(),
                "test@domain.org".to_string(),
            ])
            .unwrap();
        assert_eq!(result.len(), 2);
    }

    #[test]
    fn test_pipeline_with_multiple_actors() {
        let pipeline = PipelineBuilder::new()
            .add_actor(whitespace_filter_actor())
            .add_actor(lowercase_normalizer_actor())
            .add_actor(deduplication_actor())
            .build()
            .unwrap();

        let result = pipeline
            .execute(vec![
                "HELLO".to_string(),
                "hello".to_string(),
                "WORLD".to_string(),
            ])
            .unwrap();

        assert_eq!(result.output.len(), 2);
        assert_eq!(result.stages.len(), 3);
        assert!(result.total_duration_ms >= 0);
    }

    #[test]
    fn test_email_extraction_pipeline() {
        let pipeline = PipelineBuilder::new()
            .add_actor(email_validator_actor())
            .add_actor(email_domain_extractor_actor())
            .build()
            .unwrap();

        let result = pipeline
            .execute(vec![
                "alice@example.com".to_string(),
                "bob@test.org".to_string(),
                "notanemail".to_string(),
            ])
            .unwrap();

        assert_eq!(result.output.len(), 2);
        assert!(result.output.contains(&"example.com".to_string()));
        assert!(result.output.contains(&"test.org".to_string()));
    }

    #[test]
    fn test_truncation_actor() {
        let actor = truncation_actor(5);
        let result = actor
            .process(vec!["hello".to_string(), "verylongstring".to_string()])
            .unwrap();
        assert_eq!(result[0], "hello");
        assert_eq!(result[1], "veryl");
    }

    #[test]
    fn test_length_filter() {
        let actor = length_filter_actor(2, 5);
        let result = actor
            .process(vec![
                "a".to_string(),
                "ab".to_string(),
                "abc".to_string(),
                "abcdef".to_string(),
            ])
            .unwrap();
        assert_eq!(result.len(), 2);
        assert_eq!(result, vec!["ab".to_string(), "abc".to_string()]);
    }
}
