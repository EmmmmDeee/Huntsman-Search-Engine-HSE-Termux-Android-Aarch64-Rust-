//! General-purpose method actors: cleaning, normalisation and shape filters.
//!
//! Email and domain checks delegate to the crate's shared syntax rules. Lengths are
//! counted in characters, never bytes.

use std::sync::Arc;

use crate::method_actor::{ActorMetadata, FunctionActor, MethodActor};

/// Create an actor that filters empty or whitespace-only strings.
#[must_use]
pub fn whitespace_filter_actor() -> Arc<dyn MethodActor> {
    let metadata =
        ActorMetadata::new("whitespace_filter", "Filter Empty Values").with_cost_estimate(5);
    Arc::new(FunctionActor::new(
        metadata,
        Arc::new(|items| Ok(items.into_iter().filter(|s| !s.trim().is_empty()).collect())),
    ))
}

/// Create an actor that normalizes values to lowercase.
#[must_use]
pub fn lowercase_normalizer_actor() -> Arc<dyn MethodActor> {
    let metadata =
        ActorMetadata::new("lowercase_normalizer", "Normalize to Lowercase").with_cost_estimate(8);
    Arc::new(FunctionActor::new(
        metadata,
        Arc::new(|items| Ok(items.into_iter().map(|s| s.to_lowercase()).collect())),
    ))
}

/// Create an actor that drops every repeat of a value already seen in the batch.
#[must_use]
pub fn deduplication_actor() -> Arc<dyn MethodActor> {
    let metadata = ActorMetadata::new("deduplicator", "Deduplicate Values").with_cost_estimate(15);
    Arc::new(FunctionActor::new(
        metadata,
        Arc::new(|items| {
            let mut seen = std::collections::HashSet::new();
            Ok(items
                .into_iter()
                .filter(|item| seen.insert(item.clone()))
                .collect())
        }),
    ))
}

/// Create an actor that validates email format.
#[must_use]
pub fn email_validator_actor() -> Arc<dyn MethodActor> {
    let metadata =
        ActorMetadata::new("email_validator", "Validate Email Format").with_cost_estimate(12);
    Arc::new(FunctionActor::new(
        metadata,
        Arc::new(|items| {
            Ok(items
                .into_iter()
                .filter(|email| crate::validation::validate_email_syntax(email).valid)
                .collect())
        }),
    ))
}

/// Create an actor that validates domain format.
#[must_use]
pub fn domain_validator_actor() -> Arc<dyn MethodActor> {
    let metadata =
        ActorMetadata::new("domain_validator", "Validate Domain Format").with_cost_estimate(10);
    Arc::new(FunctionActor::new(
        metadata,
        Arc::new(|items| {
            Ok(items
                .into_iter()
                .filter(|domain| crate::value_syntax::canonical_domain(domain).is_some())
                .collect())
        }),
    ))
}

/// Create an actor that emits the lowercase domain of each syntactically valid email.
#[must_use]
pub fn email_domain_extractor_actor() -> Arc<dyn MethodActor> {
    let metadata = ActorMetadata::new("email_domain_extractor", "Extract Domain from Email")
        .with_cost_estimate(8);
    Arc::new(FunctionActor::new(
        metadata,
        Arc::new(|items| {
            Ok(items
                .into_iter()
                .filter(|email| crate::validation::validate_email_syntax(email).valid)
                .filter_map(|email| {
                    email
                        .rsplit_once('@')
                        .and_then(|(_, host)| crate::value_syntax::canonical_domain(host))
                })
                .collect())
        }),
    ))
}

/// Create an actor that truncates values to a maximum length.
#[must_use]
pub fn truncation_actor(max_length: usize) -> Arc<dyn MethodActor> {
    let metadata = ActorMetadata::new("truncator", "Truncate Values").with_cost_estimate(6);
    Arc::new(FunctionActor::new(
        metadata,
        Arc::new(move |items| {
            Ok(items
                .into_iter()
                .map(|s| match s.char_indices().nth(max_length) {
                    Some((cut, _)) => s[..cut].to_string(),
                    None => s,
                })
                .collect())
        }),
    ))
}

/// Create an actor that filters values by a length range.
#[must_use]
pub fn length_filter_actor(min_length: usize, max_length: usize) -> Arc<dyn MethodActor> {
    let metadata = ActorMetadata::new("length_filter", "Filter by Length").with_cost_estimate(5);
    Arc::new(FunctionActor::new(
        metadata,
        Arc::new(move |items| {
            Ok(items
                .into_iter()
                .filter(|s| (min_length..=max_length).contains(&s.chars().count()))
                .collect())
        }),
    ))
}

/// Create an actor that validates against a pattern (case-insensitive substring match).
#[must_use]
pub fn pattern_filter_actor(pattern: &str) -> Arc<dyn MethodActor> {
    let metadata = ActorMetadata::new("pattern_filter", "Filter by Pattern").with_cost_estimate(15);
    let pattern_lower = pattern.to_lowercase();
    Arc::new(FunctionActor::new(
        metadata,
        Arc::new(move |items| {
            Ok(items
                .into_iter()
                .filter(|s| s.to_lowercase().contains(&pattern_lower))
                .collect())
        }),
    ))
}

/// Create an actor that removes common TLDs from domains.
#[must_use]
pub fn tld_stripper_actor() -> Arc<dyn MethodActor> {
    let metadata = ActorMetadata::new("tld_stripper", "Strip Common TLDs").with_cost_estimate(8);
    let tlds = [".com", ".org", ".net", ".io", ".co", ".edu", ".gov"];
    Arc::new(FunctionActor::new(
        metadata,
        Arc::new(move |items| {
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
        }),
    ))
}

/// Create an actor that adds a prefix to each value.
#[must_use]
pub fn prefix_actor(prefix: String) -> Arc<dyn MethodActor> {
    let metadata = ActorMetadata::new("prefix_actor", "Add Prefix").with_cost_estimate(6);
    Arc::new(FunctionActor::new(
        metadata,
        Arc::new(move |items| Ok(items.into_iter().map(|s| format!("{prefix}{s}")).collect())),
    ))
}

/// Create an actor that adds a suffix to each value.
#[must_use]
pub fn suffix_actor(suffix: String) -> Arc<dyn MethodActor> {
    let metadata = ActorMetadata::new("suffix_actor", "Add Suffix").with_cost_estimate(6);
    Arc::new(FunctionActor::new(
        metadata,
        Arc::new(move |items| Ok(items.into_iter().map(|s| format!("{s}{suffix}")).collect())),
    ))
}

/// Create an actor that replaces whitespace with a separator.
#[must_use]
pub fn whitespace_normalizer_actor(separator: String) -> Arc<dyn MethodActor> {
    let metadata =
        ActorMetadata::new("whitespace_normalizer", "Normalize Whitespace").with_cost_estimate(10);
    Arc::new(FunctionActor::new(
        metadata,
        Arc::new(move |items| {
            Ok(items
                .into_iter()
                .map(|s| s.split_whitespace().collect::<Vec<_>>().join(&separator))
                .collect())
        }),
    ))
}

/// Create an actor that counts characters (represented as "length:value").
#[must_use]
pub fn char_counter_actor() -> Arc<dyn MethodActor> {
    let metadata = ActorMetadata::new("char_counter", "Count Characters").with_cost_estimate(5);
    Arc::new(FunctionActor::new(
        metadata,
        Arc::new(|items| {
            Ok(items
                .into_iter()
                .map(|s| format!("{}:{s}", s.chars().count()))
                .collect())
        }),
    ))
}

/// Create an actor that recovers the value from "length:value"; the value may contain `:`.
#[must_use]
pub fn char_counter_parser_actor() -> Arc<dyn MethodActor> {
    let metadata =
        ActorMetadata::new("char_counter_parser", "Parse Character Count").with_cost_estimate(8);
    Arc::new(FunctionActor::new(
        metadata,
        Arc::new(|items| {
            Ok(items
                .into_iter()
                .filter_map(|s| s.split_once(':').map(|(_, value)| value.to_string()))
                .collect())
        }),
    ))
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
                String::new(),
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

    #[test]
    fn email_and_domain_checks_use_the_shared_syntax_rules() {
        let emails = email_validator_actor()
            .process(vec![
                "ada@analytical.org".to_string(),
                ".ada@analytical.org".to_string(),
                "ada@@analytical.org".to_string(),
                "a@b.co".to_string(),
            ])
            .unwrap();
        assert_eq!(
            emails,
            vec!["ada@analytical.org".to_string(), "a@b.co".to_string()]
        );

        let domains = domain_validator_actor()
            .process(vec![
                "analytical.org".to_string(),
                "bad..org".to_string(),
                "-x.org".to_string(),
            ])
            .unwrap();
        assert_eq!(domains, vec!["analytical.org".to_string()]);

        let extracted = email_domain_extractor_actor()
            .process(vec![
                "Ada@Analytical.ORG".to_string(),
                "not-an-email".to_string(),
            ])
            .unwrap();
        assert_eq!(extracted, vec!["analytical.org".to_string()]);
    }

    #[test]
    fn lengths_count_characters_and_round_trip_values_with_colons() {
        let truncated = truncation_actor(3)
            .process(vec!["Zoë Å".to_string()])
            .unwrap();
        assert_eq!(truncated, vec!["Zoë".to_string()]);

        let filtered = length_filter_actor(3, 3)
            .process(vec!["Zoë".to_string()])
            .unwrap();
        assert_eq!(filtered, vec!["Zoë".to_string()]);

        let pipeline = PipelineBuilder::new()
            .add_actor(char_counter_actor())
            .add_actor(char_counter_parser_actor())
            .build()
            .unwrap();
        let url = "https://analytical.org:8443/notes".to_string();
        assert_eq!(
            pipeline.execute(vec![url.clone()]).unwrap().output,
            vec![url]
        );
        assert_eq!(
            char_counter_actor()
                .process(vec!["Zoë".to_string()])
                .unwrap(),
            vec!["3:Zoë".to_string()]
        );
    }
}
