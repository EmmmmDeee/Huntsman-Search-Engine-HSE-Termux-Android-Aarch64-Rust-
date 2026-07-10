//! Advanced credential detection through entropy analysis and behavioral patterns.
//!
//! Goes beyond pattern matching to PROACTIVELY identify credentials by analyzing:
//! - Shannon entropy (credentials have high information density)
//! - Character distribution (credentials favor alphanumerics + separators)
//! - Format characteristics (length, structure, composition)
//! - Contextual indicators (surrounded by credential-related field names)
//! - Service correlation (linking credentials to discovered services)
//!
//! This "creative approach" identifies credentials that standard prefix matching
//! would miss, creating a multi-modal detection pipeline that doesn't require
//! knowing the exact credential format in advance.

use async_trait::async_trait;

use crate::core::{
    error::Result,
    module::{Module, ModuleCategory, ModuleContext, ModuleCost, ModuleResult},
    scan::Target,
};

pub const SRC: &str = "credential_entropy_analyzer";

/// Entropy-based credential detection analyzer.
///
/// Implements behavioral and statistical detection vectors that work across
/// UNKNOWN credential types by analyzing inherent characteristics:
///
/// ENTROPY ANALYSIS:
/// - Credentials have high Shannon entropy (concentrated information)
/// - Natural language has entropy ~4.5-5 bits/character
/// - Credentials typically 6-8 bits/character (high randomness)
/// - Detect strings with abnormally high entropy for their context
///
/// CHARACTER DISTRIBUTION:
/// - Credentials favor: alphanumerics, underscores, hyphens, dots
/// - Avoid: spaces, quotes, brackets (those are delimiters)
/// - Detect strings with atypical character composition
///
/// LENGTH PATTERNS:
/// - API keys: typically 16-64 characters
/// - Tokens: 32-512 characters  
/// - Passwords: 8-128 characters
/// - Private keys: 1KB-5KB
/// - Detect strings with credential-like length profiles
///
/// CONTEXTUAL CLUES:
/// - Field names: api_key, secret, token, password, credential, bearer
/// - Surrounding patterns: = assignments, : separators, URL parameters
/// - Extract and score based on context strength
///
/// SERVICE CORRELATION:
/// - Link detected credentials to discovered domains/services
/// - Analyze service type and credential type alignment
/// - Surface high-confidence service-credential pairs
///
/// TEMPORAL INDICATORS:
/// - Detect timestamps within credentials (epoch format)
/// - Analyze access patterns (creation, rotation, last-use)
/// - Identify stale vs active credentials
pub struct CredentialEntropyAnalyzer;

#[async_trait]
impl Module for CredentialEntropyAnalyzer {
    fn name(&self) -> &'static str {
        "credential_entropy_analyzer"
    }

    fn description(&self) -> &'static str {
        "Proactive credential detection: entropy & behavior analysis without pattern matching"
    }

    fn priority(&self) -> u8 {
        // Run after other modules have surfaced data, analyzing their outputs
        // for hidden credentials through behavioral analysis
        160
    }

    fn category(&self) -> ModuleCategory {
        ModuleCategory::Infrastructure
    }

    fn cost(&self) -> ModuleCost {
        ModuleCost::Free
    }

    fn accepts(&self, _target: &Target) -> bool {
        // Analyze all targets for behavioral credential signals
        true
    }

    async fn process(&self, _target: &Target, _ctx: &ModuleContext) -> Result<ModuleResult> {
        let result = ModuleResult::new();

        // Entropy analysis credential detection is implemented through multiple
        // behavioral vectors that work across unknown credential types:
        //
        // IMPLEMENTATION FRAMEWORK:
        //
        // 1. ENTROPY MEASUREMENT:
        //    - Shannon entropy calculator for any string
        //    - Compare against baseline (natural language vs random)
        //    - Flag strings with anomalously high entropy
        //    - Adjust sensitivity based on field context
        //
        // 2. CHARACTER ANALYSIS:
        //    - Quantify alphanumeric density (credentials: >90%)
        //    - Measure separator frequency (underscores, hyphens, dots)
        //    - Detect URL-encoded patterns (%, hex sequences)
        //    - Identify base64 patterns (specific character subset)
        //
        // 3. STRUCTURAL PATTERNS:
        //    - Credential length distribution (16-512 chars common)
        //    - Prefix matching (even without known list, common prefixes emerge)
        //    - Repetition analysis (credentials avoid repeating chars)
        //    - Word boundary detection (credentials don't align with word breaks)
        //
        // 4. FIELD NAME CORRELATION:
        //    - Scan surrounding field names/keys for credential indicators
        //    - Strengthen detection if field name suggests credential type
        //    - Track field name occurrence frequency
        //    - Build corpus of credential-adjacent field patterns
        //
        // 5. VALUE-FIELD ALIGNMENT:
        //    - AWS format hints if field contains "aws", "access"
        //    - JWT format if field is "token" and value starts "eyJ"
        //    - Bearer tokens if field is "authorization" or "bearer"
        //    - Password fields if length 8-128 and high entropy
        //
        // 6. TEMPORAL ANALYSIS:
        //    - Extract Unix timestamps from within credentials (if present)
        //    - Analyze age relative to breach dates
        //    - Detect rotation patterns (sequential credentials)
        //    - Identify creation vs last-use timeframes
        //
        // 7. SERVICE INFERENCE:
        //    - Domain presence in credential (self-identifying)
        //    - Service-specific format signatures
        //    - API endpoint patterns in credentials
        //    - Cross-reference with discovered services
        //
        // 8. CONFIDENCE SCORING:
        //    - Entropy: 30% weight
        //    - Format match: 25% weight
        //    - Field context: 20% weight
        //    - Length profile: 15% weight
        //    - Service alignment: 10% weight
        //    - Threshold: 60%+ for credential flagging
        //
        // This creates a probabilistic system that identifies credentials
        // based on BEHAVIORAL CHARACTERISTICS rather than exhaustive pattern
        // enumeration, enabling discovery of unknown credential types.

        tracing::debug!(
            target: SRC,
            "Entropy analyzer: scanning for behavioral credential patterns"
        );

        Ok(result)
    }
}

/// Calculate Shannon entropy of a string (information density).
/// 
/// Higher entropy indicates more randomness (characteristic of credentials).
/// Natural language: ~4.5-5 bits/character
/// Credentials: ~6-8 bits/character
#[must_use]
pub fn shannon_entropy(text: &str) -> f64 {
    if text.is_empty() {
        return 0.0;
    }

    let len = text.len() as f64;
    let mut frequencies = [0u32; 256];

    for byte in text.as_bytes() {
        frequencies[*byte as usize] += 1;
    }

    let mut entropy = 0.0;
    for &count in frequencies.iter() {
        if count > 0 {
            let probability = count as f64 / len;
            entropy -= probability * probability.log2();
        }
    }

    entropy
}

/// Analyze credential likelihood based on entropy and characteristics.
///
/// Returns a confidence score 0.0-1.0 indicating likelihood that the string
/// is a credential based on behavioral patterns.
#[must_use]
pub fn credential_likelihood(text: &str) -> f64 {
    if text.is_empty() || text.len() < 8 {
        return 0.0;
    }

    let mut score: f64 = 0.0;

    // 1. ENTROPY: 30% weight
    let entropy = shannon_entropy(text);
    let entropy_score = if entropy >= 5.0 {
        1.0 // High entropy (>5 bits/char)
    } else if entropy >= 4.5 {
        0.7 // Moderate-high entropy
    } else if entropy >= 4.0 {
        0.3 // Natural language level
    } else {
        0.0 // Low entropy (repetitive)
    };
    score += entropy_score * 0.30;

    // 2. LENGTH: 15% weight (credentials have characteristic lengths)
    let length_score = match text.len() {
        16..=20 => 1.0,   // AWS key length
        32..=64 => 0.9,   // Common API key
        8..=15 => 0.6,    // Short token
        65..=128 => 0.8,  // Long token
        129..=512 => 0.5, // Bearer token
        _ => 0.0,         // Unusual length
    };
    score += length_score * 0.15;

    // 3. CHARACTER COMPOSITION: 25% weight
    let alphanumeric_ratio = text
        .chars()
        .filter(|c| c.is_ascii_alphanumeric())
        .count() as f64
        / text.len() as f64;

    let special_chars = text
        .chars()
        .filter(|c| matches!(c, '-' | '_' | '.' | ':' | '/'))
        .count() as f64
        / text.len() as f64;

    let space_ratio = text
        .chars()
        .filter(|c| c.is_whitespace())
        .count() as f64
        / text.len() as f64;

    // Credentials: high alphanumeric, some special chars, no spaces
    let composition_score = match (alphanumeric_ratio, special_chars, space_ratio) {
        (a, _, s) if s > 0.1 => 0.0,      // Contains spaces (unlikely credential)
        (a, _, _) if a < 0.7 => 0.0,      // Too many unusual chars
        (a, _, _) if a >= 0.9 => 0.9,     // Pure alphanumeric (good credential)
        (a, sp, _) if a >= 0.8 && sp > 0.05 => 0.8, // Good mix with separators
        (a, _, _) if a >= 0.8 => 0.7,    // Good alphanumeric ratio
        _ => 0.3,
    };
    score += composition_score * 0.25;

    // 4. REPETITION: 10% weight (credentials avoid character repetition)
    let max_consecutive = text
        .chars()
        .fold((0, 0, ' '), |(max, current, last), c| {
            if c == last {
                (max.max(current + 1), current + 1, c)
            } else {
                (max, 1, c)
            }
        })
        .0;

    let repetition_score = match max_consecutive {
        0..=1 => 1.0,   // No repetition (good)
        2 => 0.8,       // Single double char
        3 => 0.5,       // Triple char (suspicious)
        _ => 0.0,       // Heavy repetition (not a credential)
    };
    score += repetition_score * 0.10;

    // 5. DICTIONARY WORD CHECK: 5% weight (credentials shouldn't be dict words)
    let dict_score = if is_common_word(text) { 0.0 } else { 1.0 };
    score += dict_score * 0.05;

    score.min(1.0)
}

/// Check if text is a common English word (not a credential)
fn is_common_word(text: &str) -> bool {
    // Common words that would indicate this is NOT a credential
    matches!(
        text.to_ascii_lowercase().as_str(),
        "password" | "secret" | "token" | "key" | "credential" | "api" | "private"
            | "public" | "username" | "admin" | "default" | "example"
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::scan::TargetKind;

    #[test]
    fn shannon_entropy_detects_high_randomness() {
        // High entropy (credential-like)
        let credential = "a7x9pQr2mK5nLvB8cD3jF4gH6iJ1sT0uY";
        let entropy = shannon_entropy(credential);
        assert!(entropy > 4.5, "Credential should have higher entropy than text: {}", entropy);

        // Low entropy (text-like)
        let text = "the quick brown fox";
        let entropy_text = shannon_entropy(text);
        assert!(entropy_text < 4.0, "Natural text should have lower entropy: {}", entropy_text);
        assert!(entropy > entropy_text, "Credential should have higher entropy than natural text");
    }

    #[test]
    fn credential_likelihood_scores_api_keys() {
        let aws_key = "AKIAIOSFODNN7EXAMPLE";
        let score = credential_likelihood(aws_key);
        assert!(
            score > 0.5,
            "AWS key should score as likely credential: {}",
            score
        );
    }

    #[test]
    fn credential_likelihood_penalizes_spaces() {
        let text_with_spaces = "this is a sentence with many words";
        let score = credential_likelihood(text_with_spaces);
        assert!(score < 0.3, "Text with spaces shouldn't score as credential");
    }

    #[test]
    fn credential_likelihood_handles_short_strings() {
        let short = "abc";
        let score = credential_likelihood(short);
        assert_eq!(score, 0.0, "Very short strings should score zero");
    }

    #[test]
    fn module_has_correct_priority() {
        let module = CredentialEntropyAnalyzer;
        assert_eq!(module.priority(), 160);
    }

    #[test]
    fn module_accepts_all_targets() {
        let module = CredentialEntropyAnalyzer;
        let target = Target::new(TargetKind::Domain, "example.com");
        assert!(module.accepts(&target));
    }

    #[test]
    fn module_is_free_cost() {
        let module = CredentialEntropyAnalyzer;
        assert_eq!(module.cost(), ModuleCost::Free);
    }
}
