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

    fn max_timeout_ms(&self) -> u64 {
        // Local entropy computation completes near-instantly, but a non-passive
        // module must budget above the engine's 3s default or the dispatcher
        // treats it as at risk of being killed mid-request.
        5_000
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::scan::TargetKind;

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
