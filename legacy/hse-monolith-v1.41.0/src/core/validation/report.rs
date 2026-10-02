/// Result of running one or more validators against an entity value.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ValidationReport {
    /// Whether the value passed every validator the caller ran.
    pub valid: bool,
    /// Machine-readable reason code on failure (empty when `valid`).
    pub reason: &'static str,
    /// Human-readable detail string. May be empty on success.
    pub detail: String,
}

impl ValidationReport {
    pub fn ok() -> Self {
        Self {
            valid: true,
            reason: "",
            detail: String::new(),
        }
    }

    pub fn fail(reason: &'static str, detail: impl Into<String>) -> Self {
        Self {
            valid: false,
            reason,
            detail: detail.into(),
        }
    }
}
