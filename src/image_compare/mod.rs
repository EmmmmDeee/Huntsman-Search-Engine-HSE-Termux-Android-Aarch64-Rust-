//! Compare two operator-supplied images. Findings describe their pixels and original bytes.
mod matching;
mod photo;

use serde::Serialize;

use crate::entity::{Entity, EntityKind, Evidence, EvidenceProvenance};
use crate::source_outcome::SourceExecutionOutcome;

pub use photo::MAX_FILE_BYTES;
pub const SOURCE: &str = "image_compare";

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Verdict {
    IdenticalFile,
    SameFrame,
    NoVerifiedMatch,
}

impl Verdict {
    fn label(self) -> &'static str {
        match self {
            Self::IdenticalFile => "Identical file",
            Self::SameFrame => "Same frame",
            Self::NoVerifiedMatch => "No verified match",
        }
    }

    fn id(self) -> &'static str {
        match self {
            Self::IdenticalFile => "identical_file",
            Self::SameFrame => "same_frame",
            Self::NoVerifiedMatch => "no_verified_match",
        }
    }
}

#[derive(Clone, Debug, Serialize)]
pub struct ImageFile {
    pub sha256: String,
    pub bytes: usize,
    pub width: u32,
    pub height: u32,
}

#[derive(Clone, Debug, Serialize)]
pub struct Comparison {
    pub verdict: Verdict,
    pub method: &'static str,
    pub detail: String,
    pub scope: &'static str,
    pub reference: ImageFile,
    pub candidate: ImageFile,
}

impl Comparison {
    #[must_use]
    pub fn text(&self) -> String {
        format!(
            "{}\n{}\n{}\n{}\nReference SHA-256 {} ({} × {}, {} bytes)\nCandidate SHA-256 {} ({} × {}, {} bytes)",
            self.verdict.label(),
            self.method,
            self.detail,
            self.scope,
            self.reference.sha256,
            self.reference.width,
            self.reference.height,
            self.reference.bytes,
            self.candidate.sha256,
            self.candidate.width,
            self.candidate.height,
            self.candidate.bytes,
        )
    }

    /// A local observation anchors both original hashes and the operator's unverified source notes.
    #[must_use]
    pub fn observation(
        &self,
        reference_name: &str,
        candidate_name: &str,
        source_page: Option<&str>,
        asset_url: Option<&str>,
        now_unix: u64,
    ) -> Entity {
        let mut provenance = EvidenceProvenance::new(SOURCE);
        provenance.recorded_at_unix = now_unix;
        let mut evidence = Evidence::new(provenance, self.verdict.label())
            .with_attr("comparison_verdict", self.verdict.id())
            .with_attr("comparison_method", self.method)
            .with_attr("comparison_detail", &self.detail)
            .with_attr("comparison_scope", self.scope)
            .with_attr("reference_name", reference_name)
            .with_attr("reference_sha256", &self.reference.sha256)
            .with_attr(
                "reference_dimensions",
                format!("{}×{}", self.reference.width, self.reference.height),
            )
            .with_attr("reference_bytes", self.reference.bytes.to_string())
            .with_attr("candidate_name", candidate_name)
            .with_attr("candidate_sha256", &self.candidate.sha256)
            .with_attr(
                "candidate_dimensions",
                format!("{}×{}", self.candidate.width, self.candidate.height),
            )
            .with_attr("candidate_bytes", self.candidate.bytes.to_string());
        if let Some(url) = source_page {
            evidence = evidence.with_attr("operator_source_page", url);
        }
        if let Some(url) = asset_url {
            evidence = evidence.with_attr("operator_asset_url", url);
        }
        Entity::builder(
            EntityKind::Document,
            format!("sha256:{}", self.reference.sha256),
            1.0,
            SOURCE,
        )
        .tag("local_image_comparison")
        .evidence(evidence)
        .build()
    }

    #[must_use]
    pub fn outcome(&self, now_unix: u64) -> SourceExecutionOutcome {
        if self.verdict == Verdict::NoVerifiedMatch {
            SourceExecutionOutcome::inconclusive(SOURCE, now_unix, self.detail.clone())
        } else {
            SourceExecutionOutcome::success(SOURCE, now_unix, 1)
        }
    }
}

/// Accept an operator-supplied source note without fetching or rewriting it.
pub fn source_url(input: &str) -> Result<Option<String>, &'static str> {
    let url = input.trim();
    if url.is_empty() {
        return Ok(None);
    }
    if url.len() > 1024
        || url.chars().any(char::is_control)
        || !url.split_once("://").is_some_and(|(_, rest)| {
            !rest
                .split(['/', '?', '#'])
                .next()
                .unwrap_or_default()
                .contains('@')
        })
        || crate::http::parse_http_uri(url).is_err()
    {
        return Err(
            "source notes require an HTTP(S) URL without user credentials, up to 1024 bytes",
        );
    }
    Ok(Some(url.to_owned()))
}

const SCOPE: &str = "This compares supplied files. Source URLs, publication dates, authorship, local edits and identity require separate evidence.";

/// Compare original bytes, then verify full-frame or aligned pixel overlap.
pub fn compare(a: &[u8], b: &[u8]) -> Result<Comparison, String> {
    let first = photo::decode(a, "Reference image")?;
    if a == b {
        return Ok(Comparison {
            verdict: Verdict::IdenticalFile,
            method: "Exact byte comparison",
            detail: "Both files contain the same bytes.".into(),
            scope: SCOPE,
            reference: first.file.clone(),
            candidate: first.file,
        });
    }
    let second = photo::decode(b, "Candidate image")?;
    let (verdict, method, detail) = if let Some(detail) =
        matching::full_frame(&first.gray, &second.gray)
    {
        (Verdict::SameFrame, "Full-frame pixel comparison", detail)
    } else if let Some(detail) = matching::aligned_overlap(&first.gray, &second.gray) {
        (
            Verdict::SameFrame,
            "Local feature alignment and pixel comparison",
            detail,
        )
    } else {
        (Verdict::NoVerifiedMatch, "Insufficient matching evidence",
                "The comparison could not establish a shared frame. Severe edits or a very small crop can return this result.".into())
    };
    Ok(Comparison {
        verdict,
        method,
        detail,
        scope: SCOPE,
        reference: first.file,
        candidate: second.file,
    })
}
