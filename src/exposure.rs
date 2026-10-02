//! Exposure scoring over entity tags and confidence.

use serde::{Deserialize, Serialize};

use crate::confidence::Classification;
use crate::entity::Entity;
use crate::tags;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExposureReason {
    pub tag: String,
    pub weight: u32,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ExposureFinding {
    pub uid: String,
    pub score: u32,
    pub classification: Classification,
    pub reasons: Vec<ExposureReason>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ExposureIndex {
    pub findings: Vec<ExposureFinding>,
    pub total_score: u32,
}

fn tag_weight(tag: &str) -> Option<u32> {
    Some(match tag {
        tags::STEALER_LOG => 35,
        tags::PASSWORD_AT_RISK => 30,
        tags::MALICIOUS | tags::VULNERABLE => 25,
        tags::BREACH => 20,
        tags::HIGH_EXPOSURE => 15,
        tags::PASTE_EXPOSED | tags::MULTI_DEVICE => 10,
        tags::WEB_SCRAPED => 5,
        _ => return None,
    })
}

#[must_use]
pub fn compute_exposure(entities: &[Entity]) -> ExposureIndex {
    let mut findings = entities
        .iter()
        .map(|entity| {
            let mut reasons = entity
                .tags
                .iter()
                .filter_map(|tag| {
                    tag_weight(tag).map(|weight| ExposureReason {
                        tag: tag.clone(),
                        weight,
                    })
                })
                .collect::<Vec<_>>();
            let classification = entity.classify();
            if classification == Classification::Verified {
                reasons.push(ExposureReason {
                    tag: "verified".into(),
                    weight: 10,
                });
            } else if classification == Classification::Probable {
                reasons.push(ExposureReason {
                    tag: "probable".into(),
                    weight: 5,
                });
            }
            let score = reasons.iter().map(|reason| reason.weight).sum();
            ExposureFinding {
                uid: entity.uid.clone(),
                score,
                classification,
                reasons,
            }
        })
        .collect::<Vec<_>>();
    findings.sort_by(|left, right| {
        right
            .score
            .cmp(&left.score)
            .then_with(|| right.classification.rank().cmp(&left.classification.rank()))
            .then_with(|| left.uid.cmp(&right.uid))
    });
    let total_score = findings.iter().map(|finding| finding.score).sum();
    ExposureIndex {
        findings,
        total_score,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::entity::{Entity, EntityKind};

    #[test]
    fn stealer_and_password_risk_score_highest() {
        let entity = Entity::builder(EntityKind::Email, "ada@example.com", 0.8, "scan")
            .tag(tags::STEALER_LOG)
            .tag(tags::PASSWORD_AT_RISK)
            .build();
        let index = compute_exposure(&[entity]);
        assert!(index.findings[0].score >= 65);
    }
}
