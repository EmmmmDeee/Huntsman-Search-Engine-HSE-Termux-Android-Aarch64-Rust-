//! Temporal reconstruction from evidence attributes.

use serde::{Deserialize, Serialize};

use crate::entity::Entity;
use crate::tags;
use crate::timefmt::parse_timestamp_and_iso;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TimelineEventKind {
    BreachExposure,
    Registered,
    Expiry,
    AccountCreated,
    Incorporation,
    Dissolution,
    FirstSeen,
    LastSeen,
    DateOfBirth,
    LocationVisited,
    Generic,
}

impl TimelineEventKind {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::BreachExposure => "breach_exposure",
            Self::Registered => "registered",
            Self::Expiry => "expiry",
            Self::AccountCreated => "account_created",
            Self::Incorporation => "incorporation",
            Self::Dissolution => "dissolution",
            Self::FirstSeen => "first_seen",
            Self::LastSeen => "last_seen",
            Self::DateOfBirth => "date_of_birth",
            Self::LocationVisited => "location_visited",
            Self::Generic => "event",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TimelineEvent {
    pub ts: i64,
    pub iso: String,
    pub kind: TimelineEventKind,
    pub label: String,
    pub entity_uid: String,
    pub entity_value: String,
    pub entity_kind: String,
    pub source: String,
    pub confidence: f64,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct OnlineTenure {
    pub earliest_ts: i64,
    pub earliest_iso: String,
    pub latest_ts: i64,
    pub latest_iso: String,
    pub span_years: u32,
    pub event_count: usize,
    pub breach_count: usize,
}

fn classify_attribute(key: &str) -> Option<TimelineEventKind> {
    Some(match key.to_ascii_lowercase().as_str() {
        "breach_date" | "data_breach" => TimelineEventKind::BreachExposure,
        "incorporation_date" => TimelineEventKind::Incorporation,
        "dissolution_date" => TimelineEventKind::Dissolution,
        "registered" | "created" | "created_at" | "created_at_unix" => {
            TimelineEventKind::Registered
        }
        "account_created"
        | "joined_at"
        | "discord_created_date"
        | "discord_created_unix_ms"
        | "uuid_created_date"
        | "objectid_created_date"
        | "ulid_created_date"
        | "ksuid_created_date" => TimelineEventKind::AccountCreated,
        "expires" | "expire_secs" => TimelineEventKind::Expiry,
        "first_seen" | "first_seen_iso" | "first_pulse_created" => TimelineEventKind::FirstSeen,
        "last_seen" | "last_seen_iso" | "last_updated" | "last_update" | "updated" => {
            TimelineEventKind::LastSeen
        }
        "date_of_birth" | "birth_date" => TimelineEventKind::DateOfBirth,
        "shot_time" => TimelineEventKind::LocationVisited,
        "start_date" | "review_date" | "end_date" | "date" | "timestamp" | "death_date"
        | "verified_at" => TimelineEventKind::Generic,
        _ => return None,
    })
}

#[must_use]
pub fn reconstruct(entities: &[Entity]) -> Vec<TimelineEvent> {
    let mut events = Vec::new();
    for entity in entities {
        if entity.has_tag(tags::CANDIDATE) {
            continue;
        }
        for evidence in &entity.evidence {
            for (key, raw) in &evidence.attributes {
                let Some(kind) = classify_attribute(key) else {
                    continue;
                };
                let Some((ts, iso)) = parse_timestamp_and_iso(raw) else {
                    continue;
                };
                events.push(TimelineEvent {
                    ts,
                    iso,
                    kind,
                    label: format!("{} {} ({} = {raw})", entity.kind, entity.value, key),
                    entity_uid: entity.uid.clone(),
                    entity_value: entity.value.clone(),
                    entity_kind: entity.kind.to_string(),
                    source: format!("{}:{key}", evidence.provenance.source),
                    confidence: entity.confidence,
                });
            }
        }
    }
    events.sort_by(|left, right| {
        left.ts
            .cmp(&right.ts)
            .then_with(|| left.entity_value.cmp(&right.entity_value))
            .then_with(|| left.kind.as_str().cmp(right.kind.as_str()))
            .then_with(|| left.source.cmp(&right.source))
    });
    events.dedup_by(|left, right| {
        left.ts == right.ts
            && left.kind == right.kind
            && left.entity_uid == right.entity_uid
            && left.source == right.source
    });
    events
}

#[must_use]
pub fn online_tenure(events: &[TimelineEvent]) -> Option<OnlineTenure> {
    let presence = events
        .iter()
        .filter(|event| {
            !matches!(
                event.kind,
                TimelineEventKind::DateOfBirth | TimelineEventKind::Expiry
            )
        })
        .collect::<Vec<_>>();
    let earliest = presence.first()?;
    let latest = presence.last()?;
    let span_years =
        u32::try_from((latest.ts - earliest.ts).max(0) / (365 * 24 * 60 * 60)).unwrap_or(u32::MAX);
    Some(OnlineTenure {
        earliest_ts: earliest.ts,
        earliest_iso: earliest.iso.clone(),
        latest_ts: latest.ts,
        latest_iso: latest.iso.clone(),
        span_years,
        event_count: presence.len(),
        breach_count: presence
            .iter()
            .filter(|event| event.kind == TimelineEventKind::BreachExposure)
            .count(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::entity::{Entity, EntityKind, Evidence, EvidenceProvenance};

    #[test]
    fn reconstructs_events_and_tenure() {
        let entity = Entity::builder(EntityKind::Email, "ada@example.com", 0.8, "scan")
            .evidence(
                Evidence::new(EvidenceProvenance::new("hibp"), "breach")
                    .with_attr("breach_date", "2019-01-02")
                    .with_attr("first_seen", "2017-05-01"),
            )
            .build();
        let events = reconstruct(&[entity]);
        assert_eq!(events.len(), 2);
        assert_eq!(events[0].kind, TimelineEventKind::FirstSeen);
        assert_eq!(online_tenure(&events).unwrap().breach_count, 1);
    }
}
