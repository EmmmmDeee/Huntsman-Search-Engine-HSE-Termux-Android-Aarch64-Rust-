//! Hash-chained evidence ledger. Each hash covers the previous hash plus the claim.
//! A dropped middle entry or a reordered entry breaks `chain_intact`; dropping the *newest*
//! entries does not, which is what an `Anchor` recorded outside the file is for.
//! Interop is still a binding, not a label.

use std::path::Path;

use serde::{Deserialize, Serialize};

use crate::error::Error;
use crate::fsio::{read_bounded, write_atomic};
use crate::sha256::{hex32, sha256};
use crate::stage::{EvidenceLevel, Status};

pub const GENESIS: &str = "0000000000000000000000000000000000000000000000000000000000000000";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Claim {
    pub claim: String,
    pub source: String,
    pub component: String,
    pub technique_id: Option<String>,
    pub status: Status,
    pub evidence_level: EvidenceLevel,
    pub does_not_show: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LedgerEntry {
    pub prev: String,
    pub hash: String,
    pub claim: Claim,
}

impl Claim {
    /// Verified capability may exist without a technique score.
    /// Interop requires a binding this crate implements, not a caller-supplied id.
    #[must_use]
    pub fn admits_interop(&self) -> bool {
        self.admits_interop_with(BINDINGS)
    }

    /// The gate against an explicit binding table, so exporters can be exercised
    /// before this crate implements any technique.
    #[must_use]
    pub fn admits_interop_with(&self, bindings: &[(&str, &str)]) -> bool {
        self.status == Status::Verified
            && self.evidence_level.admits_interop()
            && !self.component.trim().is_empty()
            && self
                .technique_id
                .as_deref()
                .is_some_and(|id| valid_technique(id) && binds(bindings, &self.component, id))
            && !self.does_not_show.trim().is_empty()
    }
}

/// Component path to technique id. Empty until a function in this crate performs that technique.
/// Haversine is not T1591. Challenge classification is not T1592.
const BINDINGS: &[(&str, &str)] = &[];

/// The binding table this crate actually implements.
#[must_use]
pub const fn bindings() -> &'static [(&'static str, &'static str)] {
    BINDINGS
}

fn binds(bindings: &[(&str, &str)], component: &str, technique: &str) -> bool {
    bindings
        .iter()
        .any(|(path, id)| *path == component && *id == technique)
}

#[must_use]
pub fn method_implements(component: &str, technique: &str) -> bool {
    binds(BINDINGS, component, technique)
}

/// ATT&CK enterprise ids: `T` and exactly four digits, optionally `.` and three digits.
#[must_use]
pub fn valid_technique(id: &str) -> bool {
    let rest = id.strip_prefix('T').unwrap_or("");
    let (base, sub) = match rest.split_once('.') {
        Some((base, sub)) => (base, Some(sub)),
        None => (rest, None),
    };
    base.len() == 4
        && base.bytes().all(|c| c.is_ascii_digit())
        && sub.is_none_or(|s| s.len() == 3 && s.bytes().all(|c| c.is_ascii_digit()))
}

#[must_use]
pub fn seal(claim: &Claim) -> LedgerEntry {
    append(GENESIS, claim)
}

/// Hash preimage domain tag. Bump when the preimage layout changes.
const PREIMAGE_TAG: &[u8] = b"huntsman-ledger-v2";

/// Unambiguous preimage: every field is length-prefixed, and an absent technique
/// is distinct from an empty one. No field content can shift a field boundary.
fn preimage(prev: &str, claim: &Claim) -> Vec<u8> {
    fn field(out: &mut Vec<u8>, value: &[u8]) {
        out.extend_from_slice(&(value.len() as u64).to_be_bytes());
        out.extend_from_slice(value);
    }
    let mut out = Vec::with_capacity(256);
    field(&mut out, PREIMAGE_TAG);
    field(&mut out, prev.as_bytes());
    field(&mut out, claim.claim.as_bytes());
    field(&mut out, claim.source.as_bytes());
    field(&mut out, claim.component.as_bytes());
    match &claim.technique_id {
        None => out.push(0),
        Some(id) => {
            out.push(1);
            field(&mut out, id.as_bytes());
        }
    }
    field(&mut out, claim.status.as_str().as_bytes());
    field(&mut out, claim.evidence_level.as_str().as_bytes());
    field(&mut out, claim.does_not_show.as_bytes());
    out
}

#[must_use]
pub fn append(prev: &str, claim: &Claim) -> LedgerEntry {
    LedgerEntry {
        prev: prev.to_owned(),
        hash: hex32(&sha256(&preimage(prev, claim))),
        claim: claim.clone(),
    }
}

#[must_use]
pub fn chain_intact(entries: &[LedgerEntry]) -> bool {
    let mut prev = GENESIS;
    for entry in entries {
        if entry.prev != prev {
            return false;
        }
        if append(prev, &entry.claim).hash != entry.hash {
            return false;
        }
        prev = entry.hash.as_str();
    }
    true
}

#[must_use]
pub fn admitted(entries: &[LedgerEntry]) -> Vec<&LedgerEntry> {
    entries
        .iter()
        .filter(|e| e.claim.admits_interop())
        .collect()
}

const MAX_LEDGER_BYTES: u64 = 1_048_576;

/// Persist a chain atomically. A broken chain is never written.
///
/// # Errors
/// `Error::Invalid` for a broken chain; `Error::Store` for IO, size, or symlink refusal.
pub fn save_chain(path: &Path, entries: &[LedgerEntry]) -> Result<(), Error> {
    if !chain_intact(entries) {
        return Err(Error::Invalid("refusing to write a broken chain".into()));
    }
    let body = serde_json::to_vec_pretty(entries).map_err(|e| Error::Store(e.to_string()))?;
    write_atomic(path, &body, MAX_LEDGER_BYTES)
}

/// Load a chain and verify every link.
///
/// # Errors
/// `Error::Store` for IO, size, or symlink refusal (unreadable input); `Error::Invalid` for
/// malformed JSON or a broken chain (bad data). Callers map these to distinct exit codes.
pub fn load_chain(path: &Path) -> Result<Vec<LedgerEntry>, Error> {
    let body = read_bounded(path, MAX_LEDGER_BYTES)?;
    let entries: Vec<LedgerEntry> =
        serde_json::from_slice(&body).map_err(|e| Error::Invalid(e.to_string()))?;
    if !chain_intact(&entries) {
        return Err(Error::Invalid("ledger chain broken".into()));
    }
    Ok(entries)
}

/// A recorded ledger head: how many entries existed and the hash of the last one.
///
/// A hash chain authenticates every earlier entry from the tip, but nothing inside
/// the file authenticates the *end*: deleting the newest entries leaves a shorter
/// chain that still verifies. Only a head recorded outside the ledger file can
/// expose that. The same remedy is used by secure-audit-log schemes (Schneier and
/// Kelsey 1999, a final MAC stored off-site) and by Certificate Transparency (RFC
/// 6962, a signed tree head carrying the tree size). An anchor is that head without
/// the signature; store it where the ledger's writer cannot edit it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Anchor {
    pub entries: usize,
    pub tip: String,
}

impl Anchor {
    /// The head of `entries`. An empty ledger anchors at `GENESIS`.
    #[must_use]
    pub fn of(entries: &[LedgerEntry]) -> Self {
        Self {
            entries: entries.len(),
            tip: entries
                .last()
                .map_or(GENESIS, |entry| entry.hash.as_str())
                .to_owned(),
        }
    }

    /// Parse `ENTRIES:TIP`, where TIP is 64 lowercase hex digits.
    ///
    /// # Errors
    /// `Error::Invalid` when the text is not in that form.
    pub fn parse(text: &str) -> Result<Self, Error> {
        let bad = || {
            Error::Invalid(format!(
                "anchor must be ENTRIES:TIP (64 hex digits): {text:?}"
            ))
        };
        let (count, tip) = text.split_once(':').ok_or_else(bad)?;
        let entries = count.parse::<usize>().map_err(|_| bad())?;
        let hex = tip.len() == GENESIS.len()
            && tip
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b));
        if !hex {
            return Err(bad());
        }
        Ok(Self {
            entries,
            tip: tip.to_owned(),
        })
    }
}

impl std::fmt::Display for Anchor {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}:{}", self.entries, self.tip)
    }
}

/// Check that `entries` still contains everything the anchor recorded.
///
/// `entries` must already be `chain_intact` (as `load_chain` guarantees). Because every
/// hash covers its predecessor, a matching hash at the anchored position proves the whole
/// prefix is unchanged; entries appended after the anchor are allowed.
///
/// # Errors
/// `Error::Invalid` when the ledger is shorter than the anchor (truncated) or when its
/// entry at the anchored position differs (rewritten).
pub fn check_anchor(entries: &[LedgerEntry], anchor: &Anchor) -> Result<(), Error> {
    if entries.len() < anchor.entries {
        return Err(Error::Invalid(format!(
            "ledger truncated: anchor records {} entries, found {}",
            anchor.entries,
            entries.len()
        )));
    }
    let tip = match anchor.entries.checked_sub(1) {
        None => GENESIS,
        Some(index) => entries[index].hash.as_str(),
    };
    if tip != anchor.tip {
        return Err(Error::Invalid(format!(
            "ledger rewritten: entry {} does not match the anchor",
            anchor.entries
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::fs;

    use super::*;

    fn sample(status: Status, level: EvidenceLevel, technique: Option<&str>) -> Claim {
        Claim {
            claim: "haversine band holds".into(),
            source: "tests/geoint".into(),
            component: "src/geoint.rs".into(),
            technique_id: technique.map(str::to_owned),
            status,
            evidence_level: level,
            does_not_show: "not survey grade".into(),
        }
    }

    #[test]
    fn hash_changes_when_claim_changes_and_gate_rejects_unverified() {
        let a = seal(&sample(
            Status::Verified,
            EvidenceLevel::DirectObservation,
            Some("T1595"),
        ));
        let mut other = sample(
            Status::Verified,
            EvidenceLevel::DirectObservation,
            Some("T1595"),
        );
        other.claim = "different".into();
        let b = seal(&other);
        assert_ne!(a.hash, b.hash);
        assert!(
            !a.claim.admits_interop(),
            "unbound technique must not score"
        );
        let weak = seal(&sample(
            Status::Unverified,
            EvidenceLevel::EndToEndDemonstration,
            Some("T1595"),
        ));
        assert!(!weak.claim.admits_interop());
        let no_tech = seal(&sample(Status::Verified, EvidenceLevel::Reproduction, None));
        assert!(!no_tech.claim.admits_interop());
    }

    #[test]
    fn technique_ids_are_attack_shaped() {
        for ok in ["T1595", "T1595.001"] {
            assert!(valid_technique(ok), "{ok}");
        }
        for bad in [
            "",
            "T",
            "T159",
            "T15955",
            "t1595",
            "T1595.",
            "T1595.01",
            "T1595.0011",
            "T١٢٣٤",
            "T1595 ",
        ] {
            assert!(!valid_technique(bad), "{bad:?}");
        }
        assert!(!valid_technique("T1595.001.002"));
    }

    #[test]
    fn explicit_binding_table_controls_admission() {
        let claim = sample(
            Status::Verified,
            EvidenceLevel::DirectObservation,
            Some("T1595"),
        );
        assert!(!claim.admits_interop());
        assert!(claim.admits_interop_with(&[("src/geoint.rs", "T1595")]));
        assert!(!claim.admits_interop_with(&[("src/geoint.rs", "T1592")]));
        assert!(!claim.admits_interop_with(&[("src/other.rs", "T1595")]));
    }

    #[test]
    fn field_boundaries_and_absent_technique_are_unambiguous() {
        let mut a = sample(Status::Verified, EvidenceLevel::DirectObservation, None);
        a.claim = "a\nb".into();
        a.source = "c".into();
        let mut b = a.clone();
        b.claim = "a".into();
        b.source = "b\nc".into();
        assert_ne!(
            seal(&a).hash,
            seal(&b).hash,
            "moving a newline across fields must change the hash"
        );
        let none = sample(Status::Verified, EvidenceLevel::DirectObservation, None);
        let empty = sample(Status::Verified, EvidenceLevel::DirectObservation, Some(""));
        assert_ne!(
            seal(&none).hash,
            seal(&empty).hash,
            "absent technique is not an empty technique"
        );
    }

    #[test]
    fn preimage_layout_is_pinned() {
        // Changing this vector orphans every saved ledger. Bump PREIMAGE_TAG if it must change.
        let entry = seal(&sample(
            Status::Verified,
            EvidenceLevel::DirectObservation,
            Some("T1595"),
        ));
        assert_eq!(
            entry.hash,
            "29f35d985c3eac5b648f2ce8ccdaf6b8468ff4c14ae9fe6ad90d242489759a7c"
        );
    }

    #[test]
    fn reorder_breaks_the_chain() {
        let first = seal(&sample(
            Status::Verified,
            EvidenceLevel::DirectObservation,
            None,
        ));
        let mut second_claim = sample(Status::Partial, EvidenceLevel::PrimaryEvidence, None);
        second_claim.claim = "second".into();
        let second = append(&first.hash, &second_claim);
        assert!(chain_intact(&[first.clone(), second.clone()]));
        assert!(!chain_intact(&[second, first]));
    }

    fn three_entries() -> Vec<LedgerEntry> {
        let mut entries: Vec<LedgerEntry> = Vec::new();
        for name in ["one", "two", "three"] {
            let mut claim = sample(Status::Verified, EvidenceLevel::DirectObservation, None);
            claim.claim = name.into();
            let prev = entries.last().map_or(GENESIS, |e| e.hash.as_str());
            let next = append(prev, &claim);
            entries.push(next);
        }
        entries
    }

    #[test]
    fn chain_alone_cannot_see_tail_truncation_but_an_anchor_can() {
        let full = three_entries();
        let anchor = Anchor::of(&full);
        let truncated = &full[..2];
        assert!(
            chain_intact(truncated),
            "a shortened chain still verifies: this is the gap"
        );
        let err = check_anchor(truncated, &anchor).unwrap_err();
        assert!(err.to_string().contains("truncated"), "{err}");
        check_anchor(&full, &anchor).unwrap();
    }

    #[test]
    fn anchor_allows_growth_and_rejects_a_rewritten_tail() {
        let full = three_entries();
        let anchor = Anchor::of(&full[..2]);
        check_anchor(&full, &anchor).unwrap();
        let mut rewritten = full[..2].to_vec();
        let mut claim = full[2].claim.clone();
        claim.claim = "forged".into();
        rewritten.push(append(&full[1].hash, &claim));
        assert!(chain_intact(&rewritten));
        let longer_anchor = Anchor::of(&full);
        let err = check_anchor(&rewritten, &longer_anchor).unwrap_err();
        assert!(err.to_string().contains("rewritten"), "{err}");
    }

    #[test]
    fn empty_ledger_anchors_at_genesis_and_round_trips() {
        let empty = Anchor::of(&[]);
        assert_eq!(empty.to_string(), format!("0:{GENESIS}"));
        check_anchor(&three_entries(), &empty).unwrap();
        let full = Anchor::of(&three_entries());
        assert_eq!(Anchor::parse(&full.to_string()).unwrap(), full);
    }

    #[test]
    fn malformed_anchors_are_refused() {
        for bad in [
            "",
            "3",
            ":",
            "x:abc",
            "-1:0000000000000000000000000000000000000000000000000000000000000000",
            "3:abc",
            "3:00000000000000000000000000000000000000000000000000000000000000G0",
            "3:0000000000000000000000000000000000000000000000000000000000000000:",
            "3:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        ] {
            assert!(Anchor::parse(bad).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn tampered_file_fails_load() {
        let dir = std::env::temp_dir().join(format!("huntsman-ledger-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let path = dir.join("ledger.json");
        let entry = seal(&sample(
            Status::Verified,
            EvidenceLevel::DirectObservation,
            None,
        ));
        save_chain(&path, &[entry]).unwrap();
        assert!(load_chain(&path).is_ok());
        let mut raw = fs::read_to_string(&path).unwrap();
        raw = raw.replacen("haversine band holds", "tampered claim", 1);
        fs::write(&path, raw).unwrap();
        assert!(matches!(load_chain(&path), Err(Error::Invalid(_))));
        let _ = fs::remove_dir_all(&dir);
    }
}
