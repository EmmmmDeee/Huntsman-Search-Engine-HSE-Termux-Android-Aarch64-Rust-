//! Hash-chained evidence ledger. Each hash covers the previous hash plus the claim.
//! A dropped or reordered entry breaks `chain_intact`. Interop is still a binding, not a label.

use std::path::Path;

use serde::{Deserialize, Serialize};

use crate::error::Error;
use crate::fsio::{read_bounded_replacing, write_atomic_private};
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
    admitted_with(entries, BINDINGS).collect()
}

/// The entries whose claims pass the interop gate under `bindings`. An invalid,
/// reordered, missing-prefix or spliced chain admits no claims, even when individual
/// entries have plausible hashes and verified-looking statuses. A valid prefix can
/// still be truncated at the tail: the chain is not a signature or anti-rollback proof. Both STIX and
/// ATT&CK Navigator use this gate, including their explicit-binding test seams.
///
/// Verify the complete chain once before iterating, rather than rehashing it
/// for every admitted entry. Skip hashing when no technique can be bound.
pub fn admitted_with<'a>(
    entries: &'a [LedgerEntry],
    bindings: &'a [(&'a str, &'a str)],
) -> impl Iterator<Item = &'a LedgerEntry> {
    let chain_verified = !bindings.is_empty() && chain_intact(entries);
    entries
        .iter()
        .filter(move |entry| chain_verified && entry.claim.admits_interop_with(bindings))
}

/// The ceiling on a saved ledger, for writing and for reading alike. It is the ceiling on a saved
/// scan artifact: a lookup of a large domain writes one entry per name, and a ledger the writer
/// accepts must be one the reader loads. The old 1 MiB cap refused a save of a few thousand
/// entries after the lookup had already spent its requests.
const MAX_LEDGER_BYTES: u64 = crate::scan_artifact::MAX_ARTIFACT_BYTES;

/// Persist a chain atomically, mode 600 on Unix: a lookup's ledger names the addresses, phones
/// and handles it found. A broken chain is never written.
///
/// # Errors
/// `Error::Invalid` for a broken chain; `Error::Store` for IO, size, or symlink refusal.
pub fn save_chain(path: &Path, entries: &[LedgerEntry]) -> Result<(), Error> {
    if !chain_intact(entries) {
        return Err(Error::Invalid("refusing to write a broken chain".into()));
    }
    let limit = usize::try_from(MAX_LEDGER_BYTES).unwrap_or(usize::MAX);
    let body = match crate::json::to_bounded_json(&entries, limit, true) {
        Ok(Ok(bytes)) => bytes,
        Ok(Err(required_bytes)) => {
            return Err(Error::Store(format!(
                "{}: exceeds {MAX_LEDGER_BYTES} bytes (needs {required_bytes})",
                path.display()
            )));
        }
        Err(error) => return Err(Error::Store(error.to_string())),
    };
    write_atomic_private(path, &body, MAX_LEDGER_BYTES)
}

/// Load a chain and verify every link.
///
/// # Errors
/// `Error::Store` for IO, size, or symlink refusal (unreadable input); `Error::Invalid` for
/// malformed JSON or a broken chain (bad data). Callers map these to distinct exit codes.
pub fn load_chain(path: &Path) -> Result<Vec<LedgerEntry>, Error> {
    let body = read_bounded_replacing(path, MAX_LEDGER_BYTES)?;
    let entries: Vec<LedgerEntry> =
        serde_json::from_slice(&body).map_err(|e| Error::Invalid(e.to_string()))?;
    if !chain_intact(&entries) {
        return Err(Error::Invalid("ledger chain broken".into()));
    }
    Ok(entries)
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
    fn ledger_round_trips_after_atomic_replacement_without_losing_chain() {
        let dir = std::env::temp_dir().join(format!(
            "huntsman-ledger-replacement-{}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let path = dir.join("ledger.json");
        let first = append(
            GENESIS,
            &sample(Status::Verified, EvidenceLevel::DirectObservation, None),
        );
        save_chain(&path, std::slice::from_ref(&first)).unwrap();
        assert_eq!(
            load_chain(&path).unwrap().as_slice(),
            std::slice::from_ref(&first)
        );
        let mut second_claim = first.claim.clone();
        second_claim.claim = "second complete entry".into();
        let second = append(&first.hash, &second_claim);
        let chain = [first, second];
        save_chain(&path, &chain).unwrap();
        assert_eq!(load_chain(&path).unwrap(), chain);
        let _ = fs::remove_dir_all(dir);
    }

    #[cfg(unix)]
    #[test]
    fn atomic_ledger_reader_still_refuses_symlinks() {
        let dir = std::env::temp_dir().join(format!("huntsman-ledger-link-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let path = dir.join("ledger.json");
        let other = dir.join("other.json");
        save_chain(&other, &[]).unwrap();
        std::os::unix::fs::symlink(&other, &path).unwrap();
        assert!(matches!(load_chain(&path), Err(Error::Store(_))));
        assert_eq!(load_chain(&other).unwrap(), []);
        let _ = fs::remove_dir_all(dir);
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

    #[test]
    fn a_ledger_of_thousands_of_entries_saves_and_reloads() {
        let dir = std::env::temp_dir().join(format!("huntsman-ledger-long-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let path = dir.join("ledger.json");
        let mut entries = Vec::new();
        let mut prev = GENESIS.to_owned();
        for index in 0..5_000 {
            let mut claim = sample(Status::Verified, EvidenceLevel::DirectObservation, None);
            claim.claim = format!("name {index}.example.test resolves");
            let entry = append(&prev, &claim);
            prev.clone_from(&entry.hash);
            entries.push(entry);
        }
        assert!(
            serde_json::to_vec_pretty(&entries).unwrap().len() > 1_048_576,
            "the fixture must be larger than the old 1 MiB cap"
        );
        save_chain(&path, &entries).expect("a long ledger saves");
        let loaded = load_chain(&path).expect("and loads back intact");
        assert_eq!(loaded.len(), entries.len());
        assert_eq!(loaded.last(), entries.last());
        let _ = fs::remove_dir_all(&dir);
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
