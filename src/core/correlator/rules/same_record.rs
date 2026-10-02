//! Same-RECORD co-occurrence — the attribution primitive the identity and
//! wallet rules were missing.
//!
//! An entity's `corroborating_sources()` are MODULE NAMES (`ev.source`), not
//! accounts or records. So "these two entities share a corroborating source"
//! only says *one module surfaced both somewhere in this scan* — and the
//! modules that feed the attribution rules routinely surface many unrelated
//! people per scan: `npm_author` walks every maintainer of every package,
//! `github_user` every profile queried, a stealer-log provider every victim in
//! the dump. Two strangers in one such response share the module name and
//! nothing else, which is exactly the "mere co-existence in the same scan" that
//! AU-039's and AU-046's own doc comments say must not be enough
//! (REQ-CORRELATOR-002 / REQ-CORRELATOR-004).
//!
//! What actually identifies a record is in the evidence attributes the module
//! already stamps: `npm_author` writes `package`, `github_user` writes
//! `github_login` / `profile_url` / `github_id`, the stealer-log modules write
//! the victim's `username`. There is no cross-module registry of which key that
//! is, and hard-coding one would rot, so the discriminator is derived from the
//! scan itself:
//!
//! **A key discriminates within a module when it takes MORE THAN ONE value
//! across that module's evidence in this scan.** A key with a single value
//! everywhere (`npm_author`'s `source = npm_registry`) is boilerplate and
//! identifies nothing; `package` varying across packages identifies the record.
//! Self-tuning, and it needs no module to be taught anything.
//!
//! Values are compared WITHOUT their keys, because one module legitimately
//! names the same record under different keys on different evidence lines
//! (`github_user` stamps `github_id` + `profile_url` on the profile evidence but
//! `github_login` on the company/location evidence — all three name one
//! account). Key-matching would split a genuine same-account tie.
//!
//! When neither side carries a discriminating value the answer is UNKNOWN, and
//! unknown is treated as same-record — the pre-existing behaviour. This
//! deliberately only REJECTS pairs it can prove came from different records, so
//! a module that stamps nothing keeps producing exactly the links it did
//! before: the fix removes fabrications without silently deleting real leads.

use super::*;

/// Per-module index of which evidence-attribute keys actually distinguish one
/// record from another in THIS scan. Built once per rule invocation, since both
/// callers already iterate the whole entity set.
pub(in crate::core::correlator) struct RecordIndex<'a> {
    /// module → the keys that took more than one value across that module's
    /// evidence in this scan.
    discriminating: HashMap<&'a str, HashSet<&'a str>>,
}

impl<'a> RecordIndex<'a> {
    /// Derive the discriminating keys from `entities`' own evidence.
    pub(in crate::core::correlator) fn new(entities: &'a [Entity]) -> Self {
        // module → key → the distinct values seen for it.
        let mut seen: HashMap<&str, HashMap<&str, HashSet<&str>>> = HashMap::new();
        for e in entities {
            for ev in &e.evidence {
                let per_key = seen.entry(ev.source.as_str()).or_default();
                for (k, v) in &ev.attributes {
                    per_key.entry(k.as_str()).or_default().insert(v.as_str());
                }
            }
        }
        let discriminating = seen
            .into_iter()
            .map(|(module, keys)| {
                let varying: HashSet<&str> = keys
                    .into_iter()
                    .filter(|(_, values)| values.len() > 1)
                    .map(|(k, _)| k)
                    .collect();
                (module, varying)
            })
            .collect();
        Self { discriminating }
    }

    /// The discriminating attribute VALUES `e` carries on its evidence from
    /// `module` — the record(s) of that module it was extracted from, as far as
    /// the module's own stamping can say. Empty means "this module told us
    /// nothing that distinguishes records here".
    fn record_values<'e>(&self, e: &'e Entity, module: &str) -> HashSet<&'e str> {
        let Some(keys) = self.discriminating.get(module) else {
            return HashSet::new();
        };
        let mut out: HashSet<&'e str> = HashSet::new();
        for ev in e.evidence.iter().filter(|ev| ev.source == module) {
            for (k, v) in &ev.attributes {
                if keys.contains(k.as_str()) {
                    out.insert(v.as_str());
                }
            }
        }
        out
    }

    /// True when `a` and `b` plausibly came from the SAME record of some module
    /// that surfaced both — i.e. this is a real co-location tie, not two
    /// strangers a shared module name put in the same scan.
    ///
    /// False only when every module they share proved they came from DIFFERENT
    /// records (both sides carry discriminating values and none of them match).
    /// Unknown counts as true, so a module that stamps no discriminator keeps
    /// exactly its previous behaviour.
    pub(in crate::core::correlator) fn same_record(&self, a: &Entity, b: &Entity) -> bool {
        let a_srcs = a.corroborating_sources();
        let b_srcs = b.corroborating_sources();
        let mut shared = a_srcs.intersection(&b_srcs).peekable();
        if shared.peek().is_none() {
            // No shared module at all — not this predicate's call to make, and
            // never a co-location tie.
            return false;
        }
        for module in shared {
            let av = self.record_values(a, module);
            if av.is_empty() {
                return true; // undeterminable → previous behaviour
            }
            let bv = self.record_values(b, module);
            if bv.is_empty() || !av.is_disjoint(&bv) {
                return true;
            }
        }
        false
    }
}
