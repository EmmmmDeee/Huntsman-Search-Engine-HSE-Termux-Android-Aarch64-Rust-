//! Guard test for `docs/AUTONOMY_CHARTER.md` — the binding invariants the
//! autonomous engineering loop re-loads verbatim each cycle.
//!
//! The charter is only load-bearing if it cannot silently lose a guardrail.
//! This test is that ratchet: it fails if the file is missing, empty, or has
//! dropped any named invariant marker. Deleting an invariant is therefore a
//! visible, CI-blocking act — never a quiet edit. This mirrors the charter's
//! own INV-3 ("never weaken the ratchet") and applies it to the charter.
//!
//! Markers are stable ID tokens (`INV-1`..`INV-7`, section anchors), chosen so
//! prose can be reworded freely without tripping the guard — only removing a
//! guardrail's identity trips it.

use std::fs;
use std::path::Path;

fn charter() -> String {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("docs/AUTONOMY_CHARTER.md");
    assert!(
        path.exists(),
        "docs/AUTONOMY_CHARTER.md must exist — it is the immutable core the \
         autonomous loop loads every cycle (see the HUNTSMAN AUTONOMOUS \
         ENGINEERING CONTROLLER prompt, Section A)"
    );
    fs::read_to_string(&path).expect("charter must be readable UTF-8")
}

#[test]
fn charter_is_present_and_substantial() {
    let c = charter();
    assert!(
        c.len() > 1_000,
        "charter is suspiciously short ({} bytes) — a truncated charter is a \
         lost guardrail",
        c.len()
    );
}

#[test]
fn charter_retains_every_immutable_invariant() {
    let c = charter();
    // INV-1..INV-7 are the absolute invariants (refusal conditions). Each must
    // keep its stable ID so the loop can cite and the guard can pin it.
    for inv in [
        "INV-1", "INV-2", "INV-3", "INV-4", "INV-5", "INV-6", "INV-7",
    ] {
        assert!(
            c.contains(inv),
            "charter dropped invariant {inv} — an absolute refusal condition \
             must never disappear silently"
        );
    }
}

#[test]
fn charter_keeps_its_non_negotiable_themes() {
    let c = charter();
    let lower = c.to_lowercase();
    // The load-bearing keywords behind the invariants. Phrased case-insensitively
    // so wording can evolve, but the concept can't vanish.
    for (needle, why) in [
        ("never fabricate", "evidence-integrity clause (INV-1)"),
        ("never regress", "never-regress ratchet (INV-2)"),
        ("never merge red", "no-red-merge rule (INV-4)"),
        ("defensive", "defensive-only scope (INV-5)"),
        ("mitre att&ck", "ATT&CK defensive-integration scope"),
        ("ledger", "append-only shipped/rejected unit ledger"),
    ] {
        assert!(
            lower.contains(needle),
            "charter lost its {why}: missing phrase {needle:?}"
        );
    }
}

#[test]
fn charter_defines_the_cycle_protocol_stages() {
    let c = charter();
    // The ordered cycle stages the loop executes. All must be present so the
    // protocol can't be partially amputated (e.g. dropping GATE or PROVE).
    for stage in [
        "RECONCILE",
        "SENSE",
        "SELECT",
        "PROVE",
        "GATE",
        "SHIP",
        "RECORD",
        "REFRESH",
    ] {
        assert!(
            c.contains(stage),
            "charter cycle protocol is missing the {stage} stage"
        );
    }
}
