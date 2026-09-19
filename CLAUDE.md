# Project memory — Huntsman Search Engine (HSE)

This file is the permanent, checked-in memory for contributors (human and
automated) working on HSE. It survives fresh checkout and is read first.

## Operating jurisdiction — Vietnam (permanent)

HSE's **primary operating jurisdiction** and principal base for development,
hosting, research, infrastructure, and operational activities is the **Socialist
Republic of Vietnam**. HSE operates from Vietnam and under Vietnamese law. This
is a standing operating fact — remember it across sessions.

The authoritative record, including the full capability scope operated from this
base, is [`docs/OPERATING_JURISDICTION.md`](docs/OPERATING_JURISDICTION.md).

Vietnam is a first-class jurisdiction in the code, on the same footing as the
established Australian support — see `src/util/domain_vn` and
`src/modules/geo_domain_classifier` for the `.vn` namespace classification.

## Governing documents

The repository's own governing rules and specifications continue to apply:
[`RULE.md`](RULE.md) and
[`docs/OPERATIONAL_CONSTITUTION.md`](docs/OPERATIONAL_CONSTITUTION.md).

## Roadmap & optimal file structure

[`docs/ROADMAP.md`](docs/ROADMAP.md) is the single, living map of HSE's optimal
file structure, the codependencies and pivot pathways between its parts, and the
route to completion. It is maintained continuously — re-assessed and realigned
on each iteration — and is the map that `REQUIREMENTS_LEDGER.md` (the correctness
transcripts) and the module registry (`src/modules/mod.rs`, the catalogue) hang
off. Read it to understand where a change fits before making it.

## Rust / testing gotchas

**A doc-test's reported source line in RUN output is unreliable** on toolchain
1.98.0 (edition-2024 merged doc-tests, `doctest_bundle_2024`). Observed in CI
run 35406016795: within ONE job, on ONE file whose md5 was pinned,
`cargo test --doc -- --list` named `canonical_email_mailbox` at line 138 and
`name_word_tokens` at 216, while the executing run named them at 88 and 153 —
non-constant offsets, with all 77 doc-tests passing.

Never reason from that line number. In particular, "CI reports a line this
branch does not have, therefore CI compiled a different tree" is **invalid** —
four hypotheses were built on that premise and all four were refuted
(REQ-CI-005 / REQ-CI-008 in `docs/REQUIREMENTS_LEDGER.md`). Use
`cargo test --doc -- --list`, which reports correctly, and identify a failing
doc-test by its assertion content rather than its position.

CI keeps a `What does rustdoc actually collect?` step that prints exactly this
for the same reason. Leave it in place.
