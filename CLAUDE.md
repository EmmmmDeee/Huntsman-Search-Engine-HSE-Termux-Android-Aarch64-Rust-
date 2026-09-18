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
