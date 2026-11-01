# MITRE-aligned engineering and intelligence contract

Status: proposed engineering standard. This document does not certify framework conformance or operational acceptance.

## Principle

Use the most relevant maintained external standard as a baseline, and exceed it where Huntsman's evidence, security, Android or operational requirements demand. Never assign an ATT&CK technique merely because a module performs OSINT. Record `not_applicable` with a reason.

## Standards and ownership

| Domain | Reference | Huntsman requirement |
| --- | --- | --- |
| Threat behaviours | MITRE ATT&CK Enterprise and Mobile | Versioned technique identifiers, domain, observed evidence, applicability and confidence |
| Detection | ATT&CK detection strategies (DET), analytics (AN), data components (DC) | Prefer post-v18 detection model; do not introduce new dependencies on deprecated data-source objects |
| Defensive countermeasures | MITRE D3FEND | Model defensive action and supporting evidence; do not imply efficacy from a mapping alone |
| Cyber threat exchange | OASIS STIX 2.1 / TAXII 2.1 | Separate raw observations, indicators, claims, relationships and source provenance |
| Mobile investigations | ATT&CK Mobile Android | Explicit Android version, permissions, sensor capability and no-root limitations |
| AI-specific threats | MITRE ATLAS | Reference for analysing external AI systems only; no runtime LLM dependency |
| Engineering assurance | NIST SP 800-53 controls, scoped by risk | Testable control objectives and negative-path evidence, not blanket certification |
| Non-cyber OSINT | Domain-specific public records and primary sources | Entity typing, lawful access, collection timestamp, independent corroboration and uncertainty; MITRE mapping optional |

## Capability acceptance contract

For each required capability, record:
- stable capability identifier and OSINT type;
- owner file, CLI/API/Web entry point and dependency edges;
- actual provider implementation, credential and quota requirements;
- canonical entity/observable and evidence output;
- applicable standard name, edition, external identifier and rationale (or explicit not-applicable);
- fixture test, local integration test, live provider receipt and Android handset result;
- source freshness, original artifact hash, provenance, conflict handling and limitations;
- negative tests for malformed input, offline mode, unavailable keys, timeouts, redirects, denied access and provider schema drift;
- exact build SHA, acceptance state and rollback path.

An implementation file, registry entry, source URL, green CI check or successful cross-build is not proof of end-to-end functionality.

## Required invariants

1. All network requests use the guarded egress boundary; never bypass authentication, authorization or provider restrictions.
2. Discovery links are leads, not evidence. Observed data are not automatically intelligence assertions.
3. Corroboration requires independent provenance; duplicate reporting of one origin is not independent evidence.
4. Every detection or attribution retains a falsifiable basis and explicitly represents uncertainty.
5. A framework mapping is not a claim of detection, prevention, conformance or endorsement.
6. Physical Android acceptance is separate from Linux CI, cross-build and QEMU.
7. Preserve existing CLI/API contracts and evidence ledgers during migration; use compatibility adapters where needed.
8. Do not introduce duplicate provider stacks, second engines, unnecessary runtime dependencies or runtime LLMs.
9. Require reviewable tests and a clean exact-head CI run before merging.
10. Version and refresh upstream framework references; identify deprecated identifiers before migration.

## Immediate execution order

1. Validate the existing twelve primary scan-type entries against real dispatch and implementation files.
2. Build a generated, per-file traceability matrix for all tracked files, distinguishing runtime, tests, documentation and assets.
3. Add a standards mapping only for genuinely relevant capabilities; retain explicit not-applicable classifications.
4. Prove guarded fetch, provenance and provider error semantics before expanding integrations.
5. Exercise each scan type with independent fixtures and live authorized provider checks.
6. Verify CLI, Web API, exports, release artifact and real Termux handset end-to-end.
7. Gate acceptance on demonstrated evidence, not claimed module counts.

## Primary references

- https://attack.mitre.org/
- https://attack.mitre.org/matrices/mobile/android/
- https://mitre-attack.github.io/attack-data-model/docs/principles/attack-detections/
- https://d3fend.mitre.org/
- https://atlas.mitre.org/
- https://docs.oasis-open.org/cti/stix/v2.1/stix-v2.1.html
- https://csrc.nist.gov/pubs/sp/800/53/r5/final
