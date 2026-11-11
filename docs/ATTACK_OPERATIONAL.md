# ATT&CK-Informed Autonomous OSINT (experimental)

## Operating mode

Huntsman's existing SpiderFoot-compatible scan service remains the single owner of
network requests, provider credentials, checkpoint persistence, cancellation,
source outcomes and correlation. The `autonomous` use case adds a **real
execution policy**, not a second OSINT engine or a static ATT&CK report.

Start a live scan on Termux/Android AArch64:

```sh
huntsman-recon attack run "Ada Lovelace" -k people --json
huntsman-recon attack run example.org --json
huntsman-recon scans run "Brisbane, Australia" -k geocode -u autonomous --json
```

The **New Scan → By Use Case → Autonomous ATT&CK OSINT** option executes the same
saved scan path and exposes the same results in the Web UI. It accepts all
existing scan selectors and optional module restrictions.

The active mode starts with three pivot generations unless a nonzero
`--depth` is provided. Each generation collects live results through the
existing selected lookup modules, preserves source outcomes and provenance,
and proposes identity/infrastructure targets from observed entities. It also
permits geocoding an independently observed address or coordinate as an
additional route. The target's own type gives the objective:

- People, usernames, email and phone: follow identity-bearing discoveries
  earlier, then associated places and infrastructure.
- Places and radio-network selectors: prioritise geographic follow-up.
- Domains, IPs, ASNs, network blocks and crypto addresses: prioritise
  domain/network follow-up.

An ATT&CK Reconnaissance mapping must resolve in the checked-in catalogue
before it contributes a dispatch priority. Route types are dispatched in a
deterministic, one-per-type round robin; the objective orders *types* within
each round rather than letting one large kind monopolise the frontier.

These mappings are **operational analogues** to MITRE ATT&CK's description
of adversary reconnaissance. Running a public-record lookup is not proof that
an adversary used an ATT&CK technique. ATT&CK does not itself provide
people-finding, geocoding, provider access, attribution or verification.

## Safety, integrity and resource contract

- Existing selector validation, public-only egress and provider restrictions
  remain authoritative; no unauthorized network probing, phishing,
  credential attempts or intrusive techniques are introduced.
- Confidence thresholds, name-only lead restrictions, role-mailbox
  restrictions, deduplication, per-kind fan-out limits, dispatch limits,
  bounded graph execution, cancellation, persistence and raw evidence are
  unchanged.
- A configured paid or keyed provider remains eligible when allowed by the
  chosen scan and existing credentials. Select modules explicitly if a
  strict source or quota limit is required.
- A denied, throttled, absent or malformed source must retain its original
  outcome; it is never converted to evidence or a verified technique.
- Legacy `all`, `footprint`, `investigate` and `passive` scans retain
  their zero-hop defaults and established routes.
- No runtime LLM, duplicate HTTP stack, shell subprocess, root permission
  or new Cargo dependency is used.

## Verification boundaries

Unit fixtures exercise priority mappings, cross-kind fairness, legacy
zero-hop preservation and an autonomous address-to-geocode dispatch through
the scan service. Real provider success, Android handset functionality and
the compiled release require independent CI and on-device acceptance.

The full Enterprise ATT&CK table checked into this repository remains
v17.1, with a separately updated Reconnaissance overlay at v19.2; this
feature does **not** silently re-label them as the current upstream
version. MITRE lists ATT&CK v20.1 as current. Full v20.1 STIX ingestion,
technique-level collector execution receipts, closed-loop information-gain
optimisation, source-independent corroboration feedback, and scheduled
campaign-level autonomous re-planning are separate integration milestones.

Authoritative upstream references:

- https://attack.mitre.org/tactics/TA0043/
- https://attack.mitre.org/resources/versions/
- https://github.com/mitre-attack/attack-stix-data
