# How Huntsman Search Engine compares

An honest, sourced comparison of HSE against the OSINT tools it is most often
measured against. HSE is a comprehensive, **on-device** (Termux / Android,
no root), **free-first** OSINT / GEOINT and breach-intelligence engine —
147 modules (114 keyless), Rust, `#![forbid(unsafe_code)]`, ~3,800 tests.
This is written to help an operator decide what to run, not as a marketing
claim, so it states where competitors lead too.

| Capability | HSE | SpiderFoot (OSS) | Maltego | Recon-ng / theHarvester | Shodan | SEON |
|---|---|---|---|---|---|---|
| Model | Proprietary, self-host | Open-core + SaaS (HX) | Enterprise licence | Free OSS | SaaS | SaaS (fraud/KYC) |
| Runs on a phone (Termux, no root) | ✅ single binary | ⚠️ Python, server-oriented | ❌ desktop/JVM | ⚠️ Python | n/a (hosted) | n/a (hosted) |
| Keyless / free module coverage | ✅ 114 of 147 | broad (key-optional) | needs hubs/keys | narrow | n/a | n/a |
| Breach / stealer credential intel | ✅ | partial | via hubs | ❌ | ❌ | ✅ (signals) |
| Email / phone → digital footprint | ✅ | partial | via hubs | partial | ❌ | ✅ (core) |
| Australian public-records depth | ✅ registries, electoral, property, ACMA, … | ❌ | ❌ | ❌ | ❌ | ❌ |
| Geo / GEOINT correlation (centroid fusion, country coherence) | ✅ | ⚠️ | ⚠️ | ❌ | partial | ❌ |
| Inline MITRE ATT&CK (Recon TA0043) mapping | ✅ | ❌ | ❌ | ❌ | ❌ | ❌ |
| Memory-safe core | ✅ Rust, forbid(unsafe) | Python | Java | Python | — | — |
| Owns its own data (a moat) | ❌ orchestrator | ❌ orchestrator | partial | ❌ | ✅ its scans | partial |
| Indicative price | — | free / SaaS | from ~$5k/seat | free | $49–$1,099/mo | enterprise |

## Where HSE genuinely leads

- **On-device, single-binary, free-first.** Nobody else packages comprehensive
  OSINT to run on an Android phone with no root and ~114 keyless modules.
- **Australian people / registry depth** combined with email/phone → footprint
  and breach intel in one engine.
- **Engineering bar.** Rust with `forbid(unsafe)`, ~3,800 tests, enforced
  architecture guards, and ATT&CK alignment carried inline in the data.

## Where competitors genuinely lead (the honest part)

- **Data moat.** Shodan and Babel Street own the data they sell; HSE, like
  SpiderFoot, *orchestrates* third-party and public sources — powerful, but
  not a proprietary data asset.
- **Traction, trust, and compliance.** Maltego (used by the FBI / INTERPOL),
  SpiderFoot (acquired by Intel 471), and SEON (a ~$500M fraud-prevention
  company) have users, brand, and regulatory standing that HSE has not yet
  built.

## Best-fit use — authorised use only

Authorised security reconnaissance / attack-surface mapping, fraud-prevention
and KYC enrichment **with a lawful basis**, due diligence, and licensed
investigations — especially Australian-context work, and especially where
running on a phone in the field matters. See the **Licence** and **Authorised &
lawful use** notes in the [README](../README.md).

---

*Sources: public materials and reporting on Intel 471's SpiderFoot acquisition,
Maltego, Shodan, SEON, Babel Street, and Fivecast. Figures are indicative and
move over time; verify before relying on them commercially.*
