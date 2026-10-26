# MITM guard: evidence-gated Wi-Fi assessment

**Scope:** Huntsman Recon on rootless Android AArch64 Termux. No API key, network transmission, packet injection, raw monitor mode, TLS interception, deauthentication, root permission, or runtime model. The module is a **passive risk assessment**, not an intrusion-prevention system.

## Commands

Read Android's cached Wi-Fi scan through Termux:API:

```sh
huntsman-recon mitm audit --json
```

Review normalized WiGLE JSONL (historical, unverified source):

```sh
huntsman-recon mitm audit --file 20261018-03494-huntsman.jsonl --json
```

Review an offline Termux:API scan JSON array:

```sh
huntsman-recon mitm audit --file wifi-scan.json --json
```

Review against **independently verified**, operator-owned infrastructure inventory:

```sh
huntsman-recon mitm audit --file wifi-scan.json --baseline trusted-wifi.json --json
```

Example `trusted-wifi.json`:

```json
{
  "networks": [
    {
      "ssid": "Office",
      "bssids": ["3c:5a:b4:11:22:33"],
      "minimum_security": "WPA3"
    }
  ]
}
```

An allowlist only has meaning if the legitimate network administrator supplies and verifies it **independently**. Do **not** create a trusted baseline automatically from the potentially spoofed scan. On a real enterprise network, managed authentication policies and certificate validation usually scale better than manually maintaining an AP list.

The Radar Web UI automatically shows advisory MITM indicators alongside the cached Wi-Fi results when an operator explicitly clicks **Read OS scan cache**. It does not automatically collect Wi-Fi data when a page opens.

## What the detector can infer

| Evidence | Output | Notes |
|---|---|---|
| Same named SSID, different advertised security | `unverified_ssid_security_variation` (review) | Mixed WPA2/WPA3 deployments are ordinary. No evil twin claimed |
| Trusted SSID observed below policy security floor | `security_below_trusted_floor` (high) | Possible downgrade, configuration mismatch or outdated inventory; **not** proof of MITM |
| Trusted SSID observed at an unauthorised BSSID | `bssid_not_on_operator_allowlist` (review) | Equipment changes, mesh or guest access can be legitimate |
| Missing capability data on a trusted SSID | `trusted_ssid_security_unverified` (review) | Unknown must **never** be treated as open or safe |
| Hidden/no-name SSID marker | Ignored for SSID-level correlation | All hidden networks do not represent one SSID |

WiGLE records are historical observations; recorded positions are not verified transmitter locations. Old cached Android observations cannot establish that an AP is currently nearby. Reports keep `mitm_confirmed=false`. No observation is evidence that another device's private traffic was intercepted.

The security parser uses the **weakest identifiable mode** when advertised capabilities include WPA2/WPA3 transition modes; it does not equate transition mode to WPA3-only. Output is deterministic and bounded to protect phone memory.

**Identifier continuity:** All MITM assessment entry points (native radar, CLI replay, normalized WiGLE JSONL, and direct Rust callers) compare BSSIDs as case-insensitive hexadecimal MAC addresses and report canonical lowercase identifiers. SSIDs remain byte-exact; a spelling change is not proof that two networks are the same. The CLI and Web UI use the shared Rust assessment, with live clock provenance retained only for a live capture. This normalization does not change the report schema, file formats or supported commands.

**Contradictory duplicate records:** When the same canonical SSID/BSSID advertises multiple distinct known security modes, the shared evaluator retains the disagreement as a review-only `bssid_security_conflict_unverified` finding. It does not select the first row, infer a downgrade, or mistake the conflict for variation across different BSSIDs. Missing security metadata alone is not a contradictory mode; verify the current network configuration independently.

## Response and mitigation

1. **Do not authenticate** to a suspicious AP before verification. Avoid captive portals requesting unrelated credentials or downloads.
2. **Verify SSID, BSSID, authentication policy, and (for enterprise networks) server certificate and issuing authority** against independently trusted administrator documentation.
3. **On Android, manually disconnect/forget** an untrusted Wi-Fi network in Settings, disable automatic reconnection, and use a verified mobile network if necessary.
4. For infrastructure you administer, investigate AP/controller logs, RADIUS authentication, DHCP/ARP changes, DNS anomalies, TLS validation failures, and management-frame events. Use qualified instrumentation where permission and hardware allow.
5. Patch client and AP firmware, prefer WPA3/PMF where supported, enforce appropriate 802.1X certificate validation, and confirm network configuration after mitigation.
6. **Retest** using a new, independently timestamped trusted scan and infrastructure logs; absence of indicators is not proof that an attacker is gone.

Rootless Android cannot forcibly remove arbitrary access points or reliably monitor 802.11 management frames. Hence, this module reports a remediation plan rather than performing a risky automatic disconnection or deauthentication operation.

## arXiv evidence and applicability

These are **research references**, not claims that the cited authors validated this lightweight Rust heuristic implementation or its detection accuracy.

| arXiv | Main result | What Huntsman uses or excludes |
|---|---|---|
| [1903.05843](https://arxiv.org/abs/1903.05843) ETGuard, 2019 | Evil-twin pre-association fingerprinting from beacon fields | Supports multi-feature baseline concept; management frame fields unavailable in rootless Termux |
| [2203.00579](https://arxiv.org/abs/2203.00579) Multi-Channel MITM review, 2022 | Attack taxonomy, PMF and protocol limitations | Determines threat-model and mitigation messaging |
| [2302.00338](https://arxiv.org/abs/2302.00338) RCMS, 2023 | Verifying enterprise network certificates against evil twins | Motivates validating certificate trust outside SSID/BSSID matching; **not implemented** as a certificate-verification agent |
| [2110.04259](https://arxiv.org/abs/2110.04259) WPA3 IDS, 2021 | Tested signature-based detection of several WPA3 attacks | Raw management/traffic telemetry required; **not available** from Android scan cache |
| [2512.10470](https://arxiv.org/abs/2512.10470) Rogue AP stealth/evasion, 2025 | Ordinary NIDS may miss captive-portal evil-twin attacks | Do not claim a negative network-level verdict implies safety |
| [2601.22770](https://arxiv.org/abs/2601.22770) Okara, 2026 | Study of Android app TLS MITM vulnerabilities with foundation-model instrumentation | Highlights the distinct **application-level** attack surface. Not implemented: would violate rootless, low-cost, no-LLM runtime constraints |

**Validation status:** Unit tests, CLI replay fixtures and CI quality gates must pass on the actual revision before a merge. No live MITM reproduction, empirical false-positive rate, or detection sensitivity is claimed.
