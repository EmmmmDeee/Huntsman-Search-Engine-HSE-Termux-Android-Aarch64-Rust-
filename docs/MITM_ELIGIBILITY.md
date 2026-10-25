# Rootless Wi-Fi MITM evidence eligibility

Huntsman checks cached Wi-Fi information made available by Android through
Termux:API. A successful sensor call does **not** mean a usable live MITM
assessment was performed: stale records, unknown freshness, hidden network
names and duplicate access points can leave zero eligible observations.

## Run the diagnostic

From a repository checkout in Termux:

```sh
bash scripts/termux/mitm-eligibility.sh
```

Prerequisites: `huntsman`, `jq`, `timeout`, `mktemp`, `wc`, `termux-api`, and a
matching Termux:API Android app with the necessary permissions. Android owns
the Wi-Fi scan schedule; the diagnostic reads its OS-cached scan observations
and **does not actively scan, disconnect, enroll trusted baselines, or modify
network settings**.

The tool acquires **one** sensor snapshot through `huntsman radar wifi --json`
and uses the same selection order as the Rust MITM assessment: current
(`os_cached`) records, visible 1..32-byte SSIDs, valid individual BSSIDs, then
unique (SSID, BSSID) identities. It compares the calculated eligibility count
with `mitm_assessment.evaluated_access_points`. The count is an internal
consistency check, not an external confirmation of an attack.

The script prints and optionally stores only aggregate results. It does not
print SSIDs, BSSIDs or raw capture records. Temporary raw observations are
stored in a private temporary directory removed on normal exit. If a state
directory exists, it writes a mode-0600 `mitm-eligibility.*.json` diagnostic;
otherwise, it prints without saving. Under abrupt termination, temporary data
may require manual cleanup; this is not secure erasure.

## Interpretation

- `INCONCLUSIVE_ZERO_EVALUATED`: the sensor reported observations but no
  eligible access points were available for live assessment, or the OS
  returned none. This is **not a clean-network conclusion**.
- `COUNT_MISMATCH`: Rust and the independently calculated eligibility counts
  disagree. Inspect the parser/assessment before interpreting findings.
- `UNCONFIRMED_INDICATORS`: assess individual warnings against an independently
  verified access-point inventory. Neither findings nor silence establish MITM.
- `NO_SPECIFIC_INDICATORS_NOT_PROOF_OF_SAFETY`: at least one access point was
  evaluated, but no specific indicator was reported; the sensor cannot prove
  absence of interception.

A stale-only radar command may exit nonzero while still returning valid JSON;
the diagnostic handles that case without re-capturing. Other unexpected
nonzero exits are reported as inconsistencies rather than successes. The
companion Android app must come from a signing-compatible distribution with
the installed Termux application.

## Validation

```sh
bash -n scripts/termux/mitm-eligibility.sh
python3 -m unittest discover -s tests -p 'test_mitm_eligibility_shell.py' -v
```

These deterministic fixtures test the logic on a host and are not a substitute
for real-device acceptance. The broader repository gate is `cargo gate full`.
