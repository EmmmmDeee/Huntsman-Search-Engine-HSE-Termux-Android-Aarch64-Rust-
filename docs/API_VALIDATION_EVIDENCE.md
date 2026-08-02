# API Validation Evidence

Live-validation record for API integrations, kept per the Operational
Constitution: **observation separated from inference**, failures recorded as
plainly as successes, and no capability claimed that wasn't actually observed.

Each entry is the *observed* response from a real query made while integrating the
source. Reproduce with the `curl` line shown; upstream data drifts, so the sample
values are a point-in-time record, not a guarantee.

Validation date: 2026-08-01.

---

## Adopted this cycle

### `mnemonic_pdns` — Mnemonic Passive DNS v3 (keyless) — ✅ VALIDATED

Endpoint: `GET https://api.mnemonic.no/pdns/v3/{query}?limit={n}`

**Forward (domain → historical resolutions).**

```
$ curl -s "https://api.mnemonic.no/pdns/v3/github.com?limit=2"
HTTP 200
responseCode=200  count=1000
sample record: {query:"github.com", answer:"140.82.114.3", rrtype:"a",
                times:21107, firstSeenTimestamp:1565133646785,
                lastSeenTimestamp:1785518060896}
```

Observation: HTTP 200; `data[]` of observed A/AAAA/CNAME/MX/NS records; timestamps
are epoch **milliseconds**; `times` is the observation count. → mapper emits
historical `IpAddress` (A/AAAA) and related-infra `Domain` (CNAME/MX/NS).

**Reverse (IP → historical domains).**

```
$ curl -s "https://api.mnemonic.no/pdns/v3/140.82.114.3?limit=2"
HTTP 200
domains observed in data[].query: ["github.com", "ghe.com"]
```

Observation: querying an IP returns records whose `answer` is that IP and whose
`query` is a domain that resolved to it. → mapper emits reverse-pivot `Domain`
entities tagged `reverse-ip`.

**Empty case.** A non-existent name returns HTTP 200 with `data: []` and a
`messages[].messageTemplate = "object.not.found"` — so `fetch_json` (which errors
only on non-2xx) correctly treats a miss as an empty result, and a real outage
(5xx/429) still surfaces.

### `open_meteo_geo` — Open-Meteo Geocoding (GeoNames-backed, keyless) — ✅ VALIDATED

Endpoint: `GET https://geocoding-api.open-meteo.com/v1/search?name={q}&count={n}`

```
$ curl -s "https://geocoding-api.open-meteo.com/v1/search?name=Golden,%20CO&count=1"
HTTP 200
sample result: {name:"Golden", latitude:39.75554, longitude:-105.2211,
                country_code:"US", admin1:"Colorado", timezone:"America/Denver",
                population:20330, feature_code:"PPLA2", elevation:1730.0}
```

Observation: HTTP 200; comma-bearing self-reported strings ("Golden, CO") resolve
correctly; each result carries `timezone`, `population`, `feature_code`, and
`elevation` — the enrichment fields `geocode` (Nominatim) and `photon` (Komoot)
do not return. A no-match query returns HTTP 200 with the `results` key **absent**
(not `[]`), which `#[serde(default)]` handles as an empty vec. → mapper emits a
`Coordinates` anchor + `candidate` alternates with the enrichment as evidence.

---

## Reachable, roadmapped (not yet wired)

### FIRST.org EPSS (keyless) — ✅ REACHABLE

```
$ curl -s "https://api.first.org/data/v1/epss?cve=CVE-2021-44228,CVE-2019-0708"
HTTP 200
data: [{cve:"CVE-2021-44228", epss:"0.99999", percentile:"1.0"}, ...]
```

Observation: keyless, HTTP 200, clean JSON keyed by CVE. Not wired as a *module*
because there is no `Cve` `TargetKind` for it to dispatch on — the natural fit is
a **correlator enrichment** that annotates the CVE IDs `shodan` already attaches to
IP entities (roadmap §7.1 in `ULTIMATE_HSE_DESIGN.md`).

---

## Candidates rejected during validation

Recorded so they aren't re-attempted blindly (observation, then the reason):

| Candidate | Observed | Rejected because |
|---|---|---|
| Shodan InternetDB | HTTP 200, keyless host data | **Already integrated** — the `shodan` module already uses `internetdb.shodan.io`. |
| ThreatMiner API | HTTP 500 on `domain.php` | Unreliable at validation time; a source must answer before it's wired. |
| `columbus.elmasy.com` | Proxy `CONNECT tunnel failed, 502` | Not reachable/verifiable from this environment. |
| `sonar.omnisint.io`, `*.bufferover.run` | TLS error / 403 / dead | Defunct or blocked — unverifiable. |
| BigDataCloud reverse-geocode-*client* | HTTP 200, rich admin hierarchy | Keyless endpoint is documented for browser client use; server-side use is a gray-area term. Reverse geocoding is already covered by `geocode` + `photon` under clear keyless terms. |
| `crt.sh` (during probing) | HTTP 404 via proxy | Transient/proxy-specific; `crt.sh` is already the `crtsh` module and unaffected. |

---

## Method

- Every adopted source's response→entity mapping is a **pure function** unit-tested
  against fixtures derived from the samples above (`src/modules/<name>/tests.rs`),
  so the parser is verified without the network.
- Ongoing contract-drift checks belong in the `#[ignore]`d `tests/live_drift.rs`
  suite (run in its own workflow), which is where a breaking change in one of these
  upstreams is caught before it reaches an operator.
