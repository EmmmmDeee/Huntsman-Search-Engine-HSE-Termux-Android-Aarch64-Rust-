# Huntsman provider credential slots

This file is the non-secret provider manifest for `huntsman-recon`.

Credential values MUST NOT be committed. Runtime values belong in
`$HOME/.huntsman.env` (mode 600), an explicit `--keys FILE`, or the process
environment. The generic key loader documented in the repository README reads
these slots without printing their values.

## Recovered/owned provider slots

| Provider | Runtime slot(s) | Integration state |
| --- | --- | --- |
| WiGLE | `HUNTSMAN_WIGLE_USER`, `HUNTSMAN_WIGLE_TOKEN` | used by `network` (CLI, `scan -k network`, web UI) when both are set in the environment: the API Name and API Token from https://wigle.net/account (not the encoded value); one daily WiGLE query per search (a BSSID or LAT,LON searches WiFi and Bluetooth, so two); `credential-status --probe` checks the pair without spending a query |
| Brave Search | `HUNTSMAN_BRAVE_KEY` | owned credential material located; validate/reissue before production use if historical exposure applies |
| Shodan | `HUNTSMAN_SHODAN_KEY` | used by `ip` (host, no query credits) and `domain` (DNS, one query credit) whenever set; private stored credential located; validity unverified |
| Whoxy | `HUNTSMAN_WHOXY_KEY` | used by `domain` (live WHOIS, one credit each) whenever set; an empty balance is reported as a plan refusal; private stored credential located; validity unverified |
| HIBP | `HUNTSMAN_HIBP_KEY` | owned subscription/key history; clean current credential required |
| SeekNow | `HUNTSMAN_SEEKNOW_KEY` | historical credential only; clean current credential required |
| OathNet | `HUNTSMAN_OATHNET_KEY` | used by `exposure` (CLI, `scan -k exposure`, web UI) when set in the environment; one daily lookup per search; validity unverified until a live search |
| Exa | `HUNTSMAN_EXA_KEY` | account confirmed; current credential not recovered |
| OpenRouter | `HUNTSMAN_OPENROUTER_KEY` | account confirmed; current credential not recovered |
| Google Gemini | `HUNTSMAN_GEMINI_KEY` | provider key existence confirmed; current value requires provider account |
| GitHub | `HUNTSMAN_GITHUB_TOKEN` | token lifecycle confirmed; current credential requires provider account |
| VirusTotal | `HUNTSMAN_VIRUSTOTAL_KEY` | used by `domain` and `ip` (CLI, `scan`, web UI) when set in the environment; free: 4 lookups/min, 500/day |
| AbuseIPDB | `HUNTSMAN_ABUSEIPDB_KEY` | used by `ip` when set in the environment; free: 1,000 checks/day |
| GreyNoise | `HUNTSMAN_GREYNOISE_KEY` | optional for `ip`: the Community API answers without a key at a lower limit; a free Community key raises it |
| Hunter.io | `HUNTSMAN_HUNTER_KEY` | used by `domain` when set in the environment; free: 25 searches/month, 10 addresses each |
| Numverify (APILayer) | `HUNTSMAN_NUMVERIFY_KEY` | used by `phone` when set in the environment; APILayer marketplace key (`api.apilayer.com`), free: 100 lookups/month |
| LeakIX | `HUNTSMAN_LEAKIX_KEY` | used by `ip` and `domain` when set in the environment; free account key |
| Pulsedive | `HUNTSMAN_PULSEDIVE_KEY` | optional for `ip` and `domain`: Pulsedive answers without a key at a lower limit; a free key raises it |
| IPQualityScore | `HUNTSMAN_IPQS_KEY` | used by `ip` when set in the environment; free: 1,000 lookups/month |
| ThreatFox (abuse.ch) | `HUNTSMAN_THREATFOX_KEY` | used by `ip` and `domain` when set in the environment; free abuse.ch Auth-Key |
| Censys | `HUNTSMAN_CENSYS_ID`, `HUNTSMAN_CENSYS_SECRET` | do not assume usable; provider access must be revalidated |

## Private runtime template

Copy only the slots you actually use into `$HOME/.huntsman.env` and set the
file mode to 600.

```dotenv
HUNTSMAN_WIGLE_USER=
HUNTSMAN_WIGLE_TOKEN=
HUNTSMAN_BRAVE_KEY=
HUNTSMAN_SHODAN_KEY=
HUNTSMAN_WHOXY_KEY=
HUNTSMAN_HIBP_KEY=
HUNTSMAN_SEEKNOW_KEY=
HUNTSMAN_OATHNET_KEY=
HUNTSMAN_EXA_KEY=
HUNTSMAN_OPENROUTER_KEY=
HUNTSMAN_GEMINI_KEY=
HUNTSMAN_GITHUB_TOKEN=
HUNTSMAN_VIRUSTOTAL_KEY=
HUNTSMAN_ABUSEIPDB_KEY=
HUNTSMAN_GREYNOISE_KEY=
HUNTSMAN_HUNTER_KEY=
HUNTSMAN_NUMVERIFY_KEY=
HUNTSMAN_LEAKIX_KEY=
HUNTSMAN_PULSEDIVE_KEY=
HUNTSMAN_IPQS_KEY=
HUNTSMAN_THREATFOX_KEY=
HUNTSMAN_CENSYS_ID=
HUNTSMAN_CENSYS_SECRET=
```

Never place populated values in this repository, release artifacts, logs,
examples, documentation, or issue/PR text.
