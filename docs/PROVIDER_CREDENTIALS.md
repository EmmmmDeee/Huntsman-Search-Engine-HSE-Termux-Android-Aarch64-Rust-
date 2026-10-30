# Huntsman provider credential slots

This file is the non-secret provider manifest for `huntsman-recon`.

Credential values MUST NOT be committed. Runtime values belong in
`$HOME/.huntsman.env` (mode 600), an explicit `--keys FILE`, or the process
environment. The generic key loader documented in the repository README reads
these slots without printing their values.

Configured keys are available automatically to their relevant provider legs; a
key is not authorization to query unrelated services, bypass a module selection,
or spend paid API quota for an irrelevant target. Operators can inspect presence
with `huntsman-recon credential-status` and configure a slot using
`printf '%s' "$API_KEY" | huntsman-recon keys set HUNTSMAN_PROVIDER_KEY --stdin`.
No credential values are required in CLI arguments, logs or source control.

## SEC EDGAR: declared operator identity (no API key)

The free SEC EDGAR source requires an **operator-controlled, contactable** User-Agent.
The SEC's published fair-access example identifies the organisation and an administrator
email. Huntsman therefore **does not send SEC requests** until the running process
has a valid `HUNTSMAN_SEC_USER_AGENT` value.

On Termux or another shell, set the value using **your own authorised email address**
before starting `huntsman-recon`:

```sh
export HUNTSMAN_SEC_USER_AGENT='Huntsman-Recon YourAuthorisedContact@your-domain.example'
```

Replace the illustrative contact with a monitored email address you control.
The setting is **not an API key** and is transmitted to SEC as a request header:
do not use an address you are unwilling to share with that provider. It is
process-environment configuration; a shell export does not survive a new terminal
session unless configured in your private shell startup or service environment.

Missing or malformed identity produces a `not_configured` provider outcome and
no HTTP request, not an invented clean zero. Contact values are not included in
provider outcome diagnostics or `Request` debug output. Respect the SEC's aggregate
fair-access ceiling (currently 10 requests/second) and any stricter local pacing.

Primary policy: https://www.sec.gov/search-filings/edgar-search-assistance/accessing-edgar-data

## Recovered/owned provider slots

| Provider | Runtime slot(s) | Integration state |
| --- | --- | --- |
| WiGLE | `HUNTSMAN_WIGLE_USER`, `HUNTSMAN_WIGLE_TOKEN` | used by `network` (CLI, `scan -k network`, web UI) when both are set in `~/.huntsman.env` or the environment: the API Name and API Token from https://wigle.net/account (not the encoded value); one daily WiGLE query per search (a BSSID or LAT,LON searches WiFi and Bluetooth, so two); `credential-status --probe` checks the pair without spending a query |
| Brave Search | `HUNTSMAN_BRAVE_KEY` | owned credential material located; validate/reissue before production use if historical exposure applies |
| Shodan | `HUNTSMAN_SHODAN_KEY` | used by `ip` (host, no query credits) and `domain` (DNS, one query credit) whenever set; private stored credential located; validity unverified |
| Whoxy | `HUNTSMAN_WHOXY_KEY` | used by `domain` (live WHOIS, one credit each) and `email` (reverse WHOIS, one reverse credit a page) whenever set; an empty balance is reported as a plan refusal; private stored credential located; validity unverified |
| HIBP | `HUNTSMAN_HIBP_KEY` | owned subscription/key history; clean current credential required |
| SeekNow | `HUNTSMAN_SEEKNOW_KEY` | native `seeknow` CLI and keyed lookup leg; generate an API key from the [SeekNow account](https://see-know.ru/register); website search quotas do not establish API entitlements or available credits; credential is operator-supplied and never committed |
| OathNet | `HUNTSMAN_OATHNET_KEY` | used by `exposure` (CLI, `scan -k exposure`, web UI) when set in the environment; one daily lookup per search; validity unverified until a live search |
| DeHashed | `HUNTSMAN_DEHASHED_KEY` | used by `exposure` and `email` (CLI, `scan`, web UI), and by explicit `dehashed search --purpose ...`. All resolve the private `~/.huntsman.env` slot with process-environment fallback; the explicit command also supports its legacy private `~/.config/dehashed/api_key` file if the shared slot is unset. Keys are sent only to DeHashed's fixed API origin |
| stolen.tax | `HUNTSMAN_STOLEN_TAX_KEY` | used by `exposure` and the `email` and `username` lookups (CLI, `scan`, web UI) when set |
| Exa | `HUNTSMAN_EXA_KEY` | account confirmed; current credential not recovered |
| OpenRouter | `HUNTSMAN_OPENROUTER_KEY` | account confirmed; current credential not recovered |
| Google Gemini | `HUNTSMAN_GEMINI_KEY` | provider key existence confirmed; current value requires provider account |
| GitHub | `HUNTSMAN_GITHUB_TOKEN` | token lifecycle confirmed; current credential requires provider account |
| VirusTotal | `HUNTSMAN_VIRUSTOTAL_KEY` | used by `domain` and `ip` (CLI, `scan`, web UI) when set in the environment; free: 4 lookups/min, 500/day |
| AbuseIPDB | `HUNTSMAN_ABUSEIPDB_KEY` | used by `ip` when set in the environment; free: 1,000 checks/day |
| GreyNoise | `HUNTSMAN_GREYNOISE_KEY` | optional for `ip`: the Community API answers without a key at a lower limit; a free Community key raises it |
| Hunter.io | `HUNTSMAN_HUNTER_KEY` | used by `domain` (domain search) and `email` (verifier) when set in the environment; free: 25 searches and 50 verifications/month |
| Numverify (APILayer) | `HUNTSMAN_NUMVERIFY_KEY` | used by `phone` when set in the environment; APILayer marketplace key (`api.apilayer.com`), free: 100 lookups/month |
| LeakIX | `HUNTSMAN_LEAKIX_KEY` | used by `ip` and `domain` when set in the environment; free account key |
| Pulsedive | `HUNTSMAN_PULSEDIVE_KEY` | optional for `ip` and `domain`: Pulsedive answers without a key at a lower limit; a free key raises it |
| IPQualityScore | `HUNTSMAN_IPQS_KEY` | used by `ip`, `email` and `phone` when set in the environment; free: 1,000 lookups/month |
| ThreatFox (abuse.ch) | `HUNTSMAN_THREATFOX_KEY` | used by `ip` and `domain` when set in the environment; free abuse.ch Auth-Key |
| Netlas | `HUNTSMAN_NETLAS_KEY` | optional for `ip` and `domain`: Netlas answers without a key at a lower limit; a free Community key raises it |
| SecurityTrails | `HUNTSMAN_SECTRAILS_KEY` | used by `domain` when set in the environment; free: 50 queries/month |
| URLhaus (abuse.ch) | `HUNTSMAN_ABUSECH_KEY` | used by `ip` (IPv4 addresses only) and `domain` when set in the environment; the same free abuse.ch Auth-Key as `HUNTSMAN_THREATFOX_KEY` |
| AlienVault OTX | `HUNTSMAN_OTX_KEY` | optional for `ip` and `domain`: OTX answers without a key at a lower limit; a free key raises it |
| urlscan.io | `HUNTSMAN_URLSCAN_KEY` | optional for `ip` and `domain`: searches work without a key at a lower quota; a free key raises it |
| IPinfo | `HUNTSMAN_IPINFO_KEY` | optional for `ip`: IPinfo answers without a token at a lower limit; a free token gives 50,000 lookups/month |
| Cert Spotter (SSLMate) | `HUNTSMAN_CERTSPOTTER_KEY` | optional for `domain`: Cert Spotter answers without a key at a lower limit; a free key raises it |
| HackerTarget | `HUNTSMAN_HACKERTARGET_KEY` | optional for `ip` and `domain`: HackerTarget answers without a key at 50 queries a day; a membership key raises it |
| OpenCelliD | `HUNTSMAN_OPENCELLID_KEY` | required for `network cell:MCC:MNC:AREA:CELL` and for the cell sites around a point in `network LAT,LON`: without it each OpenCelliD search is `not_configured` and sends nothing; free account key, 1,000 credits a day |
| Censys Platform | `HUNTSMAN_CENSYS_TOKEN` | v3 IP host lookup (`ip`, `scan -k ip`, web UI); free accounts support host lookup with a Personal Access Token, account limits apply; a 404 means no host, failures remain explicit |
| Censys Legacy | `HUNTSMAN_CENSYS_ID`, `HUNTSMAN_CENSYS_SECRET` | legacy slots retained for import/backward compatibility but not used by Platform v3; create a new PAT to use the active source |
| X Recent Search | `HUNTSMAN_X_BEARER_TOKEN` | operator-owned official X API bearer token for `osint x-api` only; account limits and credits apply; `osint x` indexed discovery is keyless |

## Importing keys from Spiderfoot

Settings → **Import API keys** in the web UI (`POST /api/settings/keys` with `import=`) reads
Spiderfoot 4.0's settings export, the `SpiderFoot.cfg` that Spiderfoot's Settings → Export API
Keys writes, and saves each key into the slot of the source that takes it, in one rewrite of
`~/.huntsman.env`. It reads a keys file of `HUNTSMAN_…=value` lines the same way. Empty and
placeholder values are skipped. The answer names the Spiderfoot key options that no Huntsman
source takes, and never shows a value.

| Spiderfoot option | Slot |
| --- | --- |
| `sfp_abuseipdb:api_key` | `HUNTSMAN_ABUSEIPDB_KEY` |
| `sfp_alienvault:api_key` | `HUNTSMAN_OTX_KEY` |
| `sfp_censys:censys_api_key_uid` | `HUNTSMAN_CENSYS_ID` |
| `sfp_censys:censys_api_key_secret` | `HUNTSMAN_CENSYS_SECRET` |
| `sfp_certspotter:api_key` | `HUNTSMAN_CERTSPOTTER_KEY` |
| `sfp_dehashed:api_key` | `HUNTSMAN_DEHASHED_KEY` |
| `sfp_greynoise:api_key` | `HUNTSMAN_GREYNOISE_KEY` |
| `sfp_greynoise_community:api_key` | `HUNTSMAN_GREYNOISE_KEY` |
| `sfp_haveibeenpwned:api_key` | `HUNTSMAN_HIBP_KEY` |
| `sfp_hunter:api_key` | `HUNTSMAN_HUNTER_KEY` |
| `sfp_ipinfo:api_key` | `HUNTSMAN_IPINFO_KEY` |
| `sfp_ipqualityscore:api_key` | `HUNTSMAN_IPQS_KEY` |
| `sfp_leakix:api_key` | `HUNTSMAN_LEAKIX_KEY` |
| `sfp_numverify:api_key` | `HUNTSMAN_NUMVERIFY_KEY` |
| `sfp_pulsedive:api_key` | `HUNTSMAN_PULSEDIVE_KEY` |
| `sfp_securitytrails:api_key` | `HUNTSMAN_SECTRAILS_KEY` |
| `sfp_shodan:api_key` | `HUNTSMAN_SHODAN_KEY` |
| `sfp_virustotal:api_key` | `HUNTSMAN_VIRUSTOTAL_KEY` |
| `sfp_whoxy:api_key` | `HUNTSMAN_WHOXY_KEY` |
| `sfp_wigle:api_key_encoded` | `HUNTSMAN_WIGLE_USER` and `HUNTSMAN_WIGLE_TOKEN`, decoded from the base64 of `NAME:TOKEN` |

Spiderfoot's `sfp_dehashed` used DeHashed's first API. If DeHashed refuses an imported key,
issue a current key on dehashed.com.

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
HUNTSMAN_DEHASHED_KEY=
HUNTSMAN_STOLEN_TAX_KEY=
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
HUNTSMAN_NETLAS_KEY=
HUNTSMAN_SECTRAILS_KEY=
HUNTSMAN_ABUSECH_KEY=
HUNTSMAN_OTX_KEY=
HUNTSMAN_URLSCAN_KEY=
HUNTSMAN_IPINFO_KEY=
HUNTSMAN_HACKERTARGET_KEY=
HUNTSMAN_CERTSPOTTER_KEY=
HUNTSMAN_OPENCELLID_KEY=
HUNTSMAN_CENSYS_TOKEN=
HUNTSMAN_CENSYS_ID=
HUNTSMAN_CENSYS_SECRET=
HUNTSMAN_X_BEARER_TOKEN=
```

Never place populated values in this repository, release artifacts, logs,
examples, documentation, or issue/PR text.
