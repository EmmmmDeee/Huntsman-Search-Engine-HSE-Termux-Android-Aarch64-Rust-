# Huntsman provider credential slots

This file is the non-secret provider manifest for `huntsman-recon`.

Credential values MUST NOT be committed. Runtime values belong in
`$HOME/.huntsman.env` (mode 600), an explicit `--keys FILE`, or the process
environment. The generic key loader documented in the repository README reads
these slots without printing their values.

## Recovered/owned provider slots

| Provider | Runtime slot(s) | Integration state |
| --- | --- | --- |
| WiGLE | `HUNTSMAN_WIGLE_USER`, `HUNTSMAN_WIGLE_TOKEN` | credential material recovered; validate/reissue before production use if historical exposure applies |
| Brave Search | `HUNTSMAN_BRAVE_KEY` | owned credential material located; validate/reissue before production use if historical exposure applies |
| Shodan | `HUNTSMAN_SHODAN_KEY` | private stored credential located; validity unverified |
| Whoxy | `HUNTSMAN_WHOXY_KEY` | private stored credential located; validity unverified |
| Citadel | `HUNTSMAN_CITADEL_KEY` | private stored credential located; validity unverified |
| HIBP | `HUNTSMAN_HIBP_KEY` | owned subscription/key history; clean current credential required |
| SeekNow | `HUNTSMAN_SEEKNOW_KEY` | historical credential only; clean current credential required |
| OathNet | `HUNTSMAN_OATHNET_KEY` | historical credential only; clean current credential required |
| Exa | `HUNTSMAN_EXA_KEY` | account confirmed; current credential not recovered |
| OpenRouter | `HUNTSMAN_OPENROUTER_KEY` | account confirmed; current credential not recovered |
| Google Gemini | `HUNTSMAN_GEMINI_KEY` | provider key existence confirmed; current value requires provider account |
| GitHub | `HUNTSMAN_GITHUB_TOKEN` | token lifecycle confirmed; current credential requires provider account |
| VirusTotal | `HUNTSMAN_VIRUSTOTAL_KEY` | account/API relationship supported; current credential not recovered |
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
HUNTSMAN_CITADEL_KEY=
HUNTSMAN_HIBP_KEY=
HUNTSMAN_SEEKNOW_KEY=
HUNTSMAN_OATHNET_KEY=
HUNTSMAN_EXA_KEY=
HUNTSMAN_OPENROUTER_KEY=
HUNTSMAN_GEMINI_KEY=
HUNTSMAN_GITHUB_TOKEN=
HUNTSMAN_VIRUSTOTAL_KEY=
HUNTSMAN_CENSYS_ID=
HUNTSMAN_CENSYS_SECRET=
```

Never place populated values in this repository, release artifacts, logs,
examples, documentation, or issue/PR text.
