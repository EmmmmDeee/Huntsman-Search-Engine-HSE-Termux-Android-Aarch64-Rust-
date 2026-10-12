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

## Registry slots without recorded credential state

These slots are read at runtime by the service registry or a source module.
This manifest records no credential state for them. Their provider's
credential status is unknown until it is checked with `credential-status`.

| Provider | Runtime slot(s) | Integration state |
| --- | --- | --- |
| URLhaus | `HUNTSMAN_ABUSECH_KEY` | declared runtime slot; credential state not recorded |
| Criminal IP | `HUNTSMAN_CRIMINALIP_KEY` | declared runtime slot; credential state not recorded |
| DeHashed | `HUNTSMAN_DEHASHED_KEY` | declared runtime slot; credential state not recorded |
| DomainsDB | `HUNTSMAN_DOMAINSDB_KEY` | declared runtime slot; credential state not recorded |
| FullContact | `HUNTSMAN_FULLCONTACT_KEY` | declared runtime slot; credential state not recorded |
| HLR Lookups | `HUNTSMAN_HLR_KEY` | declared runtime slot; credential state not recorded |
| Hunter | `HUNTSMAN_HUNTER_KEY` | declared runtime slot; credential state not recorded |
| IntelX | `HUNTSMAN_INTELX_KEY` | declared runtime slot; credential state not recorded |
| Netlas | `HUNTSMAN_NETLAS_KEY` | declared runtime slot; credential state not recorded |
| niamonx | `HUNTSMAN_NIAMONX_KEY` | declared runtime slot; credential state not recorded |
| Numverify | `HUNTSMAN_NUMVERIFY_KEY` | declared runtime slot; credential state not recorded |
| Onyphe | `HUNTSMAN_ONYPHE_KEY` | declared runtime slot; credential state not recorded |
| OpenCNAM | `HUNTSMAN_OPENCNAM_KEY` | declared runtime slot; credential state not recorded |
| osintcat | `HUNTSMAN_OSINTCAT_KEY` | declared runtime slot; credential state not recorded |
| SecurityTrails | `HUNTSMAN_SECTRAILS_KEY` | declared runtime slot; credential state not recorded |
| ThreatFox | `HUNTSMAN_THREATFOX_KEY` | declared runtime slot; credential state not recorded |
| Trove AU | `HUNTSMAN_TROVE_KEY` | declared runtime slot; credential state not recorded |
| stolen.tax | `HUNTSMAN_STOLEN_TAX_KEY` | declared runtime slot; credential state not recorded |

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
HUNTSMAN_ABUSECH_KEY=
HUNTSMAN_CRIMINALIP_KEY=
HUNTSMAN_DEHASHED_KEY=
HUNTSMAN_DOMAINSDB_KEY=
HUNTSMAN_FULLCONTACT_KEY=
HUNTSMAN_HLR_KEY=
HUNTSMAN_HUNTER_KEY=
HUNTSMAN_INTELX_KEY=
HUNTSMAN_NETLAS_KEY=
HUNTSMAN_NIAMONX_KEY=
HUNTSMAN_NUMVERIFY_KEY=
HUNTSMAN_ONYPHE_KEY=
HUNTSMAN_OPENCNAM_KEY=
HUNTSMAN_OSINTCAT_KEY=
HUNTSMAN_SECTRAILS_KEY=
HUNTSMAN_THREATFOX_KEY=
HUNTSMAN_TROVE_KEY=
HUNTSMAN_STOLEN_TAX_KEY=
```

Never place populated values in this repository, release artifacts, logs,
examples, documentation, or issue/PR text.
