# API-key integration audit — rootless Termux AArch64

This document distinguishes *having a secret*, *having a request implementation*, and
*having a verified working provider account*. These are three separate facts.

## Executable key integration

Huntsman already loads keys from a mode-0600 `$HOME/.huntsman.env`, from
`--keys FILE`, or the process environment, and keeps them out of commits and
reports. `huntsman-recon credential-status` shows only slot presence.
`credential-status --probe` performs **network** checks only for the providers
with supported probes, so use it only when a remote request is appropriate.

IP/domain sources with existing key support include Shodan, Whoxy, VirusTotal,
AbuseIPDB, GreyNoise, Hunter.io, LeakIX, Pulsedive, IPQualityScore,
ThreatFox, Netlas, SecurityTrails, URLhaus, OTX, urlscan.io, IPinfo,
Cert Spotter and HackerTarget. Other existing selector-specific integrations
include GitHub usernames, WiGLE, OpenCelliD, Numverify, HIBP, DeHashed,
OathNet, SeekNow and stolen.tax. Whether a source runs also depends on the
selector type, selected modules, account plan, API availability and scan budgets.

**Shared abuse.ch key:** `HUNTSMAN_THREATFOX_KEY` and `HUNTSMAN_ABUSECH_KEY`
are two names for one operator-issued Auth-Key. When only one exists it
automatically authenticates both ThreatFox and URLhaus. When both exist each
explicit provider slot takes precedence. No copy or additional secret is saved;
the credential is restricted to the requested provider origin. A missing key
still sends no request to either keyed provider.

## Credential slots without executable lookup integrations

`credential-status` labels the existing Brave Search, Exa, OpenRouter,
Google Gemini and Censys catalogued credential slots as
`integration=credential_only`: they can be stored, but that does **not**
mean that an appropriate lookup leg has been implemented or invoked.

The known reserved slots for Criminal IP, DomainsDB, FullContact, HLR, IntelX,
Niamonx, Onyphe, OpenCNAM, OSINTCAT and Trove are surfaced as
`unwired_slot=...` **only when a value has been configured**. These are not
automatically called and do not represent working integrations. Their full
provider response contracts, permissions and safe data handling must be
verified before introducing any network access.

Huntsman's runtime remains LLM-free; an OpenRouter or Gemini key does not
enable an LLM in Huntsman.

## Private, interactive Termux setup

Configure only keys you personally possess and are entitled to use:

```sh
umask 077
read -r -s -p 'abuse.ch Auth-Key: ' API_KEY; printf '\n'
printf '%s' "$API_KEY" | huntsman-recon keys set HUNTSMAN_ABUSECH_KEY --stdin
unset API_KEY
huntsman-recon credential-status
```

Other supported slots can be set using the same `keys set SLOT --stdin`
command. Never place values in terminal command arguments, GitHub issues,
chat messages or public scan evidence. A slot being set is not proof of
validity: providers may reject old keys, require a paid plan or enforce
quota/rate limits. Account creation and any paid subscription must be
performed by the operator.

## Acceptance criteria

1. One configured abuse.ch Auth-Key makes both eligible sources executable.
2. Both providers' requests retain independent, fixed HTTPS origin bindings.
3. No key => neither keyed provider sends a request.
4. Explicit per-provider credentials take priority over fallback aliases.
5. All public key status output contains names and states, never values.
6. Rootless Android AArch64, pure Rust and default request budgets are unchanged.
