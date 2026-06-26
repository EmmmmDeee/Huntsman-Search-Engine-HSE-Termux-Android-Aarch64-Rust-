# OSINT API Provider Catalogue

The OSINT / recon / breach / threat-intel API providers HSE recognises as
**practitioner tooling**. A harvested API key whose provider appears here is not
just a credential — by possession it identifies its owner as an OSINT operator
(investigator, researcher, or adversary doing reconnaissance), so the key is a
first-class OSINT **pivot**: its provider reveals the holder's tradecraft.

Keys are **retained and categorised, never reused** to authenticate. A key is
attributed to a provider by any of three paths — a distinctive prefix
(`patterns.rs`), a provider-named context + key shape (`osint_keys.rs`), or the
API domain in a stealer-log URL (`service_domains.rs`) — and then classified
here (`osint_catalogue.rs`). Detected keys carry the tags `osint-practitioner`
and `osint-category:<slug>`.

> Source of truth: `src/modules/oathnet_pro/key_harvest/osint_catalogue.rs`.
> This file is kept in sync by the `osint_catalogue_doc_lists_every_service`
> test — every `service` tag below must match a catalogue entry.

## Breach / leak / stealer-credential databases (`breach-leak`)

`oathnet`, `see_know`, `dehashed`, `snusbase`, `intelx`, `leakcheck`,
`leakpeek`, `leak_lookup`, `leakbase`, `hashes`, `psbdmp`, `ghostproject`,
`scylla`, `weleakinfo`, `hackcheck`, `scrubd`, `nuclearleaks`,
`breachdirectory`, `breachforums`, `hibp`, `hudsonrock`, `proxynova`,
`scatteredsecrets`, `xposedornot`, `leakradar`, `inteltechniques`

## Internet-wide attack-surface scanners (`attack-surface`)

`shodan`, `censys`, `binaryedge`, `zoomeye`, `fofa`, `netlas`, `onyphe`,
`fullhunt`, `criminal_ip`, `leakix`, `spyse`, `quake`, `hunter_how`, `odin`

## Threat intelligence (`threat-intel`)

`virustotal`, `abuseipdb`, `greynoise`, `pulsedive`, `threatfox`, `urlscan`,
`alienvault_otx`, `hybrid_analysis`, `malwarebazaar`, `anyrun`, `maltiverse`,
`xforce`, `polyswarm`, `threatminer`, `passivetotal`, `riskiq`

## Email / identity / people search (`email-people`)

`hunter`, `snov`, `clearbit`, `fullcontact`, `apollo`, `rocketreach`, `pipl`,
`emailrep`, `tomba`, `anymailfinder`, `voilanorbert`, `dropcontact`,
`peopledatalabs`, `seon`, `epieos`, `proxycurl`, `predictasearch`,
`osint_industries`, `castrick`, `skymem`

## Phone intelligence (`phone-intel`)

`numverify`, `numlookup`, `veriphone`, `ipqs`, `hlr_lookups`, `abstractapi_phone`

## IP geolocation / ASN (`ip-geo`)

`ipinfo`, `ip2location`, `ipgeolocation`, `ipstack`, `ipdata`, `ipregistry`,
`maxmind`, `ipquery`

## Search / SERP / scraping recon (`search-recon`)

`serpapi`, `serper`, `zenserp`, `exa`, `brave_search`, `google_cse`,
`bing_search`, `dataforseo`, `scraperapi`, `scrapingbee`

## Domain / WHOIS / DNS / certificate (`domain-cert`)

`securitytrails`, `whoisxml`, `whoxy`, `domaintools`, `ip2whois`, `viewdns`,
`builtwith`, `c99`, `dnsdumpster`

## Corporate registry (`corporate`)

`opencorporates`

## Wireless / cell geolocation (`wireless-geo`)

`wigle`, `opencellid`

## Social / username link-analysis (`social-link-analysis`)

`sociallinks`, `maltego`, `lampyre`, `spiderfoot`
