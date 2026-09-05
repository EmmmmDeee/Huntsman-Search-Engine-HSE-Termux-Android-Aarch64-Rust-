# Glossary — the one spelling of every term

HSE's command line, web console, exports and documentation use the terms
below, spelled exactly as shown. A test (`cli_help_uses_canonical_terminology`
in `tests/architecture.rs`) reads every `hse … --help` page and this file and
fails on any of the retired spellings, so a new flag or help sentence cannot
drift.

## Nouns

| Term | Meaning | Not |
|---|---|---|
| **scan** | One run of the engine over one seed, stored under a **scan ID**. `latest` names the most recent completed scan wherever a scan ID is accepted. | scan id, scan_id (in prose; `--scan-id` is the flag, `SCAN_ID` its value name) |
| **seed** | The value a scan starts from, given as `--kind` + `--value`. Auto-detected when the kind is omitted. | target (SpiderFoot's word; accepted on `hse sf` only) |
| **kind** | The category of a seed or entity: `email`, `username`, `phone`, `name`, `domain`, `ip`, `url`, … (`hse scan --kind`). | type |
| **entity** | One thing a scan found: a kind, a value, a confidence, and its evidence. | record, node |
| **evidence** | One observation attached to an entity: the **source** that produced it, a summary, and attributes. | proof |
| **source** | The provider a piece of evidence came from, as its evidence carries it — a corpus name, never the module that happened to read it (see `docs/REQUIREMENTS_LEDGER.md`, REQ-SRC-002). | |
| **module** | A unit of HSE code that queries one provider or performs one derivation (`hse modules`). | plugin, collector |
| **provider** | The external service a module queries (OathNet, SeekNow, DeHashed, WiGLE, …). | vendor, site, service |
| **finding** | A correlation the engine raised across entities, numbered `AU-nnn`, with a confidence and the entities it rests on. | correlation (the engine's internal name), alert |
| **dossier** | The full per-scan write-up: every entity, every finding, full provenance (`hse scan --format dossier`, `hse export --format full`). | report (see below) |
| **report** | The quality picture of one scan — audit, benchmark and discovery gaps (`hse report`). | dossier |
| **API key** | A credential for a provider, held as a `HUNTSMAN_*` variable in `~/.huntsman.env` (`hse keys set`) or in the rotation **pool** (`hse keys add`). | api key, token, secret |
| **batch** | A plaintext list of bulk queries derived from a seed or a scan, one per line, in the syntax a provider's bulk-search page accepts (`hse batch`). | bulk, queries |
| **use case** | `hse sf`'s SpiderFoot-compatible scan preset: `all`, `footprint`, `investigate`, `passive`. | profile (HSE's own presets: `--profile`) |

## Providers — spell them as they spell themselves

| Canonical | Retired spellings |
|---|---|
| OathNet | Oathnet, oathnet (in prose) |
| SeekNow | Seeknow, Seek-Know, SeeKnow, seeknow (in prose; `see_know` is the module, `HUNTSMAN_SEEKNOW_KEY` the variable) |
| DeHashed | Dehashed |
| WiGLE | Wigle |
| OpenCelliD | OpenCellID, Opencellid |
| Termux | termux (in prose) |

Breach and stealer-log services `hse batch` renders bulk queries for (the
`--site` ids are the lower-cased left column; each is grounded in the
provider's own docs — see `src/app/batch/sites.rs`):

| Canonical (`--site` id) | Retired spellings |
|---|---|
| Stolen (`stolen-tax`) | stolen.tax in prose is the domain; the provider is Stolen |
| LeakCheck (`leakcheck`) | Leakcheck, leak-check |
| Snusbase (`snusbase`) | SnusBase |
| Intelligence X (`intelx`) | IntelX (its own short form; product name is Intelligence X) |
| Leak-Lookup (`leak-lookup`) | Leak Lookup, LeakLookup |
| Have I Been Pwned (`hibp`) | HaveIBeenPwned, Have I been pwned |

## Flags — one name per concept

| Concept | Flag | Everywhere it applies |
|---|---|---|
| Output format | `--format` (`-f` where free) | `scan`, `query`, `import`, `ingest`, `export`, `diff`, `batch`. The older `--output` / `--output-format` / `-o` / `-F` spellings still work as hidden aliases. |
| Output file | `--out` (`-o`) | `export`, `ingest`, `batch`. `--output` still works on `ingest` as a hidden alias. |
| A stored scan | `--scan-id`, `latest` allowed (short `-s` on `export` and `batch`) | `report`, `export`, `signal`, `batch`, and the hidden `audit` / `benchmark` / `gaps`. |
| A seed | `--kind` (`-k`) + `--value` (`-v`) | `scan`, `live`, `batch`, `oathnet-batch`. |
| Module selection | `--modules` (`-m`) / `--exclude` | `scan`, `live`. |
| Machine output | `--json` | Commands whose only formats are human and JSON. |
