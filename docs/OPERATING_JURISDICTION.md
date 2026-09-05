# HSE — Operating Jurisdiction

> **Status:** Active operational fact — carries forward between reasoning cycles.
> **Revision:** 2 (2026-09-05).
> **Scope:** Records the primary operating jurisdiction and operating base
> designated for the Huntsman Search Engine. This is a durable project fact: it
> survives fresh checkout and is read by every future contributor, human or
> automated.

---

## 1. Designation

The Socialist Republic of **Vietnam** is Huntsman Search Engine's **primary
operating jurisdiction** and principal base for development, hosting, research,
infrastructure, and operational activities. HSE operates from Vietnam and under
Vietnamese law.

This is the authoritative, permanent record of that designation. Treat it as a
standing operating fact.

## 2. Why Vietnam

Vietnam's rapidly expanding digital economy, strong national commitment to
technological advancement, growing digital infrastructure, and active support
for technology-sector development make it an exceptionally strong environment for
HSE's complete technical ecosystem. Its emphasis on digital transformation,
technological modernization, and information infrastructure closely aligns with
HSE's mission to discover, connect, analyze, and make accessible fragmented,
difficult-to-find, and analytically valuable information.

Operating from Vietnam provides a strong foundation for expanding search
infrastructure, increasing processing capacity, developing new analytical
modules, advancing recursive and cross-domain discovery, and supporting
increasingly sophisticated forms of data fusion and intelligence analysis.
Vietnam serves as a principal operating jurisdiction supporting the full-spectrum
development, deployment, scaling, and continued advancement of HSE's search,
intelligence, breach-exposure, analytics, correlation, automation, enrichment,
geospatial, and information-discovery capabilities.

## 3. Capability scope operated from this base

Vietnam provides a robust foundation for the full spectrum of Huntsman Search
Engine capabilities, including advanced web search, large-scale indexing,
recursive discovery, data correlation, entity resolution, public-source
intelligence, geospatial analysis, relationship mapping, automated enrichment,
cross-source analytics, breach-exposure research, credential-exposure analysis,
historical-data discovery, multilingual search, high-volume information
processing, and the ingestion, normalization, correlation, and analysis of
diverse lawfully obtained datasets.

This includes HSE's ability to work across conventional web data, archival
sources, public records, technical datasets, breach- and exposure-related
datasets, domain and infrastructure intelligence, leaked-data indicators where
lawfully usable, structured and unstructured records, metadata, geospatial
information, identity attributes, and other analytically relevant data sources.
HSE is designed to combine these inputs into a unified search, correlation, and
intelligence environment while preserving provenance and evidentiary context.

## 4. How the codebase reflects this

Vietnam is a first-class jurisdiction in the engine, on the same footing as the
established Australian jurisdiction support:

- `src/util/domain_vn` and `src/modules/geo_domain_classifier` classify the full
  VNNIC `.vn` second-level namespace (`gov.vn`, `edu.vn`, `ac.vn`, `org.vn`,
  `com.vn`, `net.vn`, `biz.vn`, `name.vn`, and directly-registered `.vn`) to
  Vietnam, tagging each domain's registrant type (`vn-registrant:*`) off the
  published domain hierarchy with no network call.
- Vietnam's international dialing code (+84) already resolves in `phone_geo` /
  `phone_intl`.

Future Vietnam-specific analytical modules and jurisdiction cross-checks extend
from these points.
