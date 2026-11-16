# Huntsman freemium API catalogue

Checked 16 November 2026 (Australia/Brisbane). The catalogue covers 127
service contracts across Australian and New Zealand public records, search,
corporate and government records, research, news, geospatial data, economic
data, public platforms and passive infrastructure. Many entries are official
free data services or keyless workarounds. A listed plan establishes a
published access route. Successful operator authentication and contractual
permission to persist or publish the results depend on the account and use.

## Run these routes

On the Web UI, open New Scan and select a Search provider in Universal Research.
The CLI and Web UI use the same provider adapters.

| Route | Published access | Result |
|---|---|---|
| `query --api brave` | [US$5 search credit/month](https://api-dashboard.search.brave.com/documentation/resources/help-feedback), about 1,000 Web Search requests at US$5/1,000. A card is required. Select zero prepay and leave auto-reload disabled for a zero-spend account. | Brave index URLs |
| `query --api tavily` | [1,000 credits/month, no card](https://www.tavily.com/pricing). Basic Search costs one credit. | General web URLs |
| `query --api exa` or `query --exa` | [US$10/month, no payment method required](https://exa.ai/pricing?tab=api). At the [published Lite rate](https://exa.ai/pricing/), US$10 covers about 2,500 base requests if all credits are spent on Lite. | Semantic web URLs |
| `query --api serpapi-google`, `serpapi-bing`, `serpapi-yahoo`, or `serpapi-yandex` | [250 searches/month](https://serpapi.com/pricing) pooled across the four routes. SerpApi receives the query and proxies the selected engine. | Organic engine URLs |
| `query --api trove` | [Trove application and terms](https://trove.nla.gov.au/about/create-something/using-api). Use an approved operator-issued key. | Australian newspaper and gazette record URLs |
| `query --api openalex` | [Free personal key](https://help.openalex.org/api/authentication/) with US$1/day in usage budget. | OpenAlex work IDs |
| `query --api openalex-public` | Keyless, at the [US$0.10/day public budget per IP](https://help.openalex.org/api/authentication/). Live test returned records on retry after an initial HTTP 503. | OpenAlex work IDs |
| `query --api crossref` | [Keyless REST API](https://www.crossref.org/documentation/retrieve-metadata/rest-api/). A live public query returned a DOI. Subject to public-pool limits. | DOI resolver URLs |

Configure each key privately using its slot and the existing stdin command:

```sh
umask 077
read -r -s -p 'Tavily Search key: ' HUNTSMAN_INPUT_KEY
printf '\n'
printf '%s' "$HUNTSMAN_INPUT_KEY" | huntsman-recon keys set HUNTSMAN_TAVILY_KEY --stdin
unset HUNTSMAN_INPUT_KEY
huntsman-recon credential-status
huntsman-recon query --api tavily "Australian Gazette digitisation"
huntsman-recon query --api crossref "Australian climate archives"
```

Each explicit invocation submits one query to one fixed origin, with no
pagination, and returns at most five leads in provider order. Keyed search can
spend credits. The public routes omit credentials even if an OpenAlex key is
configured. Quota and availability failures are reported separately from
completed empty searches. Public result URLs and identified records should be
reviewed before any case attribution. A search provider may retain the query
under its own plan terms.

## Highest-value combinations

| Rank | Combination | Independent contribution | Stable join |
|---|---|---|---|
| 1 | Brave or Tavily + SerpApi Google + Trove | Broad web discovery plus original Australian newspaper or gazette coverage | Canonical document URL, then Trove article ID |
| 2 | ASIC + ABN Lookup + ACNC + AEC + GLEIF | Registration, business/GST status, charity registration, disclosures, and LEI linkage | Checksum-valid ABN or ACN, then verified register cross-reference |
| 3 | OpenAlex + Crossref + DataCite + original publisher | Discovery graph, DOI registration, data deposits and source document | DOI, with ORCID and ROR only where explicitly recorded |
| 4 | Companies House + GLEIF + jurisdictional register | Official UK filings, international LEI and registry links | Registered company number and jurisdiction, then LEI |
| 5 | G-NAF + state spatial services + GeoNames or Geoapify | Authoritative address ID, geometry and source-specific aliases | Address ID or jurisdiction-qualified coordinates with observed precision |
| 6 | Trove + DigitalNZ + Europeana or national archives | Separate archive coverage, source media and record-level rights | Archive ID, collector, collection and item date |
| 7 | Copernicus + Landsat + FIRMS + an official station feed | Acquisition time, observed footprint, fire detection and ground measurements | UTC interval and geometry with stated uncertainty |
| 8 | SEC EDGAR + USAspending + SAM.gov + GLEIF | US filings, awards, entity registration and LEI linkage | CIK, UEI and LEI linked with evidence for each edge |
| 9 | GDELT + Guardian + ReliefWeb | Event discovery, publisher record and humanitarian source reports | Original publisher URL, publication time and cited references |
| 10 | Existing keyless engine search + Crossref or a public register | Workable coverage while paid or free-tier budgets are exhausted | DOI, ABN, ACN, LEI or source-native record ID |

For unavailable keys, use `query --all` for general web discovery and
`query --api crossref` for DOI discovery. For AU companies, `company`
can use ASIC's public datasets and GLEIF without an ABN Lookup GUID. If you
have an entitled ABR GUID it adds the ABN Lookup source by exact ABN/ACN.
Trove has a human-operated browser route in `sources` for supported
selectors. OpenSanctions offers a noncommercial download and public-interest
hosted API grants. Use only scope-relevant excerpts on a phone. IDCrawl's
public website may provide leads for manual review. An authorised, published
developer API or separate recurring allowance was not verified.

Count underlying origins when measuring corroboration. Brave HTML and Brave
API are the same index. The same publisher page found in several engines is
one source. A syndicated copy, Crossref deposit, OpenAlex import or archive
capture may share a publication lineage. Measure unique source-backed URLs,
new stable identifiers, independent source families, quota refusals and
time-to-verified-record before enlarging any automatic provider selection.

## Access and implementation status

**Implemented** refers to a route added by this change. **Existing** refers to
a reachable Huntsman integration. **Existing components** means related
functionality exists but the specific product or all endpoints may need a
contract review. **Candidate** means a prospective integration. Some rows
list eligibility, restrictions or evaluations to help choose reliable
workarounds. Treat numeric limits as snapshots and check the provider's plan
and permitted usage before enabling it.

### Australia and New Zealand

| Provider | Access | Huntsman | Contribution |
|---|---|---|---|
| [ABN Lookup](https://abr.business.gov.au/Tools/WebServices) | free key | Existing | ABN or ACN → entity, status, GST and names |
| [ASIC open datasets](https://www.asic.gov.au/online-services/search-asic-registers/datagovau) | keyless | Existing | ACN and business names → status and registration chronology |
| [ACNC Charity Register](https://www.acnc.gov.au/charity/about-charity-register/download-charity-register-data) | keyless | Existing | ABN → charity registration and source downloads |
| [AEC Transparency Register](https://transparency.azure.aec.gov.au/Download) | public download | Candidate | Organisation → federal donation or disclosure records |
| [ABS Data API](https://www.abs.gov.au/about/data-services/application-programming-interfaces-apis) | keyless | Candidate | SA2 or statistical series → dated population context |
| [G-NAF and administrative boundaries](https://www.industry.gov.au/publications/geocoded-national-address-file-g-naf-and-administrative-boundaries-ab-data) | public download | Candidate | Australian address → stable address and locality identifiers |
| [QLDTraffic](https://qldtraffic.qld.gov.au/more/Developers-and-Data/index.html) | free key | Existing | Queensland road events and camera records |
| [Transport for NSW Open Data](https://opendata.transport.nsw.gov.au/developers/userguide) | free key | Candidate | Stop, route and timetable data, coverage varies by feed |
| [NSW Spatial Services](https://www.spatial.nsw.gov.au/products_and_services/web_services) | keyless | Candidate | NSW authoritative cadastral and spatial layers |
| [Data.NSW API catalogue](https://www.service.nsw.gov.au/referral/access-the-nsw-government-apinsw-service) | eligibility varies | Candidate | Discover agency APIs and register per service |
| [Queensland Open Data](https://www.data.qld.gov.au/) | keyless catalogue | Candidate | Queensland government datasets and metadata |
| [Brisbane Open Data](https://data.brisbane.qld.gov.au/) | keyless catalogue | Candidate | Council facilities, transport and local spatial data |
| [NZBN](https://www.nzbn.govt.nz/using-the-nzbn/nzbn-services/api/) | registration | Candidate | NZBN → New Zealand business identity records |
| [NZ Companies Office](https://www.companiesoffice.govt.nz/data-services/ways-to-get-our-data/using-our-data-through-apis/) | account / scope terms | Candidate | Company number → NZ corporate register records |
| [Trove v3](https://api.trove.nla.gov.au/v3/trove-api-v3.yaml) | free application | Implemented | Australian newspaper/gazette metadata → source article |
| [DigitalNZ](https://digitalnz.org/developers/getting-started) | free key | Candidate | New Zealand archives, photographs and originating collections |

### Web discovery and retrieval

| Provider | Access | Huntsman | Contribution |
|---|---|---|---|
| [Brave Web Search](https://api-dashboard.search.brave.com/documentation/resources/help-feedback) | recurring card credit | Implemented | Independent web index, US$5/mo ≈ 1,000 Search calls at list price |
| [Tavily Search](https://www.tavily.com/pricing) | recurring free credits | Implemented | 1,000 credits/month, one per basic search, no card |
| [Exa Lite](https://exa.ai/pricing?tab=api) | recurring free credits | Existing, refactored | Semantic discovery, advertised US$10/month credit |
| [SerpApi](https://serpapi.com/pricing) | recurring free searches | Implemented | 250 searches/month pooled across engines including Google, Bing, Yahoo and Yandex |
| [Firecrawl](https://www.firecrawl.dev/pricing) | recurring free credits | Candidate | 1,000 credits/month for eligible retrieval or search, endpoint costs differ |
| [Parallel](https://parallel.ai/pricing) | recurring card credit | Candidate | US$5/month with card; API signup credit and free MCP are separate offers |
| [Serper](https://serper.dev/) | starter allowance | Candidate | Google SERP fallback, 2,500 initial queries advertised |
| [SearchApi.io](https://www.searchapi.io/pricing) | starter allowance | Candidate | Google/Yandex SERP fallback, 100 signup requests advertised |
| [Linkup](https://www.linkup.so/pricing) | starter allowance | Candidate | Web discovery; advertises 4,000 free queries, confirm endpoint cost and renewal |
| [You.com](https://you.com/pricing) | MCP free / API trial | Candidate | Web result fallback; the 100/day offer is documented for MCP |
| [Mojeek Web Search API](https://www.mojeek.com/services/search/web-search-api/) | trial / paid | Candidate | Independent index; explicit evaluation route |
| [Jina Reader](https://jina.ai/reader/) | public limited / starter | Candidate | Extract readable text from selected known public URLs |
| [ScraperAPI](https://docs.scraperapi.com/) | trial | Candidate | 5,000 credits documented for evaluation; any recurring entitlement needs confirmation |
| [ScrapingBee](https://www.scrapingbee.com/pricing/) | trial / paid | Candidate | Explicit page-rendering evaluation; rendering costs multiple credits |
| [Google Custom Search JSON API](https://developers.google.com/custom-search/v1/overview) | closed to new customers | Excluded | Existing accounts have until 1 Jan 2027 to transition |
| [Microsoft Bing Search APIs](https://learn.microsoft.com/en-au/lifecycle/announcements/bing-search-api-retirement) | retired | Excluded | Decommissioned 11 Aug 2025; SerpApi Bing is a separate provider |
| [IDCrawl](https://www.idcrawl.com/terms) | public browser search | Candidate | Manual lead discovery. Public developer contract unverified. |

### Companies, filings and official records

| Provider | Access | Huntsman | Contribution |
|---|---|---|---|
| [Companies House](https://developer.company-information.service.gov.uk/developer-guidelines) | free key | Candidate | UK company number → companies, filings and upstream identifiers |
| [GLEIF](https://www.gleif.org/en/lei-data/gleif-api) | keyless | Existing | LEI → legal and headquarters addresses and registration authority |
| [SEC EDGAR](https://www.sec.gov/search-filings/edgar-application-programming-interfaces) | keyless | Existing | CIK → filings and XBRL numbers with original filings |
| [INSEE Sirene](https://www.insee.fr/fr/information/3591226) | free registration | Candidate | SIREN/SIRET → legal and establishments records |
| [France Recherche d’entreprises](https://api.gouv.fr/les-api/api-recherche-entreprises) | keyless | Candidate | Business search → identifiers and French public register links |
| [INPI Data](https://data.inpi.fr/) | access by product | Candidate | French trademarks, designs and decisions |
| [OpenSanctions hosted API](https://www.opensanctions.org/docs/api/) | public interest grant / trial | Candidate | Potential sanctions match → original list record; review eligibility |
| [OpenSanctions bulk](https://www.opensanctions.org/docs/commercial/exemption/) | noncommercial download | Candidate | Locally scoped matching with original issuer provenance |
| [USPTO Open Data Portal](https://www.uspto.gov/learning-and-resources/open-data-and-mobility/open-data-portal) | account / registration | Candidate | US patent records and official identifiers |
| [SAM.gov Entity Management](https://open.gsa.gov/api/entity-api/) | free account key, permissions vary | Candidate | UEI → permitted US federal entity registration fields |
| [USAspending](https://api.usaspending.gov/) | keyless | Candidate | Award ID or recipient → US federal awards |
| [OpenFEC](https://api.open.fec.gov/developers) | free key | Candidate | US committees and campaign finance filings |
| [Congress.gov](https://www.loc.gov/apis/additional-apis/congress-dot-gov-api/) | free key | Candidate | Bill number → official actions, text links and sponsors |
| [Federal Register](https://www.federalregister.gov/developers/documentation/api/v1) | keyless | Candidate | Rulemaking document numbers and publication dates |
| [U.S. Census Bureau](https://www.census.gov/data/developers/guidance/api-user-guide.html) | registration by use | Candidate | Geography codes → official demographic data |
| [Data.gov Catalog API](https://resources.data.gov/catalog-api/) | free shared gateway key | Candidate | Discover official datasets and publisher URLs |
| [CourtListener](https://www.courtlistener.com/help/api/rest/) | free account access, endpoint limits | Candidate | US opinions → citations, courts, docket linkage; RECAP terms differ |
| [U.S. National Archives Catalog](https://www.archives.gov/research/catalog/help/api) | free application key | Candidate | Historical records → NARA catalog IDs and digitised originals |
| [The National Archives Discovery](https://www.api.gov.uk/tna/discovery/) | public API / terms | Candidate | UK archive records → collection and series identifiers |
| [Europeana](https://api.europeana.eu/en) | free key | Candidate | Cultural item → collection and rights statement |
| [Smithsonian Open Access](https://www.si.edu/openaccess/devtools) | free gateway key | Candidate | Collections → accession identifiers and CC0 assets where indicated |
| [Library of Congress loc.gov](https://www.loc.gov/apis/) | keyless | Candidate | Collection item → originating catalogue and digitised asset |

### Research and cultural records

| Provider | Access | Huntsman | Contribution |
|---|---|---|---|
| [OpenAlex](https://help.openalex.org/api/authentication/) | free key / usage credit | Implemented | US$1/day personal allowance; work IDs for DOI and publisher lookup |
| [Crossref](https://www.crossref.org/documentation/retrieve-metadata/rest-api/) | keyless / polite access | Implemented | DOI → publisher-deposited bibliographic metadata and updates |
| [DataCite](https://support.datacite.org/docs/api) | keyless read | Candidate | DOI → dataset, repository and relationship metadata |
| [Semantic Scholar](https://www.semanticscholar.org/product/api) | keyless / free key application | Candidate | Paper graph and citations, useful for discovery |
| [CORE](https://core.ac.uk/services/api) | keyless, key for higher limit | Candidate | Repository metadata and available open manuscripts |
| [OpenAIRE Graph](https://graph.openaire.eu/docs/10.5.1/apis/terms/) | keyless / free authentication | Candidate | DOI → project, funder and repository connections |
| [Unpaywall](https://unpaywall.org/products/api) | contact email | Candidate | DOI → public manuscript location and OA status |
| [Europe PMC](https://www.ebi.ac.uk/EuropePMC/webservices/restful-web-service) | keyless | Candidate | PMID/PMCID → biomedical citation and archive metadata |
| [NCBI E-utilities](https://www.ncbi.nlm.nih.gov/books/NBK25497/) | keyless / free key | Candidate | PubMed identifiers and source records, general literature metadata only |
| [ORCID Public API](https://info.orcid.org/documentation/integration-guide/registering-a-public-api-client/) | free noncommercial credentials | Candidate | ORCID → public, scoped researcher record |
| [NASA ADS](https://api.adsabs.harvard.edu/v1/swagger-ui.html) | account token | Candidate | Astronomy bibliographies → bibcode and original work |
| [Zenodo](https://developers.zenodo.org/) | keyless public records | Candidate | DOI or record ID → dataset release and version metadata |
| [DOAJ](https://doaj.org/api/) | keyless public search | Candidate | ISSN and journal scope → repository listing |
| [Open Library](https://openlibrary.org/developers/api) | keyless, identification encouraged | Candidate | ISBN → editions, works and identifiers |
| [Internet Archive](https://archive.org/developers/) | keyless public reads | Candidate | Archive item → manifest and source files with rights review |
| [Wikimedia APIs](https://www.mediawiki.org/wiki/API:Main_page) | keyless public read | Existing components | Reference URLs, edit metadata and multilingual leads |

### News, events and humanitarian records

| Provider | Access | Huntsman | Contribution |
|---|---|---|---|
| [The Guardian Open Platform](https://open-platform.theguardian.com/access/) | free noncommercial key | Candidate | Original publisher record and publication chronology |
| [GDELT](https://www.gdeltproject.org/data.html) | keyless | Candidate | Discover international news; deduplicate syndicated coverage |
| [NewsAPI](https://newsapi.org/pricing) | developer-only free plan | Candidate | Headline discovery for development, 100 requests/day advertised |
| [Mediastack](https://mediastack.com/pricing) | recurring limited plan | Candidate | Delayed articles, confirm eligible usage per plan |
| [GNews](https://gnews.io/pricing) | free development plan | Candidate | News discovery, delay and nonproduction restrictions |
| [NewsData.io](https://newsdata.io/pricing) | recurring limited plan | Candidate | Multilingual news discovery; plan controls retention and delivery |
| [ReliefWeb](https://apidoc.reliefweb.int/) | approved free appname | Candidate | Humanitarian chronology and original report links |
| [HDX](https://data.humdata.org/about/api) | keyless public CKAN | Candidate | Humanitarian dataset and publisher records |
| [ACLED](https://acleddata.com/api-documentation/getting-started) | eligibility / licence | Candidate | Published event chronology where use is entitled |
| [UNHCR Refugee Data](https://www.unhcr.org/refugee-statistics/insights/annexes/apis.html) | public API | Candidate | Displacement series by country, year and population definition |

### Geospatial and environmental data

| Provider | Access | Huntsman | Contribution |
|---|---|---|---|
| [Geoapify](https://www.geoapify.com/pricing/) | recurring free credits | Candidate | Geocoding, place search and geometry; respect attribution |
| [LocationIQ](https://locationiq.com/pricing) | recurring free quota | Candidate | Forward/reverse geocoding with usage and attribution restrictions |
| [OpenCage](https://opencagedata.com/pricing) | evaluation only at free level | Candidate | Geocoding and source annotations; no production on free trial |
| [TomTom](https://docs.tomtom.com/pricing) | recurring free quota | Candidate | Maps, geocoding and traffic; allowance varies by API |
| [MapTiler Cloud](https://www.maptiler.com/cloud/pricing/) | recurring limited plan | Candidate | Map or geocoding context under project and usage terms |
| [Mapbox](https://www.mapbox.com/pricing) | metered free thresholds | Candidate | Geocoding/map records; verify permanent storage cost and entitlement |
| [GraphHopper](https://www.graphhopper.com/pricing/) | recurring free credits | Candidate | Route feasibility and distances with underlying map attribution |
| [GeoNames](https://www.geonames.org/export/) | free username | Candidate | Gazetteer identifiers, aliases and admin hierarchy |
| [what3words](https://developer.what3words.com/public-api/docs) | limited free endpoint access | Candidate | Autosuggest only for address discovery; coordinate conversion requires eligible plan |
| [Open-Meteo](https://open-meteo.com/en/pricing) | noncommercial keyless | Candidate | Forecast and historical model data; record model versus measurement |
| [OpenWeather](https://openweathermap.org/price) | metered free threshold / billing terms | Candidate | Weather history and forecasts, verify product and hard daily limits |
| [WeatherAPI](https://www.weatherapi.com/pricing.aspx) | recurring limited plan | Candidate | Second weather source; historical coverage depends on tier |
| [Visual Crossing](https://www.visualcrossing.com/weather-data-editions) | limited free daily usage | Candidate | Forecast or historical weather; count records, not calls |
| [NASA Open APIs](https://api.nasa.gov/assets/html/authentication.html) | free gateway key | Candidate | Remote environmental records, default registered 1,000 requests/hour subject to endpoint |
| [NASA FIRMS](https://firms.modaps.eosdis.nasa.gov/api/area/) | free MAP_KEY | Candidate | Active fire detections → satellite acquisition time and confidence |
| [Copernicus Data Space](https://documentation.dataspace.copernicus.eu/Quotas.html) | free account quotas | Candidate | Sentinel image inventory by observed footprint, time and product ID |
| [USGS EarthExplorer M2M](https://m2m.cr.usgs.gov/api/docs/json/) | account token / roles | Candidate | Landsat and other imagery discovery with acquisition identifiers |
| [Microsoft Planetary Computer](https://planetarycomputer.microsoft.com/docs/concepts/sas/) | public catalogue / SAS access | Candidate | STAC asset lookup and scoped asset signing |
| [OpenAQ](https://developer.openaq.org/) | API key / eligibility | Candidate | Air quality measurements with station and time context |
| [USGS Water Data](https://api.waterdata.usgs.gov/docs/ogcapi/keys/) | keyless / free registration | Candidate | US water gauges, time series and reported units |
| [Nominatim public service](https://operations.osmfoundation.org/policies/nominatim/) | keyless under acceptable use | Existing | OpenStreetMap geocoding; service-specific rate and attribution rules |

### Economic and market data

| Provider | Access | Huntsman | Contribution |
|---|---|---|---|
| [FRED](https://fred.stlouisfed.org/docs/api/api_key.html) | free user key | Candidate | Macroeconomic release and series identifiers |
| [BLS Public Data](https://www.bls.gov/developers/) | keyless / registered | Candidate | US labour releases and series histories |
| [BEA](https://www.bea.gov/tools/) | free registration | Candidate | US national or regional economic accounts |
| [EIA Open Data](https://www.eia.gov/opendata/) | free key | Candidate | US energy datasets and time series |
| [World Bank Indicators](https://datahelpdesk.worldbank.org/knowledgebase/articles/889392-about-the-indicators-api-documentation) | keyless | Candidate | Country development data and indicator revisions |
| [OECD Data Explorer](https://www.oecd.org/en/data/insights/data-explainers/2024/09/api.html) | keyless subject to limits | Candidate | International statistical data with SDMX series IDs |
| [Alpha Vantage](https://www.alphavantage.co/support/) | recurring free key | Candidate | Market or economic series research under endpoint limits |
| [Twelve Data](https://twelvedata.com/pricing) | recurring basic plan | Candidate | Market pricing snapshots and exchange identifiers; licence by use |
| [Financial Modeling Prep](https://site.financialmodelingprep.com/pricing-plans) | recurring basic plan | Candidate | Issuer and market discovery; retain filing as authority |

### Public platforms and media

| Provider | Access | Huntsman | Contribution |
|---|---|---|---|
| [GitHub REST](https://docs.github.com/en/rest/using-the-rest-api/rate-limits-for-the-rest-api) | keyless / free token | Existing | Public repo, commit and account IDs with author attribution limits |
| [GitLab REST](https://docs.gitlab.com/api/rest/) | keyless public / account token | Existing components | Public projects and profiles by stable ID |
| [Hugging Face Hub](https://huggingface.co/docs/hub/rate-limits) | public endpoints / free account token | Existing components | Public repository metadata, dataset and card version references |
| [Bluesky public AppView](https://bsky.network/docs/advanced-guides/rate-limits/) | keyless | Existing | Public actor or post → DID and record URI |
| [Mastodon API](https://docs.joinmastodon.org/api/rate-limits/) | public / instance policy | Existing | Public, instance-scoped profiles and posts |
| [YouTube Data API](https://developers.google.com/youtube/data/determine_quota_cost) | free project quota | Candidate | Public channels and video IDs; verify method quota costs |
| [Flickr](https://www.flickr.com/services/api/misc.api_keys.html) | free noncommercial application subject to eligibility | Candidate | Public asset records and photographer-supplied rights |
| [Google Cloud Vision](https://cloud.google.com/vision/pricing) | metered credit / billing account | Existing | Operator-approved image web detection, source-page leads only |
| [SauceNAO](https://saucenao.com/user.php?page=search-api) | free account key, separate limits | Existing | Image reuse in specialised visual indexes |

### Passive infrastructure and defensive context

| Provider | Access | Huntsman | Contribution |
|---|---|---|---|
| [urlscan public search](https://urlscan.io/docs/api/) | keyless / free key quotas | Existing | Existing scan snapshots as passive infrastructure observations |
| [IPinfo Lite](https://ipinfo.io/products/ipinfo-lite) | free token | Existing components | ASN and country context; product-specific coverage |
| [Cert Spotter](https://sslmate.com/ct_search_api/) | free CT search | Existing | Certificate history and observed names, not asset ownership |
| [VirusTotal public API](https://docs.virustotal.com/reference/public-vs-premium-api) | free restricted key | Existing | Reputation for owned assets, noncommercial/nonbusiness restrictions |
| [AbuseIPDB](https://www.abuseipdb.com/api) | free limited key | Existing | Community reporting history for owned-infrastructure triage |
| [PeeringDB](https://www.peeringdb.com/apidocs/) | public data / account controls | Existing | Operator-published network and interconnection context |
| [OpenCelliD](https://wiki.opencellid.org/docs/api/overview) | free account access, eligibility and terms | Existing | Coarse dataset-based cell infrastructure references |
