# Historical website OSINT: Common Crawl

`common_crawl` is a keyless Rust collector for the public Common Crawl web archive. It adds a
second, independent archive to the domain lookup beside [`wayback_cdx`](WAYBACK_CDX.md): a page
Common Crawl captured is evidence the Internet Archive may not hold, and the reverse. It uses
the existing request, evidence and archived-page contracts, with no new crate, credential or
paid service.

## Entry points

- `huntsman-recon domain example.org`
- `huntsman-recon scan -k domain example.org`
- `/api/lookup` and saved domain scans

`common_crawl` is listed in the shared module catalogue (`/api/modules`, the New Scan page), so a
lookup can be limited to it or leave it out.

## Exact method

1. `GET https://index.commoncrawl.org/collinfo.json` (at most 256 KiB). The newest crawl is the
   greatest `CC-MAIN-YYYY-WW` id, whatever the list's order; other collections are ignored.
2. `GET https://index.commoncrawl.org/CC-MAIN-YYYY-WW-index` with `url=DOMAIN`,
   `matchType=domain`, `output=json`, `fl=url,timestamp,status,mime,filename,offset,length,digest`,
   `filter==status:200`, `filter=mime:html` and `limit=32`. The documented empty answer, a `404`
   whose JSON says `No Captures found`, is a valid zero; any other `404` is a failure.
3. Every index line is validated before any is admitted: a real UTC timestamp, status 200, a
   positive length, a WARC file inside that crawl's own `crawl-data/` tree (no traversal, only
   `.warc.gz`), and a URL of the domain or a subdomain. A URL with a query, fragment or user-info
   is withheld and counted, never stored.
4. At most three captures are read: contact, about and team pages first, then the site root, then
   the rest, each newest first (the same choice the Wayback source makes). Each is one
   `GET https://data.commoncrawl.org/FILENAME` with `Range: bytes=OFFSET-END`. It is accepted only
   as a `206` of exactly the indexed length, at most 1 MiB compressed. It must be one intact gzip
   member (CRC-32 and length checked), a `WARC/1.x` `response` record whose target URI is the
   indexed URL, and a captured `HTTP 200` HTML or plain-text page.

No discovered URL is fetched from its own site; the only origins contacted are
`index.commoncrawl.org` and `data.commoncrawl.org`, through the shared guarded and paced
transport, with no redirect followed.

## Evidence

- Each capture is a `Url` entity tagged `historical_capture` at confidence 0.65. A subdomain is a
  `Domain` tagged `historical_subdomain` at 0.55: a past lead, not current infrastructure. The
  evidence names the dataset, crawl, capture time, original URL, WARC file, offset, length and
  digest, so anyone can fetch the same record.
- The e-mail addresses and phone numbers a read page published become leads tagged
  `historical_content`, with confidence at most 0.6, through the shared `archived_page` reader.
  Each says it was archived by Common Crawl at the capture time, and that it is historical, not
  proof it is current. Script, comment and attribute text is not read as a contact.
- The outcome detail names the crawl, how many pages were read and why any was not (over 1 MiB,
  not the requested range, a record naming another URL, a captured error page).

## Limits

Common Crawl samples the web; it does not crawl every page of a site, and an empty index for one
crawl is not proof a site did not exist. Only the newest crawl is asked, so a lookup is one bounded
answer, not a history across crawls.

## Verification

`cargo test --locked common_crawl archived_page` covers the newest-crawl choice, filename and
crawl-id validation, index drift, the documented empty answer, gzip integrity (corrupt, oversized,
optional header fields), range and captured-status refusal, and an end-to-end lookup from a
synthetic index and WARC records with fictional contacts. The WARC reader was also checked against
a real record from `data.commoncrawl.org`.

Source contract: <https://commoncrawl.org/cdxj-index> and the pywb CDX server API.
