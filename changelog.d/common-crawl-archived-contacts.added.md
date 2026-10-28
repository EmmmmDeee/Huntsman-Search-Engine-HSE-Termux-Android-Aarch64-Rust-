- `domain` (and `scan -k domain`, saved scans and `/api/lookup`) now also asks the newest
  Common Crawl index (`common_crawl`) for at most 32 HTML captures of the domain and its
  subdomains. Each becomes a historical URL or subdomain lead naming the crawl, capture time
  and WARC location. At most three of those pages (contact, about and team pages first) are
  read by exact byte range from data.commoncrawl.org, checked against their gzip CRC and
  WARC target URI, and their e-mail addresses and phone numbers become `historical_content`
  leads through the same reader the Wayback source uses. An empty index is a valid zero,
  never proof a site did not exist.
- Wayback and Common Crawl now share one archived-page reader (`archived_page`): capture
  choice, the 1 MiB web-page bound, contact extraction, URL admission and CDX timestamps.
