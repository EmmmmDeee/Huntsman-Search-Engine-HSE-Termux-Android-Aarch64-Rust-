- `domain` (and `scan -k domain`, saved scans and `/api/lookup`) now reads what a site's
  archived pages published, not only which URLs the Internet Archive indexed. After the CDX
  index answers, at most three captures are fetched from the archive's raw replay: contact,
  about and team pages first, then the root, newest first. Each is fetched from
  web.archive.org only, with no redirect, as HTML or text within 1 MiB. The e-mail
  addresses and phone numbers in their text and in `mailto:`/`tel:` links become leads
  tagged `historical_content`, with confidence at most 0.6. Each names its capture
  timestamp, original URL and snapshot URL, and says it is historical, not current. Script,
  comment and attribute text is not read as a contact, and the outcome names any page not
  read and why.
- The HTML reader `exposure_cli` used is now the shared `html_text` module, so archived
  pages and breach descriptions are read by one implementation.
