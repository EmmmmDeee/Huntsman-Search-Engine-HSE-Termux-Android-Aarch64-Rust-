- A domain lookup (and a saved domain scan) now spends its three archived page reads on the
  captures the Wayback index recorded as web pages. Captures were chosen by their path alone
  (contact, about, team and support pages first, then the site root, then the rest), so a PDF,
  an archive or an image under such a path (`/about/annual-report-2023.pdf`,
  `/support/driver.zip`, `/team/group.jpg`) took a read: it was downloaded and turned away as
  "not a web page" (or, past the 4 MiB transport limit, cut off and reported as parser drift),
  while the site's real contact page further down was never read. The index answer now carries
  each capture's type (`mimetype`), kept as `capture_mimetype` on the historical URL and
  subdomain leads; a capture recorded as anything but HTML, XHTML or plain text is not read, and
  the row says how many captures the index recorded as no web page. A capture the index recorded
  no type for (`-`, `unk`, `warc/revisit`) can still be read, and the replay's own type decides.
  A type is read by its media type without parameters, so one that only names HTML, as a compiled
  help file's `application/vnd.ms-htmlhelp` does, is no web page at the index or in a Wayback or
  Common Crawl replay. Every capture stays a historical URL lead.
