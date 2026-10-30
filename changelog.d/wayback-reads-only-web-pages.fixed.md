- A domain lookup (and a saved domain scan) now reads the contact details from the archived pages
  the Wayback index recorded as web pages, instead of spending its three page reads on whatever
  came first. Captures were chosen by their path alone, so a PDF, an archive or an image under a
  contact, about, team or support path (`/about/annual-report-2023.pdf`, `/support/driver.zip`,
  `/team/group.jpg`) was downloaded in full and turned away as "not a web page", while the site's
  real contact page further down was never read. The index answer now carries each capture's type
  (`mimetype`), kept as `capture_mimetype` on the historical URL lead, and only a capture recorded
  as HTML, XHTML or plain text is one of the pages read. Every capture stays a historical URL
  lead.
