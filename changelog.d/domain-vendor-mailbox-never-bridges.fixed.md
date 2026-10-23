- `domain` no longer makes a DMARC or TLS-RPT report vendor's mailbox (for example a
  `rua=mailto:…@dmarc.vendor.example` address) an e-mail entity of the looked-up domain. Every
  zone that uses the vendor names the same mailbox, so as an entity it linked unrelated domain
  scans and became a pivot for recursive scans. A report mailbox is now an entity only in the
  looked-up domain or below it, the same rule as the SOA mailbox, and every report mailbox is
  still recorded on the domain as `report_mailbox`.
