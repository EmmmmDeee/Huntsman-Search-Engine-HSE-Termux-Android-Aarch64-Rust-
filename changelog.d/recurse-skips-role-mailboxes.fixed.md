- `scan --recurse` no longer looks up, or checks breach exposure for, an address that names a
  function or a service rather than a person:
  - a role mailbox such as `abuse@`, `hostmaster@`, `info@` or `support@` (a registrar's abuse
    contact or a zone's SOA mailbox);
  - a mail or hosting provider's own address;
  - a no-reply address such as `users.noreply.github.com`.
  Each such lookup found the service, not a person, and a keyed breach check spent a credit on it.
  These addresses are still kept in the crawl's graph and report.
