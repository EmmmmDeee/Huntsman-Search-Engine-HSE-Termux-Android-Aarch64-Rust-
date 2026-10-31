- Add Hudson Rock Cavalier domain-level aggregate intelligence (keyless): a `domain` lookup,
  `scan` and `/api/lookup` now report how many of the domain's employees, users and third parties
  Hudson Rock's Cavalier holds infostealer compromises for. The raw provider answer, which lists
  the URLs the stolen credentials were for, is never kept. Malformed responses are an explicit
  decode failure, never a silent zero, and the domain-wide counts are deliberately not attributed
  to any individual email address.
