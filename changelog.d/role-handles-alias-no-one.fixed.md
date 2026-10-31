- Role mailboxes at unrelated organisations are no longer linked as aliases of one identity. The
  relation graph's handle rule kept its own list of fourteen role words, so `abuse@`,
  `hostmaster@`, `billing@`, `noc@`, `tech@`, `privacy@` and the rest of the role local parts the
  crawl already declines to pursue shared a persona key: a domain scan's registry and hosting
  contacts at different companies, and a username of the same word, were joined by `AliasOf`
  edges that read as one person's addresses. The handle rule now reads the same role list as the
  crawl's mailbox rule, its separator-aware role segments included (`awsdns-hostmaster@`), so such
  handles key no alias. Two personal addresses with one local part still alias, unless a separator
  sets a system role word apart in it (`jane-abuse`), which the crawl reads as a role too.
