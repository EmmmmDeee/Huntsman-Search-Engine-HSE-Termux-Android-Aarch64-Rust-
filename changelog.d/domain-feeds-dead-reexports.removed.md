- `domain_cli::MAX_RESOLVED_HOSTS` and `domain_cli::RESOLVE_SOURCE` are no longer public library
  items. Nothing outside `domain_cli` read them; the resolver label is still
  `dns::RESOLVE_SOURCE`, and the 512-host limit and the `dnsresolve` row are unchanged.
