- Pulsedive's true or false values are kept as `true` or `false`. A flag in one of the lists
  Pulsedive names (ports, protocols, technologies, host types) or in a WHOIS, geo, DNS, TLS,
  HTTP or page field the lookup reads out was dropped: a host type list of `"Name Server"` and
  `true` gave `host_types` `Name Server`. It now gives `Name Server,true`, as the other sources
  read a flag.
