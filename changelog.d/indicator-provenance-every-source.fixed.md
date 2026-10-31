- A saved lookup (`--save`) names the module of every indicator source it ran. Four of the
  sources the domain, address, IP and network lookups run (`censys`, `submd`, `opencellid` and
  `hudsonrock`) had no entry in the save ledger's table of provider modules, so their outcome and
  evidence claims named the lookup's front end (`src/domain_cli.rs`, `src/email_cli.rs`,
  `src/ip_cli.rs`, `src/network_cli.rs`) instead: a SubMD subdomain or a Hudson Rock exposure read
  as the front end's own claim. Each is now saved under its own module, the network lookup reads
  the same table as the others, and a test holds every indicator source to an entry naming its
  own file.
