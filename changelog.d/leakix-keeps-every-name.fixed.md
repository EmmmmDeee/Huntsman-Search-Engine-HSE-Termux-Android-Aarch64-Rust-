- LeakIX (with `HUNTSMAN_LEAKIX_KEY`) keeps every distinct port, protocol, plugin, software name,
  leak severity and leak type it lists for an address or domain. Each list stopped at 15: a host
  with 16 exposed services on 16 ports read `16 exposed service(s)` but listed only the first 15
  in `ports`, and the rest were lost. Every one is now listed.
