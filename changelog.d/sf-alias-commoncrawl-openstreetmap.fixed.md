- A scan module list naming Spiderfoot's `sfp_commoncrawl` or `sfp_openstreetmap` now runs the
  rebuilt modules doing that work (`common_crawl`, `nominatim`) instead of being refused with
  "no module is named". Both were already reachable under their Huntsman names.
