- `geocode LAT,LON` (and `scan -k geocode LAT,LON`, saved scans, `/api/lookup` and the Web UI's
  Place target) now also asks the keyless Earth Search STAC catalogue which Sentinel-2 and
  Landsat scenes covered the point in the last 90 days. At most ten are kept, newest first, in
  one bounded POST of at most 1 MiB. Each scene is a URL entity for its catalogue record, with
  its collection, platform, acquisition time, cloud cover, footprint and https thumbnail. A
  scene is a record of a satellite pass, not what the imagery shows, and its footprint is an
  area, not the point. A record or thumbnail link off the catalogue's origin never becomes
  evidence. A place name never asks the catalogue.
