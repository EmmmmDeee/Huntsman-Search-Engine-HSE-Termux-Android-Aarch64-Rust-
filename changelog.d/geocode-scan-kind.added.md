- `geocode` is a scan kind. `scan QUERY -k geocode`, `scans run QUERY -k geocode`, the API's
  `kind=geocode` and the web UI's "Place, address or LAT,LON" target type run the keyless Nominatim
  lookup and save it as a scan: each written address is a `PHYSICAL_ADDRESS` element and each
  point a `PHYSICAL_COORDINATES` element, with every field Nominatim returned as evidence, and an
  address element offers "New Scan of this". The kind is never inferred: free text stays a name
  and `LAT,LON` a WiFi area, so a geocode is asked for. `geocode` itself now takes `--save FILE`
  as every other lookup does.
