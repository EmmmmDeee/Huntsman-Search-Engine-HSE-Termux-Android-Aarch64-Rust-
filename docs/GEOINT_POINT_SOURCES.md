# GEOINT around a point: satellite scenes and aircraft

A `LAT,LON` place query (`huntsman-recon geocode LAT,LON`, `scan -k geocode`, saved place scans,
`/api/lookup` and the Web UI's Place target) reverse-geocodes the point through Nominatim and asks
two keyless sources what was observed over it. Both are listed in the module catalogue, so a
lookup can choose or leave out either.

| Source | Module | Request | Bound | Entity |
|---|---|---|---|---|
| Earth Search STAC (AWS open data) | `stac` | one POST to `/v1/search`, Sentinel-2 L2A and Landsat C2 L2, last 90 days, newest first | 10 scenes, 1 MiB | `url` of the scene's catalogue record, tagged `satellite_scene` |
| OpenSky Network | `opensky` | one anonymous GET to `/api/states/all` for a box of 0.5 degrees each side (one credit of the 400 an address gets a day) | 50 aircraft, nearest first, 512 KiB | `device_id` `icao24:<address>`, tagged `aircraft` |

## What each observation is, and is not

- **A scene** is a catalogue record of a satellite pass: its collection, platform, acquisition
  time, cloud cover, footprint bounding box and, when https, a thumbnail. It does not say what
  the imagery shows; the acquisition time is when the satellite passed, not when it was
  published; the footprint is an area of tens of kilometres, not the point. Links outside the
  catalogue origin and footprints that are not a valid WGS 84 area (south above north, out of
  range) are skipped and counted.
- **An aircraft** is a state vector OpenSky's receivers reported: the ICAO 24-bit transponder
  address, callsign, the registration country OpenSky infers from the address, position and the
  time it was reported, last contact, barometric and geometric altitude, ground state, speed,
  track, vertical rate, squawk, position source (ADS-B, ASTERIX, MLAT or FLARM) and distance from
  the point. The address identifies an airframe's transponder, not anyone aboard; the position is
  not where the aircraft is now; and an aircraft near the point is not evidence of involvement
  with it. OpenSky's data is for non-commercial research and education under its terms of use.
  A row without a valid lowercase six-hex-digit address, a position inside WGS 84 bounds or its
  timestamps is skipped and counted; `states: null` is the documented empty answer, a valid zero.

The query box is clamped at the poles and the antimeridian rather than wrapped, so a point
within half a degree of either searches a smaller box.

## Verification

`cargo test --locked stac opensky nominatim_cli lookup_modules` covers the request bodies and
URLs, ordering, bounds, skipped rows, empty answers, schema drift and the geocode wiring. A live
`geocode -33.9399,151.1753` (Sydney Airport) returned Nominatim's address, Sentinel-2 and Landsat
scenes from Earth Search, and the aircraft OpenSky reported around the airport, nearest first.

Sources: <https://stacspec.org/>, <https://element84.com/earth-search/>,
<https://openskynetwork.github.io/opensky-api/rest.html>.
