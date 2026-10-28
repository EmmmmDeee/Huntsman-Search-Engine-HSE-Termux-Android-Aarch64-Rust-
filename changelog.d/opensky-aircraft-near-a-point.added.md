- `geocode LAT,LON` (and `scan -k geocode`, saved place scans and `/api/lookup`) now also asks
  the keyless OpenSky Network which aircraft its receivers last reported within half a degree
  of the point: one anonymous, one-credit query. Each aircraft, nearest first and at most 50,
  is a `device_id` `icao24:<address>` tagged `aircraft`, with its callsign, the registration
  country inferred from the address, position and reporting time, last contact, altitude,
  ground state, speed, track, vertical rate, squawk, position source and distance from the
  point. Every observation states that a transponder address identifies an airframe, not anyone
  aboard, that the position is not where the aircraft is now, and that OpenSky data is for
  non-commercial research. Rows without a valid address, position or time are skipped and
  counted; `states: null` is a valid zero.
