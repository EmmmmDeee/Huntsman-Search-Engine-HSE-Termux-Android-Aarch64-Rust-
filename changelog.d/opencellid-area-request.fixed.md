- The OpenCelliD area client now sends the documented `getInArea` request: a `BBOX`, kept under
  the 4 km² limit, plus `limit=50`. It previously sent `lat`, `lon` and `radius`, which the API
  does not accept. Its decoder no longer narrows a 5G NR cell identity wider than 32 bits to 0,
  and it no longer reads an error or a body without `cells` as an empty area.
