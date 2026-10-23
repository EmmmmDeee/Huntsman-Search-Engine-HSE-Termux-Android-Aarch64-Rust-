- `network LAT,LON` also lists the cell sites OpenCelliD places in the 1.8 km square around the
  point when `HUNTSMAN_OPENCELLID_KEY` is set: one request, at most 50 sites. Each site is a
  `cell:MCC:MNC:AREA:CELL` entity that `network` takes back, carrying its position, radio, range
  and sample count, plus a note when the area holds more. Without the key it makes no request
  and reports `not_configured`. The sites are near the point; nothing says any device there used
  them.
