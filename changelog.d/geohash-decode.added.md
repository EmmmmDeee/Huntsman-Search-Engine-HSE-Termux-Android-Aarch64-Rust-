- `geohash HASH` decodes a geohash to its cell: the centre, then the cell's latitude and
  longitude bounds, to eight decimal places, so a 12-character hash keeps its centimetre-scale
  bounds. Upper case is folded. A character outside the geohash alphabet, or more than 12
  characters, is refused. `geohash LAT,LON [PRECISION]` still encodes.
