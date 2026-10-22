### Fixed

- `docmeta` refuses XMP latitude/longitude claims with invalid hemisphere letters, negative or non-finite components, minutes/seconds outside 0–59, surplus components, or coordinates outside world bounds. Prevents invalid embedded claims from becoming GEOINT entities; valid southern/western coordinates and boundary values remain supported.
