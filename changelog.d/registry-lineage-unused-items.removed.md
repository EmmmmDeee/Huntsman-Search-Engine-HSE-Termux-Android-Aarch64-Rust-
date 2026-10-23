- Unused library items from the source registry and lineage are gone, and no output changes:
  - `source_registry::registry()`, which only its own test called; `SourceDescriptor` is now
    private to the module;
  - `source_registry::SourceCategory` and the `category` field of `SourceRoute`, which nothing
    read and nothing printed;
  - `lineage::UpstreamKind::Source`, which `Lineage::of` never produced, and the URL-keyed
    family rule only it reached, so a stored lineage can no longer name the kind `source`;
    nothing ever wrote it. `lineage::upstream_kind_label` is private, and `lineage_tsv_line`
    prints the same labels.
- Coordinate co-location reads `lat,lon` values with `geohash::parse_coords`, the parser it
  copied.
