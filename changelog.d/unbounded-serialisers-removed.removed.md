- The unbounded `gexf::to_gexf`, `snake_graph::render_snake_graph` and
  `json::to_canonical_string` are removed. Every production export already used the bounded
  `to_gexf_bounded`, `render_snake_graph_bounded` and `to_canonical_bounded`, which never
  truncate and report an oversize document's exact size; `to_gexf` could also panic. Their
  tests now drive the bounded functions. `roi::is_saturated` and its two constants are removed
  too: the dispatch planner scores seeds, which have no corroborating sources for saturation to
  read.
