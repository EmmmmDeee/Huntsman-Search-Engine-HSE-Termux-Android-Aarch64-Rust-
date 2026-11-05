- `osint matrix [--json]` and `GET /api/osint/matrix` list the curated OSINT capability groups,
  such as GEOINT, HUMINT and NETINT. For each group they give the Rust files that own it, its
  inputs and outputs, and how it combines with the others. This is a source inventory, not a
  claim that any source is reachable. The Termux runtime acceptance now checks the matrix and
  the Rhinser capture route on the device. The web UI does not show the matrix: the page has
  no budget left for the panel.
