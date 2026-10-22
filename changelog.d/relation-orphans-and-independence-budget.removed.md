- `relation::{provenance_chain, strongest_path, connection_templates, reachable_count}`,
  `graph::Graph::connected_components`, and `timeline::{online_tenure, OnlineTenure}`, which
  nothing called outside their own tests. The surviving identity searches are unchanged:
  `disjoint_pathways`, `pairwise_disjoint_pathways` and `connection_brokers` still answer exactly
  as their per-pair oracles do, and a new property test holds `resolve_identity_clusters`, which
  the correlator's AU-060 and AU-071 rules read, to a plain merge oracle on random graphs.
