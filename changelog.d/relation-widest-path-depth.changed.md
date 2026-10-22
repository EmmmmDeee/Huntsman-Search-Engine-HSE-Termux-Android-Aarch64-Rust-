- Pathway counts no longer miss a shallow path behind a wide, deep one. `disjoint_pathways` and
  the pairwise counts expanded each node once, at the width of the first path that reached it,
  and pruned every later path to that node that was no wider, however shallow, so a wide path of
  seven relations could prune a shorter path the eight-relation bound admits. On the probe, seven
  alias relations at 1.0 lead from `S` to `X`, with `S`-`X` at 0.5, `X`-`Y` at 1.0 and `Y`-`T` at
  1.0: `disjoint_pathways("S", "T", ...)` returned 0 and now returns 1, through `S`, `X`, `Y`,
  `T`. A pair's count, and the connection brokers on its strongest path, can change wherever the
  old search missed a shallower path. On a 300-node dense graph with 3000 identity relations the
  total count is unchanged.
