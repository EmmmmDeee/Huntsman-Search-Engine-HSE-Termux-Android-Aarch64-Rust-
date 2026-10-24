- `identity::resolve` returns clusters in order of their smallest member, as `UnionFind::groups`
  orders its sets; links keep their pairwise order. Its only shipped caller, selfcheck, counts
  clusters, so no output changes.
