- The `fbi_wanted` module was missing its dedicated clause in ARCHITECTURE.md L5
  entity model. Added `fbi_wanted` to the L5 module list and documented its role
  as a keyless FBI wanted-notices collector keyed by notice URL, with proper
  incomplete-page and failure handling (inconclusive, not clean zero).
