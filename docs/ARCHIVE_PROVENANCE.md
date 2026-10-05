# Historical archive provenance

The reconstruction keeps historical source material in extracted, reviewable form under
`legacy/`. The two original ZIP containers were removed from the current repository root
after their extracted trees became the canonical reviewable references. Their original
SHA-256 values, Git blob identities, extracted-tree mappings, and historical Git trees are
preserved below so the containers remain recoverable and independently identifiable from
repository history without keeping opaque snapshots in the active tree.

## Source archives

| Historical archive | SHA-256 | Git blob SHA-1 | Canonical extracted tree | Historical Git tree |
| --- | --- | --- | --- | --- |
| `Huntsman-HSE-EndToEnd-Refactor-Overlay-feef60a.zip` | `bba70abb0ac7f8c1f1ade818580273a78d169628c14b4b908ff6a5c08e90faf7` | `b1801b5efbadabf4b16bc6ccff578876bad67991` | `legacy/refactor-overlay-feef60a/` (40 files) | `39d9f765f0b58c70b2e30ae6b49538a74042ff1c` |
| `Huntsman-Search-Engine-HSE-Termux-Android-Aarch64-Rust--main (10).zip` | `c3c7f843a1c495f443344a228ce2707b097d53edaa7aea2238347452b7495241` | `f999915dc8d8208e49034df457dcb7f3974976a1` | `legacy/hse-monolith-v1.41.0/` (1314 files) | `58adb561ddad030092838234c69ed63e2c1a0314` |

The archive bytes are present in commit `01089c7e756216a33573cdefdfd7068dfa4e5380`
(the pre-reconstruction `main` baseline) and are addressable by the Git blob identities above.
They are intentionally absent from the current repository root. The extracted trees under
`legacy/` are the active, searchable, diffable, and auditable historical evidence oracle.

## Repository invariant

`tests/repository_hygiene.rs` rejects opaque archive files at the repository root, and
`.gitignore` prevents common archive forms from being accidentally added there.
`tests/legacy_reference.rs` continues to assert the expected extracted-tree file counts.
Historical container identity is preserved by this document and repository history rather
than by retaining duplicate opaque archive blobs in the current tree.
