# Historical archive provenance

The active repository no longer carries extracted historical source trees. Historical archives remain recoverable from Git history; their SHA-256 values, Git blob identities, former extracted-tree mappings, and historical Git trees are recorded here so provenance is retained without duplicating roughly 1,355 inactive files in `main`.

## Source archives

| Historical archive | SHA-256 | Git blob SHA-1 | Former extracted tree | Historical Git tree |
| --- | --- | --- | --- | --- |
| `Huntsman-HSE-EndToEnd-Refactor-Overlay-feef60a.zip` | `bba70abb0ac7f8c1f1ade818580273a78d169628c14b4b908ff6a5c08e90faf7` | `b1801b5efbadabf4b16bc6ccff578876bad67991` | `legacy/refactor-overlay-feef60a/` (40 files) | `39d9f765f0b58c70b2e30ae6b49538a74042ff1c` |
| `Huntsman-Search-Engine-HSE-Termux-Android-Aarch64-Rust--main (10).zip` | `c3c7f843a1c495f443344a228ce2707b097d53edaa7aea2238347452b7495241` | `f999915dc8d8208e49034df457dcb7f3974976a1` | `legacy/hse-monolith-v1.41.0/` (1314 files) | `58adb561ddad030092838234c69ed63e2c1a0314` |

The archive bytes are present in commit `01089c7e756216a33573cdefdfd7068dfa4e5380`
(the pre-reconstruction `main` baseline) and are addressable by the Git blob identities above.
They and their extracted trees are intentionally absent from the active repository. Use the recorded Git tree/blob identities or commit `01089c7e756216a33573cdefdfd7068dfa4e5380` when historical comparison is required.

## Repository invariant

`tests/repository_hygiene.rs` rejects opaque archive files at the repository root, and `.gitignore` prevents common archive forms from being accidentally added there. Historical identity is preserved by this document and Git history; no extracted archive is required for normal builds or tests.
