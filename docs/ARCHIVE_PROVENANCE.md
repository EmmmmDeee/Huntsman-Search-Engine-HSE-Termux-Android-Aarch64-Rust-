# Historical archive provenance

The reconstruction keeps historical source material in extracted, reviewable form under
`legacy/`. The two opaque ZIP containers that previously duplicated those trees at the
repository root are intentionally absent from HEAD. Their exact bytes remain recoverable
from Git history, so removing the duplicate containers from the current tree does not erase
provenance or rollback capability.

## Source archives

| Historical archive | SHA-256 | Git blob SHA-1 | Canonical extracted tree | Historical Git tree |
| --- | --- | --- | --- | --- |
| `Huntsman-HSE-EndToEnd-Refactor-Overlay-feef60a.zip` | `bba70abb0ac7f8c1f1ade818580273a78d169628c14b4b908ff6a5c08e90faf7` | `b1801b5efbadabf4b16bc6ccff578876bad67991` | `legacy/refactor-overlay-feef60a/` (40 files) | `39d9f765f0b58c70b2e30ae6b49538a74042ff1c` |
| `Huntsman-Search-Engine-HSE-Termux-Android-Aarch64-Rust--main (10).zip` | `c3c7f843a1c495f443344a228ce2707b097d53edaa7aea2238347452b7495241` | `f999915dc8d8208e49034df457dcb7f3974976a1` | `legacy/hse-monolith-v1.41.0/` (1314 files) | `58adb561ddad030092838234c69ed63e2c1a0314` |

The archive bytes are present in commit `01089c7e756216a33573cdefdfd7068dfa4e5380`
(the pre-reconstruction `main` baseline) and in reconstruction history before their removal.
The SHA-256 values above were previously enforced by `tests/legacy_reference.rs`; they are
retained here as provenance after the containers leave HEAD.

## Repository invariant

`tests/repository_hygiene.rs` rejects root-level opaque archive containers, and `.gitignore`
prevents the common archive forms from being accidentally re-added at the repository root.
`tests/legacy_reference.rs` continues to assert the expected extracted-tree file counts.
The extracted trees remain ordinary Git content: they are searchable, diffable and auditable,
while the historical archive bytes remain available through Git history when byte-for-byte
recovery is required.
