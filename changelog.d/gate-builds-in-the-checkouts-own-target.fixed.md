- The gate no longer certifies another checkout's compiled code. Cargo names a workspace crate's
  build without its checkout's path and judges it fresh by file times. So when two checkouts
  share a target directory (`CARGO_TARGET_DIR`), a checkout whose files are older than the
  other's last build ran that build's test binaries, and its gate passed or failed on the other
  checkout's code. Every gate step now builds in a directory of the checkout's own: its
  `target/`, or `checkouts/<name>-<checksum of its path>` inside `CARGO_TARGET_DIR` when that is
  set, which keeps a target directory chosen for an executable filesystem (a Termux checkout on
  shared storage). Cargo's build directory, where cargo 1.91 and later keep compiled crates, is
  the same directory. The gate binary itself is built where the command that runs it says, so a
  `CARGO_TARGET_DIR` shared with a checkout of a revision before this one can still run that
  revision's gate.
- `scripts/lifecycle.sh` builds each checkout in a cache of its own,
  `~/.cache/huntsman-recon-checkouts/<name>-<checksum of its path>`, or `checkouts/<name>-<checksum>`
  inside `CARGO_TARGET_DIR` when that is set, instead of one cache shared by every checkout, and
  its `run` builds before it runs. Before, two clones or worktrees on one device built, tested
  and synced each other's code, and `run` ran whatever binary the last build left. A checkout
  whose path cannot be checksummed is refused rather than given a shared cache, and
  `huntsman clean` removes these caches too. The cache `install.sh` keeps is unchanged: it
  builds each revision from a fresh checkout and checks the revision the binary reports.
