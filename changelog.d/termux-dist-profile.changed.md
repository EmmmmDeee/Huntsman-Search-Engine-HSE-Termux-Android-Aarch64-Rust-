- Build the prebuilt Termux binary with a new `dist` profile: `release` plus whole-program LTO in
  one codegen unit. Measured on x86_64, the binary is 11% smaller and accented-name matching
  about 17% faster with identical results, for about 2.6 times the build time, which only CI
  pays. `cargo install` on the phone keeps the lighter `release` link. CI now reports the Termux
  binary's size on every run and fails past a 13.5 MiB budget, below the 13.9 MiB thin-LTO
  binary published before this change.
