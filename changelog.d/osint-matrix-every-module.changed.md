- `osint matrix` and `GET /api/osint/matrix` now place every reachable module in a capability
  group. Before, the matrix covered 44 of the 144 modules `/api/modules` lists. Its breach,
  threat and social groups were missing sources they cover, such as OathNet, Shodan and Keybase.
  Nothing tied it to the module registry, so new modules never reached it.
  - **Each group names its modules.** `osint matrix` prints them as `modules=`. The JSON adds
    `modules` to each row, with `reachable_modules_count` and `modules_in_rows_count`.
  - **Three new groups.**
    - Email identity: Gravatar, OpenPGP keys, Kickbox, Hunter, Duolingo and email parsing.
    - Phone numbers: the numbering plans and Numverify.
    - List-based blocklists: DNSBLs, filtering resolvers and downloaded threat feeds.
  - **A guard.** A test now fails when a module sits in no group or in two, or when a group
    names a module that no longer exists.
- `docs/OSINT_FILE_MATRIX.csv` is gone. It was a hand-made snapshot of an old tree, with nothing
  to regenerate it, and no longer matched the repository. It omitted 161 tracked files and gave
  wrong hashes and sizes for 269 more. The compiled matrix replaces it, and
  `docs/OSINT_FILE_MATRIX.md` now describes that matrix.
