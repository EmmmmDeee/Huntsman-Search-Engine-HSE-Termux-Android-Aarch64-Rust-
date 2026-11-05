- SHA-256 is faster on AArch64 phones that report the SHA2 extension. From 32 bytes up, `sha256()`
  uses `ring`'s hardware-backed digest, and from 1024 bytes up it does so on every CPU. On
  GitHub's ARM64 runner this was 3.4 times faster at 32 bytes and 8 times faster at 1 MiB,
  with identical digests at every size tested. No handset measurement exists yet.
