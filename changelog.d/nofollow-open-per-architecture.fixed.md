- On aarch64 and 32-bit Arm, Termux included, a file read no longer follows a symlink swapped in
  after its check. The no-follow open used the x86 `O_NOFOLLOW` value, which on Arm is
  `O_LARGEFILE`, so the open followed the link. The device/inode check after the open still
  refused the swap for bounded reads, but `doctor`'s Cargo `CACHEDIR.TAG` check, which gates its
  `rm -rf` repair of a stale build cache, had no such check. The flags now come from one per-arch
  table in `fsio` (Arm and PowerPC use one `O_NOFOLLOW` value; x86, RISC-V, s390x and LoongArch
  another; other architectures set neither flag), and `doctor` also requires the opened tag to be
  the inode it checked.
- The private-file gate behind `~/.huntsman.env` and the HIBP and DeHashed `api_key` files now
  opens the same way on Linux and Android on those architectures: a FIFO swapped in after the
  check no longer blocks the open, and the swap is refused as `changed between the check and the
  open`.
- CI runs the library and xtask unit tests as aarch64 code under qemu-user, so a wrong Arm flag
  value fails CI instead of only a manual run.
