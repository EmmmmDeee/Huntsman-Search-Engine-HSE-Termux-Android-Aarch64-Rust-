- On aarch64 and 32-bit Arm, Termux included, a file read no longer follows a symlink swapped in
  after its check. The no-follow open used the x86 `O_NOFOLLOW` value, which on Arm is
  `O_LARGEFILE`, so the open followed the link. The device/inode check after the open still
  refused the swap for bounded reads, but `doctor`'s Cargo `CACHEDIR.TAG` check, which gates its
  `rm -rf` repair of a stale build cache, had no such check. The flags now come from one per-arch
  table in `fsio`, and `doctor` also requires the opened tag to be the inode it checked.
- The private-file gate behind `~/.huntsman.env` and the HIBP and DeHashed `api_key` files now
  opens the same way on Linux and Android: a FIFO swapped in after the check no longer blocks the
  open, and the swap is refused as `changed between the check and the open`.
