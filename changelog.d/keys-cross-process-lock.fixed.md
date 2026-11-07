- A key saved from the CLI and one saved from the Web UI's Settings page at the same moment no
  longer lose one of the two. Both saves read the keys file, change it and rename a new one over
  it, and only an in-process lock kept them apart.
  - **The lock.** A save now holds a lock file beside the keys file
    (`~/.huntsman.env.lock`, private, naming its holder) for its whole read, check and rename.
  - **When it is busy.** A save that finds the lock held for five seconds saves nothing and says
    so (exit 74): "busy or has a stale lock … remove the lock only after verifying no Huntsman
    writer is running".
  - **One lock rule.** `radar`'s track log already had this lock; `fsio::ExclusiveLock` is now
    that one lock for both.
  - **A sharper holder check.** A holder now removes the lock only while the file still holds its
    own name, not just its inode, since a lock deleted and created again can reuse the inode.
