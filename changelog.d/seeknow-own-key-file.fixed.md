- SeekNow's key can now be supplied by its own private file, `~/.config/seeknow/api_key`, the way
  DeHashed's and HIBP's can. The file joins `PROVIDER_KEY_FILES`, and the `seeknow` credential
  builder and both of its "is a key configured" gates now read the `HUNTSMAN_SEEKNOW_KEY` slot
  through the shared slot rule, so a key kept only in that file is used by the CLI, the lookup leg,
  `credential-status`, its probe and the web UI's key settings alike. A Termux install driven
  through the web UI, with no persistent shell environment, previously had no durable place to hold
  the SeekNow key; the file now survives restart and reinstall. The file is read under the same
  private-file checks (bounded, mode 600, symlinks refused) as the other providers'.
