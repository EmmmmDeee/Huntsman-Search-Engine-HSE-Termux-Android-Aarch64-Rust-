- A source build in the Termux installer no longer overwrites the installed `huntsman-recon`
  before checking it. Cargo used to install straight into `$PREFIX/bin`, so a build that then
  failed its `build-sha` or offline acceptance check left the phone with that failed binary and
  nothing to go back to. Cargo now installs into a staging directory, the new binary is checked
  there, and it replaces the installed one only once it passes, through the same staged,
  checksum-verified move as a published build.
- Before that move the installer keeps the current binary as
  `$PREFIX/bin/.huntsman-recon.previous`, and puts it back if the newly installed binary does not
  report the expected commit. It refuses to replace a `huntsman-recon` that is a symlink.
- The installer refuses to run as root, and refuses to start while another run holds
  `~/.huntsman/.install.lock`, so two installs can no longer race over the binary and its install
  record. If Termux is stopped mid-install, the refusal names the lock to remove.
