- Stop a slow Ubuntu mirror from holding the aarch64 qemu CI job: twice in one day it stalled
  for over nine minutes inside a package install that nothing bounded. `scripts/apt-install-retry.sh`
  now bounds each package-list refresh and download, retries up to three times on new
  connections, installs only from fully downloaded packages, and fails when the attempts run
  out. The job also has a 40-minute limit in place of GitHub's six hours. Offline tests with a
  fake `apt-get` cover a healthy run, a cut-off stall, a failed refresh, exhaustion, a failed
  install and bad input, and the CI policy keeps every workflow's apt calls behind the script.
