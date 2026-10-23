- A saved scan left `RUNNING` by a server that stopped is marked `ABORTED` when the store next
  opens even when another process now holds the dead server's pid, as after a restart or a
  reboot of the phone. The row now records when its owning process started (`owner_started`,
  from `/proc/PID/stat`), and recovery leaves a scan alone only while that same process runs.
  Before, such a scan stayed active for good: it could not be stopped, as its owner was another
  process, nor deleted, as it was still active. Rows saved before the field keep the pid check.
