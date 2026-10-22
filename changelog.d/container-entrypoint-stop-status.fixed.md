- The container entrypoint exits with the server's own status when a stop signal arrives while
  it is starting the server. Under load the shell could lose the server's status to a signal
  race and exit 143, as if it had been killed, instead of the status the server returned. The
  shell now waits for the server inside the stop handler, and that handler is installed before
  the server starts, so a stop request in that window is not dropped.
