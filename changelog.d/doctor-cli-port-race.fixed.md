- The `doctor_cli` tests no longer fail intermittently in a full parallel run. A port one test
  freed (`free_port`, a stopped server) could be handed by the kernel to another test's
  listener, so a probe met the wrong program, or a stray connection spent one of the two
  accepts the "foreign program" fixture counted and left the next `doctor` facing a closed port
  (`not running`, exit 0 instead of 78). Every test that binds, frees or probes a loopback port
  now holds one lock, and the fixture answers any number of connections until dropped. A
  deliberate stray connection in the test reproduces the old failure and now passes.
