- Make Termux on Android AArch64 the permanent first priority: the canonical directive and its
  mirrors now say to optimise first for a rootless userland install operated through its web
  UI, judge every change by its effect there, and never trade that target's correctness,
  install, footprint, battery or web UI for a gain elsewhere. The directive lock requires that
  wording, so dropping the priority fails CI.
