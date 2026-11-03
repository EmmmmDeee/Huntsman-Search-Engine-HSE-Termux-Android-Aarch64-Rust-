- The Web UI Scans list gains a **Sources** column: how many sources each scan ran and, when
  some ended unresolved, an `N unresolved` label — from the `modules_run` and `errors` fields every
  saved scan already carries — so a people scan of a name no register knows reads "6 sources ·
  1 unresolved" rather than a bare "1 element", and a scan whose lookup never ran reads "none ran".
