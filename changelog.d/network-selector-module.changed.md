- The network selector grammar moved from `scan_route` to its own `network_selector` module, so
  the `wigle` collector no longer depends on scan routing; `scan_route` re-exports it unchanged.
