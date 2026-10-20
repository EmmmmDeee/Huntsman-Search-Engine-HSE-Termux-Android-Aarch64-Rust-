- A console tab left open while `serve` is upgraded now says so: "Huntsman was updated while this
  page was open. Reload to use the new version.", with a Reload button. The page is served with
  the id of the page the build embeds, the first 16 hex digits of its SHA-256, and
  `/api/health` names the same id as `page`, so the tab notices on its next health answer: when
  the server comes back after the upgrade, or when the tab comes back into view. Until now such
  a tab kept running the old page against the new server, as the pre-console Look up page did on
  a phone after the console shipped. A server started again on the same build asks nothing.
