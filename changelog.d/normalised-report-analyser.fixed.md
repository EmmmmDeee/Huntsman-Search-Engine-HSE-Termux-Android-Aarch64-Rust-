- A normalised report now records the build that derived it (`normalisation.analyser`). A
  restarted `serve` or a scheduled `scans cycle` no longer re-analyses unchanged evidence and
  rotates an identical copy into `.previous.json`, which used to push out the real historical
  report. A report written by another build, or before this change, is analysed once more.
