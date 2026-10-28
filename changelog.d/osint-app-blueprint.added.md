- `huntsman-recon blueprint [--json] [--docx FILE|-]`, `GET /api/blueprint[?format=docx]` and the
  About view's **OSINT app blueprint (.docx)** give the OSINT app blueprint. It maps each Android
  OSINT app (Termux:API, Network Survey, ICdetection, AIMSICD, NetMonster, Tower Collector,
  SnoopSnitch, WiGLE, WiFiAnalyzer, Fieldwatch, Spectre, Exodus, App Manager, PCAPdroid, Ghost,
  Orbot, GPSTest, Scrambled Exif) to its package, source, licence, features, Huntsman modules and
  commands, Termux requirements, priority, status with the gap or Android limit, and acceptance
  criterion. `docs/OSINT_APK_BLUEPRINT.docx` is generated from the same entries by a new
  dependency-free Word writer (`docx`) on the Excel writer's stored ZIP. Tests fail when the
  document is stale or an entry names a command or module Huntsman lacks.
- `huntsman-recon radar --help` now documents `radar track`, which it omitted.
