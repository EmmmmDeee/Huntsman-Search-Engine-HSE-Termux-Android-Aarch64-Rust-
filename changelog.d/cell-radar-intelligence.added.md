- `radar cells`, `GET /api/radar/cells` and the Radar tab now keep what Android's telephony API
  reports beyond the cell identity, as rootless survey apps (ICdetection, Network Survey, AIMSICD)
  do: each cell's PCI or WCDMA scrambling code and bands; the eNodeB and sector of an LTE cell,
  or the RNC and cell of a WCDMA one, so sectors of one site share a site ID; and the LTE serving
  cell's timing advance as a 78.125 m distance band. Neighbours Android measures by PCI only were
  rejected as incomplete and are now kept as neighbours. Each read is audited for a GSM serving
  cell while the same operator's 4G/5G is heard, eNodeB sectors in different tracking areas, and
  a registered cell without neighbours. These are shown as indicators to corroborate, never as
  IMSI-catcher detections.
