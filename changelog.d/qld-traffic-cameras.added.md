- `traffic-cameras [--district NAME] [--locality NAME] [--limit N] [--reconcile]` reads the
  Queensland QLDTraffic webcam catalogue once: each camera's location, direction and JPEG URL,
  without downloading an image or claiming the image is current. `--reconcile` also reads TMR's
  state-road camera GIS layer and lists the camera IDs both, or only one, of them carry, the
  shared IDs whose positions differ by more than 100 metres or whose directions differ, and
  nearby cameras with different IDs as review candidates, never identities. Both catalogues come
  from the same publisher, so agreement is consistency, not corroboration. A partly rejected
  catalogue, or a GIS reply capped by the layer's transfer limit, gives no reconciliation rather
  than invented differences. The webcam feed needs a key in the new `HUNTSMAN_QLDTRAFFIC_KEY`
  slot (the API specification prints a shared public one); without it nothing is sent and the
  command exits 66. CLI only: there is no web route or web UI panel.
