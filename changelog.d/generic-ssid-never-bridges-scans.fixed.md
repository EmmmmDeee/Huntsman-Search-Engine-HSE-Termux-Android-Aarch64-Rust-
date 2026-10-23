- Saved-scan correlation no longer links two scans because both saw the same generic Wi-Fi name.
  An SSID such as `xfinitywifi`, `NETGEAR-Guest` or `Free Public WiFi` is broadcast by countless
  unrelated networks, so it never bridges scans; a distinctive SSID still does. The generic-SSID
  rule, which nothing called, moves from `rf` to `value_syntax` so the correlation layer can use it.
