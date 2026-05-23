# Huntsman Search Engine (Termux Android aarch64 Rust)

A rootless Termux-first OSINT signal viewer written in modern Rust (edition 2024).

## Features

- Chrome-accessible web UI (`http://127.0.0.1:8080`)
- Live mobile signal polling from Termux APIs:
  - `termux-battery-status`
  - `termux-location`
  - `termux-wifi-connectioninfo`
  - `termux-wifi-scaninfo`
  - `termux-telephony-deviceinfo`
- Optional **Live OSINT** mode (user-controlled toggle) that continuously extracts indicators (for example, IPs) from detected runtime/mobile signals.

## Run from Termux (no root)

```bash
pkg update
pkg install rust termux-api
cargo run --release
```

Then open Chrome on the same device and visit:

- `http://127.0.0.1:8080`

> Tip: grant Android permissions to Termux (Location, etc.) so Termux API commands can return data.
