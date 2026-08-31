import { API } from '/static/js/api.js';
import { esc } from '/static/js/helpers.js';
import { S } from '/static/js/state.js';
import { renderExposureHtml, renderScanSettingsHtml } from '/static/hse_wasm_ui.js';

/* ── Scan Settings — the scan's configuration + run metadata. Surfaced as the
   "Scan Settings" lens under Insights (SpiderFoot's Scan Settings tab), and
   readable from S.scan so it fits the (host) lens signature. The HTML
   templating lives in wasm-ui/src/scan_info/info.rs. ── */
export function renderScanSettings(host, scan){
  scan = scan || S.scan || {};
  host.innerHTML = renderScanSettingsHtml(scan);
}

/* ── Exposure Index ──
   The calibrated 0–100 headline verdict with its per-signal breakdown. The CLI
   dossier and the debug bundle both OPEN with this; the web console — the
   primary interface on a Termux/Android device — must too, so the Summary tab
   leads with it. Fetched separately so a failure here degrades to a quiet
   notice instead of taking the surrounding view down with it. Writes into
   `host` directly so it can headline the Summary or stand alone. The HTML
   templating lives in wasm-ui/src/scan_info/info.rs. */
export async function renderExposure(host, scanId){
  if (!host) return;
  let x = null;
  try { x = await API.exposure(scanId); }
  catch { host.innerHTML = ''; return; }   // never block the surrounding view
  try { host.innerHTML = renderExposureHtml(x); }
  catch { host.innerHTML = ''; }
}
