import { API } from '/static/js/api.js';
import { esc } from '/static/js/helpers.js';
import { S } from '/static/js/state.js';
import { renderExposureHtml, renderProviderCoverageHtml, renderScanSettingsHtml } from '/static/hse_wasm_ui.js';

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

/* ── Provider Coverage ──
   What the scan managed to ASK, not what it found. Every other panel in the
   console shows findings, and without this one a thin result is ambiguous: a
   sweep that queried everything and found little is a real negative, while a
   sweep where a third of its providers broke or were never configured is not,
   and the two look identical everywhere else. On a Termux/Android device this
   console is the primary interface, so the distinction has to be visible here
   rather than only in `hse export`. Fetched separately so a failure degrades to
   a quiet notice instead of taking the Summary down with it. The HTML
   templating lives in wasm-ui/src/scan_info/coverage.rs, over the same
   core::intelligence derivation report.json and the CLI dossier carry. */
export async function renderProviderCoverage(host, scanId){
  if (!host) return;
  let c = null;
  try { c = await API.coverage(scanId); }
  catch { host.innerHTML = ''; return; }   // never block the surrounding view
  try { host.innerHTML = renderProviderCoverageHtml(c); }
  catch { host.innerHTML = ''; }
}
