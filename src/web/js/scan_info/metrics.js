import { API } from '/static/js/api.js';
import { renderMetricsHtml } from '/static/hse_wasm_ui.js';

/* ── Scan-quality dashboard — objective per-scan telemetry (GET /scans/{id}/metrics):
   how much corroborated intelligence the scan formed. A nicety, so it fails quietly.
   The HTML templating lives in wasm-ui/src/scan_info/metrics.rs. ── */
export async function renderMetrics(host, id){
  try { host.innerHTML = renderMetricsHtml(await API.metrics(id)); }
  catch(e){ host.innerHTML = ''; }
}

