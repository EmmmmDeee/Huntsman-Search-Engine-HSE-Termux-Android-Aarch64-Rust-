import { API } from '/static/js/api.js';
import { renderBenchmarkHtml } from '/static/hse_wasm_ui.js';

/* ── Benchmark scorecard — HTTP twin of `hse benchmark`. /scans/{id}/benchmark.
      The HTML templating lives in wasm-ui/src/scan_info/benchmark.rs. ── */
export async function renderBenchmark(host, id){
  try { host.innerHTML = renderBenchmarkHtml(await API.benchmark(id)); }
  catch(e){ host.innerHTML = ''; }
}

