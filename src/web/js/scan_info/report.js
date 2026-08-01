import { $, esc } from '/static/js/helpers.js';
import { nav } from '/static/js/router.js';
import { S } from '/static/js/state.js';
import { renderExposure } from '/static/js/scan_info/info.js';
import { renderMetrics } from '/static/js/scan_info/metrics.js';
import { renderNetwork } from '/static/js/scan_info/network.js';
import { renderLocation } from '/static/js/scan_info/location.js';
import { renderLeads } from '/static/js/scan_info/leads.js';

/* ── Summary tab — the at-a-glance scan verdict, SpiderFoot-style.
   Leads with the calibrated Exposure Index (the single headline number the CLI
   dossier opens with), then the scan-quality metrics, the subject's network,
   residency, and recommended next pivots. Correlations are a COUNT + a jump
   link here — they get their own tab because a large scan produces tens of
   thousands of pixels of them. The deeper analytical lenses (identities,
   timeline, communities, trust, pivots, gaps, duplicates, benchmark, audit,
   scan settings) live under the Insights tab, each loaded on demand.

   This replaces the former "Report" tab, which stacked ~15 sections into a
   single ~90-screen scroll and fired ~17 API calls on open. ── */
export async function renderSummary(host, id, scan){
  const corrN = S.correlations.length;
  host.innerHTML = `
    <div id="sum-exposure"></div>
    <div id="sum-metrics"  style="margin-top:18px"></div>
    <div id="sum-network"  style="margin-top:18px"></div>
    <div id="sum-location" style="margin-top:18px"></div>
    <div id="sum-leads"    style="margin-top:18px"></div>
    <div id="sum-corr"     style="margin-top:18px"></div>`;
  // Each renderer owns its own async fetch; the Summary only composes the few
  // highest-value ones (5 fetches, not the old ~17).
  renderExposure($('#sum-exposure'), id);
  renderMetrics($('#sum-metrics'), id);
  renderNetwork($('#sum-network'), id);
  renderLocation($('#sum-location'), id);
  renderLeads($('#sum-leads'), id);

  const co = $('#sum-corr');
  if (co){
    co.innerHTML = corrN
      ? `<div class="callout callout-corr">
           <b>${corrN}</b> correlation${corrN===1?'':'s'} fired across the entities —
           multi-source breach clusters, infrastructure consensus, and other
           high-signal aggregations.
           <a href="#" data-goto-corr>Open the Correlations tab &rarr;</a>
         </div>`
      : `<div class="callout"><span class="text-muted">No correlations fired for this scan.</span></div>`;
    co.querySelector('[data-goto-corr]')?.addEventListener('click', e=>{
      e.preventDefault();
      nav(`#/scaninfo?id=${encodeURIComponent(id)}&tab=corr`);
    });
  }
}
