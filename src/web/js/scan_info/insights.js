import { $, $$, esc } from '/static/js/helpers.js';
import { renderIdentities } from '/static/js/scan_info/identities.js';
import { renderTimeline } from '/static/js/scan_info/timeline.js';
import { renderCommunities } from '/static/js/scan_info/communities.js';
import { renderTrust } from '/static/js/scan_info/trust.js';
import { renderPivots } from '/static/js/scan_info/pivots.js';
import { renderGaps } from '/static/js/scan_info/gaps.js';
import { renderPathTool } from '/static/js/scan_info/path.js';
import { renderDuplicates } from '/static/js/scan_info/duplicates.js';
import { renderBenchmark } from '/static/js/scan_info/benchmark.js';
import { renderAudit } from '/static/js/scan_info/audit.js';
import { renderScanSettings } from '/static/js/scan_info/info.js';

/* ── Insights tab — the deeper analytical lenses, one at a time.

   These were previously stacked into the single "Report" scroll, so opening a
   scan fired ~10 extra API calls and produced a ~90-screen page. Here each lens
   is a sub-tab that renders (and fetches) ONLY when selected — lazy, so the
   Insights tab costs exactly one fetch per lens you actually look at. No
   capability is removed; it is reorganised from a wall into a drawer. ── */
const LENSES = [
  { key:'identities',  label:'Identities',   fn:(h,id)=>renderIdentities(h,id) },
  { key:'timeline',    label:'Timeline',     fn:(h,id)=>renderTimeline(h,id) },
  { key:'communities', label:'Communities',  fn:(h,id)=>renderCommunities(h,id) },
  { key:'trust',       label:'Trust',        fn:(h,id)=>renderTrust(h,id) },
  { key:'pivots',      label:'Pivots',       fn:(h,id)=>renderPivots(h,id) },
  { key:'gaps',        label:'Gaps',         fn:(h,id)=>renderGaps(h,id) },
  { key:'path',        label:'Path',         fn:(h,id)=>renderPathTool(h,id) },
  { key:'duplicates',  label:'Duplicates',   fn:(h,id)=>renderDuplicates(h,id) },
  { key:'benchmark',   label:'Benchmark',    fn:(h,id)=>renderBenchmark(h,id) },
  { key:'audit',       label:'Audit',        fn:(h,id)=>renderAudit(h,id) },
  { key:'settings',    label:'Scan Settings',fn:(h)=>renderScanSettings(h) },
];

export function renderInsights(host, id, sub){
  const start = LENSES.find(l=>l.key===sub) ? sub : LENSES[0].key;
  host.innerHTML = `
    <div class="insights-nav" role="tablist">
      ${LENSES.map(l=>`<button type="button" class="insights-lens${l.key===start?' active':''}" data-lens="${esc(l.key)}">${esc(l.label)}</button>`).join('')}
    </div>
    <div id="insights-body" style="margin-top:14px"></div>`;
  // Scope DOM queries to host so multiple concurrent views don't interfere.
  const body = host.querySelector('#insights-body');
  const lensButtons = host.querySelectorAll('.insights-lens');
  const show = async key=>{
    const lens = LENSES.find(l=>l.key===key) || LENSES[0];
    lensButtons.forEach(b=>b.classList.toggle('active', b.dataset.lens===lens.key));
    body.innerHTML = '<div class="text-muted" style="padding:10px">Loading…</div>';
    // Lazy: render (and fetch) only the selected lens. Catch both sync and async errors.
    try {
      await lens.fn(body, id);
    } catch(e){
      body.innerHTML = `<div class="empty-state"><h3>Could not render ${esc(lens.label)}</h3><p class="text-muted">${esc(e.message||String(e))}</p></div>`;
    }
  };
  lensButtons.forEach(b=>b.addEventListener('click', ()=>show(b.dataset.lens)));
  show(start);
}
