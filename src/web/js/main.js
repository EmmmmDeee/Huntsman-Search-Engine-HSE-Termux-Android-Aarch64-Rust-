/* ════════════════════════════════════════════════════════════════════════
 * Huntsman Search Engine — SPA entry point.
 *
 * Wires the CSRF fetch guard, the hash router, the top-level page dispatcher,
 * and the startup bootstrap. Also re-exposes on `window` every function that
 * a rendered template's inline HTML attribute (`onclick="foo()"`, etc.)
 * invokes by name — those strings are parsed by the browser as global lookups
 * at click-time, which ES module scope does not provide automatically.
 *
 * Layout patterns and component vocabulary (panels, nav-tabs, tables,
 * btn-danger "Run Scan Now", "By Use Case / By Required Data / By Module"
 * wizard tabs) mirror SpiderFoot's templates so operators get the same
 * mental model. The state machine, router, and API client are HSE-specific
 * and talk to /api/v1/* (see src/api/routes/mod.rs).
 * ═══════════════════════════════════════════════════════════════════════ */
import { $, $$, esc } from '/static/js/helpers.js';
import { API } from '/static/js/api.js';
import { S } from '/static/js/state.js';
import { parseHash, nav } from '/static/js/router.js';
import { clearLiveTimer, clearScanTimer, clearEnginesTimer } from '/static/js/timers.js';
import { applyTheme } from '/static/js/theme.js';
import { renderDash } from '/static/js/views/dash.js';
import { renderScans } from '/static/js/views/scans.js';
import { renderDiff } from '/static/js/views/diff.js';
import {
  renderNewScan, previewPlan, uploadDossier, autoInvestigate, autoQueuePreview,
  autoSweepGo, submitWizard, submitBatch,
} from '/static/js/views/new_scan.js';
import { renderScanInfo } from '/static/js/scan_info/index.js';
import { closeSse, closeLiveSse } from '/static/js/scan_info/log.js';
import { entityPivot, toggleDetail } from '/static/js/scan_info/browse.js';
import { toggleCorrMembers, pivotToEntity } from '/static/js/scan_info/correlations.js';
import { renderOpts, pollUpdateBadge } from '/static/js/views/opts.js';
import { globalSearch, renderSearch } from '/static/js/views/search.js';
import { renderEngines, refreshEngines } from '/static/js/views/engines.js';
import { renderLive, closeLiveStream } from '/static/js/views/live.js';
import { initCompatShims, initNavbarToggle, initModals } from '/static/js/ui.js';

/* Installed at module-load time (before any view can run) so the
 * `alertify.*`/`jQuery(...).tablesorter(...)` call sites scattered across
 * the view files — unchanged from when they targeted the real vendored
 * libraries — keep working against the vanilla-JS replacements. */
initCompatShims();

/* CSRF: the API rejects any state-changing request (POST/PUT/DELETE/PATCH) that
 * lacks the X-HSE-CSRF header — a custom header a cross-site page can't set on a
 * CORS simple request without triggering a preflight the API's strict CORS
 * rejects. We're same-origin, so inject it transparently on every mutating fetch
 * (rather than threading it through each call site). Handles both plain-object
 * and Headers-instance init.headers. */
(function(){
  var _fetch = window.fetch;
  window.fetch = function(input, init){
    init = init || {};
    var m = (init.method || (input && typeof input !== 'string' && input.method) || 'GET').toUpperCase();
    if (m === 'POST' || m === 'PUT' || m === 'DELETE' || m === 'PATCH') {
      if (init.headers instanceof Headers) { init.headers.set('X-HSE-CSRF', '1'); }
      else { init.headers = Object.assign({}, init.headers, {'X-HSE-CSRF': '1'}); }
    }
    return _fetch.call(this, input, init);
  };
})();

/* ─── Top-level dispatcher ─── */
export async function render(){
  closeSse();
  closeLiveSse();
  clearLiveTimer();
  clearScanTimer();
  clearEnginesTimer();
  S.route = parseHash();
  $$('#main-navbar-collapse li').forEach(li=>li.classList.remove('active'));
  const navMap = {dash:'nav-dash', scans:'nav-scans', live:'nav-live', newscan:'nav-newscan', opts:'nav-opts', scaninfo:'nav-scans', engines:'nav-engines'};
  const navEl = $('#'+navMap[S.route.name]); if (navEl) navEl.classList.add('active');

  const v = $('#view');
  v.innerHTML = '<div class="empty-state"><h3>Loading…</h3></div>';
  try {
    if (S.route.name==='dash')     return await renderDash(v);
    if (S.route.name==='scans')    return await renderScans(v);
    if (S.route.name==='newscan')  return await renderNewScan(v);
    if (S.route.name==='scaninfo') return await renderScanInfo(v);
    if (S.route.name==='opts')     return await renderOpts(v);
    if (S.route.name==='search')   return await renderSearch(v);
    if (S.route.name==='live')     return await renderLive(v);
    if (S.route.name==='engines')  return await renderEngines(v);
    if (S.route.name==='diff')     return await renderDiff(v);
  } catch(e){
    v.innerHTML = `<div class="alert alert-danger"><strong>Error.</strong> ${esc(e.message)}
                   <button class="btn btn-default btn-sm" style="margin-left:12px" onclick="render()">Retry</button></div>`;
  }
}
window.addEventListener('hashchange', ()=>render());

/* Rendered templates reference these by name from inline HTML attributes
 * (`onclick="foo()"`), which the browser resolves as a global lookup at
 * click-time — module-scope top-level bindings are not implicitly global,
 * so each must be re-attached to `window` explicitly. */
Object.assign(window, {
  render, nav, globalSearch, previewPlan, uploadDossier, autoInvestigate,
  autoQueuePreview, autoSweepGo, submitWizard, submitBatch, entityPivot,
  toggleDetail, toggleCorrMembers, pivotToEntity, refreshEngines,
  closeLiveStream,
});

/* ═══════════ Bootstrap ═══════════ */
(async function init(){
  applyTheme();
  initNavbarToggle();
  initModals();
  if (typeof alertify !== 'undefined') alertify.set('notifier','position','top-right');
  try {
    const h = await API.health();
    S.health = h; S.version = h.version || '?';
    $('#ver').textContent = S.version;
    $('#ver2').textContent = S.version;
  } catch {
    $('#ver').textContent = 'offline';
  }
  // Populate the update badge in the background — never blocks first render.
  pollUpdateBadge();
  await render();
})();
