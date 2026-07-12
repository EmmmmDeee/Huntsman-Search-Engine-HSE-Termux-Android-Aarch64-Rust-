import { API } from '/static/js/api.js';
import { $, $$, attr, esc, kindPill, toast } from '/static/js/helpers.js';
import { S } from '/static/js/state.js';
import { clearEnginesTimer } from '/static/js/timers.js';

export async function renderEngines(v){
  let health, toggles, scraperHealth;
  try {
    [health, toggles, scraperHealth] = await Promise.all([
      API.engines(), API.togglesGet(),
      API.scraperHealth().catch(()=>null), // best-effort — a stale/empty DB must not blank the whole page
    ]);
  }
  catch(e){ v.innerHTML = `<div class="alert alert-danger"><strong>Could not load engine liveness.</strong> ${esc(e.message)}</div>`; return; }
  const when = health.checked_at ? new Date(health.checked_at*1000).toLocaleString() : '—';
  // Probe results for currently-enabled engines, keyed by engine name.
  const probed = {};
  (health.engines||[]).forEach(e=>{ probed[e.engine] = e; });
  // Full roster (enabled + disabled) from the toggle catalogue; fall back to the
  // probed list if the catalogue is somehow unavailable.
  const grp = (toggles.groups||[]).find(g=>g.group==='engines');
  let engines = (grp ? grp.toggles.slice() : (health.engines||[]).map(e=>({key:'engine.'+e.engine, name:e.engine, enabled:true})));
  engines.sort((a,b)=>a.name.localeCompare(b.name));
  // Tally from the merged roster (not health.up/blocked/down) so the cards stay
  // consistent with the rows the instant a toggle flips — the cached sweep can
  // lag a just-disabled engine until the next background probe.
  const cnt = {up:0, blocked:0, down:0, disabled:0, pending:0};
  const dot = st => {
    const c = st==='up' ? '#3c763d' : (st==='blocked' ? '#8a6d3b'
            : (st==='disabled'||st==='pending') ? '#777' : '#a94442');
    return `<span style="color:${c};font-weight:600">&#9679;&nbsp;${esc(st)}</span>`;
  };
  const rows = engines.map(en=>{
    const p = probed[en.name];
    let status, latency, results;
    let detail='';
    if (!en.enabled){ status='disabled'; latency='—'; results='—'; }
    else if (p){ status=p.status; latency=esc(String(p.latency_ms))+' ms'; results=esc(String(p.results)); detail=esc(p.detail||''); }
    else { status='pending'; latency='—'; results='—'; }   // enabled, awaiting next sweep
    cnt[status] = (cnt[status]||0) + 1;
    const btn = en.enabled
      ? `<button class="btn btn-default btn-xs" data-tg="${attr(en.key)}" data-on="1" title="Disable ${attr(en.name)} for the probe and all scans">Disable</button>`
      : `<button class="btn btn-success btn-xs" data-tg="${attr(en.key)}" data-on="0" title="Re-enable ${attr(en.name)}">Enable</button>`;
    return `<tr${en.enabled?'':' class="text-muted"'}>
      <td><b>${esc(en.name)}</b></td>
      <td>${dot(status)}</td>
      <td class="text-right">${latency}</td>
      <td class="text-right">${results}</td>
      <td style="color:var(--text-dim);font-size:12px">${detail}</td>
      <td class="text-right">${btn}</td>
    </tr>`;
  }).join('');
  v.innerHTML = `
    <div class="page-header" style="margin-top:0;border-bottom:1px solid #eee;padding-bottom:8px">
      <h3 style="margin:0"><i class="glyphicon glyphicon-search"></i>&nbsp;Search-engine liveness
        <button class="btn btn-default btn-sm pull-right" onclick="refreshEngines()"><i class="glyphicon glyphicon-refresh"></i>&nbsp;Refresh</button>
      </h3>
    </div>
    <div class="row">
      <div class="col-md-3 col-sm-6 col-xs-6"><div class="stat-card"><div class="lab">Up</div><div class="val" style="color:var(--success)">${cnt.up}</div></div></div>
      <div class="col-md-3 col-sm-6 col-xs-6"><div class="stat-card"><div class="lab">Blocked</div><div class="val" style="color:var(--warning)">${cnt.blocked}</div></div></div>
      <div class="col-md-3 col-sm-6 col-xs-6"><div class="stat-card"><div class="lab">Down</div><div class="val" style="color:var(--danger)">${cnt.down}</div></div></div>
      <div class="col-md-3 col-sm-6 col-xs-6"><div class="stat-card"><div class="lab">Disabled</div><div class="val" style="color:var(--text-dim)">${cnt.disabled}</div></div></div>
    </div>
    <p class="text-muted" style="margin-top:8px">Free, keyless engines — probed at startup and on a periodic cycle. Last sweep: ${esc(when)}. Auto-refreshes every 30&nbsp;s. Disable a noisy/blocked engine inline — it's then skipped by the probe and every scan (manage all toggles under <a href="#/opts">Settings</a>).</p>
    <div class="table-responsive"><table class="table table-striped table-condensed">
      <thead><tr><th>Engine</th><th>Status</th><th class="text-right">Latency</th><th class="text-right">Results</th><th>Diagnosis</th><th class="text-right">Action</th></tr></thead>
      <tbody>${rows || '<tr><td colspan="6" class="text-center text-muted">No engines</td></tr>'}</tbody>
    </table></div>
    <div id="scraper-health-host"></div>
    <div id="modgraph-host"></div>`;
  wireEngineToggles();
  renderScraperHealth($('#scraper-health-host'), scraperHealth);
  renderModuleGraph($('#modgraph-host'));
  clearEnginesTimer();
  S.enginesTimer = setInterval(refreshEngines, 30000);
}

/* Per-source scraper health (T2.7 / SOL-HEALTH-SIGNAL): the au_people /
   au_electoral / username_search / search_engines family parse churning
   third-party HTML, so a source can silently break (layout change, endpoint
   retirement) with no operator-visible signal beyond re-reading verbose
   per-scan logs. GET /api/v1/health/scrapers surfaces the same cross-scan
   failure-streak signal `hse doctor` already prints, so the web operator
   gets it too without dropping to a shell. */
export function renderScraperHealth(host, data){
  if (!host) return;
  if (!data){
    host.innerHTML = `<p class="text-muted" style="margin-top:18px">Scraper health unavailable (could not read the event log).</p>`;
    return;
  }
  const drifted = data.drifted || [];
  const rows = drifted.map(d=>{
    const lastOk = d.last_success_at ? new Date(d.last_success_at*1000).toLocaleString() : 'no success in this window';
    return `<tr>
      <td><b>${esc(d.module)}</b></td>
      <td class="text-right"><span class="status-pill s-failed">${esc(String(d.consecutive_failures))} failures</span></td>
      <td>${esc(lastOk)}</td>
      <td style="color:var(--text-dim);font-size:12px">${esc(d.last_error||'')}</td>
    </tr>`;
  }).join('');
  host.innerHTML = `
    <div class="page-header" style="margin-top:26px;border-bottom:1px solid #eee;padding-bottom:8px">
      <h3 style="margin:0"><i class="glyphicon glyphicon-flash"></i>&nbsp;Scraper health
        <small class="text-muted">${data.tracked||0} source(s) tracked over ${data.events_checked||0} recent outcome event(s)</small></h3>
    </div>
    <p class="text-muted">Cross-scan failure streaks for the HTML-parsing modules (au_people, au_electoral, username_search, search_engines, …) — a source flagged here has failed on its last ${esc(String(data.drifted_threshold||3))}+ dispatches with no success in between, across ALL recent scans, not just this one.</p>
    ${drifted.length
      ? `<div class="table-responsive"><table class="table table-striped table-condensed">
           <thead><tr><th>Module</th><th class="text-right">Streak</th><th>Last success</th><th>Last error</th></tr></thead>
           <tbody>${rows}</tbody>
         </table></div>`
      : `<div class="empty-state"><h3>No drifted sources</h3><p>Every tracked module has succeeded recently.</p></div>`}`;
}

/* Module capability map (GET /modules/graph): for every seed/target kind, how
   many modules consume it and the resulting graph richness — i.e. what an
   operator can expect to discover from each kind of seed before launching a
   scan. The graph is static for a build, so it's fetched once and cached. */
export async function renderModuleGraph(host){
  if (!host) return;
  try {
    if (!S.modGraph) S.modGraph = await API.modulesGraph();
  } catch(e){ host.innerHTML = `<p class="text-muted" style="margin-top:18px">Capability map unavailable: ${esc(e.message)}</p>`; return; }
  const g = S.modGraph;
  const kinds = (g.kinds||[]).filter(k=>k.module_count>0);
  const rows = kinds.map(k=>`<tr style="cursor:pointer" onclick="this.nextElementSibling.style.display=this.nextElementSibling.style.display==='none'?'':'none'">
      <td>${kindPill(k.kind)}</td>
      <td class="text-right"><code>${k.module_count}</code></td>
      <td class="text-right"><code>${(k.richness!=null?Number(k.richness):0).toFixed(2)}</code></td>
      <td class="text-muted" style="font-size:11px">${(k.modules||[]).slice(0,6).map(esc).join(', ')}${(k.modules||[]).length>6?` +${k.modules.length-6}`:''}</td>
    </tr>
    <tr style="display:none"><td colspan="4" class="grp-row"><div style="padding:6px 4px">
      <b>${esc(k.kind)}</b> is consumed by ${(k.modules||[]).length} module(s): ${(k.modules||[]).map(m=>`<span class="tag">${esc(m)}</span>`).join(' ')}</div></td></tr>`).join('');
  host.innerHTML = `
    <div class="page-header" style="margin-top:26px;border-bottom:1px solid #eee;padding-bottom:8px">
      <h3 style="margin:0"><i class="glyphicon glyphicon-random"></i>&nbsp;Module capability map
        <small class="text-muted">${g.module_count||0} modules · produces ${(g.produced_kinds||[]).length} entity kinds</small></h3>
    </div>
    <p class="text-muted">What each seed type can discover — module coverage and graph richness per target kind. Tap a row for the full module list.</p>
    <div class="table-responsive"><table class="table table-striped table-condensed">
      <thead><tr><th>Seed / target kind</th><th class="text-right">Modules</th><th class="text-right">Richness</th><th>Top modules</th></tr></thead>
      <tbody>${rows || '<tr><td colspan="4" class="text-center text-muted">No capability data</td></tr>'}</tbody>
    </table></div>`;
}
/* Inline Enable/Disable on each liveness row → PUT /settings/toggles, then
   re-render so the row (and the Disabled tally) reflects the new state. */
export function wireEngineToggles(){
  $$('button[data-tg]').forEach(b=>b.addEventListener('click', async ()=>{
    const key = b.dataset.tg, next = b.dataset.on !== '1';
    b.disabled = true;
    try {
      await API.togglesPut({key, enabled: next});
      toast(`${key} ${next?'on':'off'}`);
      await renderEngines($('#view'));
    } catch(e){ alertify.error(e.message); b.disabled = false; }
  }));
}
export async function refreshEngines(){
  if (S.route && S.route.name === 'engines') { await renderEngines($('#view')); }
  else { clearEnginesTimer(); }
}
