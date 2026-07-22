import { API } from '/static/js/api.js';
import { $, $$, attr, esc, fmtDate, toast } from '/static/js/helpers.js';
import { S } from '/static/js/state.js';
import { render } from '/static/js/main.js';

/* ═══════════ Page: OPTS / Settings (#/opts) ═══════════ */
export async function renderOpts(v){
  const [data, toggles] = await Promise.all([API.keysGet(), API.togglesGet()]);
  S.settings = data;
  // The key pool is loopback-only and may be empty / forbidden — never let it
  // block the rest of Settings from rendering.
  let pool = null;
  try { pool = await API.poolGet(); } catch { pool = null; }
  // Best-effort operator diagnostics (loopback-only; never block Settings).
  let kstatus = null, kpatterns = null, khealth = null;
  try { kstatus = await API.keysStatus(); } catch { kstatus = null; }
  try { kpatterns = await API.keysPatterns(); } catch { kpatterns = null; }
  // Observed dead-key diagnosis (configured keys the upstream is rejecting).
  // Best-effort + loopback-only, like the sibling diagnostics — never blocks Settings.
  try { khealth = await API.keysHealth(); } catch { khealth = null; }
  // Cell-tower DB status is ungated but still best-effort — a corrupt/locked
  // DB file must never block the rest of Settings from rendering.
  let cells = null;
  try { cells = await API.cellsStatus(); } catch { cells = null; }

  v.innerHTML = `
    <h2>Settings</h2>
    <hr style="margin:8px 0 14px 0">

    <div class="panel panel-default">
      <div class="panel-heading">
        <b>Module API keys</b>
        <div class="pull-right">
          ${data.write_enabled
            ? '<span class="label label-warning">write enabled (loopback only)</span>'
            : '<span class="label label-default">read-only</span>'}
        </div>
      </div>
      <div class="panel-body">
        <p class="text-muted" style="font-size:12px">
          ${data.write_enabled
            ? `Edits write to <code>${esc(data.env_path)}</code> at <code>mode 0600</code>. Comments and non-<code>HUNTSMAN_*</code> lines are preserved. Writes require a loopback peer.`
            : `Write access is disabled (you launched with <code>hse serve --no-key-write</code>). Restart without that flag to edit keys here — editing is on by default, loopback-only.`}
        </p>
        <div id="keygrid">
          ${data.keys.map(k=>keyRow(k, data.write_enabled)).join('')}
        </div>
        ${data.write_enabled ? `
          <div style="margin-top:14px">
            <button class="btn btn-primary" id="k-save" disabled>Save changes</button>
            <span class="text-muted" id="k-pending" style="margin-left:10px"></span>
          </div>` : ''}
      </div>
    </div>

    ${deadKeysPanel(khealth)}
    ${acquisitionPanel(data.acquisition)}
    ${poolPanel(pool, data.write_enabled)}
    ${keysDiagPanel(kstatus, kpatterns)}

    <div class="panel panel-default">
      <div class="panel-heading"><b>Capability toggles</b>
        <span class="text-muted pull-right" style="font-size:12px">${toggles.count} switches · click to flip · persisted (loopback-only)</span>
      </div>
      <div class="panel-body">
        <p class="text-muted" style="font-size:12px">
          Universal toggleability (SpiderFoot-style): turn any feature, search
          engine or module on/off across <b>all</b> scans. Saved to
          <code>~/.huntsman/settings.json</code> — no restart. A disabled module
          is skipped at the scan gate (and shows in the summary's <code>skipped</code>
          count); a disabled engine is never queried.
        </p>
        <input id="tg-filter" type="text" class="form-control input-sm"
               placeholder="Filter by name… (e.g. yandex, wikidata, regional)"
               autocomplete="off" style="max-width:340px;margin-bottom:12px">
        ${(toggles.groups||[]).map(g=>`
          <div class="tg-group" data-group="${attr(g.group)}" style="margin-top:8px">
            <h5 style="margin:6px 0"><b>${esc(g.label)}</b>
              <span class="text-muted tg-count" style="font-weight:normal"></span></h5>
            <div class="tg-grid">${(g.toggles||[]).map(toggleChip).join('')}</div>
            <div class="tg-empty text-muted" style="display:none;font-size:12px">no matches in this group</div>
          </div>`).join('')}
      </div>
    </div>

    <div class="panel panel-default">
      <div class="panel-heading"><b>Diagnostics</b></div>
      <div class="panel-body">
        <p class="text-muted" style="font-size:12px">
          One click captures the engine's <b>entire</b> diagnostic state in a
          single self-diagnosing file &mdash; an auto-computed
          <b>DETECTED&nbsp;ISSUES</b> verdict, the environment fingerprint, the
          full self-test, live and cross-scan module / engine / scraper health,
          the recent-scan index (with each failed scan's error), the verbose
          log ring, and the source-file manifest. It is everything needed to
          repair HSE, organised for offline debugging. Loopback-only (it
          contains scan targets); secret-free (key names only, never values).
        </p>
        <p>
          <a class="btn btn-primary btn-sm" href="${API.debugBundleUrl()}" download>Download full diagnostic bundle</a>
          &nbsp;
          <button id="st-run" class="btn btn-default btn-sm">Run self-test</button>
          &nbsp;
          <a class="btn btn-link btn-sm" href="${API.logsUrl()}" download title="Just the raw TRACE log ring (a subset of the full bundle)">logs only</a>
          &nbsp;<span id="st-summary" class="text-muted" style="font-size:12px"></span>
        </p>
        <div id="st-results" style="margin-top:8px"></div>
      </div>
    </div>

    <div class="panel panel-default">
      <div class="panel-heading">
        <b>Software Update</b>
        <span id="upd-phase-label" style="float:right;font-size:12px"></span>
      </div>
      <div class="panel-body">
        <p class="text-muted" style="font-size:12px">
          Huntsman checks for upstream commits every 6&nbsp;h and applies them
          automatically when <code>feature.auto_update</code> is ON (the default).
          The binary restarts in-place — no data is lost. Manual trigger below.
        </p>
        <div id="upd-info" style="margin-bottom:10px;font-size:13px">
          <span class="text-muted">Loading update status…</span>
        </div>
        <button id="upd-trigger-btn" class="btn btn-primary btn-sm">Update Now</button>
        <span id="upd-trigger-msg" class="text-muted" style="margin-left:10px;font-size:12px"></span>
      </div>
    </div>

    ${cellsPanel(cells)}

    <div class="panel panel-default">
      <div class="panel-heading"><b>Server</b></div>
      <table class="table table-striped table-condensed" style="margin-bottom:0">
        <tbody>
          <tr><td style="width:220px;color:var(--text-muted)">Version</td><td><code>${esc(S.version||'?')}</code></td></tr>
          <tr><td style="color:var(--text-muted)">Health</td><td>${S.health ? '<span class="label label-success">ok</span>' : '<span class="label label-danger">unreachable</span>'}</td></tr>
          <tr><td style="color:var(--text-muted)">Env file path</td><td><code>${esc(data.env_path)}</code></td></tr>
          <tr><td style="color:var(--text-muted)">Known keys</td><td>${data.count}</td></tr>
        </tbody>
      </table>
    </div>
  `;

  if (data.write_enabled) wireKeyEditor();
  // Key-pool "Add" — previously CLI-only (`hse keys add`); the primary
  // HUNTSMAN_*_KEY env var is editable above, this is the separate rotation
  // POOL's own add, for a backup/second key per service.
  const poolAddBtn = $('#pool-add-btn');
  if (poolAddBtn) poolAddBtn.addEventListener('click', async()=>{
    const service = ($('#pool-add-service').value||'').trim();
    const key = ($('#pool-add-key').value||'').trim();
    const notes = ($('#pool-add-notes').value||'').trim();
    const msgEl = $('#pool-add-msg');
    if (!service || !key){ alertify.error('Service and key value are required'); return; }
    poolAddBtn.disabled = true;
    msgEl.textContent = 'Adding…';
    try {
      const r = await API.poolAdd({service, key, notes: notes||undefined});
      toast(r.status==='duplicate' ? 'Key already in pool' : `Key added to '${service}' pool`);
      renderOpts($('#view'));
    } catch(e){
      alertify.error(e.message);
      msgEl.textContent = '';
    } finally {
      poolAddBtn.disabled = false;
    }
  });
  // Key-pool revoke/rotate buttons (reference keys by non-secret id).
  $$('button[data-revoke]').forEach(b=>b.addEventListener('click', ()=>{
    const service = b.dataset.revoke, id = b.dataset.revokeId;
    alertify.confirm('Revoke key', `Revoke this ${service} key? It is kept for audit but never used again.`, async()=>{
      try { await API.poolRevoke({service, id}); toast('Key revoked'); renderOpts($('#view')); }
      catch(e){ alertify.error(e.message); }
    }, ()=>{});
  }));
  $$('button[data-rotate]').forEach(b=>b.addEventListener('click', ()=>{
    const service = b.dataset.rotate, id = b.dataset.rotateId;
    alertify.prompt(`Rotate ${service} key`, 'Paste the NEW key value. The old key is revoked (kept for audit) and the new one takes its place in the same environment.', '',
      async(_e, val)=>{
        const next = (val||'').trim();
        if (!next){ alertify.error('No new value entered'); return; }
        try { await API.poolRotate({service, id, new: next}); toast('Key rotated'); renderOpts($('#view')); }
        catch(e){ alertify.error(e.message); }
      }, ()=>{});
  }));
  wireToggles();
  wireToggleFilter();
  updateGroupCounts();
  wireDiagnostics();
  wireUpdate();
  wireCells();
}

/* ─── Capability toggles (universal toggleability) ─── */
export function toggleChip(t){
  const on = !!t.enabled;
  return `<button type="button" class="btn btn-xs ${on?'btn-success':'btn-default'} tg-chip"
    data-key="${attr(t.key)}" data-name="${attr(t.name)}" data-on="${on?1:0}" title="${attr(t.key)}">
    <i class="glyphicon glyphicon-${on?'ok':'remove'}"></i> ${esc(t.name)}</button>`;
}
export function wireToggles(){
  $$('.tg-chip').forEach(btn=>{
    btn.addEventListener('click', async ()=>{
      const key = btn.dataset.key;
      const next = btn.dataset.on !== '1';   // flip current state
      btn.disabled = true;
      try {
        await API.togglesPut({key, enabled: next});
        btn.dataset.on = next ? '1' : '0';
        btn.className = 'btn btn-xs '+(next?'btn-success':'btn-default')+' tg-chip';
        btn.innerHTML = `<i class="glyphicon glyphicon-${next?'ok':'remove'}"></i> ${esc(btn.dataset.name)}`;
        toast(`${key} ${next?'on':'off'}`);
        updateGroupCounts();   // keep the per-group "N on" tally live
      } catch(e){ alertify.error(e.message); }
      finally { btn.disabled = false; }
    });
  });
}
/* Per-group tally: "(total · N on)", or "(shown/total · N on)" while filtering. */
export function updateGroupCounts(){
  $$('.tg-group').forEach(grp=>{
    const chips = [...grp.querySelectorAll('.tg-chip')];
    const total = chips.length;
    const on    = chips.filter(c=>c.dataset.on==='1').length;
    const shown = chips.filter(c=>c.style.display!=='none').length;
    const span  = grp.querySelector('.tg-count');
    if (span) span.textContent = shown===total
      ? ` (${total} · ${on} on)`
      : ` (${shown}/${total} shown · ${on} on)`;
  });
}
/* Instant client-side filter across all groups (matches name or full key). */
export function wireToggleFilter(){
  const inp = $('#tg-filter');
  if (!inp) return;
  inp.addEventListener('input', ()=>{
    const q = inp.value.trim().toLowerCase();
    $$('.tg-chip').forEach(c=>{
      const hay = (c.dataset.name + ' ' + c.dataset.key).toLowerCase();
      c.style.display = (!q || hay.includes(q)) ? '' : 'none';
    });
    // Hide a whole group (and show its "no matches" note) when nothing matches.
    $$('.tg-group').forEach(grp=>{
      const anyShown = [...grp.querySelectorAll('.tg-chip')].some(c=>c.style.display!=='none');
      const empty = grp.querySelector('.tg-empty');
      if (empty) empty.style.display = (q && !anyShown) ? '' : 'none';
    });
    updateGroupCounts();
  });
}

/* ─── Diagnostics: on-demand self-test + verbose-log download ─── */
export function wireDiagnostics(){
  const btn = $('#st-run');
  if (!btn) return;
  btn.addEventListener('click', async ()=>{
    btn.disabled = true;
    const orig = btn.textContent;
    btn.textContent = 'Running…';
    $('#st-summary').textContent = '';
    $('#st-results').innerHTML = '';
    try {
      const r = await API.selftest();
      const pill = s => s==='pass' ? '<span class="label label-success">pass</span>'
                      : s==='warn' ? '<span class="label label-warning">warn</span>'
                      : '<span class="label label-danger">fail</span>';
      const rows = (r.checks||[]).map(c =>
        `<tr><td>${pill(c.status)}</td><td><code>${esc(c.name)}</code></td><td style="color:var(--text-dim)">${esc(c.detail)}</td></tr>`
      ).join('');
      $('#st-results').innerHTML =
        `<table class="table table-condensed" style="margin-bottom:0"><tbody>${rows}</tbody></table>`;
      const cls = r.ok ? 'label-success' : 'label-danger';
      $('#st-summary').innerHTML =
        `<span class="label ${cls}">${r.ok?'OK':'FAILED'}</span> `+
        `${r.passed}/${r.total} pass, ${r.warned} warn, ${r.failed} fail · ${r.elapsed_ms} ms`;
      (r.ok?toast:alertify.error)(r.ok?'Self-test passed':'Self-test reported failures');
    } catch(e){
      alertify.error('Self-test failed: '+e.message);
    } finally {
      btn.disabled = false;
      btn.textContent = orig;
    }
  });
}
/* ─── Update panel wiring (#/opts → Software Update section) ─── */
export function wireUpdate(){
  const infoEl     = $('#upd-info');
  const phaseEl    = $('#upd-phase-label');
  const btn        = $('#upd-trigger-btn');
  const msgEl      = $('#upd-trigger-msg');
  if (!btn) return;

  const PHASE_LABEL = {idle:'', checking:'checking…', applying:'applying…',
                       restarting:'restarting…', error:'error'};
  const PHASE_CLS   = {idle:'', checking:'label-info', applying:'label-warning',
                       restarting:'label-warning', error:'label-danger'};

  async function refreshStatus(){
    try {
      const s = await API.updateStatus();
      const p = s.phase || 'idle';
      phaseEl.innerHTML = p !== 'idle'
        ? `<span class="label ${PHASE_CLS[p]||'label-default'}">${esc(PHASE_LABEL[p]||p)}</span>`
        : '';

      let html = '';
      if (s.commits_behind == null){
        html = '<span class="text-muted">Not yet checked — next automatic check within 6&nbsp;h.</span>';
      } else if (s.commits_behind === 0){
        html = '<span class="text-success"><i class="glyphicon glyphicon-ok"></i>&nbsp;Up to date.</span>';
        const b = $('#update-badge'); if(b) b.style.display='none';
      } else {
        html = `<span class="text-warning"><b>${s.commits_behind}</b> update(s) available.</span>`;
        // The navbar badge is the proactive, unsolicited "notification" the
        // feature.update_notify toggle governs (its doc: "shows a badge and
        // notification when commits are available") — gate it here too, not
        // just in pollUpdateBadge(), since this same element is also set on
        // every Settings-page status refresh. The on-page status TEXT above
        // is left ungated: the operator navigated here specifically to check,
        // so it stays truthful regardless of the notify toggle.
        if (s.update_notify) {
          const b = $('#update-badge');
          if(b){ b.textContent = s.commits_behind; b.style.display=''; }
        }
      }
      if (s.last_checked){
        html += ` <span class="text-muted" style="font-size:11px">Last checked: ${esc(fmtDate(s.last_checked))}</span>`;
      }
      if (!s.auto_update){
        html += ' <span class="label label-default" style="font-size:10px;margin-left:4px">auto-update OFF</span>';
      }
      if (p === 'error'){
        html += ' <span class="text-danger" style="font-size:11px">(last attempt failed — retry below)</span>';
      }
      infoEl.innerHTML = html;
      btn.disabled = ['checking','applying','restarting'].includes(p);
      if (p === 'restarting') showRestartOverlay();
      return s;
    } catch(e){
      infoEl.innerHTML = `<span class="text-danger">Could not fetch update status: ${esc(e.message)}</span>`;
      return null;
    }
  }

  // Stored in shared state (not a closure local) so render()'s clearOptsTimers()
  // tears it down on navigation — otherwise navigating away mid-update leaks the
  // interval and re-entering #/opts spawns a duplicate.
  function startPoll(){
    if (S.optsUpdateTimer) return;
    S.optsUpdateTimer = setInterval(async()=>{
      const s = await refreshStatus();
      if (!s || ['idle','error'].includes(s.phase||'idle')){
        clearInterval(S.optsUpdateTimer); S.optsUpdateTimer = null;
      }
    }, 2500);
  }

  refreshStatus().then(s=>{
    if (s && ['checking','applying','restarting'].includes(s.phase||'idle')) startPoll();
  });

  btn.addEventListener('click', async()=>{
    btn.disabled = true;
    msgEl.textContent = 'Triggering update…';
    try {
      await API.updateTrigger();
      msgEl.textContent = 'Update in progress — tracking status…';
      startPoll();
    } catch(e){
      alertify.error('Update trigger failed: '+e.message);
      btn.disabled = false;
      msgEl.textContent = '';
    }
  });
}

/* Fullscreen overlay shown while Huntsman restarts after an update.
   Polls the health endpoint and reloads when the server responds. */
export function showRestartOverlay(){
  if ($('#restart-overlay')) return;
  const overlay = document.createElement('div');
  overlay.id = 'restart-overlay';
  overlay.style.cssText =
    'position:fixed;top:0;left:0;right:0;bottom:0;background:rgba(0,0,0,.75);'+
    'z-index:9999;display:flex;align-items:center;justify-content:center';
  overlay.innerHTML =
    '<div style="background:var(--bg-elevated);border-radius:6px;padding:32px 44px;text-align:center;max-width:400px">'+
    '<h3 style="margin:0 0 10px">Update Applied!</h3>'+
    '<p style="color:var(--text-muted);font-size:13px">Huntsman is restarting in the background.<br>'+
    'This page will reload automatically.</p>'+
    '<div class="progress" style="height:6px;margin:14px 0 0">'+
    '<div class="progress-bar progress-bar-striped active" style="width:100%"></div></div></div>';
  document.body.appendChild(overlay);
  const poll = setInterval(async()=>{
    try { await API.health(); clearInterval(poll); location.reload(); } catch {}
  }, 2500);
}

/* ─── Cell-tower DB panel (backs Live Signal Radar / cell_intel geolocation) ───
   Web-UI equivalent of `hse cells status|import|clear` — previously CLI-only
   despite backing web-reachable features, so a browser-only operator had no
   way to populate, refresh, or inspect it. `import` covers the download-by-
   country-code path (the CLI's --country flag, its first documented use
   case); raw local-file import remains a CLI-only power path. */
export function cellsPanel(status){
  if (!status){
    return `<div class="panel panel-default">
      <div class="panel-heading"><b>Cell Tower Database</b></div>
      <div class="panel-body"><p class="text-muted" style="font-size:12px">Could not load cell-tower database status.</p></div>
    </div>`;
  }
  const li = status.last_import;
  const byMcc = (status.by_mcc||[]).slice(0,10)
    .map(m=>`<span class="label label-default" style="margin-right:4px">MCC ${m.mcc}: ${m.count}</span>`).join(' ');
  return `<div class="panel panel-default">
    <div class="panel-heading">
      <b>Cell Tower Database</b>
      <span id="cells-phase-label" style="float:right;font-size:12px"></span>
    </div>
    <div class="panel-body">
      <p class="text-muted" style="font-size:12px">
        Local OpenCelliD cache used for cell-tower geolocation (Live Signal
        Radar, <code>cell_intel</code>). Download-by-country requires an
        OpenCelliD key set above.
      </p>
      <div id="cells-info" style="margin-bottom:10px;font-size:13px">
        ${status.present
          ? `<b>${status.total}</b> towers${byMcc?` &nbsp; ${byMcc}`:''}<br>
             ${li
               ? `<span class="text-muted" style="font-size:11px">Last import: <code>${esc(li.source_file)}</code> — ${li.row_count} rows, ${esc(fmtDate(li.imported_at))}</span>`
               : '<span class="text-muted" style="font-size:11px">No import history.</span>'}
             ${li && li.is_stale
               ? `<br><span class="label label-warning" style="white-space:normal">STALE — ${li.age_days}d since last import (&ge; ${li.stale_threshold_days}d). GEOINT cell-tower correlation is working from data that old; refresh below.</span>`
               : ''}`
          : '<span class="text-muted">Not populated — import below to get started.</span>'}
      </div>
      <div style="display:flex;gap:8px;align-items:center;flex-wrap:wrap">
        <input id="cells-country" type="text" class="form-control input-sm" style="max-width:160px"
               placeholder="AU, NZ, world, or MCC" autocomplete="off">
        <button id="cells-import-btn" class="btn btn-primary btn-sm">Import</button>
        <button id="cells-clear-btn" class="btn btn-default btn-sm"${status.present?'':' disabled'}>Clear</button>
        <span id="cells-msg" class="text-muted" style="font-size:12px"></span>
      </div>
    </div>
  </div>`;
}

export function wireCells(){
  const importBtn = $('#cells-import-btn');
  if (!importBtn) return;   // status fetch failed — nothing to wire
  const clearBtn  = $('#cells-clear-btn');
  const countryEl = $('#cells-country');
  const msgEl     = $('#cells-msg');
  const phaseEl   = $('#cells-phase-label');

  const PHASE_LABEL = {running:'importing…', error:'last import failed'};
  const PHASE_CLS   = {running:'label-warning', error:'label-danger'};

  // Shared-state timer (see the update poller above) so render()'s
  // clearOptsTimers() reaps it on navigation instead of leaking a duplicate.
  function startPoll(){
    if (S.optsCellsTimer) return;
    S.optsCellsTimer = setInterval(async()=>{
      try {
        const s = await API.cellsStatus();
        const p = s.import_phase || 'idle';
        phaseEl.innerHTML = p !== 'idle'
          ? `<span class="label ${PHASE_CLS[p]||'label-default'}">${esc(PHASE_LABEL[p]||p)}</span>` : '';
        if (p !== 'running'){
          clearInterval(S.optsCellsTimer); S.optsCellsTimer = null;
          if (p === 'error'){
            alertify.error('Cell DB import failed: '+(s.import_error||'unknown error'));
          } else {
            toast('Cell DB import complete');
          }
          renderOpts($('#view'));
        }
      } catch { clearInterval(S.optsCellsTimer); S.optsCellsTimer = null; }
    }, 2500);
  }

  importBtn.addEventListener('click', async()=>{
    const country = (countryEl.value||'').trim();
    if (!country){ alertify.error('Enter a country code, MCC, or "world"'); return; }
    importBtn.disabled = true;
    msgEl.textContent = 'Starting import…';
    try {
      await API.cellsImport(country);
      msgEl.textContent = 'Import in progress — tracking status…';
      startPoll();
    } catch(e){
      alertify.error('Import failed: '+e.message);
      msgEl.textContent = '';
    } finally {
      importBtn.disabled = false;
    }
  });

  if (clearBtn) clearBtn.addEventListener('click', ()=>{
    alertify.confirm('Clear cell tower database',
      'This permanently deletes all imported cell-tower data. Continue?',
      async()=>{
        try { await API.cellsClear(); toast('Cell tower database cleared'); renderOpts($('#view')); }
        catch(e){ alertify.error(e.message); }
      }, ()=>{});
  });
}

/* Lightweight navbar badge update — called at boot and not on every render.
   Gated on feature.update_notify: "update-available notification" is exactly
   this badge per the toggle's own doc, so an operator who turns it off must
   not keep seeing it merely because they reload the page. */
export async function pollUpdateBadge(){
  try {
    const s = await API.updateStatus();
    const b = $('#update-badge');
    if (!b) return;
    if (s.update_notify && s.commits_behind > 0){
      b.textContent = s.commits_behind;
      b.style.display = '';
    }
  } catch {}
}

export function keyRow(k, writeEnabled){
  return `<div class="keyrow" data-key="${attr(k.name)}">
    <div>
      <div class="kn">${esc(k.name)}</div>
      <div class="kd">${k.set ? '<span class="status-pill s-complete">set</span>' : '<span class="status-pill s-pending">unset</span>'}</div>
    </div>
    ${writeEnabled ? `
      <input type="password" class="form-control input-sm" placeholder="${k.set?'enter new value':'paste key'}" autocomplete="off" data-input>
      <div class="kactions">
        <button class="btn btn-default btn-sm" data-action="update">${k.set?'Update':'Set'}</button>
        ${k.set ? '<button class="btn btn-danger btn-sm" data-action="delete">Delete</button>' : ''}
      </div>
    ` : ''}
  </div>`;
}
/* Tier badge for the acquisition guidance. Multiplier keys are the highest-
   leverage (they discover infrastructure/identities that unlock MORE sources),
   so they get the most prominent colour. */
function acqTierBadge(tier){
  const m = {
    multiplier: ['label-success', 'multiplier — highest leverage'],
    expansion:  ['label-info',    'expansion'],
    terminal:   ['label-default', 'terminal'],
  };
  const [cls, txt] = m[tier] || ['label-default', tier || 'unranked'];
  return `<span class="label ${cls}">${esc(txt)}</span>`;
}
/* Turn the first URL inside a signup hint into a real (new-tab, no-opener) link,
   escaping the surrounding text. Everything is escaped — the hint strings are
   server-owned constants, but this stays XSS-safe regardless. */
function linkifyHint(hint){
  if (!hint) return '<span class="text-muted">no public signup page</span>';
  const m = hint.match(/https?:\/\/\S+/);
  if (!m) return esc(hint);
  const url = m[0];
  return `${esc(hint.slice(0, m.index))}<a href="${attr(url)}" target="_blank" rel="noopener noreferrer">${esc(url)}</a>${esc(hint.slice(m.index + url.length))}`;
}
/* Convex acquisition guidance: the unset keys the backend ranked highest-leverage
   first (multiplier > expansion > terminal), each with a free-signup link — the
   same ranking `hse doctor` prints, brought to the web UI so a Termux operator
   with no shell access can register the highest-value free keys directly. */
function acquisitionPanel(list){
  if (!Array.isArray(list) || !list.length) return '';
  const mult = list.filter(k=>k.tier==='multiplier').length;
  const rows = list.map(k=>`
    <tr>
      <td style="white-space:nowrap">${acqTierBadge(k.tier)}</td>
      <td><code>${esc(k.name)}</code></td>
      <td class="text-muted" style="font-size:12px">${linkifyHint(k.hint)}</td>
    </tr>`).join('');
  return `
    <div class="panel panel-default">
      <div class="panel-heading"><b>Acquire keys — ranked by leverage</b>
        <span class="text-muted pull-right" style="font-size:12px">${list.length} unset · ${mult} multiplier-tier</span>
      </div>
      <div class="panel-body">
        <p class="text-muted" style="font-size:12px">
          The single highest-value action for every future query is registering the
          free <b>multiplier-tier</b> keys first — each one multiplies coverage
          across all subsequent scans (they discover infrastructure and identities
          that unlock more sources), for a one-time near-zero cost. A module needing
          an unset key skips cleanly — it is never an error.
        </p>
        <div style="overflow-x:auto">
          <table class="table table-condensed" style="margin-bottom:0">
            <thead><tr><th>Tier</th><th>Key</th><th>Where to get it (mostly free)</th></tr></thead>
            <tbody>${rows}</tbody>
          </table>
        </div>
      </div>
    </div>`;
}
/* Dead-key panel: CONFIGURED keys the upstream is actively REJECTING, observed
   from real scan outcomes (GET /api/v1/keys/health). Shown ABOVE acquisition
   because renewing a rejected key you already registered is more urgent than
   getting a new one — a dead key silently wastes every query that touches it.
   Empty/absent → renders nothing (no false alarm). */
function deadKeysPanel(khealth){
  const rejected = (khealth && Array.isArray(khealth.rejected)) ? khealth.rejected : [];
  if (!rejected.length) return '';
  const rows = rejected.map(k=>`
    <tr>
      <td><code>${esc(k.env_var || k.module || '?')}</code></td>
      <td class="text-muted" style="font-size:12px">${esc(String(k.detail || '').slice(0, 200))}</td>
      <td class="text-muted" style="font-size:12px">${k.hint ? linkifyHint(k.hint) : '<span class="text-muted">—</span>'}</td>
    </tr>`).join('');
  return `
    <div class="panel panel-danger">
      <div class="panel-heading"><b>⚠ Configured keys being rejected</b>
        <span class="pull-right" style="font-size:12px">${rejected.length} dead</span>
      </div>
      <div class="panel-body">
        <p class="text-muted" style="font-size:12px">
          These keys ARE configured but the provider is rejecting them (bad,
          expired, or malformed credential) — every scan that touches them wastes
          the call and yields nothing. This is observed from real scan outcomes,
          not a synthetic test, so it won't flag a working key. Renew each below
          (edit it in <b>Module API keys</b> above), then re-run a scan to clear it.
        </p>
        <div style="overflow-x:auto">
          <table class="table table-condensed" style="margin-bottom:0">
            <thead><tr><th>Key</th><th>Upstream rejection</th><th>Renew at</th></tr></thead>
            <tbody>${rows}</tbody>
          </table>
        </div>
      </div>
    </div>`;
}
/* Key-pool panel: multi-key-per-service entries (discovered keys, imported pools)
   shown MASKED with status/environment, and a Revoke button per usable key. The
   plaintext never reaches the browser — keys are referenced by a non-secret id.
   Import/export and rotation live in the `hse keys` CLI (shell-access-gated). */
export function poolPanel(pool, writeEnabled){
  const hasKeys = pool && (pool.services||[]).length;
  const tierBadge = s => `<span class="status-pill s-${s==='revoked'?'failed':(s==='active'?'complete':'pending')}">${esc(s)}</span>`;
  const rows = hasKeys ? pool.services.map(svc=>`
    <tr><td colspan="5" class="grp-row" style="font-weight:600">${esc(svc.service)}</td></tr>
    ${svc.keys.map(k=>`<tr data-svc="${attr(svc.service)}" data-id="${attr(k.id)}">
      <td><code>${esc(k.masked)}</code></td>
      <td>${tierBadge(k.status)}</td>
      <td><span class="tag">${esc(k.environment)}</span></td>
      <td class="text-right text-muted" style="font-size:11px">uses ${k.use_count} · ${esc(k.tier)}</td>
      <td class="text-right">${(writeEnabled && k.status!=='revoked')
        ? `<button class="btn btn-default btn-xs" data-rotate="${attr(svc.service)}" data-rotate-id="${attr(k.id)}">Rotate</button>
           <button class="btn btn-danger btn-xs" data-revoke="${attr(svc.service)}" data-revoke-id="${attr(k.id)}">Revoke</button>` : ''}</td>
    </tr>`).join('')}`).join('') : '';
  return `
    <div class="panel panel-default">
      <div class="panel-heading"><b>Key pool</b>
        <span class="text-muted pull-right" style="font-size:12px">multi-key per service · masked · loopback-only</span>
      </div>
      <div class="panel-body">
        <p class="text-muted" style="font-size:12px">Keys discovered during scans, added below, or imported via <code>hse keys import-json</code>, grouped by service and environment. Add a backup key for a service to rotate across when one hits a quota limit; revoke a compromised key (retained for audit, never used again). Raw-value export/import (<code>hse keys export</code>/<code>import-json</code>/<code>import-tsv</code>) stays CLI-only — it round-trips plaintext to a file.</p>
        ${writeEnabled ? `
        <div style="display:flex;gap:8px;align-items:center;flex-wrap:wrap;margin-bottom:12px">
          <input id="pool-add-service" type="text" class="form-control input-sm" style="max-width:160px" placeholder="service (e.g. shodan)" autocomplete="off">
          <input id="pool-add-key" type="password" class="form-control input-sm" style="max-width:260px" placeholder="key value" autocomplete="off">
          <input id="pool-add-notes" type="text" class="form-control input-sm" style="max-width:160px" placeholder="notes (optional)" autocomplete="off">
          <button id="pool-add-btn" class="btn btn-primary btn-sm">Add key</button>
          <span id="pool-add-msg" class="text-muted" style="font-size:12px"></span>
        </div>` : ''}
        ${hasKeys
          ? `<div class="table-responsive"><table class="table table-condensed">
               <thead><tr><th>Key</th><th>Status</th><th>Env</th><th class="text-right">Usage</th><th></th></tr></thead>
               <tbody>${rows}</tbody>
             </table></div>`
          : '<p class="text-muted" style="font-size:12px">No keys in the pool yet.</p>'}
      </div>
    </div>`;
}
/* Read-only operator telemetry: per-service key-pool health/quota (/keys/status)
   + the detector coverage catalogue size (/keys/patterns). Surfaces the dashboard
   diagnostics the handlers were built for but the SPA never showed. */
export function keysDiagPanel(status, patterns){
  const svcs = (status && status.services) || [];
  const rows = svcs.map(s=>`<tr>
      <td><b>${esc(s.service)}</b></td>
      <td class="text-right">${s.total}</td><td class="text-right">${s.active}</td>
      <td class="text-right">${s.rate_limited}</td><td class="text-right">${s.exhausted}</td>
      <td class="text-right">${s.invalid}</td><td class="text-right">${s.untested}</td>
      <td class="text-right">${s.revoked}</td><td class="text-right">${s.uses}</td>
      <td class="text-right">${s.errors}</td>
      <td class="text-right">${Math.round((s.avg_health||0)*100)}%</td>
    </tr>`).join('');
  const cov = patterns
    ? `<p class="text-muted" style="font-size:12px">Detector coverage: <b>${esc(patterns.count)}</b> key-shape patterns across <b>${esc(patterns.unique_services)}</b> services.</p>`
    : '';
  return `
    <div class="panel panel-default">
      <div class="panel-heading"><b>Key diagnostics</b>
        <span class="text-muted pull-right" style="font-size:12px">per-service pool health · loopback-only</span>
      </div>
      <div class="panel-body">
        ${cov}
        ${svcs.length ? `<div class="table-responsive"><table class="table table-condensed">
          <thead><tr><th>Service</th><th class="text-right">Total</th><th class="text-right">Active</th><th class="text-right">Rate-lim</th><th class="text-right">Exh.</th><th class="text-right">Invalid</th><th class="text-right">Untested</th><th class="text-right">Revoked</th><th class="text-right">Uses</th><th class="text-right">Errors</th><th class="text-right">Health</th></tr></thead>
          <tbody>${rows}</tbody>
        </table></div>` : '<p class="text-muted" style="font-size:12px">No keys in the pool yet.</p>'}
      </div>
    </div>`;
}
export function wireKeyEditor(){
  const pending = {updates:{}, deletes:new Set()};
  const refresh = ()=>{
    const n = Object.keys(pending.updates).length + pending.deletes.size;
    $('#k-save').disabled = n===0;
    $('#k-pending').textContent = n===0?'':`${n} pending change${n===1?'':'s'}`;
  };
  $$('.keyrow').forEach(row=>{
    const name = row.dataset.key;
    row.querySelectorAll('button').forEach(btn=>{
      btn.addEventListener('click', ()=>{
        if (btn.dataset.action==='update'){
          const inp = row.querySelector('input[data-input]');
          const v = (inp.value||'').trim();
          if (!v){ inp.focus(); alertify.warning('value required'); return; }
          pending.updates[name] = v;
          pending.deletes.delete(name);
          inp.value = '';
          toast(`${name} queued`);
          refresh();
        } else if (btn.dataset.action==='delete'){
          alertify.confirm('Delete key', `Delete ${name} from ${S.settings.env_path}?`, ()=>{
            pending.deletes.add(name);
            delete pending.updates[name];
            refresh();
          }, ()=>{});
        }
      });
    });
  });
  $('#k-save').addEventListener('click', async()=>{
    try { await API.keysPut({updates:pending.updates, deletes:Array.from(pending.deletes)});
          toast('Saved'); render(); }
    catch(e){ alertify.error(e.message); }
  });
}

