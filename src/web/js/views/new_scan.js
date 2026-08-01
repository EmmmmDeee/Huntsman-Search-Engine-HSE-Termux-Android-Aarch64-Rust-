import { API } from '/static/js/api.js';
import { $, $$, attr, costPill, esc, kindPill, toast } from '/static/js/helpers.js';
import { nav } from '/static/js/router.js';
import { DATA_TYPES, S, TARGET_KINDS, USE_CASES } from '/static/js/state.js';
import { render } from '/static/js/main.js';

/* ═══════════ Page: NEWSCAN (#/newscan) ═══════════ */
/* ── Forward-only scan-plan preview: which modules a seed engages, before spending
   battery/time on a scan. GET /api/v1/plan?value=. Pure, offline, no scan run. ── */
export async function previewPlan(){
  const value = ($('#scantarget').value || '').trim();
  const out = $('#plan-preview');
  if (!value){ out.innerHTML = '<span class="text-muted" style="font-size:12px">Enter a target above to preview.</span>'; return; }
  out.innerHTML = '<span class="text-muted" style="font-size:12px">Resolving plan…</span>';
  let p;
  try { p = await API.plan(value); }
  catch(e){ out.innerHTML = `<div class="alert alert-danger" style="margin:0;padding:6px 10px">${esc(e.message)}</div>`; return; }
  const cats = (p.categories || []).map(c=>`<span class="tag" style="margin:0 4px 2px 0;display:inline-block">${esc(c.category)}&nbsp;${c.count}</span>`).join('');
  const shown = (p.modules || []).slice(0, 40);
  // Colour each module chip by its convex OPTIONALITY tier (how much new query
  // surface firing it unlocks): high = green, moderate = amber, terminal = grey.
  // The list arrives already ordered by convex query value, so the leading chips
  // are the cheapest, highest-return queries — the ones a budget-truncated scan
  // keeps. The tooltip carries the exact query value / cost for the curious.
  const optColour = o => o==='high' ? '#4cae4c' : (o==='moderate' ? '#d9a441' : '#8a8f98');
  const mods = shown.map(m=>{
    const o = m.optionality || 'moderate';
    const qv = (typeof m.query_value === 'number') ? m.query_value.toFixed(2) : '?';
    const tip = `${m.description||''}\n[query value ${qv} · optionality ${o} · cost ${m.cost||'free'}]`;
    return `<code style="margin:0 4px 3px 0;display:inline-block;border-left:3px solid ${optColour(o)};padding-left:5px" title="${attr(tip.trim())}">${esc(m.name)}</code>`;
  }).join('');
  const convex = p.order === 'convex_query_value';
  out.innerHTML = `<div style="padding:8px 10px;border-left:3px solid #5bc0de;background:rgba(91,192,222,0.07)">
    <div>Detected type: <span class="tag">${esc(p.kind)}</span> &middot; <b>${p.module_count}</b> module${p.module_count===1?'':'s'} will run</div>
    ${convex ? `<div class="text-muted" style="font-size:11px;margin-top:3px">Ordered by <b>convex query value</b> — cheapest, highest-optionality queries first, so a budget-limited scan keeps the ones that pay. <span style="color:#4cae4c">&#9632;</span> high &middot; <span style="color:#d9a441">&#9632;</span> moderate &middot; <span style="color:#8a8f98">&#9632;</span> terminal.</div>` : ''}
    <div style="margin-top:5px">${cats}</div>
    <div style="margin-top:6px;line-height:1.9">${mods}${(p.modules||[]).length>40?' <span class="text-muted">…</span>':''}</div>
  </div>`;
}

export async function renderNewScan(v){
  if (!S.modules){ const m = await API.modules(); S.modules = m.modules || []; }
  if (!S.scanProfiles){
    try { S.scanProfiles = (await API.scanProfiles()).profiles || []; }
    catch { S.scanProfiles = []; }
  }
  const W = S.wizard;

  v.innerHTML = `
    <h2>New Scan</h2>
    <hr style="margin:8px 0 14px 0">

    <div class="panel panel-default" style="border-color:var(--danger);margin-bottom:14px">
      <div class="panel-heading" style="background:var(--danger-dim)"><b><i class="glyphicon glyphicon-flash" style="color:var(--danger)"></i>&nbsp;Autonomous investigation</b>
        <span class="text-muted" style="font-weight:400">— no input required</span></div>
      <div class="panel-body">
        <p class="text-muted" style="margin:0 0 10px 0;font-size:12px">
          One tap. The platform ranks every entity it has already collected by cross-investigation
          leverage, auto-selects the highest-value one, and investigates it with the comprehensive
          defaults — no seed, no target type, nothing to choose. The manual form below stays available
          as an optional refinement; it is never required.
        </p>
        <button id="auto-go" class="btn btn-danger" type="button" onclick="autoInvestigate()"><i class="glyphicon glyphicon-flash"></i>&nbsp;Auto-Investigate</button>
        <span id="auto-status" class="text-muted" style="margin-left:10px;font-style:italic">zero input — investigates the highest-value known entity</span>
        <hr style="margin:12px 0">
        <div class="form-inline" style="margin-bottom:6px">
          <button id="auto-plan-go" class="btn btn-default btn-sm" type="button" onclick="autoQueuePreview()"><i class="glyphicon glyphicon-eye-open"></i>&nbsp;Preview queue</button>
          <span class="text-muted" style="margin-left:8px;font-size:12px">— the ranked, diversity-aware order the platform would investigate next; <b>dispatches nothing</b></span>
        </div>
        <div class="form-inline" style="margin-bottom:6px">
          <button id="auto-sweep-go" class="btn btn-warning btn-sm" type="button" onclick="autoSweepGo()"><i class="glyphicon glyphicon-flash"></i>&nbsp;Auto-sweep top</button>
          <input id="auto-sweep-breadth" type="number" class="form-control input-sm" value="5" min="1" max="25" style="width:64px">
          <span class="text-muted" style="margin-left:8px;font-size:12px">— dispatch the top N queued targets in one input-free call (spread across kinds)</span>
        </div>
        <div id="auto-plan-out" style="margin-top:8px"></div>
      </div>
    </div>

    <div class="alert alert-info" style="padding:10px 12px;margin-bottom:14px">
      <b><i class="glyphicon glyphicon-import"></i>&nbsp;Import a file</b>
      — upload a breach/dossier compilation (<code>Entry #N</code> + a
      <code>CONTACT&nbsp;SUMMARY</code> of <code>EMAILS:</code>/<code>NAMES:</code>/
      <code>PHONE&nbsp;NUMBERS:</code>/<code>ADDRESSES:</code>/… lists, as SeekNow
      exports), a Combined&nbsp;Search or DeHashed CSV, a
      <code>Module:&nbsp;Stealerlogs</code> victim export, an OathNet
      SEARCH&nbsp;REPORT (<code>Entry&nbsp;N:</code> blocks), or an OathNet
      JSON/HTML/stealer-log export. The format is auto-detected, parsed and
      ingested as a scan you can browse, correlate and export.
      <div style="margin-top:8px">
        <input type="file" id="dossier-file" accept=".txt,.json,.html,text/plain,application/json,text/html" style="display:inline-block;max-width:60%">
        <button class="btn btn-primary btn-sm" type="button" onclick="uploadDossier()">Import</button>
        <span id="import-status" class="text-muted" style="margin-left:8px"></span>
      </div>
    </div>

    <div class="panel panel-default" style="margin-bottom:14px">
      <div class="panel-heading" style="cursor:pointer" onclick="var b=document.getElementById('batch-body');b.style.display=b.style.display==='none'?'':'none'">
        <i class="glyphicon glyphicon-th-list"></i>&nbsp;<b>Batch scan</b>
        <small class="text-muted">— queue up to 50 targets at once (one per line), using the options selected below</small>
        <span class="pull-right text-muted">&#9662;</span>
      </div>
      <div class="panel-body" id="batch-body" style="display:none">
        <p class="text-muted" style="margin-bottom:6px">Each line is one target. The <b>Target Type</b> selected below applies to all
          (use <i>Auto-detect</i> for mixed kinds). Per-line <code>kind value</code> is also accepted, e.g. <code>email bob@x.com</code>.</p>
        <textarea id="batch-targets" class="form-control" rows="5" spellcheck="false" autocapitalize="off"
          placeholder="example.com&#10;1.2.3.4&#10;bob@example.com&#10;email alice@example.com"></textarea>
        <button class="btn btn-primary btn-sm" type="button" style="margin-top:8px" onclick="submitBatch()"><i class="glyphicon glyphicon-play"></i>&nbsp;Queue batch</button>
        <span id="batch-status" class="text-muted" style="margin-left:8px"></span>
      </div>
    </div>

    <form id="scan-form" class="form" onsubmit="event.preventDefault();submitWizard();">
      <div class="row">
        <div class="col-sm-4" style="padding-bottom:10px">
          <label for="scanname">Scan Name</label>
          <div class="input-group" style="padding-bottom:10px">
            <input class="form-control" type="text" id="scanname" value="${attr(W.name)}" placeholder="The name of this scan.">
          </div>
          <label for="scantarget">Scan Target</label>
          <div class="input-group" style="padding-bottom:6px">
            <input class="form-control" type="text" id="scantarget" value="${attr(W.value)}" placeholder="The target of your scan." autocomplete="off" autocorrect="off" autocapitalize="off" spellcheck="false">
          </div>
          <div style="padding-bottom:10px">
            <button class="btn btn-default btn-xs" type="button" onclick="previewPlan()"><i class="glyphicon glyphicon-eye-open"></i>&nbsp;Preview plan</button>
            <span class="text-muted" style="font-size:11px;margin-left:6px">see which modules run, before scanning</span>
            <div id="plan-preview" style="margin-top:8px"></div>
          </div>
          <label for="scankind">Target Type</label>
          <select id="scankind" class="form-control">
            ${TARGET_KINDS.map(k=>`<option value="${attr(k.v)}"${W.kind===k.v?' selected':''}>${esc(k.label)}</option>`).join('')}
          </select>
        </div>
        <div class="col-sm-8" style="padding-bottom:10px">
          <div class="help-panel">
            <i class="glyphicon glyphicon-question-sign"></i>&nbsp;&nbsp;
            Your scan target may be one of the following. Pick the matching Target Type on the left:
            <div class="row" style="margin-top:8px">
              <div class="col-sm-6">
                <b>Domain Name</b>: e.g. <i>example.com</i><br>
                <b>IPv4 Address</b>: e.g. <i>1.2.3.4</i><br>
                <b>IPv6 Address</b>: e.g. <i>2606:4700:4700::1111</i><br>
                <b>Hostname / Subdomain</b>: e.g. <i>abc.example.com</i><br>
                <b>Network ASN</b>: e.g. <i>AS13335</i> or <i>13335</i>
              </div>
              <div class="col-sm-6">
                <b>E-mail Address</b>: e.g. <i>bob@example.com</i><br>
                <b>Phone Number</b>: e.g. <i>+12345678901</i> (E.164)<br>
                <b>Human Name</b>: e.g. <i>"Jane Doe"</i><br>
                <b>Username</b>: e.g. <i>jsmith2000</i><br>
                <b>GPS Coordinates</b>: e.g. <i>-33.8688,151.2093</i>
              </div>
            </div>
          </div>
        </div>
      </div>

      <div class="control-group">
        <ul class="nav nav-tabs">
          <li id="usetab"    class="${W.activeTab==='usecase'?'active':''}"><a href="#" data-tab="usecase">By Use Case</a></li>
          <li id="datatab"   class="${W.activeTab==='data'?'active':''}"><a href="#" data-tab="data">By Required Data</a></li>
          <li id="moduletab" class="${W.activeTab==='module'?'active':''}"><a href="#" data-tab="module">By Module</a></li>
          <div class="btn-group-sm pull-right" id="selectors" style="display:${W.activeTab==='module'?'block':'none'};padding:6px">
            <button id="btn-select-all" type="button" class="btn btn-info btn-sm">Select All</button>&nbsp;
            <button id="btn-deselect-all" type="button" class="btn btn-info btn-sm">De-Select All</button>&nbsp;
            <button id="btn-reset-preset" type="button" class="btn btn-default btn-sm">Use Preset</button>
          </div>
        </ul>

        <table class="table table-striped table-condensed" id="usetable" style="display:${W.activeTab==='usecase'?'table':'none'}">
          ${Object.entries(USE_CASES).map(([k,uc])=>`
            <tr>
              <td style="width:50px;vertical-align:middle">
                <input type="radio" name="usecase" value="${attr(k)}" id="usecase_${attr(k)}" ${W.usecase===k?'checked':''}>
              </td>
              <td style="width:140px;vertical-align:middle"><label for="usecase_${attr(k)}" style="margin:0;font-weight:600">${esc(uc.label)}</label></td>
              <td>${uc.desc}</td>
            </tr>
          `).join('')}
        </table>

        <div id="datatable-host" style="display:${W.activeTab==='data'?'block':'none'}">
          <p class="text-muted" style="margin:10px 0 6px;font-size:13px">
            Select the type of data you have about your target. Huntsman will enable only the modules that can use that data.
          </p>
          <div id="data-type-chips" style="margin-bottom:12px">
            ${DATA_TYPES.map(dt=>`
              <button type="button" class="btn btn-sm ${W.dataType===dt.label?'btn-primary':'btn-default'} data-type-chip"
                data-label="${attr(dt.label)}" data-kinds="${attr(JSON.stringify(dt.kinds))}"
                style="margin:3px">${esc(dt.label)}</button>
            `).join('')}
          </div>
          <div id="data-type-hint" class="text-muted" style="font-size:12px">
            ${W.dataType ? `Showing modules that accept <b>${esc(W.dataType)}</b> as input.` : 'Click a data type above to filter modules.'}
          </div>
          <div id="data-moduletable-host" style="margin-top:8px"></div>
        </div>

        <div id="moduletable-host" style="display:${W.activeTab==='module'?'block':'none'}"></div>
      </div>

      <div class="control-group" style="margin-top:14px">
        <label for="w-profile">Scan Profile <span class="text-muted" style="font-weight:normal">(optional preset — same as <code>hse scan --profile</code>)</span></label>
        <select id="w-profile" class="form-control">
          <option value=""${W.profile?'':' selected'}>None — use the tuning fields below as typed</option>
          ${(S.scanProfiles||[]).map(p=>`<option value="${attr(p.name)}"${W.profile===p.name?' selected':''}>${esc(p.name)}</option>`).join('')}
        </select>
        <span class="help-block" id="w-profile-desc" style="font-size:12px">
          ${W.profile ? esc((S.scanProfiles.find(p=>p.name===W.profile)||{}).description||'') : 'Picking a profile overrides the depth / confidence / concurrency / entity-cap / wall-time fields below with its own tuned values. Module selection above, tags, and notes still apply.'}
        </span>
      </div>

      <p style="margin-top:14px;margin-bottom:6px">
        <a href="#" id="adv-toggle" style="font-size:12px;color:var(--accent)">${W.showAdv?'▾':'▸'} Advanced options</a>
      </p>
      <div id="adv-box" style="display:${W.showAdv?'block':'none'}">
        <div class="row">
          <div class="col-sm-3">
            <label for="w-depth">Expansion depth</label>
            <input type="number" class="form-control input-sm" id="w-depth" min="0" max="5" value="${W.options.depth}">
            <span class="help-block">0 = single round. ≥1 enables autonomous expansion.</span>
          </div>
          <div class="col-sm-3">
            <label for="w-mxc">Min expand C_eff</label>
            <input type="number" class="form-control input-sm" id="w-mxc" min="0" max="1" step="0.05" value="${W.options.min_expand_confidence}">
            <span class="help-block">Only expand entities ≥ this effective confidence.</span>
          </div>
          <div class="col-sm-3">
            <label for="w-concurrent">Concurrent modules</label>
            <input type="number" class="form-control input-sm" id="w-concurrent" min="0" value="${W.options.max_concurrent}">
            <span class="help-block">0 = sequential. N&gt;0 = up to N in flight.</span>
          </div>
          <div class="col-sm-3">
            <label for="w-timeout">Module timeout (ms)</label>
            <input type="number" class="form-control input-sm" id="w-timeout" min="100" placeholder="module default" value="${W.options.module_timeout_ms??''}">
          </div>
        </div>
        <div class="row" style="margin-top:8px">
          <div class="col-sm-3">
            <label for="w-throttle">Throttle (ms)</label>
            <input type="number" class="form-control input-sm" id="w-throttle" min="0" value="${W.options.throttle_ms}">
          </div>
          <div class="col-sm-3">
            <label for="w-maxent">Max entities</label>
            <input type="number" class="form-control input-sm" id="w-maxent" min="0" placeholder="unlimited" value="${W.options.max_entities??''}">
          </div>
          <div class="col-sm-3">
            <label for="w-maxwt">Max wall time (sec)</label>
            <input type="number" class="form-control input-sm" id="w-maxwt" min="0" placeholder="unlimited" value="${W.options.max_wall_time_secs??''}">
          </div>
          <div class="col-sm-3">
            <label for="w-minc">Min confidence</label>
            <input type="number" class="form-control input-sm" id="w-minc" min="0" max="1" step="0.05" placeholder="no filter" value="${W.options.min_confidence??''}">
          </div>
        </div>
        <label style="margin-top:10px;font-weight:normal">
          <input type="checkbox" id="w-free" ${W.options.free_only?'checked':''}> Free-only (skip key-gated and paid modules)
        </label>
      </div>

      <div class="control-group" style="margin-top:14px">
        <label class="text-muted" style="font-size:12px">Tags <span class="text-muted">(comma-separated labels for campaign tracking)</span></label>
        <input type="text" class="form-control input-sm" id="w-tags" placeholder="e.g. investigation-001, apt-29">
      </div>
      <div class="control-group" style="margin-top:6px">
        <label class="text-muted" style="font-size:12px">Notes</label>
        <textarea class="form-control input-sm" id="w-notes" rows="2" placeholder="Investigation context…" style="resize:vertical"></textarea>
      </div>

      <div class="control-group" style="margin-top:14px">
        <button id="btn-run-scan" type="submit" class="btn btn-danger"><i class="glyphicon glyphicon-play"></i>&nbsp;Run Scan Now</button>
        <a href="#/scans" class="btn btn-default">Cancel</a>
      </div>
    </form>
  `;

  renderWizardModuleTable();

  // Bind handlers.
  $('#scanname').addEventListener('input', e=>{ W.name = e.target.value; });
  $('#scantarget').addEventListener('input', e=>{ W.value = e.target.value; });
  $('#scankind').addEventListener('change', e=>{ W.kind = e.target.value; renderWizardModuleTable(); });
  $('#w-profile').addEventListener('change', e=>{
    W.profile = e.target.value || null;
    const desc = (S.scanProfiles||[]).find(p=>p.name===W.profile);
    $('#w-profile-desc').textContent = desc
      ? desc.description
      : 'Picking a profile overrides the depth / confidence / concurrency / entity-cap / wall-time fields below with its own tuned values. Module selection above, tags, and notes still apply.';
  });
  $$('input[name=usecase]').forEach(r=>r.addEventListener('change', e=>{
    W.usecase = e.target.value; W.modules = null; renderWizardModuleTable();
  }));
  $$('.nav-tabs a[data-tab]').forEach(a=>a.addEventListener('click', e=>{
    e.preventDefault();
    W.activeTab = a.dataset.tab;
    $('#usetab').classList.toggle('active', W.activeTab==='usecase');
    $('#datatab').classList.toggle('active', W.activeTab==='data');
    $('#moduletab').classList.toggle('active', W.activeTab==='module');
    $('#usetable').style.display = W.activeTab==='usecase' ? 'table' : 'none';
    $('#datatable-host').style.display = W.activeTab==='data' ? 'block' : 'none';
    $('#moduletable-host').style.display = W.activeTab==='module' ? 'block' : 'none';
    $('#selectors').style.display = W.activeTab==='module' ? 'block' : 'none';
    if (W.activeTab==='data') renderDataTypeModules();
  }));
  // "By Required Data" chip clicks
  $('#datatable-host').addEventListener('click', e=>{
    const chip = e.target.closest('.data-type-chip');
    if (!chip) return;
    e.preventDefault();
    const label = chip.dataset.label;
    W.dataType = W.dataType===label ? null : label;
    $$('.data-type-chip').forEach(c=>c.classList.toggle('btn-primary', c.dataset.label===W.dataType));
    $$('.data-type-chip').forEach(c=>c.classList.toggle('btn-default', c.dataset.label!==W.dataType));
    const hint = $('#data-type-hint');
    if (hint) hint.innerHTML = W.dataType ? `Showing modules that accept <b>${esc(W.dataType)}</b> as input.` : 'Click a data type above to filter modules.';
    renderDataTypeModules();
  });
  $('#adv-toggle').addEventListener('click', e=>{
    e.preventDefault();
    W.showAdv = !W.showAdv;
    $('#adv-box').style.display = W.showAdv?'block':'none';
    $('#adv-toggle').innerHTML = (W.showAdv?'▾':'▸')+' Advanced options';
  });
  ['depth','mxc','throttle','timeout','concurrent','maxent','maxwt','minc'].forEach(id=>{
    const el = $('#w-'+id); if (!el) return;
    el.addEventListener('input', e=>{
      const v = e.target.value===''?null:Number(e.target.value);
      const map = {depth:'depth',mxc:'min_expand_confidence',throttle:'throttle_ms',timeout:'module_timeout_ms',
                   concurrent:'max_concurrent',maxent:'max_entities',maxwt:'max_wall_time_secs',minc:'min_confidence'};
      W.options[map[id]] = v;
    });
  });
  $('#w-free').addEventListener('change', e=>{ W.options.free_only = e.target.checked; });
  $('#btn-select-all').addEventListener('click', e=>{
    e.preventDefault();
    const accepting = S.modules.filter(m=>W.kind==='auto' || !m.accepts || m.accepts.includes(W.kind));
    W.modules = accepting.map(m=>m.name); renderWizardModuleTable();
  });
  $('#btn-deselect-all').addEventListener('click', e=>{
    e.preventDefault();
    W.modules = []; renderWizardModuleTable();
  });
  $('#btn-reset-preset').addEventListener('click', e=>{
    e.preventDefault();
    W.modules = null; renderWizardModuleTable();
  });
}
export function renderWizardModuleTable(){
  const W = S.wizard;
  const host = $('#moduletable-host');
  if (!host) return;
  const uc = USE_CASES[W.usecase];
  const accepting = S.modules.filter(m=>W.kind==='auto' || !m.accepts || m.accepts.includes(W.kind));
  const ucMatches = accepting.filter(m=>uc.pick(m));
  let active;
  if (W.modules!==null) active = new Set(W.modules);
  else if (W.usecase==='all'||W.usecase==='passive') active = new Set(accepting.map(m=>m.name));
  else active = new Set(ucMatches.map(m=>m.name));

  host.innerHTML = `
    <div style="padding:6px 0;color:var(--text-muted);font-size:12px">
      <b>${active.size}</b> of <b>${accepting.length}</b> module${accepting.length===1?'':'s'} selected
      ${W.usecase==='passive' ? ' · <span class="text-warning">passive_only flag will further restrict at runtime</span>':''}
    </div>
    ${W.kind==='auto' ? `<div style="padding:0 0 6px;color:var(--text-dim);font-size:12px">
      <i class="glyphicon glyphicon-flash"></i> Target type is auto-detected from the value; at runtime only modules that accept the detected type run.
    </div>`:''}
    <div class="mod-grid">
      ${accepting.map(m=>{
        const checked = active.has(m.name);
        const cost = m.cost || 'free';
        // Native browser tooltip on the row — server returns
        // `description` for every module (issue #28). Empty descriptions
        // render no tooltip (graceful degrade for any module added
        // without overriding the default).
        const desc = m.description || '';
        return `<label${desc ? ` title="${attr(desc)}"` : ''}>
          <input type="checkbox" data-mod="${attr(m.name)}" ${checked?'checked':''}>
          <span class="mn">${esc(m.name)}</span>
          ${m.passive ? '<span class="cost-pill" style="background:var(--bg-elevated-2);color:var(--text-muted)" title="passive (no outbound)">passive</span>':''}
          ${costPill(cost)}
        </label>`;
      }).join('')}
      ${accepting.length===0 ? `<div class="empty-state"><p>No modules accept the <code>${esc(W.kind)}</code> target kind.</p></div>` : ''}
    </div>
  `;
  $$('.mod-grid input[type=checkbox]').forEach(cb=>cb.addEventListener('change', ()=>{
    const set = new Set(W.modules || Array.from(active));
    if (cb.checked) set.add(cb.dataset.mod); else set.delete(cb.dataset.mod);
    W.modules = Array.from(set);
    renderWizardModuleTable();
  }));
}
export function renderDataTypeModules(){
  const W = S.wizard;
  const host = $('#data-moduletable-host');
  if (!host) return;
  if (!W.dataType){
    host.innerHTML = '';
    return;
  }
  const dt = DATA_TYPES.find(d=>d.label===W.dataType);
  if (!dt){ host.innerHTML = ''; return; }
  const matching = S.modules.filter(m=>
    !m.accepts || dt.kinds.some(k=>m.accepts.includes(k))
  );
  if (!matching.length){
    host.innerHTML = `<div class="empty-state"><p>No modules accept <code>${esc(W.dataType)}</code> as input.</p></div>`;
    return;
  }
  const activeFromData = new Set(matching.map(m=>m.name));
  host.innerHTML = `
    <div style="padding:6px 0 4px;color:var(--text-muted);font-size:12px">
      <b>${matching.length}</b> module${matching.length===1?'':'s'} accept ${esc(W.dataType)} as input.
      <a href="#" id="apply-data-selection" style="margin-left:8px;color:var(--accent)">Apply selection →</a>
    </div>
    <div class="mod-grid">
      ${matching.map(m=>{
        const cost = m.cost || 'free';
        const desc = m.description || '';
        return `<label${desc ? ` title="${attr(desc)}"` : ''}>
          <input type="checkbox" data-mod="${attr(m.name)}" checked>
          <span class="mn">${esc(m.name)}</span>
          ${m.passive ? '<span class="cost-pill" style="background:var(--bg-elevated-2);color:var(--text-muted)" title="passive">passive</span>':''}
          ${costPill(cost)}
        </label>`;
      }).join('')}
    </div>
  `;
  const applyLink = $('#apply-data-selection');
  if (applyLink) applyLink.addEventListener('click', e=>{
    e.preventDefault();
    W.modules = Array.from(activeFromData);
    W.activeTab = 'module';
    renderNewScan($('#view')).catch(e=>alertify.error(e.message));
  });
}

export async function uploadDossier(){
  const inp = $('#dossier-file');
  const st  = $('#import-status');
  const f = inp && inp.files && inp.files[0];
  if (!f){ st.textContent = 'Choose a file first.'; return; }
  st.textContent = 'Reading…';
  try {
    const text = await f.text();
    st.textContent = 'Importing…';
    const r = await API.importDossier(text);
    st.textContent = `Imported ${r.entity_count} entities` + (r.correlation_count ? `, ${r.correlation_count} correlations.` : '.');
    toast(`Imported ${r.entity_count} entities`);
    nav(`#/scaninfo?id=${encodeURIComponent(r.scan_id)}`);
  } catch(e){
    st.textContent = 'Import failed: ' + e.message;
    alertify.error('Import failed: ' + e.message);
  }
}

/* Build the ScanOptions payload from the wizard's current state. Shared by the
   single-target submit and the batch submit so they can never drift on which
   options a scan launched from this page carries. */
export function buildWizardOptions(){
  const W = S.wizard;
  const base = USE_CASES[W.usecase].options(W.modules);
  const opts = {
    ...base,
    exclude_modules: W.options.exclude_modules,
    throttle_ms: Number(W.options.throttle_ms)||0,
    max_concurrent: Number(W.options.max_concurrent)||0,
    depth: Number(W.options.depth)||0,
    min_expand_confidence: Number(W.options.min_expand_confidence)||0.20,
    free_only: !!W.options.free_only
  };
  if (W.options.module_timeout_ms!=null && W.options.module_timeout_ms!=='') opts.module_timeout_ms = Number(W.options.module_timeout_ms);
  if (W.options.max_entities!=null && W.options.max_entities!=='') opts.max_entities = Number(W.options.max_entities);
  if (W.options.max_wall_time_secs!=null && W.options.max_wall_time_secs!=='') opts.max_wall_time_secs = Number(W.options.max_wall_time_secs);
  if (W.options.min_confidence!=null && W.options.min_confidence!=='') opts.min_confidence = Number(W.options.min_confidence);
  if (W.modules!==null) opts.modules = W.modules.length?W.modules:null;
  if (W.profile) opts.profile = W.profile;
  const tagsStr = ($('#w-tags')||{}).value||'';
  if (tagsStr.trim()) opts.scan_tags = tagsStr.split(',').map(t=>t.trim()).filter(Boolean);
  const notesStr = ($('#w-notes')||{}).value||'';
  if (notesStr.trim()) opts.notes = notesStr.trim();
  return opts;
}

/* Fully autonomous investigation — NO input. The server ranks the entities the
   platform has already collected by cross-investigation leverage, auto-selects
   the strongest, and scans it. Navigates to the resulting scan's live log. */
export async function autoInvestigate(){
  const btn = $('#auto-go'), st = $('#auto-status');
  if (btn){ btn.disabled = true; btn.innerHTML = '<i class="glyphicon glyphicon-refresh glyphicon-spin"></i>&nbsp;Selecting…'; }
  if (st) st.textContent = 'ranking known entities and selecting the highest-value seed…';
  try {
    const r = await API.autoScan();
    // `toast` → `showToast` escapes the message once via `esc()` before setting
    // innerHTML, so pass the seed raw here — pre-escaping double-escapes it (a
    // value like O'Brien would render as the literal "O&#39;Brien").
    const seed = r.selected_seed ? `${r.selected_seed.kind} = ${r.selected_seed.value}` : 'auto-selected entity';
    toast('Autonomous scan queued — investigating '+seed);
    nav(`#/scaninfo?id=${encodeURIComponent(r.scan_id)}&tab=log`);
  } catch(e){
    if (btn){ btn.disabled = false; btn.innerHTML = '<i class="glyphicon glyphicon-flash"></i>&nbsp;Auto-Investigate'; }
    // A 422 means the base is empty — guide the operator to seed it once.
    const msg = (e && e.message) ? e.message : 'autonomous scan failed';
    if (st) st.textContent = '';
    if (typeof alertify !== 'undefined') alertify.error(msg.includes('nothing to investigate')
      ? 'No data yet — run one scan or import a file to seed the intelligence base, then Auto-Investigate.'
      : msg);
  }
}

/* Read-only preview of the diversity-aware autonomous queue — what the platform
   would investigate next, in order, and why. Dispatches nothing; renders the
   ranked list into #auto-plan-out so the operator can see the execution order
   before committing. Mirrors /api/v1/scan/auto/plan. */
export async function autoQueuePreview(){
  const btn = $('#auto-plan-go'), out = $('#auto-plan-out');
  if (btn){ btn.disabled = true; btn.innerHTML = '<i class="glyphicon glyphicon-refresh glyphicon-spin"></i>&nbsp;Planning…'; }
  try {
    const p = await API.autoPlan(20);
    const q = (p && p.queue) || [];
    if (!q.length){
      if (out) out.innerHTML = '<div class="text-muted" style="font-size:12px">No high-leverage identifier to queue yet — run one scan or import a file to seed the base.</div>';
      return;
    }
    let rows = q.map((t,i)=>`<tr>
      <td class="text-right text-muted">${i+1}</td>
      <td>${kindPill(t.kind)}</td>
      <td><code>${esc(t.value)}</code></td>
      <td class="text-right">${(Number(t.score)||0).toFixed(3)}</td>
      <td class="text-right text-muted" title="distinct prior investigations that observed this value">${t.cross_scan_degree!=null?t.cross_scan_degree:0}</td>
    </tr>`).join('');
    if (out) out.innerHTML = `<div class="table-responsive">
      <table class="table table-condensed" style="margin-bottom:4px">
        <thead><tr><th class="text-right">#</th><th>Kind</th><th>Value</th><th class="text-right">Score</th><th class="text-right">Degree</th></tr></thead>
        <tbody>${rows}</tbody>
      </table>
      <div class="text-muted" style="font-size:11px">${q.length} queued · ${p.kinds_covered!=null?p.kinds_covered:0} kind${(p.kinds_covered===1)?'':'s'} covered · ${p.considered!=null?p.considered:0} considered · diversity ${esc(p.diversity)}</div>
    </div>`;
  } catch(e){
    if (out) out.innerHTML = '<div class="text-danger" style="font-size:12px">Plan failed: '+esc((e&&e.message)||'unknown error')+'</div>';
  } finally {
    if (btn){ btn.disabled = false; btn.innerHTML = '<i class="glyphicon glyphicon-eye-open"></i>&nbsp;Preview queue'; }
  }
}

/* Fully autonomous MULTI-target sweep — NO seed input. Plans the diversity-aware
   queue and dispatches its top `breadth` targets in one call, each an ordinary
   comprehensive scan. Mirrors /api/v1/scan/auto/sweep. */
export async function autoSweepGo(){
  const btn = $('#auto-sweep-go'), out = $('#auto-plan-out');
  const breadth = Math.max(1, Math.min(25, parseInt(($('#auto-sweep-breadth')||{}).value || '5', 10) || 5));
  if (btn){ btn.disabled = true; btn.innerHTML = '<i class="glyphicon glyphicon-refresh glyphicon-spin"></i>&nbsp;Sweeping…'; }
  try {
    const r = await API.autoSweep(breadth);
    const dispatched = (r && r.dispatched) || [];
    const ok = dispatched.filter(d=>d && d.scan_id);
    toast(`Autonomous sweep dispatched ${ok.length} scan${ok.length===1?'':'s'}`);
    if (out){
      const links = ok.map(d=>`<a href="#/scaninfo?id=${encodeURIComponent(d.scan_id)}&tab=log"><code>${esc((d.kind?d.kind+' = ':'')+(d.value||d.scan_id))}</code></a>`).join('<br>');
      out.innerHTML = links
        ? `<div style="font-size:12px"><b>Dispatched ${ok.length} scan${ok.length===1?'':'s'}:</b><br>${links}</div>`
        : '<div class="text-muted" style="font-size:12px">Nothing dispatched.</div>';
    }
    render();
  } catch(e){
    const msg = (e && e.message) ? e.message : 'autonomous sweep failed';
    if (out) out.innerHTML = '<div class="text-danger" style="font-size:12px">'+esc(msg.includes('nothing to investigate')
      ? 'No data yet — run one scan or import a file to seed the intelligence base, then sweep.'
      : msg)+'</div>';
  } finally {
    if (btn){ btn.disabled = false; btn.innerHTML = '<i class="glyphicon glyphicon-flash"></i>&nbsp;Auto-sweep top'; }
  }
}

export async function submitWizard(){
  const W = S.wizard;
  const target = (W.value||'').trim();
  if (!target){ alertify.error('Target value is required'); $('#scantarget').focus(); return; }
  const opts = buildWizardOptions();

  const btn = $('#btn-run-scan');
  btn.disabled = true; btn.innerHTML = '<i class="glyphicon glyphicon-refresh glyphicon-spin"></i>&nbsp;Queuing…';
  try {
    // Unified scan: 'auto' omits `kind` so the server detects it from the value.
    const payload = W.kind==='auto' ? {value: target, options: opts} : {kind: W.kind, value: target, options: opts};
    const r = await API.create(payload);
    toast('Scan queued');
    W.value = ''; W.name = '';
    nav(`#/scaninfo?id=${r.scan_id}&tab=log`);
  } catch(e){
    btn.disabled = false; btn.innerHTML = '<i class="glyphicon glyphicon-play"></i>&nbsp;Run Scan Now';
    alertify.error(e.message);
  }
}

/* Queue many scans in one request (POST /scans/batch). Reuses the wizard's
   selected options so a batch behaves exactly like N single scans. Each line is
   one target; an optional leading kind token (`email bob@x.com`) overrides the
   form's Target Type, else the form kind (or auto-detect) applies. */
export async function submitBatch(){
  const W = S.wizard;
  const raw = ($('#batch-targets')||{}).value||'';
  const lines = raw.split('\n').map(l=>l.trim()).filter(Boolean);
  const st = $('#batch-status');
  if (!lines.length){ st.textContent = 'Enter at least one target.'; return; }
  if (lines.length > 50){ st.textContent = `Too many (${lines.length}); max 50 per batch.`; return; }
  const kinds = new Set(TARGET_KINDS.map(k=>k.v).filter(v=>v!=='auto'));
  const opts = buildWizardOptions();
  const reqs = lines.map(line=>{
    const sp = line.indexOf(' ');
    let kind = W.kind, value = line;
    if (sp > 0){
      const head = line.slice(0, sp).toLowerCase();
      if (kinds.has(head)){ kind = head; value = line.slice(sp+1).trim(); }
    }
    // 'auto' → omit kind so the server detects it from the value.
    return (kind==='auto' || !kind) ? {value, options: opts} : {kind, value, options: opts};
  }).filter(r=>r.value);
  st.textContent = `Queuing ${reqs.length}…`;
  try {
    const r = await API.batch(reqs);
    const ok = (r.scans||[]).filter(x=>x.scan_id).length;
    const errs = (r.scans||[]).filter(x=>x.error);
    st.textContent = `Queued ${ok} of ${r.count}.` + (errs.length?` ${errs.length} rejected.`:'');
    toast(`Batch: ${ok} scan${ok===1?'':'s'} queued`);
    if (errs.length) alertify.warning(errs.map(e=>e.error).slice(0,3).join('; '));
    if (ok) nav('#/scans');
  } catch(e){ st.textContent = 'Batch failed: ' + e.message; alertify.error(e.message); }
}

