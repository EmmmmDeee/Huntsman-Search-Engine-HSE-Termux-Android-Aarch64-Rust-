import { API } from '/static/js/api.js';
import { $, ENRICHMENT_SOURCES, attr, attrText, classify, effC, esc, extLink, fmtDate, kindPill, sourceCount } from '/static/js/helpers.js';
import { S } from '/static/js/state.js';

// A large scan can produce thousands of entities; rendering each as two <tr>s
// with its full (hidden) evidence detail, and re-running that + re-initialising
// tablesorter on every filter keystroke, is heavy on a Termux phone. Cap what
// is rendered (the count label still reports the full match total) and debounce
// the filter. Entities arrive confidence-ranked, so the top slice is shown.
const BROWSE_ROW_CAP = 500;
function debounce(fn, ms) {
  let t;
  return (...a) => { clearTimeout(t); t = setTimeout(() => fn(...a), ms); };
}

/* ── Browse tab ── */
export function renderBrowse(host){
  const kinds = Array.from(new Set(S.entities.map(e=>e.kind))).sort();
  const qKind = S.route.query.k || '';
  // SpiderFoot 4.0-style data-element rollup: per-kind Unique + Total (sum of corroboration)
  const roll = {};
  S.entities.forEach(e=>{ const r = roll[e.kind] || (roll[e.kind] = {u:0, t:0}); r.u++; r.t += (e.corroboration||1); });
  const rollRows = Object.keys(roll).sort((a,b)=>roll[b].u-roll[a].u);
  // SpiderFoot-identical two-column Browse layout:
  // left = sticky "Data Element" sidebar with per-kind counts (click to filter);
  // right = search/tier controls + paginated results table.
  const sidebarRows = rollRows.map(k=>`
    <tr class="rollup-row${k===qKind?' active-kind':''}" data-kind="${attr(k)}" style="cursor:pointer">
      <td>${kindPill(k)}</td>
      <td class="text-right"><b>${roll[k].u}</b></td>
      <td class="text-right text-muted">${roll[k].t}</td>
    </tr>`).join('');
  const sidebarHtml = rollRows.length ? `
    <div class="panel panel-default" style="margin-bottom:0">
      <div class="panel-heading" style="padding:8px 12px;font-size:12px;font-weight:600">
        Data Elements &nbsp;<span class="badge">${S.entities.length}</span>
        <a href="#" id="b-all-types" class="pull-right" style="font-size:11px;font-weight:400">All</a>
      </div>
      <div style="max-height:calc(100vh - 180px);overflow-y:auto">
        <table class="table table-condensed table-hover" id="browse-rollup" style="margin:0;font-size:12px">
          <thead><tr><th>Type</th><th class="text-right" title="Unique values">Uniq</th><th class="text-right" title="Total corroboration">Tot</th></tr></thead>
          <tbody>${sidebarRows}</tbody>
        </table>
      </div>
    </div>` : '';

  host.innerHTML = `
    <div class="row">
      ${sidebarHtml ? `<div class="col-sm-3 col-md-2" id="b-sidebar">${sidebarHtml}</div>` : ''}
      <div class="${sidebarHtml ? 'col-sm-9 col-md-10' : 'col-sm-12'}" id="b-main">
        <div class="row" style="margin-bottom:10px">
          <div class="col-sm-5">
            <input type="search" id="b-q" class="form-control input-sm" placeholder="Filter value, evidence, tags…" autocomplete="off">
          </div>
          <div class="col-sm-3">
            <select id="b-cls" class="form-control input-sm">
              <option value="">All tiers</option>
              <option value="VERIFIED">✓ Verified</option>
              <option value="PROBABLE">~ Probable+</option>
              <option value="CANDIDATE">? Candidate only</option>
            </select>
          </div>
          <div class="col-sm-4 text-right" style="padding-top:6px">
            <span class="text-muted" style="font-size:11px" id="b-ct"></span>
          </div>
        </div>
        <input type="hidden" id="b-kind" value="${attr(qKind)}">
        <div id="b-table-host"></div>
      </div>
    </div>
  `;
  function refresh(){
    const q = $('#b-q').value.trim().toLowerCase();
    const ks = $('#b-kind').value, cs = $('#b-cls').value;
    let rows = S.entities.slice();
    if (ks) rows = rows.filter(e=>e.kind===ks);
    if (cs) rows = rows.filter(e=>{const t=classify(effC(e)); return t===cs || (cs==='PROBABLE' && effC(e)>=0.40);});
    if (q)  rows = rows.filter(e =>
      (e.value||'').toLowerCase().includes(q)
      || (e.tags||[]).some(t=>t.toLowerCase().includes(q))
      || (e.evidence||[]).some(ev=>(ev.summary||'').toLowerCase().includes(q) || (ev.source||'').toLowerCase().includes(q)));
    $('#b-ct').textContent = `${rows.length} of ${S.entities.length}`;
    const shown = rows.length > BROWSE_ROW_CAP ? rows.slice(0, BROWSE_ROW_CAP) : rows;
    $('#b-table-host').innerHTML = renderBrowseTable(shown, rows.length);
    if (window.jQuery && jQuery.fn.tablesorter && shown.length){
      try { jQuery('#browse-table').tablesorter({sortList:[[2,1]]}); } catch {}
    }
  }
  $('#b-q').addEventListener('input', debounce(refresh, 180));
  $('#b-cls').addEventListener('change', refresh);
  // Sidebar: click a row to filter by kind (toggle off if already active)
  host.querySelectorAll('.rollup-row').forEach(tr=>tr.addEventListener('click', ()=>{
    const k = tr.getAttribute('data-kind');
    const inp = $('#b-kind');
    inp.value = (inp.value === k) ? '' : k;
    host.querySelectorAll('.rollup-row').forEach(r=>r.classList.toggle('active-kind', r.getAttribute('data-kind')===inp.value && inp.value!==''));
    refresh();
  }));
  const allLink = $('#b-all-types');
  if (allLink) allLink.addEventListener('click', e=>{ e.preventDefault(); $('#b-kind').value=''; host.querySelectorAll('.rollup-row').forEach(r=>r.classList.remove('active-kind')); refresh(); });
  // Deep-link: a `q` query param pre-fills the value filter
  if (S.route.query.q){ $('#b-q').value = S.route.query.q; }
  refresh();
}
export function renderBrowseTable(rows, total){
  if (!rows.length){
    return '<div class="empty-state"><h3>No entities match</h3><p>Adjust the filter, or check the Scan Log if the scan is still running.</p></div>';
  }
  const capNote = (total != null && total > rows.length)
    ? `<div class="text-muted" style="font-size:11px;margin-bottom:6px">Showing the top ${rows.length} of ${total} matching entities (confidence-ranked) — filter by type or search to narrow, or export CSV/JSON for the full set.</div>`
    : '';
  const body = rows.map((e,idx)=>{
    const eff = effC(e), tier = classify(eff), srcN = sourceCount(e);
    const sources = Array.from(new Set((e.evidence||[]).map(ev=>ev.source))).sort();
    const evDetail = (e.evidence||[]).map(ev=>{
      const attrs = Object.entries(ev.attributes||{}).map(([k,v])=>`<span class="ev-attr"><span class="ak">${esc(k)}:</span> ${extLink(attrText(v),90)}</span>`).join('');
      // Mirrors the CLI dossier's "(non-corroborating: …)" marker (see
      // `is_non_corroborating_source` in core::entity) so the web UI stops
      // implying every listed source independently boosted C_eff when some
      // are self-enrichment/recall/cross-scan passes that don't.
      const nonCorrob = ev.source && ENRICHMENT_SOURCES.has(ev.source);
      const marker = nonCorrob ? ' <span class="text-muted" style="font-size:10px">(non-corroborating: enrichment/recall/cross-scan)</span>' : '';
      return `<div class="ev-block"><span class="ev-src">${esc(ev.source)}</span>${marker}<span class="text-muted pull-right" style="font-size:10px">${esc(fmtDate(ev.recorded_at))}</span><div class="ev-sum">${esc(ev.summary)}</div>${attrs?`<div class="ev-attrs">${attrs}</div>`:''}</div>`;
    }).join('');
    return `<tr onclick="toggleDetail(this)" data-idx="${idx}">
      <td>${kindPill(e.kind)}</td>
      <td style="word-break:break-word"><code>${extLink(e.raw_value||e.value)}</code></td>
      <td class="text-right"><code>${eff.toFixed(3)}</code></td>
      <td class="text-right"><code>${(e.confidence??0).toFixed(3)}</code></td>
      <td class="text-right">${e.corroboration||1}</td>
      <td class="text-right" title="Distinct corroborating sources (excludes enrichment/recall/cross-scan)">${srcN}</td>
      <td><span class="cls c-${attr(tier)}">${tier}</span></td>
      <td>${(e.tags||[]).map(t=>`<span class="tag">${esc(t)}</span>`).join('')}</td>
      <td>${sources.map(s=>`<span class="src-pill">${esc(s)}</span>`).join('')}</td>
      <td><span class="text-muted" style="font-family:monospace;font-size:11px">${esc(fmtDate(e.observed_at))}</span></td>
    </tr>
    <tr class="entity-detail-row" style="display:none"><td colspan="10"><div class="entity-detail">
      <div style="margin-bottom:4px"><b>UID:</b> <code style="font-size:10px">${esc(e.uid||'')}</code>
        <span style="margin-left:10px"><b>Generation:</b> ${e.generation??0} hop${(e.generation===1)?'':'s'} from seed</span>
        <button class="btn btn-default btn-xs" style="margin-left:8px" data-uid="${attr(e.uid||'')}" onclick="event.stopPropagation();entityPivot(this.dataset.uid,this)"
                title="Find every scan this exact identifier appears in"><i class="glyphicon glyphicon-globe"></i>&nbsp;Seen across scans</button>
        <span class="pivot-out" style="margin-left:8px"></span></div>
      <div style="margin-bottom:6px"><b>${(e.evidence||[]).length} evidence entries:</b></div>
      ${evDetail || '<span class="text-muted">No evidence attached</span>'}
    </div></td></tr>`;
  }).join('');
  return `${capNote}<div class="table-responsive"><table class="table table-striped table-condensed tablesorter" id="browse-table">
    <thead><tr>
      <th>Type</th><th>Value</th><th class="text-right">C_eff</th><th class="text-right" title="Base confidence, before corroboration boost">Conf</th>
      <th class="text-right">Corr</th><th class="text-right" title="Distinct corroborating sources">Src</th><th>Tier</th>
      <th class="sorter-false">Tags</th><th class="sorter-false">Sources</th><th>Observed</th>
    </tr></thead><tbody>${body}</tbody></table></div>`;
}

/* Cross-scan entity pivot: resolve an entity's UID to every scan it appears in
   (GET /entities/{uid}). Turns a single finding into "everywhere this identifier
   was ever seen" — the correlation the operator actually wants. */
export async function entityPivot(uid, btn){
  const out = btn.parentElement.querySelector('.pivot-out');
  if (!uid){ out.innerHTML = '<span class="text-danger">no uid</span>'; return; }
  out.innerHTML = '<span class="text-muted">resolving…</span>';
  try {
    const r = await API.entityGet(uid);
    const ids = r.scan_ids||[];
    const here = S.scan ? S.scan.id : null;
    const links = ids.map(sid=>{
      const cur = sid===here ? ' (this scan)' : '';
      return `<a href="#/scaninfo?id=${encodeURIComponent(sid)}&tab=browse" class="tag" style="text-decoration:none">${esc(String(sid).slice(0,18))}${esc(cur)}</a>`;
    }).join(' ');
    out.innerHTML = `<b>${r.observation_count||0}</b> observation${(r.observation_count===1)?'':'s'} across <b>${ids.length}</b> scan${ids.length===1?'':'s'}: ${links||'<span class="text-muted">none</span>'}`;
  } catch(e){ out.innerHTML = `<span class="text-danger">${esc(e.message)}</span>`; }
}

export function toggleDetail(tr){
  const next = tr.nextElementSibling;
  if (next && next.classList.contains('entity-detail-row')){
    next.style.display = next.style.display === 'none' ? '' : 'none';
  }
}
