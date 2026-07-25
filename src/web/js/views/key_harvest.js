import { API } from '/static/js/api.js';
import { $, esc, fmtDate, healthCell } from '/static/js/helpers.js';

/* ═══════════ Page: Key Harvest (#/harvest) ═══════════
 * Dedicated operator dashboard for HSE's proactive API-key-harvesting
 * pipeline: the permanent cross-scan `key_vault` bank, the ROI-tiered
 * `key_pool`, and a live SeekNow/OathNet/WiGLE account-health probe (the
 * same calls `hse doctor` makes, surfaced here so the check doesn't need a
 * CLI hop). Backed by the single loopback-only `/api/v1/keys/harvest` feed
 * — see `src/api/key_harvest_handlers.rs`. */

/* Last-fetched feed, cached at module scope so the pool table's sort/filter/
 * group controls can re-render from memory without re-hitting the endpoint
 * (which re-runs the live SeekNow/WiGLE network probes — not something a
 * keystroke in the filter box should trigger). */
let _data = null;
/* Pool-table view state, persisted across in-place re-renders. */
const _poolUi = { q: '', roi: 'all', sort: 'total', dir: 'desc', group: false };

export async function renderHarvest(v){
  let data = null, loadError = null;
  try { data = await API.keysHarvest(); }
  catch(e){ loadError = e; }
  _data = data;

  if (!data){
    v.innerHTML = `
      <div class="page-header" style="margin-top:0;border-bottom:1px solid #eee;padding-bottom:8px">
        <h3 style="margin:0"><i class="glyphicon glyphicon-flash"></i>&nbsp;Key Harvest</h3>
      </div>
      <div class="alert alert-danger">
        <strong>Could not load the key harvest feed.</strong> ${esc(loadError ? loadError.message : 'unknown error')}
        <p style="margin:8px 0 0;font-size:12px">This dashboard is loopback-only — if HSE is bound to a LAN
        address, open it from <code>127.0.0.1</code>/<code>localhost</code> on the device itself.</p>
      </div>`;
    return;
  }

  v.innerHTML = `
    <div class="page-header" style="margin-top:0;border-bottom:1px solid #eee;padding-bottom:8px">
      <h3 style="margin:0"><i class="glyphicon glyphicon-flash"></i>&nbsp;Key Harvest
        <button class="btn btn-default btn-sm pull-right" onclick="refreshHarvest()"><i class="glyphicon glyphicon-refresh"></i>&nbsp;Refresh</button>
      </h3>
      <p class="text-muted" style="font-size:12px;margin:6px 0 0">
        Every foreign API key HSE has ever harvested during a scan — OathNet/SeekNow breach
        queries, leaked bios, crawled pages — plus live account health for the two paid
        breach-search providers that drive the harvest.
      </p>
    </div>
    ${accountHealthPanel(data.accounts)}
    ${vaultPanel(data.vault)}
    ${poolPanel(data.pool)}
  `;
}

/* Re-render in place (bound to window in main.js, invoked from the Refresh button). */
export async function refreshHarvest(){
  const v = $('#view');
  if (v) await renderHarvest(v);
}

/* ─── Provider account health: SeekNow / OathNet / WiGLE ─── */
function accountHealthPanel(accounts){
  const a = accounts || {};
  const seeknow = a.seeknow || {};
  const oathnet = a.oathnet || {};
  const wigle = a.wigle || {};

  const card = (title, bodyHtml, ok) => `
    <div class="col-md-4 col-sm-6">
      <div class="stat-card" style="text-align:left;padding:12px 14px">
        <div class="lab" style="display:flex;justify-content:space-between;align-items:center">
          <b>${esc(title)}</b>
          ${ok === true ? '<span class="label label-success">ok</span>'
            : ok === false ? '<span class="label label-danger">attention</span>'
            : '<span class="label label-default">unknown</span>'}
        </div>
        <div style="font-size:12px;margin-top:6px;color:var(--text-dim)">${bodyHtml}</div>
      </div>
    </div>`;

  const seeknowBody = seeknow.invalid
    ? 'INVALID — the configured key was rejected. Set a valid key via Settings or <code>HUNTSMAN_SEEKNOW_KEY</code>.'
    : seeknow.reachable
      ? `Credits remaining: <b>${esc(seeknow.credits_remaining)}</b>${seeknow.credits_limit != null ? ' / ' + esc(seeknow.credits_limit) : ' (daily limit not reported)'}`
      : 'Could not reach SeekNow (network error or unexpected response).';
  const seeknowOk = seeknow.invalid ? false : (seeknow.reachable ? true : null);

  const rq = oathnet.real_quota;
  const oathnetBody = `Scan budget: <b>${esc(oathnet.scan_used)}</b> / ${esc(oathnet.scan_cap)}
    &nbsp;·&nbsp; Session: <b>${esc(oathnet.session_used)}</b> / ${esc(oathnet.session_cap)}
    ${oathnet.quota_exhausted ? '<br><span class="text-danger">daily quota exhausted</span>' : ''}
    ${rq
      ? `<br>Real daily quota: <b>${esc(rq.left_today)}</b>${rq.daily_limit != null ? ' / ' + esc(rq.daily_limit) : ''}${rq.is_unlimited ? ' (unlimited plan)' : ''} remaining
         &nbsp;·&nbsp; <b>${esc(rq.used_today)}</b> used today
         <br><span style="font-size:11px">Observed on the last successful search this process — OathNet has no dedicated
         account-status endpoint to probe on demand, but every search response carries this for free.</span>`
      : `<br><span style="font-size:11px">OathNet has no dedicated account-status endpoint to probe on demand — the real
         daily quota will appear here after the first successful search this process makes. Until then, this is only
         HSE's own process-local budget/quota state, not the provider's.</span>`}`;
  const oathnetOk = oathnet.quota_exhausted ? false : (rq ? rq.left_today > 0 : true);

  const wigleFresh = wigle.last_polled_ts
    ? `<br><span style="font-size:11px">Checked ${esc(fmtDate(wigle.last_polled_ts))}</span>`
    : '<br><span style="font-size:11px">Not polled yet this process — a WiGLE lookup during a scan populates this.</span>';
  const wigleBody = (wigle.verified === false
    ? 'Email NOT verified — WiGLE throttles DB queries until the account email is confirmed.'
    : wigle.verified === true
      ? `Email verified${wigle.user ? ' · user <code>' + esc(wigle.user) + '</code>' : ''}`
      : '/profile/user not reachable this check.') + wigleFresh;
  const wigleOk = wigle.verified === undefined || wigle.verified === null ? null : wigle.verified;

  return `
    <div class="panel panel-default">
      <div class="panel-heading"><b>Provider account health</b>
        <span class="text-muted pull-right" style="font-size:12px">live probe · loopback-only</span>
      </div>
      <div class="panel-body">
        <div class="row">
          ${card('SeekNow', seeknowBody, seeknowOk)}
          ${card('OathNet', oathnetBody, oathnetOk)}
          ${card('WiGLE', wigleBody, wigleOk)}
        </div>
      </div>
    </div>`;
}

/* ─── Key vault: the permanent cross-scan bank ─── */
const ROI_LABEL = { multiplier: 'Multiplier', expansion: 'Expansion', terminal: 'Terminal' };
const ROI_WEIGHT = { multiplier: 3, expansion: 2, terminal: 1 };
function roiBadge(tier){
  const cls = tier === 'multiplier' ? 'label-success' : tier === 'expansion' ? 'label-info' : 'label-default';
  return `<span class="label ${cls}">${esc(ROI_LABEL[tier] || tier)}</span>`;
}

function vaultPanel(vault){
  const v = vault || {};
  const census = v.osint_provider_census || [];
  const recent = v.recent || [];
  const total = v.total_count || 0;
  const osint = v.osint_count || 0;
  const recentLimit = v.recent_limit || recent.length;

  const censusRows = census.map(c => `
    <tr>
      <td><span class="tag">${esc(c.category)}</span></td>
      <td><b>${esc(c.service)}</b></td>
      <td class="text-right">${esc(c.count)}</td>
      <td>${roiBadge(c.roi_tier)}</td>
    </tr>`).join('');

  const recentRows = recent.map(e => `
    <tr>
      <td><b>${esc(e.service)}</b></td>
      <td><code>${esc(e.masked)}</code></td>
      <td>${e.category ? `<span class="tag">${esc(e.category)}</span>` : '<span class="text-muted">infra</span>'}</td>
      <td>${roiBadge(e.roi_tier)}</td>
      <td style="font-size:11px">${e.provider ? esc(e.provider) : '<span class="text-muted">—</span>'}</td>
      <td class="text-right">${esc(e.discovery_count)}</td>
      <td style="font-size:11px;color:var(--text-dim)">${esc(fmtDate(e.first_seen_at))}</td>
      <td style="font-size:11px;color:var(--text-dim)">${esc(fmtDate(e.last_seen_at))}</td>
    </tr>`).join('');

  return `
    <div class="panel panel-default">
      <div class="panel-heading"><b>Key vault — permanent harvest bank</b>
        <span class="text-muted pull-right" style="font-size:12px">${esc(total)} key(s) ever seen · never auto-purged</span>
      </div>
      <div class="panel-body">
        <p class="text-muted" style="font-size:12px">
          Every foreign API key found in any scan is recorded here permanently, deduplicated by
          value, with first/last-seen timestamps and a discovery count. Masked; the plaintext is
          never sent to the browser.
        </p>
        ${census.length ? `
          <h5 style="margin:10px 0 4px"><b>OSINT provider census</b>
            <span class="text-muted" style="font-weight:normal;font-size:11px">(${esc(osint)} of ${esc(total)} key(s) are catalogued OSINT/recon tooling)</span></h5>
          <div class="table-responsive"><table class="table table-condensed">
            <thead><tr><th>Category</th><th>Service</th><th class="text-right">Keys</th><th>ROI tier</th></tr></thead>
            <tbody>${censusRows}</tbody>
          </table></div>`
          : `<p class="text-muted" style="font-size:12px">No catalogued OSINT-provider keys harvested yet${total ? ' — the ' + esc(total) + ' key(s) below are generic infrastructure (cloud, payment, tokens, …)' : ''}.</p>`}
        ${recent.length ? `
          <h5 style="margin:14px 0 4px"><b>Recently seen</b>
            <span class="text-muted" style="font-weight:normal;font-size:11px">(every harvested key, most-recent first${total > recent.length ? ` · showing the ${esc(recent.length)} newest of ${esc(total)} — capped at ${esc(recentLimit)}` : ''})</span></h5>
          <div class="table-responsive"><table class="table table-condensed">
            <thead><tr><th>Service</th><th>Key</th><th>Category</th><th>ROI</th><th>Found by</th><th class="text-right">Seen</th><th>First</th><th>Last</th></tr></thead>
            <tbody>${recentRows}</tbody>
          </table></div>`
          : (total ? '' : '<p class="text-muted" style="font-size:12px">Nothing harvested yet — run a scan and foreign keys found along the way land here.</p>')}
      </div>
    </div>`;
}

/* ─── Key pool: ROI-tiered rotation-ready keys ───
 * The pool routinely runs to dozens of services (generic_hex alone can hold
 * hundreds of thousands of keys), so the table is sortable, filterable by name
 * and ROI tier, and groupable by tier. All interaction is client-side over the
 * already-fetched feed (`_data`) — see the re-render note at the top. */
const POOL_COLS = [
  { key: 'service',      label: 'Service', num: false, align: '' },
  { key: 'roi_tier',     label: 'ROI',     num: false, align: '' },
  { key: 'total',        label: 'Total',   num: true,  align: 'text-right' },
  { key: 'active',       label: 'Active',  num: true,  align: 'text-right' },
  { key: 'rate_limited', label: 'Rate-lim',num: true,  align: 'text-right' },
  { key: 'exhausted',    label: 'Exh.',    num: true,  align: 'text-right' },
  { key: 'invalid',      label: 'Invalid', num: true,  align: 'text-right' },
  { key: 'untested',     label: 'Untested',num: true,  align: 'text-right' },
  { key: 'revoked',      label: 'Revoked', num: true,  align: 'text-right' },
  { key: 'uses',         label: 'Uses',    num: true,  align: 'text-right' },
  { key: 'errors',       label: 'Errors',  num: true,  align: 'text-right' },
  { key: 'avg_health',   label: 'Health',  num: true,  align: 'text-right' },
];

/* A single service's value for the active sort key, normalised to a number for
 * numeric columns so the comparison is total and stable. `avg_health === null`
 * (an all-untested pool) sorts BELOW every graded pool. */
function poolSortVal(s, key){
  if (key === 'service') return String(s.service || '');
  if (key === 'roi_tier') return ROI_WEIGHT[s.roi_tier] || 0;
  if (key === 'avg_health') return s.avg_health == null ? -1 : s.avg_health;
  return s[key] || 0;
}

function poolSorted(services){
  const { q, roi, sort, dir } = _poolUi;
  const needle = q.trim().toLowerCase();
  let rows = services.filter(s =>
    (!needle || String(s.service || '').toLowerCase().includes(needle)) &&
    (roi === 'all' || s.roi_tier === roi));
  const mul = dir === 'asc' ? 1 : -1;
  rows.sort((a, b) => {
    const va = poolSortVal(a, sort), vb = poolSortVal(b, sort);
    let c;
    if (typeof va === 'string') c = va.localeCompare(vb);
    else c = va < vb ? -1 : va > vb ? 1 : 0;
    // Deterministic tie-break on service name so equal rows never reorder.
    if (c === 0 && sort !== 'service') c = String(a.service).localeCompare(String(b.service));
    return c * mul;
  });
  return rows;
}

function poolRowHtml(s){
  return `
    <tr>
      <td><b>${esc(s.service)}</b></td>
      <td>${roiBadge(s.roi_tier)}</td>
      <td class="text-right">${esc(s.total)}</td>
      <td class="text-right">${esc(s.active)}</td>
      <td class="text-right">${esc(s.rate_limited)}</td>
      <td class="text-right">${esc(s.exhausted)}</td>
      <td class="text-right">${esc(s.invalid)}</td>
      <td class="text-right">${esc(s.untested)}</td>
      <td class="text-right">${esc(s.revoked)}</td>
      <td class="text-right">${esc(s.uses)}</td>
      <td class="text-right">${esc(s.errors)}</td>
      <td class="text-right">${healthCell(s)}</td>
    </tr>`;
}

function poolHeadHtml(){
  const { sort, dir } = _poolUi;
  return '<tr>' + POOL_COLS.map(c => {
    const caret = c.key === sort ? (dir === 'asc' ? ' ▲' : ' ▼') : '';
    return `<th class="${c.align}" style="cursor:pointer;white-space:nowrap" onclick="harvestPoolSort('${c.key}')" title="Sort by ${esc(c.label)}">${esc(c.label)}${caret}</th>`;
  }).join('') + '</tr>';
}

/* The sortable/filterable body only — re-rendered in place by the controls so
 * the filter input keeps focus between keystrokes. */
function poolTableHtml(pool){
  const services = (pool && pool.services) || [];
  const rows = poolSorted(services);
  const summary = `<p class="text-muted" style="font-size:11px;margin:0 0 6px">
    Showing <b>${rows.length}</b> of ${services.length} service(s)${_poolUi.q || _poolUi.roi !== 'all' ? ' (filtered)' : ''}.</p>`;

  if (!services.length) return '<p class="text-muted" style="font-size:12px">No keys in the pool yet.</p>';
  if (!rows.length) return summary + '<p class="text-muted" style="font-size:12px">No service matches the current filter.</p>';

  let body;
  if (_poolUi.group){
    // Group by ROI tier (Multiplier → Expansion → Terminal), each block still
    // ordered by the active column sort.
    const order = ['multiplier', 'expansion', 'terminal'];
    const groups = order
      .map(t => [t, rows.filter(r => r.roi_tier === t)])
      .filter(([, rs]) => rs.length);
    // Any tier not in the canonical order (defensive) trails at the end.
    const known = new Set(order);
    const extra = rows.filter(r => !known.has(r.roi_tier));
    body = groups.map(([t, rs]) => `
      <tr class="active"><td colspan="${POOL_COLS.length}" style="font-weight:bold">
        ${roiBadge(t)} <span class="text-muted" style="font-weight:normal;font-size:11px">${rs.length} service(s)</span>
      </td></tr>${rs.map(poolRowHtml).join('')}`).join('');
    if (extra.length) body += extra.map(poolRowHtml).join('');
  } else {
    body = rows.map(poolRowHtml).join('');
  }

  return summary + `<div class="table-responsive"><table class="table table-condensed">
      <thead>${poolHeadHtml()}</thead>
      <tbody>${body}</tbody>
    </table></div>`;
}

function poolPanel(pool){
  const count = (pool && pool.count) || 0;
  const roiOpt = (val, label) => `<option value="${val}"${_poolUi.roi === val ? ' selected' : ''}>${label}</option>`;
  return `
    <div class="panel panel-default" id="harvest-pool">
      <div class="panel-heading"><b>Key pool — ROI-tiered rotation view</b>
        <span class="text-muted pull-right" style="font-size:12px">${esc(count)} service(s) · loopback-only</span>
      </div>
      <div class="panel-body">
        <p class="text-muted" style="font-size:12px">
          Per-service pool health with each service's key-discovery ROI tier attached — Multiplier
          services (Shodan, Hunter, the breach pools, …) cascade into more keys and are the
          highest-value targets to keep healthy. <b>Health</b> is the mean over each pool's
          <i>exercised</i> keys, or <span class="text-muted">untested</span> when none have been
          dispatched yet. Manage/rotate/revoke individual keys on the <a href="#/opts">Settings</a> page.
        </p>
        <div class="form-inline" style="margin-bottom:8px">
          <input type="text" class="form-control input-sm" placeholder="Filter by service…"
            value="${esc(_poolUi.q)}" oninput="harvestPoolFilter(this.value)" style="max-width:220px">
          <select class="form-control input-sm" onchange="harvestPoolRoi(this.value)" style="max-width:170px">
            ${roiOpt('all', 'All ROI tiers')}
            ${roiOpt('multiplier', 'Multiplier only')}
            ${roiOpt('expansion', 'Expansion only')}
            ${roiOpt('terminal', 'Terminal only')}
          </select>
          <label style="font-weight:normal;font-size:12px;margin-left:6px">
            <input type="checkbox" onchange="harvestPoolGroup(this.checked)"${_poolUi.group ? ' checked' : ''}> group by ROI tier
          </label>
        </div>
        <div id="harvest-pool-table">${poolTableHtml(pool)}</div>
      </div>
    </div>`;
}

/* Re-render ONLY the pool table body from the cached feed — leaves the controls
 * (and the filter input's focus/caret) untouched. */
function rerenderPoolTable(){
  const host = $('#harvest-pool-table');
  if (host && _data) host.innerHTML = poolTableHtml(_data.pool);
}

/* ─── Pool-table control handlers (bound to window in main.js) ─── */
export function harvestPoolFilter(val){ _poolUi.q = val || ''; rerenderPoolTable(); }
export function harvestPoolRoi(val){ _poolUi.roi = val || 'all'; rerenderPoolTable(); }
export function harvestPoolGroup(on){ _poolUi.group = !!on; rerenderPoolTable(); }
export function harvestPoolSort(col){
  if (_poolUi.sort === col){
    _poolUi.dir = _poolUi.dir === 'asc' ? 'desc' : 'asc';
  } else {
    _poolUi.sort = col;
    // Sensible first click: names ascend A→Z, counts/health descend high→low.
    _poolUi.dir = (col === 'service') ? 'asc' : 'desc';
  }
  rerenderPoolTable();
}
