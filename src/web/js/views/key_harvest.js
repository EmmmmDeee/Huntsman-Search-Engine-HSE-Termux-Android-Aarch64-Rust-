import { API } from '/static/js/api.js';
import { $, esc, fmtDate } from '/static/js/helpers.js';

/* ═══════════ Page: Key Harvest (#/harvest) ═══════════
 * Dedicated operator dashboard for HSE's proactive API-key-harvesting
 * pipeline: the permanent cross-scan `key_vault` bank, the ROI-tiered
 * `key_pool`, and a live SeekNow/OathNet/WiGLE account-health probe (the
 * same calls `hse doctor` makes, surfaced here so the check doesn't need a
 * CLI hop). Backed by the single loopback-only `/api/v1/keys/harvest` feed
 * — see `src/api/key_harvest_handlers.rs`. */
export async function renderHarvest(v){
  let data = null, loadError = null;
  try { data = await API.keysHarvest(); }
  catch(e){ loadError = e; }

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

  const oathnetBody = `Scan budget: <b>${esc(oathnet.scan_used)}</b> / ${esc(oathnet.scan_cap)}
    &nbsp;·&nbsp; Session: <b>${esc(oathnet.session_used)}</b> / ${esc(oathnet.session_cap)}
    ${oathnet.quota_exhausted ? '<br><span class="text-danger">daily quota exhausted</span>' : ''}
    <br><span style="font-size:11px">OathNet has no live account-health endpoint — this is the
    process-local budget/quota state, not a network probe.</span>`;
  const oathnetOk = oathnet.quota_exhausted ? false : true;

  const wigleBody = wigle.verified === false
    ? 'Email NOT verified — WiGLE throttles DB queries until the account email is confirmed.'
    : wigle.verified === true
      ? `Email verified${wigle.user ? ' · user <code>' + esc(wigle.user) + '</code>' : ''}`
      : '/profile/user not reachable this check.';
  const wigleOk = wigle.verified === undefined ? null : wigle.verified;

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
function roiBadge(tier){
  const cls = tier === 'multiplier' ? 'label-success' : tier === 'expansion' ? 'label-info' : 'label-default';
  return `<span class="label ${cls}">${esc(ROI_LABEL[tier] || tier)}</span>`;
}

function vaultPanel(vault){
  const v = vault || {};
  const census = v.osint_provider_census || [];
  const recent = v.recent || [];

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
      <td class="text-right">${esc(e.discovery_count)}</td>
      <td style="font-size:11px;color:var(--text-dim)">${esc(fmtDate(e.first_seen_at))}</td>
      <td style="font-size:11px;color:var(--text-dim)">${esc(fmtDate(e.last_seen_at))}</td>
    </tr>`).join('');

  return `
    <div class="panel panel-default">
      <div class="panel-heading"><b>Key vault — permanent harvest bank</b>
        <span class="text-muted pull-right" style="font-size:12px">${esc(v.total_count||0)} key(s) ever seen · never auto-purged</span>
      </div>
      <div class="panel-body">
        <p class="text-muted" style="font-size:12px">
          Every foreign API key found in any scan is recorded here permanently, deduplicated by
          value, with first/last-seen timestamps and a discovery count. Masked; the plaintext is
          never sent to the browser.
        </p>
        ${census.length ? `
          <h5 style="margin:10px 0 4px"><b>OSINT provider census</b></h5>
          <div class="table-responsive"><table class="table table-condensed">
            <thead><tr><th>Category</th><th>Service</th><th class="text-right">Keys</th><th>ROI tier</th></tr></thead>
            <tbody>${censusRows}</tbody>
          </table></div>` : '<p class="text-muted" style="font-size:12px">No OSINT-provider keys harvested yet.</p>'}
        ${recent.length ? `
          <h5 style="margin:14px 0 4px"><b>Recently seen</b>
            <span class="text-muted" style="font-weight:normal;font-size:11px">(top ${esc(v.recent_limit||recent.length)})</span></h5>
          <div class="table-responsive"><table class="table table-condensed">
            <thead><tr><th>Service</th><th>Key</th><th>Category</th><th>ROI</th><th class="text-right">Seen</th><th>First</th><th>Last</th></tr></thead>
            <tbody>${recentRows}</tbody>
          </table></div>` : ''}
      </div>
    </div>`;
}

/* ─── Key pool: ROI-tiered rotation-ready keys ─── */
function poolPanel(pool){
  const services = (pool && pool.services) || [];
  const rows = services.map(s => `
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
      <td class="text-right">${Math.round((s.avg_health||0)*100)}%</td>
    </tr>`).join('');

  return `
    <div class="panel panel-default">
      <div class="panel-heading"><b>Key pool — ROI-tiered rotation view</b>
        <span class="text-muted pull-right" style="font-size:12px">${esc((pool&&pool.count)||0)} service(s) · loopback-only</span>
      </div>
      <div class="panel-body">
        <p class="text-muted" style="font-size:12px">
          Per-service pool health with each service's key-discovery ROI tier attached — Multiplier
          services (Shodan, Hunter, the breach pools, …) cascade into more keys and are the
          highest-value targets to keep healthy. Manage/rotate/revoke individual keys on the
          <a href="#/opts">Settings</a> page.
        </p>
        ${services.length ? `<div class="table-responsive"><table class="table table-condensed">
          <thead><tr><th>Service</th><th>ROI</th><th class="text-right">Total</th><th class="text-right">Active</th>
            <th class="text-right">Rate-lim</th><th class="text-right">Exh.</th><th class="text-right">Invalid</th>
            <th class="text-right">Untested</th><th class="text-right">Revoked</th><th class="text-right">Health</th></tr></thead>
          <tbody>${rows}</tbody>
        </table></div>` : '<p class="text-muted" style="font-size:12px">No keys in the pool yet.</p>'}
      </div>
    </div>`;
}
