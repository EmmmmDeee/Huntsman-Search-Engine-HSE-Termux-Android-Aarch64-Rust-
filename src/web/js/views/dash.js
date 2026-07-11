import { API } from '/static/js/api.js';
import { esc, statusPill } from '/static/js/helpers.js';
import { apiBudgetsPanel, renderScansTable, wireScansTable } from '/static/js/views/scans.js';

/* ═══════════ Page: DASHBOARD (#/dash) ═══════════ */
export async function renderDash(v){
  const [stats, mods, scansData] = await Promise.all([API.stats(), API.modules(), API.scans()]);
  const s = stats;
  const recent = (scansData.scans || []).slice(0, 8);
  const byStatus = s.scans_by_status || {};
  v.innerHTML = `
    <div class="page-header" style="margin-top:0;border-bottom:1px solid #eee;padding-bottom:8px">
      <h3 style="margin:0"><i class="glyphicon glyphicon-dashboard"></i>&nbsp;Dashboard</h3>
    </div>
    <div class="row">
      <div class="col-md-3 col-sm-6 col-xs-6">
        <div class="stat-card">
          <div class="lab">Total Scans</div>
          <div class="val">${s.scans_total||0}</div>
        </div>
      </div>
      <div class="col-md-3 col-sm-6 col-xs-6">
        <div class="stat-card">
          <div class="lab">Total Entities</div>
          <div class="val">${s.entities_total||0}</div>
        </div>
      </div>
      <div class="col-md-3 col-sm-6 col-xs-6">
        <div class="stat-card">
          <div class="lab">Modules Loaded</div>
          <div class="val">${s.modules||0}</div>
        </div>
      </div>
      <div class="col-md-3 col-sm-6 col-xs-6">
        <a href="#/live" class="stat-card" style="display:block;text-decoration:none;color:inherit" title="Open Live Monitor">
          <div class="lab">Live Sessions</div>
          <div class="val">${s.live_sessions||0}</div>
        </a>
      </div>
    </div>
    <div class="row" style="margin-top:12px">
      <div class="col-md-4">
        <div class="panel panel-default">
          <div class="panel-heading"><b>Scan Status</b></div>
          <div class="panel-body">
            <table class="table table-condensed" style="margin-bottom:0">
              ${Object.entries(byStatus).map(([k,n])=>`<tr><td>${statusPill(k)}</td><td class="text-right"><b>${n}</b></td></tr>`).join('')}
              ${Object.keys(byStatus).length===0?'<tr><td colspan="2" class="text-center text-muted">No scans yet</td></tr>':''}
            </table>
          </div>
        </div>
      </div>
      <div class="col-md-4">
        <div class="panel panel-default">
          <div class="panel-heading"><b>Quick Actions</b></div>
          <div class="panel-body">
            <a href="#/newscan" class="btn btn-danger btn-block"><i class="glyphicon glyphicon-plus"></i>&nbsp;New Scan</a>
            <a href="#/scans" class="btn btn-default btn-block" style="margin-top:6px"><i class="glyphicon glyphicon-list"></i>&nbsp;View Scans</a>
            <a href="#/opts" class="btn btn-default btn-block" style="margin-top:6px"><i class="glyphicon glyphicon-wrench"></i>&nbsp;Settings</a>
          </div>
        </div>
      </div>
      <div class="col-md-4">
        <div class="panel panel-default">
          <div class="panel-heading"><b>System</b></div>
          <div class="panel-body">
            <table class="table table-condensed" style="margin-bottom:0">
              <tr><td>Version</td><td class="text-right"><code>v${esc(s.version||'?')}</code></td></tr>
              <tr><td>Modules</td><td class="text-right"><b>${mods.count||0}</b></td></tr>
              <tr><td>Free modules</td><td class="text-right">${(mods.modules||[]).filter(m=>m.cost==='free').length}</td></tr>
              <tr><td>Key-gated</td><td class="text-right">${(mods.modules||[]).filter(m=>m.cost==='key_gated').length}</td></tr>
              <tr><td>Paid</td><td class="text-right">${(mods.modules||[]).filter(m=>m.cost==='paid').length}</td></tr>
            </table>
          </div>
        </div>
      </div>
    </div>

    ${apiBudgetsPanel(s)}

    <div class="panel panel-default" style="margin-top:12px">
      <div class="panel-heading"><b>Recent Scans</b>
        <a href="#/scans" class="pull-right" style="font-size:12px">View all &rarr;</a>
      </div>
      ${recent.length ? renderScansTable(recent)
        : '<div class="panel-body text-center text-muted">No scans yet — start one from <a href="#/newscan">New Scan</a>.</div>'}
    </div>`;
  if (recent.length) wireScansTable();
}

