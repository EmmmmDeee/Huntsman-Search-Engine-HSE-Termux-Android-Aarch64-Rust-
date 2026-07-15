import { esc, fmtDate, kindPill, statusPill } from '/static/js/helpers.js';

/* ── Info / Scan Settings tab ── */
export function renderInfo(host, scan){
  const opts = scan.options || {};
  const fmtList = xs => !xs || !xs.length ? '<span class="text-muted">all (default)</span>' : xs.map(x=>`<code>${esc(x)}</code>`).join(' ');
  const rows = [
    ['Scan ID', `<code>${esc(scan.id)}</code>`],
    ['Target type', kindPill(scan.target?.kind)],
    ['Target value', `<code>${esc(scan.target?.value)}</code>`],
    ['Status', statusPill(scan.status)],
    ['Started', esc(fmtDate(scan.started_at))],
    ['Finished', esc(fmtDate(scan.finished_at))],
    ['Entities recorded', String(scan.entity_count||0)],
    ['Error', scan.error ? `<span class="scan-error">${esc(scan.error)}</span>` : '<span class="text-muted">none</span>'],
    ['Modules (allow)', fmtList(opts.modules)],
    ['Modules (exclude)', fmtList(opts.exclude_modules)],
    ['Free-only', String(opts.free_only??false)],
    ['Passive-only', String(opts.passive_only??false)],
    ['Throttle (ms)', String(opts.throttle_ms??0)],
    ['Module timeout (ms)', opts.module_timeout_ms!=null?String(opts.module_timeout_ms):'<span class="text-muted">module default</span>'],
    ['Max concurrent', String(opts.max_concurrent??0)],
    ['Min confidence', opts.min_confidence!=null?opts.min_confidence.toFixed(2):'<span class="text-muted">no filter</span>'],
    ['Depth', String(opts.depth??0)],
    ['Min expand C_eff', String(opts.min_expand_confidence??0.20)],
    ['Max entities', opts.max_entities!=null?String(opts.max_entities):'<span class="text-muted">unlimited</span>'],
    ['Max wall time (s)', opts.max_wall_time_secs!=null?String(opts.max_wall_time_secs):'<span class="text-muted">unlimited</span>'],
    ['Tags', (opts.scan_tags||[]).length ? opts.scan_tags.map(t=>`<span class="tag">${esc(t)}</span>`).join(' ') : '<span class="text-muted">none</span>'],
    ['Notes', opts.notes ? `<span style="font-size:12px">${esc(opts.notes)}</span>` : '<span class="text-muted">none</span>'],
  ];
  host.innerHTML = `
    <div class="panel panel-default">
      <div class="panel-heading"><b>Scan settings</b></div>
      <table class="table table-striped table-condensed" style="margin-bottom:0">
        <tbody>${rows.map(([k,v])=>`<tr><td style="width:220px;color:var(--text-muted)">${esc(k)}</td><td>${v}</td></tr>`).join('')}</tbody>
      </table>
    </div>
  `;
}

