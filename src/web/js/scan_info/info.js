import { API } from '/static/js/api.js';
import { esc, fmtDate, kindPill, statusPill } from '/static/js/helpers.js';
import { S } from '/static/js/state.js';

/* ── Scan Settings — the scan's configuration + run metadata. Surfaced as the
   "Scan Settings" lens under Insights (SpiderFoot's Scan Settings tab), and
   readable from S.scan so it fits the (host) lens signature. ── */
export function renderScanSettings(host, scan){
  scan = scan || S.scan || {};
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
    </div>`;
}

/* ── Exposure Index ──
   The calibrated 0–100 headline verdict with its per-signal breakdown. The CLI
   dossier and the debug bundle both OPEN with this; the web console — the
   primary interface on a Termux/Android device — must too, so the Summary tab
   leads with it. Fetched separately so a failure here degrades to a quiet
   notice instead of taking the surrounding view down with it. Writes into
   `host` directly so it can headline the Summary or stand alone. */
const BAND_CLASS = { MINIMAL:'label-success', LOW:'label-info', MODERATE:'label-warning', HIGH:'label-danger', CRITICAL:'label-danger' };
export async function renderExposure(host, scanId){
  if (!host) return;
  let x = null;
  try { x = await API.exposure(scanId); }
  catch { host.innerHTML = ''; return; }   // never block the surrounding view
  if (!x || x.score == null){ host.innerHTML = ''; return; }

  const band = String(x.band || '');
  const cls = BAND_CLASS[band.toUpperCase()] || 'label-default';
  const comps = (x.components || []).map(c => {
    // Coerce to numbers and clamp to 0–100: the values are trusted backend
    // integers today, but a non-numeric/over-max value must never emit
    // `width:NaN%` or `width:120%` and break the bar layout.
    const max = Number(c.max) || 0;
    const score = Number(c.score) || 0;
    const pct = max ? Math.max(0, Math.min(100, Math.round((score / max) * 100))) : 0;
    return `
      <tr>
        <td style="width:190px">${esc(c.name)}</td>
        <td class="text-right" style="width:70px"><code>${esc(score)}/${esc(max)}</code></td>
        <td style="width:120px">
          <div style="background:var(--border,#eee);height:6px;border-radius:3px;overflow:hidden">
            <div style="width:${pct}%;height:6px;background:var(--accent,#337ab7)"></div>
          </div>
        </td>
        <td style="font-size:12px;color:var(--text-dim)">${esc(c.detail || '')}</td>
      </tr>`;
  }).join('');

  host.innerHTML = `
    <div class="panel panel-default">
      <div class="panel-heading"><b>Exposure Index</b>
        <span class="text-muted pull-right" style="font-size:12px">calibrated 0–100 · same assessment as the CLI dossier</span>
      </div>
      <div class="panel-body">
        <div style="font-size:22px;margin-bottom:2px">
          <b>${esc(x.score)}</b><span class="text-muted" style="font-size:14px">/100</span>
          &nbsp;<span class="label ${cls}">${esc(band)}</span>
        </div>
        ${x.summary ? `<div class="text-muted" style="font-size:12px;margin-bottom:8px">${esc(x.summary)}</div>` : ''}
        ${comps ? `<table class="table table-condensed" style="margin-bottom:0"><tbody>${comps}</tbody></table>` : ''}
      </div>
    </div>`;
}
