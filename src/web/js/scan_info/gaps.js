import { API } from '/static/js/api.js';
import { esc } from '/static/js/helpers.js';

/* ── Discovery gaps — validated seeds with no evidence-backed link, why they're
   isolated, and the corrective scans that would connect them. GET /scans/{id}/gaps.
   The gap-resolution loop made legible: turns "no links" into "run these next". ── */
export async function renderGaps(host, id){
  let data;
  try { data = await API.gaps(id); }
  catch(e){ host.innerHTML = ''; return; }
  if (!data || data.null_state){ host.innerHTML = ''; return; }
  const orphans = data.orphans || [];
  const linkedPct = Math.round((Number(data.linked_fraction)||0)*100);
  let html = `<h4 style="margin-top:0"><i class="glyphicon glyphicon-unchecked"></i>&nbsp;Discovery gaps</h4>
    <p class="text-muted" style="font-size:12px;margin-bottom:8px">${data.linked_seeds}/${data.total_seeds} seeds linked (${linkedPct}%). Isolated seeds below are discovery blind spots — each shows the corrective scan that would connect it.</p>`;
  if (!orphans.length){
    html += `<p class="text-success" style="font-size:12px"><i class="glyphicon glyphicon-ok"></i> Every validated seed is linked into the graph.</p>`;
    host.innerHTML = html; return;
  }
  const badge = { unexpanded:'label-warning', below_expand_floor:'label-default', terminal:'label-info' };
  const nonTerminal = orphans.filter(o=>o.isolation!=='terminal');
  const terminalCount = orphans.length - nonTerminal.length;
  for (const o of nonTerminal.slice(0,15)){
    const mods = (o.corrective_modules||[]);
    const modStr = mods.length ? `<span class="text-muted" style="font-size:11px"> → run: ${mods.slice(0,6).map(esc).join(', ')}${mods.length>6?'…':''}</span>` : '';
    html += `<div style="margin-bottom:6px;font-size:12px">
      <span class="label ${badge[o.isolation]||'label-default'}">${esc(String(o.isolation).replace(/_/g,' '))}</span>
      <code>${esc(o.value||o.uid)}</code> <span class="text-muted">(${esc(o.kind)})</span>
      <div class="text-muted" style="font-size:11px;margin-left:4px">${esc(o.action)}${modStr}</div>
    </div>`;
  }
  if (nonTerminal.length>15){ html += `<div class="text-muted" style="font-size:11px">…and ${nonTerminal.length-15} more actionable gaps.</div>`; }
  if (terminalCount>0){ html += `<div class="text-muted" style="font-size:11px">+ ${terminalCount} terminal leaf/leaves (non-scannable; expected isolation).</div>`; }
  host.innerHTML = html;
}

