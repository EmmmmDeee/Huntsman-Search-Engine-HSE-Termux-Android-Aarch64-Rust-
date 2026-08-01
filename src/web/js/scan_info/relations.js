import { esc, kindPill } from '/static/js/helpers.js';
import { S } from '/static/js/state.js';

/* ── Relations tab — typed edges from the recursive crawl (provenance) ── */
export function renderRelations(host){
  const rels = S.relations||[];
  if (!rels.length){
    host.innerHTML = '<div class="empty-state"><h3>No relations yet</h3>'
      + '<p>Typed edges appear here — infrastructure '
      + '(<code>subdomain_of</code>, <code>hosted_on</code>, <code>resolves_to</code>), '
      + 'identity (<code>identified_by</code>, <code>alias_of</code>, '
      + '<code>located_at</code>, <code>associated_with</code>) and affiliation '
      + '(<code>officer_of</code>, <code>employed_by</code>, <code>member_of</code>, '
      + '<code>controlled_by</code>, <code>operated_by</code>) — binding the subject to '
      + 'their accounts, places, associates and organisations. Run a deeper scan '
      + '(<code>--depth ≥ 1</code>) to populate them.</p></div>';
    return;
  }
  const byUid = {};
  (S.entities||[]).forEach(e=>{ byUid[e.uid] = e; });
  // Prefer the server-resolved value+kind (present for EVERY edge, regardless
  // of which entities are paged into the browser); fall back to the local
  // entity map, then to a truncated UID only if all else is missing.
  const cell = (uid, value, kind) => {
    if (value && value !== uid) return `${kindPill(kind)} <code>${esc(value)}</code>`;
    const e = byUid[uid];
    return e ? `${kindPill(e.kind)} <code>${esc(e.raw_value||e.value)}</code>`
             : `<code class="text-muted" style="font-size:10px">${esc(String(uid).slice(0,16))}…</code>`;
  };
  const rows = rels.map(r=>`<tr>
      <td>${cell(r.from_uid, r.from_value, r.from_kind)}</td>
      <td class="text-center"><span class="tag">${esc(r.kind)}</span></td>
      <td>${cell(r.to_uid, r.to_value, r.to_kind)}</td>
      <td class="text-right"><code>${r.confidence!=null?Number(r.confidence).toFixed(2):''}</code></td>
    </tr>`).join('');
  host.innerHTML = `<p class="text-muted" style="margin-bottom:8px">`
    + `${rels.length} typed edge${rels.length===1?'':'s'} — the provenance graph the recursive expansion built.</p>`
    + `<div class="table-responsive"><table class="table table-condensed table-striped tablesorter" id="rel-table">`
    + `<thead><tr><th>From</th><th class="text-center">Relation</th><th>To</th><th class="text-right">Conf</th></tr></thead>`
    + `<tbody>${rows}</tbody></table></div>`;
  if (window.jQuery && jQuery.fn.tablesorter){ try{ jQuery('#rel-table').tablesorter(); }catch(_){} }
}

