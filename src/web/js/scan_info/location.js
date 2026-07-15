import { API } from '/static/js/api.js';
import { attr, esc } from '/static/js/helpers.js';

/* ── Residency fix — the "where is the subject" verdict (AU-059). Powered by
      /scans/{id}/location. The map LINK opens OpenStreetMap in a new tab; it is
      a navigational anchor, NOT an embedded resource, so it stays within the
      airtight no-external-resource CSP. ── */
export async function renderLocation(host, id){
  let data;
  try { data = await API.location(id); }
  catch(e){ host.innerHTML = ''; return; }
  const loc = data && data.best_location;
  if (!loc || loc.lat == null || loc.lon == null){ host.innerHTML = ''; return; }
  const lat = Number(loc.lat), lon = Number(loc.lon);
  const place = [loc.locality, loc.state].filter(Boolean).join(', ');
  const conf = loc.synergy_confidence != null ? loc.synergy_confidence
             : (loc.confidence != null ? loc.confidence : null);
  const classes = loc.classes || [];
  const osm = `https://www.openstreetmap.org/?mlat=${lat}&mlon=${lon}#map=12/${lat}/${lon}`;
  let rows = '';
  if (place) rows += `<div style="font-size:14px"><b>${esc(place)}</b></div>`;
  rows += `<div class="text-muted" style="font-size:12px;margin-top:2px">`
    + `${lat.toFixed(4)}, ${lon.toFixed(4)}`
    + (loc.radius_km != null ? ` · ±${esc(loc.radius_km)} km` : '')
    + (conf != null ? ` · confidence ${(Number(conf)||0).toFixed(2)}` : '')
    + (loc.source ? ` · ${esc(loc.source)}` : (loc.rule_id ? ` · ${esc(loc.rule_id)}` : ''))
    + `</div>`;
  if (loc.basis) rows += `<div class="text-muted" style="font-size:11px;margin-top:2px">basis: ${esc(loc.basis)}</div>`;
  if (classes.length) rows += `<div style="margin-top:4px">`
    + classes.map(c=>`<span class="label label-info">${esc(c)}</span>`).join(' ') + `</div>`;
  host.innerHTML = `<h4 style="margin-top:0"><i class="glyphicon glyphicon-map-marker"></i>&nbsp;Residency fix</h4>
    <div style="padding:8px 10px;border-left:3px solid #5cb85c;background:rgba(92,184,92,0.07)">
      ${rows}
      <div style="margin-top:6px"><a href="${attr(osm)}" target="_blank" rel="noopener noreferrer" class="btn btn-default btn-xs"><i class="glyphicon glyphicon-globe"></i>&nbsp;View on OpenStreetMap</a></div>
    </div>`;
}

