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
  /* `best_location` has TWO server shapes and this view has to read both.
     The AU-059 synergy fix carries {synergy_confidence, rule_id, class_count}
     and no top-level locality; the single-signal fallback carries
     {locality, confidence, basis, source}. BOTH nest the independent-source
     agreement under `corroboration`, which is the only place `classes` has
     ever existed.

     This view previously read `loc.locality` and `loc.classes` off the top
     level only. `loc.classes` is emitted at the top level by neither shape, so
     the class labels never rendered at all; and `locality` is absent from the
     AU-059 shape — the headline case this panel is named after — so the place
     line degraded to the bare state exactly when the verdict was strongest.
     The server had computed both and put them one level down the whole time.

     Read through to `corroboration` rather than asking the server to also
     promote these to the top level: duplicating them would give the same value
     two homes in one payload, and one of them would eventually drift. */
  const corr = loc.corroboration || {};
  const locality = loc.locality != null ? loc.locality : corr.locality;
  const place = [locality, loc.state || corr.state].filter(Boolean).join(', ');
  const conf = loc.synergy_confidence != null ? loc.synergy_confidence
             : (loc.confidence != null ? loc.confidence : null);
  const classes = loc.classes || corr.classes || [];
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

