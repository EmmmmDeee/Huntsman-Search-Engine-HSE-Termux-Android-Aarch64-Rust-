import { API } from '/static/js/api.js';
import { esc, kindPill } from '/static/js/helpers.js';

/* ── Timeline section — the subject's footprint reconstructed as one chronology
   (when each breach/registration/account/expiry happened), oldest first. The
   server already parses every dated evidence attribute into typed events. ── */
export const TL_KIND = {
  breach_exposure:{ic:'glyphicon-alert',cl:'#d9534f',lbl:'Breach'},
  registered:{ic:'glyphicon-globe',cl:'#337ab7',lbl:'Registered'},
  expiry:{ic:'glyphicon-time',cl:'#f0ad4e',lbl:'Expiry'},
  account_created:{ic:'glyphicon-user',cl:'#5cb85c',lbl:'Account'},
  incorporation:{ic:'glyphicon-briefcase',cl:'#337ab7',lbl:'Incorporated'},
  dissolution:{ic:'glyphicon-briefcase',cl:'#777',lbl:'Dissolved'},
  first_seen:{ic:'glyphicon-eye-open',cl:'#5bc0de',lbl:'First seen'},
  last_seen:{ic:'glyphicon-eye-close',cl:'#777',lbl:'Last seen'},
  date_of_birth:{ic:'glyphicon-gift',cl:'#777',lbl:'Born'},
  location_visited:{ic:'glyphicon-map-marker',cl:'#8e44ad',lbl:'Location'},
  event:{ic:'glyphicon-calendar',cl:'#777',lbl:'Event'},
};
export async function renderTimeline(host, id){
  host.innerHTML = '<div class="empty-state"><h3>Reconstructing the timeline…</h3></div>';
  let data;
  try { data = await API.timeline(id); }
  catch(e){ host.innerHTML = `<div class="alert alert-danger"><b>Error.</b> ${esc(e.message)}</div>`; return; }
  const events = (data && data.events) || [];
  if (!events.length){
    host.innerHTML = `<h4 style="margin-top:0"><i class="glyphicon glyphicon-time"></i>&nbsp;Footprint timeline</h4>
      <div class="empty-state"><h3>No dated events</h3>
      <p>The timeline appears when the scan surfaces dated facts — a breach date, a domain
      registration, an account-created date. None were found in this scan's evidence.</p></div>`;
    return;
  }
  const day = s => esc((s||'').slice(0,10));
  const span = events.length>1 ? ` · ${day(events[0].iso)} → ${day(events[events.length-1].iso)}` : '';
  let html = `<h4 style="margin-top:0"><i class="glyphicon glyphicon-time"></i>&nbsp;Footprint timeline</h4>
    <p class="text-muted" style="font-size:12px;margin-bottom:10px"><b>${events.length}</b> dated event${events.length===1?'':'s'}, oldest first${span}.</p>
    <div class="tl">`;
  for (const ev of events){
    const k = TL_KIND[ev.kind] || TL_KIND.event;
    html += `<div class="tl-item">
      <div class="tl-dot" style="background:${k.cl}"></div>
      <div class="tl-date">${day(ev.iso)}</div>
      <div class="tl-body">
        <span class="tl-badge" style="background:${k.cl}"><i class="glyphicon ${k.ic}"></i>&nbsp;${k.lbl}</span>
        ${esc(ev.entity_value)} ${kindPill(ev.entity_kind)}
        <div class="tl-src">${esc(ev.source)}</div>
      </div>
    </div>`;
  }
  html += '</div>';
  // Movement path — the timeline's own `location_visited` fixes walked in
  // chronological order (server-computed, `core::timeline::movement_path`).
  // Only present with ≥2 dated location fixes (e.g. ≥2 geotagged photos with
  // different capture times), so most scans simply won't show this panel.
  const mv = data && data.movement;
  if (mv && mv.legs && mv.legs.length){
    html += `<h4><i class="glyphicon glyphicon-road"></i>&nbsp;Movement path</h4>
      <p class="text-muted" style="font-size:12px;margin-bottom:10px"><b>${mv.locations_visited}</b> dated location fixes, <b>${mv.total_km.toFixed(1)} km</b> total straight-line distance.</p>
      <div class="tl">`;
    for (const leg of mv.legs){
      html += `<div class="tl-item">
        <div class="tl-dot" style="background:${TL_KIND.location_visited.cl}"></div>
        <div class="tl-date">${day(leg.from_iso)} → ${day(leg.to_iso)}</div>
        <div class="tl-body">
          <span class="tl-badge" style="background:${TL_KIND.location_visited.cl}"><i class="glyphicon glyphicon-road"></i>&nbsp;${leg.distance_km.toFixed(1)} km</span>
          ${esc(leg.from_coords)} → ${esc(leg.to_coords)}
        </div>
      </div>`;
    }
    html += '</div>';
  }
  host.innerHTML = html;
}

