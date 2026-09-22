/* ═══════════ Page: SIGNAL RADAR (#/radar) ═══════════
 * The signals around this device, read from the sighting table
 * (GET /api/v1/radar/signals — REQ-RADAR-002): one sweep's device roll-up on a
 * polar plot and in a table, one device's sighting track, the sweep history,
 * and the two activations (one sweep, continuous radar).
 *
 * The plot places a device by its best level — rings at −40/−60/−80/−100 dBm,
 * strongest at the centre — and at a bearing hashed from its address. The
 * bearing is a stable place to find the same device again, NOT a measured
 * direction: no on-device sensor reports one, and drawing one would fabricate
 * it. Distance is not shown for the same reason: HSE never re-derives a
 * distance from a level (docs/ROADMAP.md T5). */
import { API } from '/static/js/api.js';
import { $, $$, attr, esc, fmtClock, fmtDate, statusPill, toast, triggerBlobDownload } from '/static/js/helpers.js';
import { S } from '/static/js/state.js';
import { clearRadarTimer, pageHidden } from '/static/js/timers.js';
import { createMap } from '/static/js/radar_map.js';
import { closeLiveSse, openLiveSse } from '/static/js/scan_info/log.js';

const RADIOS = [['wifi','Wi-Fi'], ['ble','BLE'], ['bt','BT'], ['cell','Cell']];
const RADIO_LABEL = Object.fromEntries(RADIOS);
const RADIO_COLOUR = { wifi:'var(--accent)', ble:'var(--success)', bt:'var(--warning)', cell:'var(--critical)' };
const SUMMARY_KEY = { wifi:'wifi', ble:'ble', bt:'bt', cell:'cellular' };

/* View choices survive a re-render within the session: the filter an operator
   set must not reset because a sweep finished. `sid` null = the latest sweep. */
const view = { sid: null, radio: 'all', sort: 'signal', trackable: false, track: null, data: null, print: '' };
/* The map controller and the sweep it was centred on: a refresh of the same
   sweep keeps the operator's pan and zoom; a different sweep re-centres. */
let map = null, mapSweep = null;

const SORTS = {
  signal: (a,b) => ((b.best_signal_dbm ?? -999) - (a.best_signal_dbm ?? -999)) || a.network_id.localeCompare(b.network_id),
  seen:   (a,b) => ((b.last_epoch ?? 0) - (a.last_epoch ?? 0)) || a.network_id.localeCompare(b.network_id),
  name:   (a,b) => label(a).localeCompare(label(b)) || a.network_id.localeCompare(b.network_id),
};

function label(d){ return d.name || d.vendor || d.device_class || d.network_id; }
function dbm(v){ return v == null ? '—' : `${Math.round(v)} dBm`; }
function ago(epoch){
  if (!epoch) return '—';
  const s = Math.max(0, Math.floor(Date.now()/1000) - epoch);
  if (s < 60) return `${s}s ago`;
  if (s < 3600) return `${Math.floor(s/60)}m ago`;
  if (s < 86400) return `${Math.floor(s/3600)}h ago`;
  return fmtDate(epoch);
}
/* FNV-1a over the address → 0..359. Stable per device, meaningless as a
   direction (see the header). */
function hashBearing(id){
  let h = 2166136261;
  for (const c of String(id)){ h ^= c.charCodeAt(0); h = Math.imul(h, 16777619) >>> 0; }
  return h % 360;
}
/* −30 dBm or stronger sits at the centre, −100 dBm on the outer ring; a device
   the receiver never got a level for is drawn hollow on the outer ring. */
function ringRadius(v){
  if (v == null) return 140;
  const t = (-30 - v) / 70;
  return Math.round(140 * Math.min(1, Math.max(0.04, t)) * 10) / 10;
}
function colour(d){ return RADIO_COLOUR[d.radio] || 'var(--text-muted)'; }

function visibleDevices(){
  const all = view.data ? (view.data.devices || []) : [];
  const f = view.radio === 'all' ? all : all.filter(d => d.radio === view.radio);
  return f.slice().sort(SORTS[view.sort] || SORTS.signal);
}

function renderPlot(devices){
  const cx = 150, cy = 150;
  let out = `<svg class="radar-plot" viewBox="0 0 300 300" role="img" aria-label="Signal plot: strongest at the centre">`;
  out += `<line x1="${cx}" y1="8" x2="${cx}" y2="292" class="radar-axis"/><line x1="8" y1="${cy}" x2="292" y2="${cy}" class="radar-axis"/>`;
  for (const [db, r] of [[-40, 20], [-60, 60], [-80, 100], [-100, 140]]) {
    out += `<circle cx="${cx}" cy="${cy}" r="${r}" class="radar-ring"/><text x="${cx+3}" y="${cy-r-2}" class="radar-ring-lbl">${db}</text>`;
  }
  const labelled = new Set(devices.slice().sort(SORTS.signal).slice(0, 8).map(d => d.network_id));
  for (const d of devices) {
    const r = ringRadius(d.best_signal_dbm), a = hashBearing(d.network_id) * Math.PI / 180;
    const x = (cx + r * Math.sin(a)).toFixed(1), y = (cy - r * Math.cos(a)).toFixed(1);
    const fill = d.best_signal_dbm == null ? 'none' : colour(d);
    out += `<circle cx="${x}" cy="${y}" r="5" fill="${fill}" stroke="${colour(d)}" stroke-width="1.5" class="radar-dot" data-track="${attr(d.network_id)}">`
         + `<title>${esc(label(d))} · ${esc(RADIO_LABEL[d.radio] || d.radio)} · ${esc(dbm(d.best_signal_dbm))}</title></circle>`;
    if (labelled.has(d.network_id)) out += `<text x="${(+x + 7).toFixed(1)}" y="${(+y + 3).toFixed(1)}" class="radar-dot-lbl">${esc(String(label(d)).slice(0, 18))}</text>`;
  }
  return out + '</svg>';
}

function renderTable(devices){
  if (!devices.length) {
    return '<div class="empty-state"><h3>No devices in this view</h3><p>Nothing matched the current radio filter.</p></div>';
  }
  const rows = devices.map(d => `<tr>
    <td><span class="radar-swatch" style="background:${colour(d)}"></span><b>${esc(label(d))}</b>
        ${d.name && d.vendor ? `<span class="text-muted"> · ${esc(d.vendor)}</span>` : ''}
        ${d.device_class && d.device_class !== label(d) ? `<span class="text-muted"> · ${esc(d.device_class)}</span>` : ''}
        <br><code class="text-muted" style="font-size:11px">${esc(d.network_id)}</code></td>
    <td><span class="kind-pill">${esc(RADIO_LABEL[d.radio] || d.radio)}</span></td>
    <td>${d.address === 'random' ? '<span class="label label-warning" title="A rotating privacy address: seeing it twice is not seeing one device twice (AU-122)">random</span>'
         : d.address === 'fixed' ? '<span class="label label-default" title="A fixed hardware address — followable across sweeps">fixed</span>' : '<span class="text-muted">—</span>'}</td>
    <td class="text-right"><code>${esc(dbm(d.best_signal_dbm))}</code></td>
    <td class="text-right">${d.sightings}</td>
    <td>${esc(ago(d.last_epoch))}</td>
    <td class="text-right"><button class="btn btn-default btn-xs" data-track="${attr(d.network_id)}" title="Every sighting of this device in the sweep, oldest first"><i class="glyphicon glyphicon-time"></i>&nbsp;Track</button></td>
  </tr>`).join('');
  return `<div class="table-responsive"><table class="table table-condensed table-striped">
    <thead><tr><th>Device</th><th>Radio</th><th>Address</th><th class="text-right">Best</th><th class="text-right">Seen</th><th>Last</th><th></th></tr></thead>
    <tbody>${rows}</tbody></table></div>`;
}

function renderChips(){
  const s = (view.data && view.data.summary) || {};
  const chip = (key, text) => `<button type="button" class="radar-chip${view.radio === key ? ' active' : ''}" data-chip="${key}">${text}</button>`;
  let out = chip('all', `all <span class="badge">${s.devices ?? 0}</span>`);
  for (const [key, text] of RADIOS) out += chip(key, `<span class="radar-swatch" style="background:${RADIO_COLOUR[key]}"></span>${text} <span class="badge">${s[SUMMARY_KEY[key]] ?? 0}</span>`);
  return out;
}

function renderSummaryLine(){
  const d = view.data; if (!d) return '';
  const s = d.summary || {};
  const when = s.last_epoch ? fmtDate(s.last_epoch) : '—';
  return `sweep <code>${esc(d.scan_id)}</code> · ${s.sightings ?? 0} sightings · ${s.devices ?? 0} devices · `
       + `${s.fixed_address ?? 0} fixed / ${s.randomised_address ?? 0} random · ${s.named ?? 0} named · ${s.with_position ?? 0} positioned · last ${esc(when)}`
       + (d.trackable_only ? ' · <b>fixed addresses only</b>' : '')
       + (d.total > d.count ? ` · <b>showing ${d.count} of ${d.total}</b>` : '');
}

/* The map: every device with a position, at its position. Live-sweep
   sightings all carry the sweep's own fix, so they cluster on one marker with
   a count; a wardriving import spreads out. Devices without a position are
   not drawn — nothing is placed where it was not heard. */
function paintMap(devices){
  const panel = $('#radar-map-panel'), host = $('#radar-map'), note = $('#radar-map-note');
  if (!panel || !host) return;
  const positioned = devices.filter(d => d.latitude != null && d.longitude != null);
  if (!positioned.length) {
    panel.style.display = view.data ? '' : 'none';
    if (map) { map.destroy(); map = null; mapSweep = null; }
    host.style.display = 'none';
    if (note) note.textContent = 'No positioned sightings in this view — the sweep had no fresh GNSS fix, so nothing is placed on the map.';
    return;
  }
  panel.style.display = ''; host.style.display = '';
  if (note) note.textContent = `${positioned.length} of ${devices.length} devices positioned · drag to pan, +/− to zoom`;
  const groups = new Map();
  for (const d of positioned) {
    const key = `${d.latitude.toFixed(6)},${d.longitude.toFixed(6)}`;
    const g = groups.get(key) || { lat: d.latitude, lon: d.longitude, items: [] };
    g.items.push(d); groups.set(key, g);
  }
  const markers = Array.from(groups.values()).map(g => ({
    lat: g.lat, lon: g.lon, count: g.items.length,
    colour: g.items.length === 1 ? colour(g.items[0]) : 'var(--accent)',
    label: g.items.length === 1 ? `${label(g.items[0])} · ${dbm(g.items[0].best_signal_dbm)}` : g.items.slice(0, 8).map(label).join(', ') + (g.items.length > 8 ? ` +${g.items.length - 8}` : ''),
  }));
  const lat = positioned.reduce((a, d) => a + d.latitude, 0) / positioned.length;
  const lon = positioned.reduce((a, d) => a + d.longitude, 0) / positioned.length;
  if (!map) map = createMap(host, { lat, lon, zoom: 17 });
  const sweep = view.data ? view.data.scan_id : null;
  if (sweep !== mapSweep) { map.setView(lat, lon, 17); mapSweep = sweep; }
  map.setMarkers(markers);
}

function paintSignals(){
  const host = $('#radar-signals'); if (!host) return;
  paintMap(view.data ? visibleDevices() : []);
  if (!view.data) {
    host.innerHTML = '<div class="empty-state"><h3>No signals recorded yet</h3>'
      + '<p>Run a sweep or start the continuous radar above. Every Wi-Fi access point, Bluetooth device and cell tower the '
      + 'device hears becomes a sighting — level, time and the sweep\'s own GNSS fix — and appears here.</p></div>';
    const sl = $('#radar-summary'); if (sl) sl.innerHTML = '';
    const ch = $('#radar-chips'); if (ch) ch.innerHTML = '';
    return;
  }
  const devices = visibleDevices();
  const sl = $('#radar-summary'); if (sl) sl.innerHTML = renderSummaryLine();
  const ch = $('#radar-chips'); if (ch) ch.innerHTML = renderChips();
  host.innerHTML = `<div class="row"><div class="col-sm-5">${renderPlot(devices)}</div><div class="col-sm-7">${renderTable(devices)}</div></div>`;
  $$('[data-track]', host).forEach(el => el.addEventListener('click', () => showTrack(el.dataset.track)));
  $$('[data-chip]').forEach(el => el.addEventListener('click', () => { view.radio = el.dataset.chip; paintSignals(); }));
}

/* Fetch the sweep the view is about. `quiet` (the poller) repaints only when
   the answer changed, so an open table is not rebuilt under the operator's
   finger every 8 s. A 404 is "nothing recorded" (or a sweep that vanished). */
async function refreshSignals(quiet){
  let data = null;
  try { data = await API.radarSignals(view.sid, view.trackable); }
  catch (e) {
    if (!/^HTTP 404|no RF sightings|not found/i.test(e.message)) { if (!quiet) toast('Signals: ' + e.message, 'error'); return; }
  }
  const print = data ? `${data.scan_id}|${data.count}|${data.total}|${(data.summary||{}).sightings}|${(data.summary||{}).last_epoch}|${data.trackable_only}` : '';
  if (quiet && print === view.print) return;
  view.print = print; view.data = data;
  paintSignals();
  syncSweepPicker();
  const j = $('#radar-json'); if (j) j.href = API.radarSignalsUrl(data ? data.scan_id : null);
}

async function showTrack(id){
  view.track = id;
  const panel = $('#radar-track-panel'), host = $('#radar-track'), lab = $('#radar-track-label');
  if (!panel || !host) return;
  panel.style.display = '';
  if (lab) lab.textContent = ' — ' + id;
  host.innerHTML = '<div class="text-muted">Loading…</div>';
  try {
    const t = await API.radarTrack(id, view.data ? view.data.scan_id : null);
    const rows = t.sightings || [];
    if (!rows.length) { host.innerHTML = '<div class="text-muted">No sightings of this device in the sweep.</div>'; return; }
    // Across every sweep: the level over time and the trail on the map. The
    // per-sweep rows below stay the sweep's own.
    let across = null;
    try { across = await API.radarDeviceTrack(id, 500); } catch (_) {}
    const pts = across ? (across.points || []) : [];
    if (map) map.setTrail(pts.filter(p => p.latitude != null && p.longitude != null).map(p => ({ lat: p.latitude, lon: p.longitude })));
    const acrossHtml = across
      ? `<div class="text-muted" style="margin-bottom:4px">${pts.length} sighting${pts.length === 1 ? '' : 's'} across ${across.sweeps} sweep${across.sweeps === 1 ? '' : 's'}${across.count >= across.limit ? ` (newest ${across.limit})` : ''}${pts.some(p => p.latitude != null) ? ' · trail drawn on the map' : ''}</div>${renderSparkline(pts)}`
      : '';
    host.innerHTML = acrossHtml + `<div class="table-responsive"><table class="table table-condensed table-striped">
      <thead><tr><th>Observed</th><th class="text-right">Level</th><th class="text-right">Latitude</th><th class="text-right">Longitude</th><th class="text-right">±m</th><th>Source</th><th>Name</th></tr></thead>
      <tbody>${rows.map(r => `<tr>
        <td>${esc(r.observed_epoch ? fmtDate(r.observed_epoch) : (r.observed_at || '—'))}</td>
        <td class="text-right"><code>${esc(dbm(r.signal_dbm))}</code></td>
        <td class="text-right">${r.latitude == null ? '<span class="text-muted">—</span>' : esc(r.latitude.toFixed(6))}</td>
        <td class="text-right">${r.longitude == null ? '<span class="text-muted">—</span>' : esc(r.longitude.toFixed(6))}</td>
        <td class="text-right">${r.accuracy_m == null ? '—' : esc(Math.round(r.accuracy_m))}</td>
        <td><span class="kind-pill">${esc(r.source)}</span></td>
        <td>${esc(r.name || '—')}</td></tr>`).join('')}</tbody></table></div>`;
  } catch (e) { host.innerHTML = `<div class="alert alert-danger">${esc(e.message)}</div>`; }
}

function closeTrack(){ view.track = null; const p = $('#radar-track-panel'); if (p) p.style.display = 'none'; if (map) map.setTrail([]); }

/* The level over time, as the oracle app draws beside each device: one point
   per sighting that carried a level, oldest left. Nothing is interpolated. */
function renderSparkline(points){
  const levelled = points.filter(p => p.signal_dbm != null);
  if (levelled.length < 2) return '';
  const W = 420, H = 48, pad = 4;
  const lo = Math.min(-100, ...levelled.map(p => p.signal_dbm)), hi = Math.max(-30, ...levelled.map(p => p.signal_dbm));
  const x = i => (pad + i * (W - 2 * pad) / (levelled.length - 1)).toFixed(1);
  const y = v => (H - pad - (v - lo) / (hi - lo) * (H - 2 * pad)).toFixed(1);
  const pts = levelled.map((p, i) => `${x(i)},${y(p.signal_dbm)}`).join(' ');
  return `<svg class="radar-spark" viewBox="0 0 ${W} ${H}" role="img" aria-label="Level over ${levelled.length} sightings">
    <line class="radar-spark-axis" x1="${pad}" y1="${H - pad}" x2="${W - pad}" y2="${H - pad}"/>
    <polyline points="${pts}"/>
    <text x="${pad}" y="9">${Math.round(hi)} dBm</text><text x="${pad}" y="${H - pad - 2}">${Math.round(lo)} dBm</text>
    <text x="${W - 60}" y="9">${levelled.length} readings</text></svg>`;
}

/* The device's own Wi-Fi link across the sweep history (core::link::review
   over the wifi_links records): forced disconnections while the access point
   was still heard, a deauthentication pattern, an evil twin, outages on a
   schedule, and the outage timeline — each with the advice the CLI prints. */
const DISRUPTION_LABEL = { forced_disconnect: ['Forced disconnect', 'label-danger'], deauth_suspected: ['Deauthentication suspected', 'label-danger'], evil_twin_suspected: ['Evil twin suspected', 'label-danger'], periodic_outage: ['Periodic outage', 'label-warning'], outage: ['Outage', 'label-default'] };
function describeDisruption(f){
  const when = t => esc(fmtDate(t));
  switch (f.kind) {
    case 'forced_disconnect': return `${when(f.at)} — off <b>${esc(f.ssid || '?')}</b> <code>${esc(f.bssid)}</code> while it was still heard at ${esc(dbm(f.heard_dbm))}`;
    case 'deauth_suspected': return `${f.count} forced disconnections from <b>${esc(f.ssid || '?')}</b> <code>${esc(f.bssid)}</code> between ${when(f.from)} and ${when(f.to)}`;
    case 'evil_twin_suspected': return `${when(f.at)} — <b>${esc(f.ssid)}</b> from a new address <code>${esc(f.new_bssid)}</code> at ${esc(dbm(f.new_dbm))}, louder than the known <code>${esc(f.known_bssid)}</code> at ${esc(dbm(f.known_dbm))}`;
    case 'periodic_outage': return `${f.occurrences} outages every ~${esc(String(f.period_secs))} s, ${when(f.from)} → ${when(f.to)}`;
    case 'outage': return `${f.sweeps} sweep${f.sweeps === 1 ? '' : 's'} off the network, ${when(f.from)} → ${when(f.to)}`;
    default: return esc(JSON.stringify(f));
  }
}
async function refreshDisruptions(){
  const host = $('#radar-disruptions'); if (!host) return;
  let r = null;
  try { r = await API.radarDisruptions(100); } catch (e) { host.innerHTML = `<div class="text-muted" style="padding:8px 12px">${esc(e.message)}</div>`; return; }
  const findings = (r.findings || []).filter(f => f.kind !== 'outage');
  const outages = (r.findings || []).filter(f => f.kind === 'outage');
  const badge = $('#radar-disruptions-count'); if (badge) badge.textContent = findings.length;
  const note = $('#radar-disruptions-note');
  if (note) note.textContent = `— ${r.sweeps || 0} sweep${r.sweeps === 1 ? '' : 's'} reviewed, ${r.disconnected_sweeps || 0} off the network${r.unrecorded_sweeps ? `, ${r.unrecorded_sweeps} older without a link record` : ''}`;
  if (!findings.length && !outages.length) {
    host.innerHTML = '<div class="text-muted" style="padding:8px 12px">No disruption found: the link was up on every reviewed sweep, or nothing has been reviewed yet.</div>';
    return;
  }
  const row = f => { const [label, cls] = DISRUPTION_LABEL[f.kind] || [f.kind, 'label-default']; return `<div class="radar-finding"><span class="label ${cls}">${esc(label)}</span> ${describeDisruption(f)}<div class="text-muted radar-advice">${esc(f.advice || '')}</div></div>`; };
  host.innerHTML = findings.map(row).join('') + (outages.length ? `<details class="radar-outages"><summary class="text-muted">${outages.length} outage${outages.length === 1 ? '' : 's'} on the timeline</summary>${outages.map(row).join('')}</details>` : '');
}

/* Devices recurring across sweeps — the counter-surveillance review
   (core::radar_track over the sighting table): fixed hardware addresses the
   phone is not bonded to, seen in ≥2 sweeps, with the strongest level and
   how many distinct places they were heard from. */
async function refreshRecurring(){
  const host = $('#radar-recurring'); if (!host) return;
  let r = null;
  try { r = await API.radarRecurring(2, 100); } catch (e) { host.innerHTML = `<div class="text-muted" style="padding:8px 12px">${esc(e.message)}</div>`; return; }
  const devices = r.devices || [];
  const badge = $('#radar-recurring-count'); if (badge) badge.textContent = devices.length;
  const note = $('#radar-recurring-note');
  if (note) note.textContent = `— ${r.sweeps || 0} sweep${r.sweeps === 1 ? '' : 's'} reviewed${r.legacy_sweeps ? `, ${r.legacy_sweeps} from before readings were kept (recurrence only)` : ''}`;
  if (!devices.length) {
    host.innerHTML = '<div class="text-muted" style="padding:8px 12px">No fixed-address device has recurred across two sweeps yet. A randomised address cannot recur; the phone\'s own paired kit is not counted.</div>';
    return;
  }
  host.innerHTML = `<div class="table-responsive"><table class="table table-condensed table-striped">
    <thead><tr><th>Device</th><th class="text-right">Sweeps</th><th class="text-right">Best</th><th class="text-right">Places</th><th>First</th><th>Last</th><th></th></tr></thead>
    <tbody>${devices.map(d => `<tr>
      <td><b>${esc(d.name || d.vendor || d.mac)}</b>${d.vendor && d.name ? `<span class="text-muted"> · ${esc(d.vendor)}</span>` : ''}${d.device_class ? `<span class="text-muted"> · ${esc(d.device_class)}</span>` : ''}<br><code class="text-muted" style="font-size:11px">${esc(d.mac)}</code></td>
      <td class="text-right"><span class="badge">${d.sweeps_seen}</span></td>
      <td class="text-right"><code>${esc(dbm(d.best_signal_dbm))}</code></td>
      <td class="text-right">${d.distinct_positions}</td>
      <td>${esc(fmtDate(d.first_ts))}</td><td>${esc(fmtDate(d.last_ts))}</td>
      <td class="text-right"><button class="btn btn-default btn-xs" data-track="${attr(d.mac)}" title="Its sightings in the current sweep and its trail across all of them"><i class="glyphicon glyphicon-time"></i>&nbsp;Track</button></td>
    </tr>`).join('')}</tbody></table></div>`;
  $$('[data-track]', host).forEach(el => el.addEventListener('click', () => showTrack(el.dataset.track)));
}

/* Sweep history — every sweep the radar button or continuous radar queued,
   from the persisted scans table, so it survives a restart. "Load" pins the
   view to that sweep; "Latest" follows the newest again. */
function renderSweepHistory(sweeps){
  if (!sweeps.length) {
    return '<div class="empty-state"><h3>No sweeps yet</h3><p>Every sweep queued here is listed once it runs, newest first — reviewable later, even after a restart.</p></div>';
  }
  const rows = sweeps.map(sw => {
    const dur = sw.finished_at && sw.started_at ? (sw.finished_at - sw.started_at) : null;
    const cur = view.data && view.data.scan_id === sw.id;
    return `<tr${cur ? ' class="active"' : ''}>
      <td>${esc(fmtDate(sw.started_at))}</td>
      <td>${statusPill(sw.status)}${sw.interrupted ? ' <span class="label label-warning">interrupted</span>' : ''}</td>
      <td class="text-right">${dur == null ? '<span class="text-muted">—</span>' : (dur + 's')}</td>
      <td class="text-right">${sw.entity_count || 0}</td>
      <td class="text-right">
        <button class="btn btn-default btn-xs" data-load="${attr(sw.id)}" title="Show this sweep's signals"${cur ? ' disabled' : ''}><i class="glyphicon glyphicon-eye-open"></i>&nbsp;Load</button>
        <a href="#/scaninfo?id=${attr(sw.id)}" class="btn btn-default btn-xs" title="The sweep's entity graph">Entities</a>
      </td></tr>`;
  }).join('');
  return `<div class="table-responsive"><table class="table table-condensed table-striped">
    <thead><tr><th>When</th><th>Status</th><th class="text-right">Duration</th><th class="text-right">Entities</th><th></th></tr></thead>
    <tbody>${rows}</tbody></table></div>`;
}

async function refreshHistory(){
  const host = $('#radar-history'); if (!host) return;
  try {
    const sweeps = (await API.radarHistory(50)).sweeps || [];
    const badge = $('#radar-history-count'); if (badge) badge.textContent = sweeps.length;
    host.innerHTML = renderSweepHistory(sweeps);
    $$('[data-load]', host).forEach(el => el.addEventListener('click', async () => { view.sid = el.dataset.load; closeTrack(); await refreshSignals(false); await refreshHistory(); }));
  } catch (e) { host.innerHTML = `<div class="alert alert-danger">${esc(e.message)}</div>`; }
}

function syncSweepPicker(){
  const b = $('#radar-latest'); if (b) b.style.display = view.sid ? '' : 'none';
}

function syncLiveButtons(){
  const start = $('#radar-live'), stop = $('#radar-stop');
  if (start) start.style.display = S.radarLiveId ? 'none' : '';
  if (stop) stop.style.display = S.radarLiveId ? '' : 'none';
}
function setLiveStatus(text){ const el = $('#radar-live-status'); if (el) el.textContent = text; }

/* Follow a continuous radar over its own event stream (the same SSE the Live
   page tails): a `live_tick` says a sweep started, a `scan_complete` says its
   readings are persisted — the engine writes the row before it emits the
   event — so the view refreshes exactly then, not on a timer. `live_stop`
   releases the session. One stream at a time; render() closes it on leaving. */
function onLiveEvent(ev){
  if (!ev || !ev.type) return;
  if (ev.type === 'live_tick') { setLiveStatus(`continuous radar · sweep #${ev.iteration} running…`); return; }
  if (ev.type === 'scan_complete') {
    setLiveStatus(`continuous radar · sweep done at ${fmtClock()}`);
    view.sid = null; syncSweepPicker();
    refreshSignals(true); refreshRecurring(); refreshDisruptions();
    return;
  }
  if (ev.type === 'live_stop') {
    setLiveStatus(`radar stopped: ${ev.reason || ''}`);
    S.radarLiveId = null; closeLiveSse();
    const start = $('#radar-live'), stop = $('#radar-stop');
    if (start) start.style.display = ''; if (stop) stop.style.display = 'none';
  }
}
/* Attach to a radar session's stream. The browser reconnects a dropped
   EventSource on its own; while it is down the timer below polls instead
   (`S.radarStreamDown`), and on `open` after a drop the view re-reads
   everything the stream would have told it — a broadcast stream replays
   nothing emitted while the link was down. A stream the server closed for
   good (readyState CLOSED: the process went away) is released; the poller's
   `adoptRunningRadar` re-attaches if the session is listed again. */
function attachLive(id){
  S.radarLiveId = id;
  let wasDown = false;
  S.radarStreamDown = false;
  openLiveSse(id, onLiveEvent, (state, es) => {
    if (!S.liveSse) return;
    if (state === 'open') {
      S.radarStreamDown = false;
      if (wasDown) {
        wasDown = false;
        setLiveStatus('continuous radar · stream back — re-reading');
        view.sid = null; syncSweepPicker();
        refreshSignals(true); refreshRecurring(); refreshDisruptions(); refreshHistory(); adoptRunningRadar();
      }
      return;
    }
    if (es.readyState === 2) {
      // Closed for good: the server idle-closed it or is gone. Release the
      // session; a restart empties the in-memory session list, and the
      // poller says so when nothing is there to adopt.
      S.radarStreamDown = true; wasDown = true;
      setLiveStatus('radar stream closed — polling; the session is re-attached if it is still running');
      S.radarLiveId = null; closeLiveSse();
      const start = $('#radar-live'), stop = $('#radar-stop');
      if (start) start.style.display = ''; if (stop) stop.style.display = 'none';
      return;
    }
    S.radarStreamDown = true; wasDown = true;
    setLiveStatus('continuous radar · stream reconnecting… (polling meanwhile)');
  });
  setLiveStatus('continuous radar · following its sweeps');
  syncLiveButtons();
}
/* A radar session this page did not start (a reload, or `hse radar` from the
   shell against the same server) is recognised by what only the radar sets:
   `allow_live_sensors` on its scan options. */
async function adoptRunningRadar(){
  try {
    const d = await API.liveList();
    const running = (d.sessions || []).find(x => x.status === 'running' && x.scan_options && x.scan_options.allow_live_sensors);
    if (running) { if (S.radarLiveId !== running.id || !S.liveSse) attachLive(running.id); }
    else if (S.radarLiveId) {
      // Listed no more: it finished, was stopped elsewhere, or the server
      // restarted (a session lives in memory). Say which is knowable and
      // offer Start again; the last sweep stays on screen from the store.
      S.radarLiveId = null; closeLiveSse(); syncLiveButtons();
      setLiveStatus('radar session ended — no longer listed by the server (finished, stopped, or the server restarted); the last sweep is shown from the store');
    }
  } catch (_) {}
}

/* One sweep: queue it, follow the scan to its terminal state (each sensor tool
   has its own timeout, so a sweep takes seconds), then show the latest. */
async function sweepOnce(){
  const btn = $('#radar-sweep'); if (btn) btn.disabled = true;
  try {
    const r = await API.radarSweep();
    toast('Sweep queued — reading the sensors');
    for (let i = 0; i < 90; i++) {
      await new Promise(res => setTimeout(res, 2000));
      let sc = null;
      try { sc = await API.scan(r.scan_id); } catch (_) { continue; }
      if (sc && ['complete', 'failed', 'aborted'].includes(sc.status)) break;
    }
    view.sid = null; closeTrack();
    await refreshSignals(false);
    await refreshHistory();
    // A sweep changes every review built on the history, not just the rows.
    await refreshRecurring();
    await refreshDisruptions();
  } catch (e) { toast('Sweep failed: ' + e.message, 'error'); }
  finally { if (btn) btn.disabled = false; }
}

async function startLive(){
  try {
    const r = await API.radarLive();
    toast('Continuous radar started — sightings land as each iteration completes');
    view.sid = null; syncSweepPicker();
    attachLive(r.live_id);
  } catch (e) { toast('Radar failed: ' + e.message, 'error'); }
}
async function stopLive(){
  try { await API.liveStop(S.radarLiveId); toast('Radar stopped'); setLiveStatus('radar stopped'); }
  catch (e) { toast('Stop failed: ' + e.message, 'error'); }
  S.radarLiveId = null; closeLiveSse(); syncLiveButtons();
}

function exportCsv(){
  const devices = visibleDevices();
  if (!devices.length) { toast('Nothing to export', 'error'); return; }
  const cols = ['network_id','radio','address','vendor','device_class','name','sightings','distinct_fixes','best_signal_dbm','worst_signal_dbm','latitude','longitude','first_epoch','last_epoch'];
  const q = v => v == null ? '' : `"${String(v).replace(/"/g, '""')}"`;
  const csv = [cols.join(',')].concat(devices.map(d => cols.map(c => q(d[c])).join(','))).join('\n') + '\n';
  triggerBlobDownload(new Blob([csv], {type:'text/csv'}), `hse-radar-${(view.data && view.data.scan_id) || 'latest'}.csv`);
}

export async function renderRadar(v){
  v.innerHTML = `
    <h2>Signal Radar <small class="text-muted">the signals around this device — every reading a sighting</small>
      <div class="pull-right"><button class="btn btn-default btn-sm" onclick="render()" title="Refresh"><i class="glyphicon glyphicon-refresh"></i></button></div>
    </h2>
    <hr style="margin:8px 0 14px 0">
    <div class="panel panel-default" style="border-color:var(--accent)">
      <div class="panel-body">
        <div class="form-inline" style="display:flex;flex-wrap:wrap;gap:6px;align-items:center">
          <button id="radar-sweep" class="btn btn-info btn-sm" title="One sweep of the on-device sensors: Wi-Fi, Bluetooth, cell, GNSS, LAN"><i class="glyphicon glyphicon-record"></i>&nbsp;Sweep once</button>
          <button id="radar-live" class="btn btn-danger btn-sm" title="A continuous radar: the sensors re-run on a loop until stopped"><i class="glyphicon glyphicon-play"></i>&nbsp;Start continuous radar</button>
          <button id="radar-stop" class="btn btn-default btn-sm" style="display:none"><i class="glyphicon glyphicon-stop"></i>&nbsp;Stop continuous radar</button>
          <span id="radar-live-status" class="text-muted" style="font-size:12px"></span>
          <span style="flex:1"></span>
          <label class="text-muted" style="font-weight:normal;margin:0" title="Fixed hardware addresses only — the ones whose recurrence across sweeps means anything (AU-122)"><input type="checkbox" id="radar-trackable">&nbsp;fixed only</label>
          <select id="radar-sort" class="form-control input-sm" title="Sort">
            <option value="signal">strongest first</option><option value="seen">last seen</option><option value="name">name</option>
          </select>
          <button id="radar-latest" class="btn btn-default btn-sm" style="display:none" title="Follow the newest sweep again"><i class="glyphicon glyphicon-time"></i>&nbsp;Latest</button>
          <a id="radar-json" class="btn btn-default btn-sm" href="${attr(API.radarSignalsUrl(view.sid))}" download="hse-radar.json" title="This view's rows as the API returns them">JSON</a>
          <button id="radar-csv" class="btn btn-default btn-sm" title="The devices shown, as CSV">CSV</button>
        </div>
        <div id="radar-summary" class="radar-summary"></div>
        <div id="radar-chips"></div>
      </div>
    </div>
    <div class="panel panel-default" id="radar-map-panel" style="display:none">
      <div class="panel-heading"><b><i class="glyphicon glyphicon-globe"></i>&nbsp;Map</b>
        <span id="radar-map-note" class="text-muted" style="font-weight:400"></span></div>
      <div id="radar-map" style="display:none"></div>
    </div>
    <div id="radar-signals"></div>
    <div class="panel panel-default" id="radar-track-panel" style="display:none;border-color:var(--info)">
      <div class="panel-heading" style="background:rgba(91,192,222,0.12)">
        <b><i class="glyphicon glyphicon-time" style="color:var(--info)"></i>&nbsp;Sighting track</b>
        <span id="radar-track-label" class="text-muted" style="font-weight:400"></span>
        <button class="btn btn-default btn-xs pull-right" id="radar-track-close"><i class="glyphicon glyphicon-stop"></i>&nbsp;Close</button>
      </div>
      <div class="panel-body" id="radar-track" style="max-height:320px;overflow:auto;padding:6px 10px;font-size:12px"></div>
    </div>
    <div class="panel panel-default" id="radar-disruptions-panel" style="border-color:var(--danger)">
      <div class="panel-heading"><b><i class="glyphicon glyphicon-flash" style="color:var(--danger)"></i>&nbsp;Network disruption</b> <span class="badge" id="radar-disruptions-count">…</span>
        <span id="radar-disruptions-note" class="text-muted" style="font-weight:400"></span></div>
      <div id="radar-disruptions"><div class="text-muted" style="padding:8px 12px">Loading…</div></div>
    </div>
    <div class="panel panel-default" id="radar-recurring-panel" style="border-color:var(--warning)">
      <div class="panel-heading"><b><i class="glyphicon glyphicon-eye-open" style="color:var(--warning)"></i>&nbsp;Recurring across sweeps</b> <span class="badge" id="radar-recurring-count">…</span>
        <span id="radar-recurring-note" class="text-muted" style="font-weight:400"></span></div>
      <div id="radar-recurring"><div class="text-muted" style="padding:8px 12px">Loading…</div></div>
    </div>
    <div class="panel panel-default">
      <div class="panel-heading"><b><i class="glyphicon glyphicon-time"></i>&nbsp;Sweep history</b> <span class="badge" id="radar-history-count">…</span>
        <span class="text-muted" style="font-weight:400">— every sweep ever queued, newest first, even after a restart</span></div>
      <div id="radar-history"><div class="text-muted" style="padding:8px 12px">Loading…</div></div>
    </div>`;
  $('#radar-sweep').addEventListener('click', sweepOnce);
  $('#radar-live').addEventListener('click', startLive);
  $('#radar-stop').addEventListener('click', stopLive);
  $('#radar-latest').addEventListener('click', async () => { view.sid = null; closeTrack(); await refreshSignals(false); await refreshHistory(); });
  $('#radar-csv').addEventListener('click', exportCsv);
  $('#radar-track-close').addEventListener('click', closeTrack);
  const sort = $('#radar-sort'); sort.value = view.sort;
  sort.addEventListener('change', () => { view.sort = sort.value; paintSignals(); });
  const tr = $('#radar-trackable'); tr.checked = view.trackable;
  tr.addEventListener('change', async () => { view.trackable = tr.checked; await refreshSignals(false); });
  syncLiveButtons();
  await adoptRunningRadar();
  await refreshSignals(false);
  await refreshHistory();
  await refreshRecurring();
  await refreshDisruptions();
  // Without a stream to follow, poll the latest sweep while this page is open:
  // the producers a stream cannot see (`hse radar` from the shell, an import)
  // still land here. With a continuous radar attached, its `scan_complete`
  // events drive the refresh and this timer only re-checks for a session to
  // adopt. A pinned sweep never changes, so the poller leaves it alone; a
  // hidden page skips the fetch (see `pageHidden`).
  clearRadarTimer();
  S.radarTimer = setInterval(async () => {
    if (pageHidden() || view.sid) return;
    if (S.liveSse && !S.radarStreamDown) { await adoptRunningRadar(); return; }
    await refreshSignals(true);
    await refreshRecurring();
    await refreshDisruptions();
    // A history panel left showing a fetch error from an outage is repainted
    // by the first poll that gets through.
    if (!$('#radar-history table')) await refreshHistory();
    await adoptRunningRadar();
  }, 8000);
}
