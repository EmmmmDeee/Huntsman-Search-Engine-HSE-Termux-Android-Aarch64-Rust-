/* ─── Helpers ─── */
export const $ = (s,r)=>(r||document).querySelector(s);
export const $$ = (s,r)=>Array.from((r||document).querySelectorAll(s));
export function esc(s){return s==null?'':String(s).replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));}
export function attr(s){return esc(s);}
export function nowSec(){return Math.floor(Date.now()/1000);}
export function fmtDate(ts){
  if(!ts) return '—';
  const d=new Date(ts*1000);
  const p=n=>String(n).padStart(2,'0');
  return `${d.getFullYear()}-${p(d.getMonth()+1)}-${p(d.getDate())} ${p(d.getHours())}:${p(d.getMinutes())}:${p(d.getSeconds())}`;
}
export function fmtDuration(secs){
  if(secs==null||secs<0) return '—';
  if(secs<60) return `${secs}s`;
  const m=Math.floor(secs/60),s=secs%60;
  if(m<60) return `${m}m ${s}s`;
  const h=Math.floor(m/60),mm=m%60;
  return `${h}h ${mm}m`;
}
export function fmtClock(){const d=new Date(),p=n=>String(n).padStart(2,'0');return `${p(d.getHours())}:${p(d.getMinutes())}:${p(d.getSeconds())}`;}
export function statusPill(s){const m={complete:'s-complete',running:'s-running',failed:'s-failed',pending:'s-pending',aborted:'s-aborted'};return `<span class="status-pill ${m[s]||'s-pending'}">${esc(s||'pending')}</span>`;}
export function costPill(c){return `<span class="cost-pill cost-${attr(c)}">${esc(c)}</span>`;}
// Render a per-service pool's mean health for a table cell, honestly. The
// backend sends `avg_health: null` when a service has NO tested key yet (every
// key is still Untested) — an untested key carries no operational history, so
// its internal score defaults optimistically to ~0.97 and folding that in would
// paint a wholly-unproven pool as "healthy". In that case show "untested", not
// a fabricated percentage (and "—" for a genuinely empty pool). Otherwise the
// value is the mean over the exercised keys only.
export function healthCell(s){
  const total = (s && s.total) || 0;
  if (s == null || s.avg_health == null){
    return total
      ? '<span class="text-muted" title="no key exercised yet — health is unknown until the first real dispatch grades one">untested</span>'
      : '<span class="text-muted">—</span>';
  }
  const pct = Math.round(s.avg_health*100);
  // The score is a mean over the *tested* keys only; surface that population in
  // a tooltip so the number is self-explanatory (and untested keys visibly do
  // not count toward it). `tested` may be absent on older payloads.
  const tested = s.tested;
  const title = (tested != null)
    ? `mean over ${tested} of ${total} key(s) that have been exercised${tested < total ? ` (${total - tested} still untested)` : ''}`
    : 'mean health over exercised keys';
  return `<span title="${attr(title)}">${pct}%</span>`;
}
// Flatten an EntityKind to a display string. Unit variants arrive as plain
// strings; the catch-all `Other(s)` arrives as {"other":"…"} (externally-tagged
// enum) and must become "other:…" rather than "[object Object]".
export function kindToStr(k){
  if (k == null) return 'unknown';
  if (typeof k === 'string') return k;
  if (typeof k === 'object'){
    if (k.other != null) return 'other:'+k.other;
    const ks = Object.keys(k);
    if (ks.length) return ks[0]+':'+k[ks[0]];
  }
  return String(k);
}
export function kindPill(k){const s=kindToStr(k);return `<span class="kind-pill k-${attr(s)}">${esc(s)}</span>`;}
// Non-corroborating evidence sources — NOT independent intelligence, so they
// must not count toward the C_eff boost. Mirrors the backend's
// is_non_corroborating_source() exactly — all SIX members: the deterministic
// self-enrichment passes ENRICHMENT_ONLY_SOURCES ('geo_normalize',
// 'name_intel', 'payid'), the recall replay ('recall'), the cross-scan history
// link ('cross_scan_history'), and the breach-consensus grading summary
// ('breach_consensus' = core::entity::CONSENSUS_SOURCE). Any omission
// reintroduces over-credit: an entity corroborated only by these sources (e.g.
// a name-permuted email plus a cross-scan hit, or a breach_consensus summary
// plus one real source) renders a higher C_eff/tier in Browse than the
// server's authoritative classification (CSV export, CLI dossier, debug
// bundle) — the exact bug these exclusions exist to close, reopened in the
// display layer. 'breach_consensus' was added to the backend set after this
// JS copy was last synced and drifted out; keep the two in lockstep (see the
// backend doc comments on ENRICHMENT_ONLY_SOURCES/RECALL_SOURCE/
// CROSS_SCAN_SOURCE/CONSENSUS_SOURCE in core::entity).
export const ENRICHMENT_SOURCES = new Set(['geo_normalize', 'name_intel', 'payid', 'recall', 'cross_scan_history', 'breach_consensus']);
// Distinct corroborating sources drive the C_eff boost — must match the
// backend's Entity::source_count() exactly, branch for branch: (1) evidence
// exists with >=1 distinct non-enrichment source -> that distinct count; (2)
// no evidence at all (synthetic/test entity) -> the explicit corroboration
// field; (3) evidence exists but EVERY record is non-corroborating -> forced
// to 1, NOT the corroboration field. Branch 3 matters: `recall` ratchets
// corroboration up by one on every re-scan, so falling back to it here (as
// an earlier version of this function did) let a purely enrichment-sourced
// entity's on-screen Src/C_eff/tier climb indefinitely while the backend's
// own classification correctly stayed pinned at one source — the exact
// recall-ratchet bug `Entity::source_count()`'s own doc comment (core::entity)
// describes fixing server-side, just reopened client-side.
export function sourceCount(e){
  const evs=e.evidence||[];
  const s=new Set();
  for(const ev of evs){if(ev&&ev.source&&!ENRICHMENT_SOURCES.has(ev.source))s.add(ev.source);}
  if(s.size) return s.size;
  if(!evs.length) return Math.max(1,e.corroboration??1);
  return 1;
}
// Mirror the backend Entity::c_effective(): the STRONGER of the multiplicative
// boost and the independent-agreement (noisy-OR) term over the distinct
// corroborating source count n, so Browse tiers/confidence match the engine's
// authoritative classification + the CSV export instead of under-reporting
// genuinely multi-source entities. gamma = 0.65 (CORROBORATION_DOUBT_DECAY); at
// n = 1 both terms equal the base confidence, so single-source rows are unchanged.
export function effC(e){
  const c=e.confidence??0, n=sourceCount(e);
  const mult=c*(1+0.15*Math.log(n));
  const agreement=1-(1-c)*Math.pow(0.65,n-1);
  return Math.min(1,Math.max(0,Math.max(mult,agreement)));
}
export function trunc(s,n){s=String(s||'');return s.length>n?s.slice(0,n)+'…':s;}
/* Linkify http(s) values only (javascript:/data: stay inert escaped text), so
   URL entities and pivot/avatar evidence are clickable — SpiderFoot/NAMINT UX. */
/* Stringify any attribute value for display: null/undefined -> '', objects ->
   JSON (not "[object Object]"), and numeric 0 preserved (not dropped by ||). */
export function attrText(v){return v==null?'':(typeof v==='object'?JSON.stringify(v):String(v));}
export function extLink(url,maxText){
  url=url==null?'':String(url);
  const text=esc(maxText?trunc(url,maxText):url);
  if(!/^https?:\/\//i.test(url)) return text;
  return `<a href="${attr(url)}" target="_blank" rel="noopener noreferrer">${text}</a>`;
}
export function classify(eff){return eff>=0.75?'VERIFIED':eff>=0.4?'PROBABLE':'CANDIDATE';}
export function toast(msg,kind){
  if (typeof alertify === 'undefined') return;
  const fn = kind==='err'?'error':kind==='warn'?'warning':'success';
  alertify.notify(msg, fn, 3);
}

/* ═══════════ Downloads ═══════════
 * One canonical path for every file the UI hands to the user. A bare
 * `<a href download>` is unusable for HSE's server-generated bundles: the
 * debug / diagnostic bundles run a self-test + `curl` + many DB reads (seconds
 * on a phone) with ZERO feedback, so a tap looks dead and gets re-tapped; and a
 * loopback-only 403 or a 500 navigates the browser to a raw JSON error page — a
 * dead end on Termux mobile with no way back to the app. Instead we `fetch()`
 * the artifact (showing a spinner on the clicked control), surface any error as
 * a toast, and save the response as a Blob — the one download mechanism that is
 * honoured identically across desktop and Android browsers. */

/* Parse the download filename out of a `Content-Disposition` header, honouring
 * both `filename*=UTF-8''…` (RFC 5987, percent-decoded) and plain
 * `filename="…"`. Returns null when absent so the caller can fall back. */
export function filenameFromDisposition(cd){
  if (!cd) return null;
  const ext = cd.match(/filename\*\s*=\s*(?:UTF-8'')?([^;]+)/i);
  if (ext){ try { return decodeURIComponent(ext[1].trim().replace(/^["']|["']$/g,'')); } catch { /* fall through */ } }
  const plain = cd.match(/filename\s*=\s*"([^"]+)"|filename\s*=\s*([^;]+)/i);
  if (plain){ return (plain[1] || plain[2] || '').trim(); }
  return null;
}

/* Save an in-memory Blob under `name`. The blob → object-URL → synthetic-anchor
 * → click → revoke sequence is the cross-browser-reliable save path (a
 * `blob:` URL always honours the `download` attribute, unlike a same-origin
 * `text/plain` href that Android browsers may open inline). Single definition —
 * the stealer-log ".txt" export and every fetch-based download share it. */
export function triggerBlobDownload(blob, name){
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = name || 'download';
  a.style.display = 'none';
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  // Revoke on the next tick — some mobile browsers need the URL to outlive the
  // synchronous click handler for the save to actually start.
  setTimeout(()=>URL.revokeObjectURL(url), 0);
}

/* Serialise the `.log-row` rows currently rendered inside `selector` to a .log
 * file and save it. This is the always-available capture path shared by the
 * scan-log panel and the live-activity panel: it records exactly what is on
 * screen, so it works for a live/streaming scan and even when a server-side
 * history fetch failed. `opts.emptyMsg` is toasted when nothing is shown;
 * `opts.header` is a string or a `(count) => string` prepended to the file;
 * `opts.filename` names the download. Single-sourced so the row DOM shape
 * (`.ts`/`.typ`/`.msg`) and the on-disk line format live in one place. */
export function saveShownRows(selector, opts){
  opts = opts || {};
  const host = document.querySelector(selector);
  const rows = host ? host.querySelectorAll('.log-row') : [];
  if (!rows.length){ toast(opts.emptyMsg || 'Nothing shown yet — nothing to save.', 'warn'); return; }
  const lines = [];
  rows.forEach(r=>{
    const ts  = (r.querySelector('.ts')?.textContent  || '').trim();
    const typ = (r.querySelector('.typ')?.textContent || '').trim();
    const msg = (r.querySelector('.msg')?.textContent || '').trim();
    lines.push(`${ts}  ${typ.padEnd(7)}  ${msg}`.trimEnd());
  });
  const header = typeof opts.header === 'function' ? opts.header(rows.length) : (opts.header || '');
  const blob = new Blob([header + lines.join('\n') + '\n'], { type: 'text/plain;charset=utf-8' });
  triggerBlobDownload(blob, opts.filename || 'hse-log.log');
}

/* Fetch `url` and save it as a file, with a spinner on `opts.button` while the
 * server works and a toast on any failure (never a navigation away). Resolves
 * to true on success, false on a handled error. `opts.fallbackName` names the
 * file when the response carries no `Content-Disposition`. */
export async function downloadFile(url, opts){
  opts = opts || {};
  const btn = opts.button;
  let restore = null;
  if (btn && !btn.dataset.dlBusy){
    const orig = btn.innerHTML;
    btn.dataset.dlBusy = '1';
    btn.classList.add('disabled');
    btn.setAttribute('aria-busy','true');
    btn.innerHTML = '<span class="dl-spin" aria-hidden="true"></span>&nbsp;Preparing…';
    restore = ()=>{ btn.innerHTML = orig; btn.classList.remove('disabled'); btn.removeAttribute('aria-busy'); delete btn.dataset.dlBusy; };
  } else if (btn && btn.dataset.dlBusy){
    return false; // a download from this control is already in flight
  }
  try {
    const resp = await fetch(url, { headers: { 'Accept': 'application/octet-stream' } });
    if (!resp.ok){
      let msg = 'HTTP ' + resp.status;
      try { const j = await resp.clone().json(); if (j && j.error) msg = j.error; }
      catch { try { const t = (await resp.text()).trim(); if (t) msg = trunc(t, 160); } catch { /* keep HTTP status */ } }
      toast('Download failed: ' + msg, 'err');
      return false;
    }
    const name = filenameFromDisposition(resp.headers.get('content-disposition')) || opts.fallbackName || 'hse-download';
    triggerBlobDownload(await resp.blob(), name);
    return true;
  } catch (e){
    toast('Download failed: ' + ((e && e.message) || e), 'err');
    return false;
  } finally {
    if (restore) restore();
  }
}

/* One delegated, document-level handler for every `[data-download]` control
 * (anchor or button). Intercepts the click, cancels the default navigation, and
 * routes it through `downloadFile` so the spinner + error-toast behaviour is
 * automatic everywhere — a control opts in purely by markup
 * (`data-download` + its `href`/`data-download-url`, optional `data-download-name`).
 * The raw `href` remains a no-JS fallback. Idempotent; call once at bootstrap. */
export function initDownloads(){
  if (window.__hseDownloadsInit) return;
  window.__hseDownloadsInit = true;
  document.addEventListener('click', e=>{
    const el = e.target.closest('[data-download]');
    if (!el) return;
    const url = el.getAttribute('data-download-url') || el.getAttribute('href');
    if (!url || url === '#') return;
    e.preventDefault();
    downloadFile(url, { button: el, fallbackName: el.getAttribute('data-download-name') || undefined });
  });
}

