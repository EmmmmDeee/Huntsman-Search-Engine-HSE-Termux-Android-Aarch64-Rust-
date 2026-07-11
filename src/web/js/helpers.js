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
// is_non_corroborating_source() exactly: the deterministic self-enrichment
// passes ENRICHMENT_ONLY_SOURCES ('geo_normalize', 'name_intel', 'payid'),
// the recall replay ('recall'), and the cross-scan history link
// ('cross_scan_history'). This set previously carried only 2 of the 5 —
// missing 'name_intel', 'payid', and 'cross_scan_history' — so an entity
// corroborated only by those sources (e.g. a name-permuted email plus a
// cross-scan hit) rendered a higher C_eff/tier in Browse than the server's
// authoritative classification, reintroducing the exact over-credit bugs
// those three exclusions exist to close (see the backend doc comments on
// ENRICHMENT_ONLY_SOURCES/RECALL_SOURCE/CROSS_SCAN_SOURCE in
// core::entity), just in the display layer instead of the confidence engine.
export const ENRICHMENT_SOURCES = new Set(['geo_normalize', 'name_intel', 'payid', 'recall', 'cross_scan_history']);
// Distinct corroborating sources drive the C_eff boost — must match the
// backend's Entity::source_count()/corroborating_sources(): count distinct
// non-enrichment evidence.source strings; when none are present, fall back to
// the corroboration field. (The old version boosted on the raw corroboration
// field, which over-credited single-source findings whose within-module counts
// were summed by merge.)
export function sourceCount(e){
  const evs=e.evidence||[];
  if(evs.length){const s=new Set();for(const ev of evs){if(ev&&ev.source&&!ENRICHMENT_SOURCES.has(ev.source))s.add(ev.source);}if(s.size)return Math.max(1,s.size);}
  return Math.max(1,e.corroboration??1);
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

