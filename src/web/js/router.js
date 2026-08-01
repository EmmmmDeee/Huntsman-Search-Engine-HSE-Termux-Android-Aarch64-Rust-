/* ─── Router (hash-based, mirrors SpiderFoot's path semantics) ─── */
export function parseHash(){
  const raw = (location.hash||'#/dash').replace(/^#/,'');
  const [path, qs] = raw.split('?');
  const segs = path.split('/').filter(Boolean);
  const query = {};
  (qs||'').split('&').filter(Boolean).forEach(p=>{
    const [k,v] = p.split('=');
    // A malformed percent-encoding (e.g. a bare trailing '%', or one hex digit
    // short — plausible from a hand-edited address bar or a corrupted bookmark)
    // throws URIError. parseHash() is called synchronously before render()'s own
    // try/catch (main.js), so an uncaught throw here blanks the entire SPA on
    // load, or freezes it mid-navigation on a later hashchange. Skip just the
    // one malformed pair rather than letting it take down the whole route —
    // any other valid params in the same query string still parse.
    try { query[decodeURIComponent(k)] = decodeURIComponent(v||''); } catch {}
  });
  if (segs.length===0 || segs[0]==='dash' || segs[0]==='dashboard') return {name:'dash', params:{}, query};
  if (segs[0]==='scans')                    return {name:'scans', params:{}, query};
  if (segs[0]==='newscan')                  return {name:'newscan', params:{}, query};
  if (segs[0]==='opts'||segs[0]==='settings') return {name:'opts', params:{}, query};
  if (segs[0]==='search')                   return {name:'search', params:{}, query};
  if (segs[0]==='live')                     return {name:'live', params:{}, query};
  if (segs[0]==='engines')                  return {name:'engines', params:{}, query};
  if (segs[0]==='harvest')                  return {name:'harvest', params:{}, query};
  if (segs[0]==='diff')                     return {name:'diff', params:{a:query.a||'', b:query.b||''}, query};
  if (segs[0]==='scaninfo' && query.id)     return {name:'scaninfo', params:{id:query.id, tab:query.tab||'summary'}, query};
  return {name:'dash', params:{}, query};
}
export function nav(href){ location.hash = href; }

