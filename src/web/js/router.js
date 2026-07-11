/* ─── Router (hash-based, mirrors SpiderFoot's path semantics) ─── */
export function parseHash(){
  const raw = (location.hash||'#/dash').replace(/^#/,'');
  const [path, qs] = raw.split('?');
  const segs = path.split('/').filter(Boolean);
  const query = {};
  (qs||'').split('&').filter(Boolean).forEach(p=>{
    const [k,v] = p.split('='); query[decodeURIComponent(k)] = decodeURIComponent(v||'');
  });
  if (segs.length===0 || segs[0]==='dash' || segs[0]==='dashboard') return {name:'dash', params:{}, query};
  if (segs[0]==='scans')                    return {name:'scans', params:{}, query};
  if (segs[0]==='newscan')                  return {name:'newscan', params:{}, query};
  if (segs[0]==='opts'||segs[0]==='settings') return {name:'opts', params:{}, query};
  if (segs[0]==='search')                   return {name:'search', params:{}, query};
  if (segs[0]==='live')                     return {name:'live', params:{}, query};
  if (segs[0]==='engines')                  return {name:'engines', params:{}, query};
  if (segs[0]==='diff')                     return {name:'diff', params:{a:query.a||'', b:query.b||''}, query};
  if (segs[0]==='scaninfo' && query.id)     return {name:'scaninfo', params:{id:query.id, tab:query.tab||'report'}, query};
  return {name:'dash', params:{}, query};
}
export function nav(href){ location.hash = href; }

