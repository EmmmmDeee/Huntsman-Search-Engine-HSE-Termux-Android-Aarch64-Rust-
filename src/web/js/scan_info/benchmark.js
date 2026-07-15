import { API } from '/static/js/api.js';
import { esc } from '/static/js/helpers.js';

/* ── Benchmark scorecard — HTTP twin of `hse benchmark`. /scans/{id}/benchmark. ── */
export async function renderBenchmark(host, id){
  let data;
  try { data = await API.benchmark(id); }
  catch(e){ host.innerHTML = ''; return; }
  if (!data){ host.innerHTML = ''; return; }
  const sc = data.scorecard || {};
  const pct = v => Math.round((Number(v)||0)*100)+'%';
  const row = (k,v) => `<tr><td>${esc(k)}</td><td class="text-right">${esc(v)}</td></tr>`;
  host.innerHTML = `<h4 style="margin-top:0"><i class="glyphicon glyphicon-dashboard"></i>&nbsp;Benchmark scorecard</h4>
    <div class="table-responsive"><table class="table table-condensed"><tbody>
      ${row('Entities', sc.total_entities!=null?sc.total_entities:0)}
      ${row('Relations', sc.total_relations!=null?sc.total_relations:0)}
      ${row('Modules run', data.modules_run!=null?data.modules_run:0)}
      ${row('Modules errored', data.modules_errored!=null?data.modules_errored:0)}
      ${row('Modules timed out', data.modules_timed_out!=null?data.modules_timed_out:0)}
      ${row('Pivot count', data.pivot_count!=null?data.pivot_count:0)}
      ${row('Entities/sec', (Number(data.entities_per_sec)||0).toFixed(2))}
      ${row('Multi-hop depth', sc.multi_hop_depth!=null?sc.multi_hop_depth:0)}
      ${row('Graph coverage', pct(sc.graph_coverage))}
      ${row('Corroborated fraction', pct(sc.corroborated_fraction))}
    </tbody></table></div>`;
}

