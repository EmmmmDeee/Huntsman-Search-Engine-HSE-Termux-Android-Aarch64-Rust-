/* ─── API client ─── */
export const API = {
  async _req(path, opts){
    opts = opts || {};
    const init = {method: opts.method||'GET'};
    if (opts.body){ init.headers = {'Content-Type':'application/json'}; init.body = JSON.stringify(opts.body); }
    const r = await fetch(path, init);
    if (opts.raw) return r;
    if (!r.ok){
      let err = `HTTP ${r.status}`;
      try { const j = await r.json(); err = j.error || JSON.stringify(j); } catch {}
      throw new Error(err);
    }
    const ct = r.headers.get('content-type')||'';
    return ct.includes('application/json') ? r.json() : r.text();
  },
  health:    ()=>API._req('/api/v1/health'),
  modules:   ()=>API._req('/api/v1/modules'),
  engines:   ()=>API._req('/api/v1/engines/health'),
  scraperHealth: ()=>API._req('/api/v1/health/scrapers'),
  // Per-module failure streaks this process (PROBLEM_TREE T2.7 / SOLUTION_TREE
  // SOL-HEALTH-SIGNAL) — the same live dispatch-outcome data `hse doctor` reports.
  // Complements scraperHealth (cross-scan, persisted) rather than replacing it.
  moduleHealth: ()=>API._req('/api/v1/modules/health'),
  scans:     ()=>API._req('/api/v1/scans'),
  scan:      id=>API._req('/api/v1/scans/'+encodeURIComponent(id)),
  entities:  id=>API._req('/api/v1/scans/'+encodeURIComponent(id)+'/entities'),
  correlations: id=>API._req('/api/v1/scans/'+encodeURIComponent(id)+'/correlations'),
  relations: id=>API._req('/api/v1/scans/'+encodeURIComponent(id)+'/relations'),
  // Paired stealer-log credential rows (login+password+domain+machine, kept
  // together) — powers the Stealer Logs Viewer sub-tab.
  stealerRows: id=>API._req('/api/v1/scans/'+encodeURIComponent(id)+'/stealer-rows'),
  // Subject network: the seed hub + its connections grouped/ranked server-side
  // (people, identifiers, aliases, locations, infrastructure) — the analyst view.
  network:   id=>API._req('/api/v1/scans/'+encodeURIComponent(id)+'/network'),
  // People-centric co-reference: which selectors (email/username/phone/person)
  // name the same individual, scored by cross-identifier record linkage.
  identities: id=>API._req('/api/v1/scans/'+encodeURIComponent(id)+'/identities'),
  // Proactive leads: ranked untapped pivots the scan surfaced but didn't pursue,
  // each a one-click follow-up scan.
  leads:     id=>API._req('/api/v1/scans/'+encodeURIComponent(id)+'/leads'),
  // Footprint timeline: every dated event the evidence implies, oldest-first.
  timeline:  id=>API._req('/api/v1/scans/'+encodeURIComponent(id)+'/timeline'),
  // Graph communities: relationship sub-clusters via label propagation.
  communities: id=>API._req('/api/v1/scans/'+encodeURIComponent(id)+'/communities'),
  // Network trust: entities ranked by graph-corroborated trust propagation.
  trust:     id=>API._req('/api/v1/scans/'+encodeURIComponent(id)+'/trust'),
  // Connection path: how two named entities are linked through the relation graph.
  // `cross` extends the search across every scan in the local intelligence database.
  path: (id,from,to,n,cross)=>API._req('/api/v1/scans/'+encodeURIComponent(id)+'/path?from='+encodeURIComponent(from)+'&to='+encodeURIComponent(to)+(n?'&paths='+n:'')+(cross?'&cross=true':'')),
  // Per-scan quality / telemetry measures (the empirical scan-quality dashboard).
  metrics:    id=>API._req('/api/v1/scans/'+encodeURIComponent(id)+'/metrics'),
  // Near-duplicate entity-resolution suggestions (probable same-identity groups).
  duplicates: id=>API._req('/api/v1/scans/'+encodeURIComponent(id)+'/duplicates'),
  // Pivot nodes: the graph's high-connectivity intermediaries (betweenness centrality).
  pivots:     id=>API._req('/api/v1/scans/'+encodeURIComponent(id)+'/pivots'),
  gaps:       id=>API._req('/api/v1/scans/'+encodeURIComponent(id)+'/gaps'),
  // The AU-059 residency fix — the "where is the subject" location verdict.
  location:  id=>API._req('/api/v1/scans/'+encodeURIComponent(id)+'/location'),
  // Consolidated benchmark scorecard (HTTP twin of `hse benchmark`).
  benchmark: id=>API._req('/api/v1/scans/'+encodeURIComponent(id)+'/benchmark'),
  auditScan: id=>API._req('/api/v1/scans/'+encodeURIComponent(id)+'/audit'),
  create:    body=>API._req('/api/v1/scans',{method:'POST',body}),
  // Fully autonomous scan — NO seed input; the server auto-selects the highest
  // cross-investigation-leverage entity from the local base and investigates it.
  autoScan:  ()=>API._req('/api/v1/scan/auto',{method:'POST'}),
  // Read-only preview of the diversity-aware autonomous investigation queue — what
  // the platform would investigate next, in order. Dispatches nothing.
  autoPlan:  (limit,diversity)=>API._req('/api/v1/scan/auto/plan?limit='+(limit||20)+'&diversity='+(diversity==null?0.5:diversity)),
  // Fully autonomous MULTI-target sweep — NO seed input; the server plans the
  // diversity-aware queue and dispatches its top `breadth` targets in one call.
  autoSweep: (breadth,diversity)=>API._req('/api/v1/scan/auto/sweep?breadth='+(breadth||5)+'&diversity='+(diversity==null?0.5:diversity),{method:'POST'}),
  // Forward-only scan-plan preview: which modules a seed engages, before scanning.
  plan:      value=>API._req('/api/v1/plan?value='+encodeURIComponent(value)),
  // Named scan-profile catalogue (recommended/passive/footprint/investigate/
  // fast/skiptrace) for the New Scan wizard's profile picker.
  scanProfiles: ()=>API._req('/api/v1/scan/profiles'),
  // Raw-text upload (not JSON): POST a dossier file's contents to be parsed and
  // ingested as a scan. Bypasses _req's JSON envelope.
  // The X-HSE-CSRF header makes this a non-simple request: same-origin (here) it
  // sends straight through, but a cross-site caller must preflight, which CORS
  // rejects — so a hostile page can't POST a forged dossier into the local DB.
  importDossier: text=>fetch('/api/v1/scans/import',{method:'POST',headers:{'Content-Type':'text/plain','X-HSE-CSRF':'1'},body:text}).then(async r=>{ if(!r.ok){ let e='HTTP '+r.status; try{ e=(await r.json()).error||e; }catch{} throw new Error(e); } return r.json(); }),
  rerun:     id=>API._req('/api/v1/scans/'+encodeURIComponent(id)+'/rerun',{method:'POST'}),
  cancel:    id=>API._req('/api/v1/scans/'+encodeURIComponent(id)+'/cancel',{method:'POST'}),
  remove:    id=>API._req('/api/v1/scans/'+encodeURIComponent(id),{method:'DELETE'}),
  csvUrl:    id=>'/api/v1/scans/'+encodeURIComponent(id)+'/entities.csv',
  // `includeInfra` mirrors `hse export --format report --include-infra`: the
  // JSON report is the one curated/subject-focused export format that hides
  // platform-infra entities (cloud buckets, CDN IPs, tracking IDs) by
  // default — CSV/GEXF/debug-bundle/Browse never filter them, so only this
  // one download needs the toggle.
  reportUrl: (id, includeInfra)=>'/api/v1/scans/'+encodeURIComponent(id)+'/report.json'+(includeInfra?'?include_infra=1':''),
  gexfUrl:   id=>'/api/v1/scans/'+encodeURIComponent(id)+'/graph.gexf',
  debugUrl:  id=>'/api/v1/scans/'+encodeURIComponent(id)+'/debug.txt',
  keysGet:   ()=>API._req('/api/v1/settings/keys'),
  keysPut:   body=>API._req('/api/v1/settings/keys',{method:'PUT',body}),
  // Key POOL (multi-key per service): masked list + revoke-by-non-secret-id.
  // Loopback-only; revoke also needs --allow-key-write. Plaintext never leaves
  // the device — the raw values come from `hse keys export` in the shell.
  poolGet:    ()=>API._req('/api/v1/keys/pool'),
  poolAdd:    body=>API._req('/api/v1/keys/pool/add',{method:'POST',body}),
  poolRevoke: body=>API._req('/api/v1/keys/pool/revoke',{method:'POST',body}),
  poolRotate: body=>API._req('/api/v1/keys/pool/rotate',{method:'POST',body}),
  // Operator diagnostics: per-service key-pool health/quota + the detector
  // coverage catalogue. Surfaced read-only in Settings (loopback-only).
  keysStatus:   ()=>API._req('/api/v1/keys/status'),
  keysPatterns: ()=>API._req('/api/v1/keys/patterns'),
  // Key Harvest dashboard feed: vault bank + ROI tiering + live SeekNow/
  // OathNet/WiGLE account health. Loopback-only.
  keysHarvest:  ()=>API._req('/api/v1/keys/harvest'),
  togglesGet: ()=>API._req('/api/v1/settings/toggles'),
  togglesPut: body=>API._req('/api/v1/settings/toggles',{method:'PUT',body}),
  stats:     ()=>API._req('/api/v1/stats'),
  search:    (q,limit)=>API._req('/api/v1/search?q='+encodeURIComponent(q)+'&limit='+(limit||50)),
  liveList:   ()=>API._req('/api/v1/live'),
  liveCreate: body=>API._req('/api/v1/live',{method:'POST',body}),
  liveStop:   id=>API._req('/api/v1/live/'+encodeURIComponent(id),{method:'DELETE'}),
  // Live Signal Radar — the sole activation path for the on-device live sensors
  // (signal_radar, device_sensors, wifi_intel, cell_intel, local_net); an ordinary
  // scan never runs them. Both take NO input whatsoever.
  //   radarLive():  CONTINUOUS autonomous radar — a zero-input live session that
  //                 re-enumerates the device's passive signals in real time.
  //   radarSweep(): ONE autonomous sweep (kept for API back-compat; optional seed).
  radarLive: ()=>API._req('/api/v1/radar/live',{method:'POST'}),
  radarSweep: seed=>API._req('/api/v1/radar'+(seed?('?seed='+encodeURIComponent(seed)):''),{method:'POST'}),
  // Historical review of past radar sweeps — sourced from the persisted scans
  // table, so it survives a server restart (unlike the in-memory live-session
  // list above). This is what makes "what was around me earlier" reviewable.
  radarHistory: limit=>API._req('/api/v1/radar/history'+(limit?('?limit='+encodeURIComponent(limit)):'')),
  selftest:     ()=>API._req('/api/v1/selftest'),
  logsUrl:      ()=>'/api/v1/logs',
  // One-click consolidated system self-diagnosis bundle (loopback-only):
  // DETECTED ISSUES verdict + environment + self-test + module/engine/scraper
  // health + recent scans + logs + source manifest — everything needed to
  // repair the engine, in one downloadable file.
  debugBundleUrl: ()=>'/api/v1/debug/bundle',
  updateStatus: ()=>API._req('/api/v1/update/status'),
  updateTrigger:()=>API._req('/api/v1/update/trigger',{method:'POST'}),
  // Cell-tower DB (backs Live Signal Radar / cell_intel geolocation).
  // status is ungated; import/clear are loopback-only, mirroring update/trigger.
  cellsStatus: ()=>API._req('/api/v1/cells/status'),
  cellsImport: country=>API._req('/api/v1/cells/import',{method:'POST',body:{country}}),
  cellsClear:  ()=>API._req('/api/v1/cells/clear',{method:'POST',body:{confirm:true}}),
  // Batch: queue many scans in one request (array of ScanRequest). Returns
  // {scans:[{scan_id,status}|{error}], count}.
  batch:      reqs=>API._req('/api/v1/scans/batch',{method:'POST',body:reqs}),
  // Temporal diff of two stored scans of the same subject → what the later run
  // added/removed/re-scored. {added,removed,common,confidence_shifts}.
  diff:       (a,b)=>API._req('/api/v1/scans/'+encodeURIComponent(a)+'/diff/'+encodeURIComponent(b)),
  // Module capability graph: which input kinds flow to which produced kinds.
  modulesGraph: ()=>API._req('/api/v1/modules/graph'),
  // Cross-scan entity pivot: everywhere an identifier appears, across every
  // scan. {entity, scan_ids:[…], observation_count}.
  entityGet:  uid=>API._req('/api/v1/entities/'+encodeURIComponent(uid))
};

