/* ════════════════════════════════════════════════════════════════════════
 * Huntsman Search Engine — SPA logic.
 *
 * Layout patterns and component vocabulary (panels, nav-tabs, tables,
 * btn-danger "Run Scan Now", "By Use Case / By Required Data / By Module"
 * wizard tabs) mirror SpiderFoot's templates so operators get the same
 * mental model. The state machine, router, and API client are
 * HSE-specific and talk to /api/v1/* (see src/api/routes.rs).
 * ═══════════════════════════════════════════════════════════════════════ */

export const TARGET_KINDS = [
  {v:'auto',        label:'Auto-detect (recommended)'},
  {v:'email',       label:'E-mail Address'},
  {v:'username',    label:'Username'},
  {v:'phone',       label:'Phone Number'},
  {v:'full_name',   label:'Human Name'},
  {v:'ip_address',  label:'IP Address'},
  {v:'domain',      label:'Domain Name'},
  {v:'url',         label:'URL'},
  {v:'asn',         label:'Network ASN'},
  {v:'coordinates', label:'GPS Coordinates'},
  {v:'address',     label:'Postal Address'},
];

export const USE_CASES = {
  all: {
    label:'Complete (All)',
    desc:'<b>Get anything and everything about the target — the no-compromise scan.</b><br><br>Every Huntsman module is enabled (slow), expansion runs to maximum depth (3) at the comprehensive 0.20 floor (so even the seed\'s own derived identifiers expand), the wrong-identity gate is lifted so every discovered alias is chased (not just corroborated ones), and ROI pruning is disabled so nothing is skipped. The seed kind is auto-detected. Matches the CLI <code>hse scan --full</code>\'s scan behaviour; check "Include infrastructure entities" on the JSON report download (Scan page) for full parity with <code>--full</code>\'s report output too — Browse, CSV, GEXF and the debug bundle already show infrastructure entities unconditionally.',
    pick:_m=>true,
    options:()=>({depth:3, min_expand_confidence:0.20, max_roi:false, expand_all_identities:true})
  },
  footprint: {
    label:'Footprint',
    desc:"<b>Understand what information this target exposes to the Internet.</b><br><br>Gain an understanding about the target's network perimeter, associated identities and other information that is obtained through web crawling and infrastructure lookups.",
    pick:m=>['crtsh','dns_intel','doh_resolver','dns_axfr','wayback','bgpview','whois','ip_geo','rdap_domain','phone_intl','webserver_banner'].includes(m.name),
    options:picked=>({modules:picked})
  },
  investigate: {
    label:'Investigate',
    desc:'<b>Best for when you suspect the target to be malicious but need more information.</b><br><br>Some basic footprinting will be performed in addition to querying of breach datasets, threat-intelligence feeds, identity sources, and credential exposure databases (paid sources used when keys are present).',
    pick:m=>['hudsonrock','xposed_or_not','threatfox','urlhaus','greynoise','gravatar','github_user','username_search','email_parse','oathnet_pro'].includes(m.name),
    options:picked=>({modules:picked})
  },
  passive: {
    label:'Passive',
    desc:"<b>When you don't want the target to even suspect they are being investigated.</b><br><br>As much information will be gathered without touching the target or their affiliates, therefore only modules that do not touch the target will be enabled.",
    pick:m=>!!m.passive,
    options:()=>({passive_only:true})
  }
};

// SpiderFoot "By Required Data" vocabulary: maps a data-type label to the
// TargetKind values (wire strings) that match it, so clicking a chip auto-
// selects the modules that accept those kinds.
export const DATA_TYPES = [
  {label:'Domain Name',     kinds:['domain']},
  {label:'E-mail Address',  kinds:['email']},
  {label:'IP Address',      kinds:['ip_address']},
  {label:'Phone Number',    kinds:['phone']},
  {label:'Username',        kinds:['username']},
  {label:'Human Name',      kinds:['full_name']},
  {label:'URL',             kinds:['url']},
  {label:'Network ASN',     kinds:['asn']},
  {label:'GPS Coordinates', kinds:['coordinates']},
];

export const S = {
  route:    {name:'scans', params:{}, query:{}},
  version:  '',
  health:   null,
  modules:  null,
  scanProfiles: null,
  scans:    null,
  scan:     null,
  entities: null,
  correlations: null,
  relations: null,
  settings: null,
  sse:      null,
  events:   [],
  graph:    null,
  wizard: {
    name:'', value:'', kind:'auto',
    usecase:'all', modules:null,
    activeTab:'usecase', dataType:null,
    showAdv:false,
    // Comprehensive standard-scan defaults, matching `hse scan` and the API's
    // default_scan_options: depth 3 / expansion floor 0.20 / entity cap 2500,
    // plus convex (optionality/barbell) budget allocation ON so each scan spends
    // its bounded budget on cheap, high-upside identity leads over saturated
    // infrastructure, and capability-aware dispatch (skip_dead_modules) ON so it
    // never wastes that budget on modules whose parser has provably gone dead —
    // both maximising the value of every query out of the box. buildWizardOptions()
    // submits these, and the Advanced-options form displays them, so a web scan is
    // as thorough as the CLI out of the box.
    options:{ exclude_modules:[], throttle_ms:250, module_timeout_ms:null, depth:3,
              min_expand_confidence:0.20, max_entities:2500, max_wall_time_secs:null,
              max_concurrent:2, min_confidence:null, free_only:false, convex_budget:true,
              skip_dead_modules:true },
    // Named server-side scan profile (recommended/passive/footprint/investigate/
    // fast/skiptrace), e.g. `--profile skiptrace` on the CLI. `null` = none
    // selected — every Advanced-options field above applies as typed. When
    // set, the server's apply_profile_overlay overrides depth/min_expand_
    // confidence/max_concurrent/max_entities/max_wall_time_secs/free_only/
    // passive_only/category_focus/expansion_strategy/regional_search with the
    // profile's own values — module selection, tags, and notes still apply.
    profile: null
  }
};

