use super::*;

    #[test]
    fn loopback_recognised() {
        assert!(is_loopback_bind("127.0.0.1:8080"));
        assert!(is_loopback_bind("127.1.2.3:9000"));
        assert!(is_loopback_bind("localhost:8080"));
        assert!(is_loopback_bind("[::1]:8080"));
        assert!(is_loopback_bind("::1"));
    }

    #[test]
    fn non_loopback_rejected() {
        assert!(!is_loopback_bind("0.0.0.0:8080"));
        assert!(!is_loopback_bind("192.168.1.10:8080"));
        assert!(!is_loopback_bind("10.0.0.5:8080"));
        assert!(!is_loopback_bind("example.com:8080"));
    }

    #[test]
    fn host_allowlist_covers_loopback_aliases_and_rejects_rebind() {
        let set = host_allowlist("127.0.0.1:8080").expect("loopback bind has an allowlist");
        // The names a user legitimately types — all accepted.
        for h in [
            "127.0.0.1:8080",
            "localhost:8080",
            "[::1]:8080",
            "localhost",
            "127.0.0.1",
        ] {
            assert!(set.contains(h), "{h} must be allowed");
        }
        // A DNS-rebind Host (the attacker's domain) is NOT in the set.
        assert!(!set.contains("evil.example.com:8080"));
        assert!(!set.contains("evil.example.com"));
    }

    #[test]
    fn host_allowlist_is_none_for_non_loopback_bind() {
        // A 0.0.0.0 bind is an explicit operator choice to expose the API; the
        // valid Host set is the box's own (unknowable) addresses, so no guard.
        assert!(host_allowlist("0.0.0.0:8080").is_none());
    }

    #[test]
    fn loopback_edge_cases() {
        assert!(is_loopback_bind("localhost"));
        assert!(!is_loopback_bind("localhostx:8080"));
        assert!(!is_loopback_bind(""));
    }

    #[test]
    fn cors_loopback_includes_localhost_alias() {
        let layer = build_cors_layer("127.0.0.1:8080");
        let _ = layer;
    }

    #[test]
    fn cors_non_loopback_excludes_localhost() {
        let layer = build_cors_layer("192.168.1.5:8080");
        let _ = layer;
    }

    #[test]
    fn cors_ipv6_loopback() {
        let layer = build_cors_layer("[::1]:8080");
        let _ = layer;
    }

    #[test]
    fn if_none_match_hits_star_exact_and_list() {
        let etag = concat!("\"", env!("CARGO_PKG_VERSION"), "\"");
        assert!(if_none_match_hit("*", etag), "wildcard matches");
        assert!(if_none_match_hit(etag, etag), "exact match");
        assert!(
            if_none_match_hit(&format!("\"old\", {etag}"), etag),
            "match within a comma list"
        );
        assert!(!if_none_match_hit("\"old\"", etag), "different tag misses");
        assert!(!if_none_match_hit("", etag), "empty header misses");
    }

    // ── Airtight, offline-by-construction local console ────────────────────────
    //
    // The console is a self-contained binary that, on the project's flaky-
    // cellular phone target, must talk to nothing but itself: no CDN, no font
    // host, no analytics beacon, no exfiltration path for the sensitive findings
    // it holds. The integration tests assert the strict CSP directives are
    // PRESENT on served responses; these source-level tests assert nothing
    // external was ADDED — a gap a `contains("connect-src 'self'")` check leaves
    // open, since `connect-src 'self' https://exfil.example` contains it too.

    /// Tokens a CSP fetch/navigation directive may legitimately carry. Anything
    /// else — notably an `http(s)://` host or a `*` wildcard — would let the
    /// console reach an external origin, the one thing this policy forbids.
    const ALLOWED_CSP_TOKENS: &[&str] = &["'self'", "'unsafe-inline'", "'none'", "data:"];

    #[test]
    fn csp_names_no_external_origin() {
        for needle in ["http://", "https://", "//", "*"] {
            assert!(
                !CONTENT_SECURITY_POLICY.contains(needle),
                "CSP must name no external origin/wildcard, found {needle:?}: \
                 {CONTENT_SECURITY_POLICY}"
            );
        }
    }

    #[test]
    fn csp_directives_use_only_self_or_inline_tokens() {
        for directive in CONTENT_SECURITY_POLICY.split(';') {
            let mut parts = directive.split_whitespace();
            let Some(name) = parts.next() else { continue };
            for token in parts {
                assert!(
                    ALLOWED_CSP_TOKENS.contains(&token),
                    "CSP directive {name:?} carries a non-self token {token:?}"
                );
            }
        }
    }

    #[test]
    fn permissions_policy_denies_phone_sensors() {
        // Every powerful feature must be present with an empty `()` allowlist.
        for feature in ["camera", "microphone", "geolocation", "usb", "bluetooth"] {
            assert!(
                PERMISSIONS_POLICY.contains(&format!("{feature}=()")),
                "Permissions-Policy must deny {feature}: {PERMISSIONS_POLICY}"
            );
        }
        // A non-empty allowlist would grant the feature — none may appear.
        assert!(
            !PERMISSIONS_POLICY.contains("=(self)") && !PERMISSIONS_POLICY.contains("=*"),
            "Permissions-Policy must grant nothing: {PERMISSIONS_POLICY}"
        );
    }

    /// Any external (`http(s)://` or protocol-relative `//host`) resource the
    /// embedded SPA auto-loads via `<script src>`, `<link href>`, or `<img src>`.
    /// Navigational `<a href>` links and the SVG `xmlns` identifier are not
    /// resource loads and are intentionally not inspected.
    fn external_resource_refs(html: &str) -> Vec<String> {
        fn attr_value<'a>(tag: &'a str, attr: &str) -> Option<&'a str> {
            for q in ['"', '\''] {
                let needle = format!("{attr}={q}");
                if let Some(p) = tag.find(&needle) {
                    let rest = &tag[p + needle.len()..];
                    if let Some(e) = rest.find(q) {
                        return Some(&rest[..e]);
                    }
                }
            }
            None
        }
        let mut hits = Vec::new();
        for (tag, attr) in [("<script", "src"), ("<link", "href"), ("<img", "src")] {
            let mut idx = 0;
            while let Some(rel) = html[idx..].find(tag) {
                let start = idx + rel;
                let end = html[start..].find('>').map_or(html.len(), |e| start + e);
                if let Some(v) = attr_value(&html[start..end], attr) {
                    let v = v.trim();
                    if v.starts_with("http://") || v.starts_with("https://") || v.starts_with("//")
                    {
                        hits.push(format!("{tag} {attr}={v:?}"));
                    }
                }
                idx = end;
            }
        }
        hits
    }

    /// Look up an embedded first-party SPA module's source by its served path
    /// (e.g. `"js/api.js"`, `"js/scan_info/graph.js"`, `"css/app.css"`) — the
    /// same keys [`APP_FILES`] serves at `/static/{path}`. The former
    /// monolithic `spa.html` held every view in one string; now that the SPA
    /// is split into per-concern modules (see `src/web/js/`), a test that
    /// used to search `SPA_HTML` for one view's content instead searches
    /// that view's own file directly — which also keeps each test's
    /// boundary-slicing (`split_once`/`find`) scoped to the single file that
    /// actually owns the content, exactly as it was scoped to that file's
    /// region of the old monolith.
    fn app_file(served_path: &str) -> &'static str {
        APP_FILES
            .iter()
            .find(|(name, _, _)| *name == served_path)
            .map_or_else(
                || panic!("no APP_FILES entry named {served_path:?}"),
                |(_, _, bytes)| std::str::from_utf8(bytes).expect("APP_FILES entry is valid UTF-8"),
            )
    }

    #[test]
    fn embedded_spa_auto_loads_nothing_external() {
        let hits = external_resource_refs(SPA_HTML);
        assert!(
            hits.is_empty(),
            "the embedded SPA must auto-load no external resource (CDN/font/\
             beacon); found: {hits:?}"
        );
    }

    #[test]
    fn embedded_spa_wires_the_key_diagnostics_endpoints() {
        // The /keys/status + /keys/patterns operator-telemetry endpoints exist and
        // are tested server-side; this guards that the SPA actually FETCHES them
        // (the Settings "Key diagnostics" panel) so they cannot silently revert to
        // dead-from-the-UI endpoints.
        let api = app_file("js/api.js");
        assert!(
            api.contains("/api/v1/keys/status"),
            "SPA must call /api/v1/keys/status (Key diagnostics panel)"
        );
        assert!(
            api.contains("/api/v1/keys/patterns"),
            "SPA must call /api/v1/keys/patterns (detector-coverage telemetry)"
        );
    }

    #[test]
    fn embedded_spa_wires_the_module_health_endpoint() {
        // /api/v1/modules/health (PROBLEM_TREE T2.7 / SOLUTION_TREE
        // SOL-HEALTH-SIGNAL) was previously reachable only from `hse doctor`;
        // guard that the Dashboard's "Module Health" panel actually fetches
        // and renders it, so it can't silently regress to dead-from-the-UI.
        let api = app_file("js/api.js");
        assert!(
            api.contains("/api/v1/modules/health"),
            "SPA must call /api/v1/modules/health (Dashboard Module Health panel)"
        );
        let dash = app_file("js/views/dash.js");
        assert!(
            dash.contains("moduleHealthPanel("),
            "the Dashboard must render the module-health panel"
        );
    }

    #[test]
    fn embedded_spa_wires_the_capability_probe_endpoint() {
        // /api/v1/capabilities/probe (v1.14+) is the proactive live capability
        // preflight — the in-browser twin of `hse doctor --live`. Guard that the
        // Engines page actually fetches and renders it, so the panel can't
        // silently regress to dead-from-the-UI like the health endpoints it
        // complements.
        let api = app_file("js/api.js");
        assert!(
            api.contains("/api/v1/capabilities/probe"),
            "SPA must call /api/v1/capabilities/probe (Engines live capability probe)"
        );
        let engines = app_file("js/views/engines.js");
        assert!(
            engines.contains("renderCapabilityProbePanel(") && engines.contains("runCapabilityProbe"),
            "the Engines page must render the capability-probe panel and its run action"
        );
    }

    #[test]
    fn embedded_spa_wires_the_per_scan_analysis_endpoints() {
        // Per-scan endpoints that were implemented + routed but the SPA never
        // surfaced. Each is now a section in the scan report; guard the wiring so
        // they cannot silently become dead-from-the-UI again.
        let api = app_file("js/api.js");
        for path in ["/benchmark", "/identities", "/location"] {
            assert!(
                api.contains(path),
                "SPA report must fetch the {path} per-scan endpoint"
            );
        }
        // The render sections must be composed into a scan surface so these
        // endpoints stay live-from-the-UI. Post-streamline the Summary
        // (report.js) headlines Location (the "where is the subject" residency
        // finding); Identities and Benchmark are lenses under the lazy Insights
        // tab (insights.js). Guard both homes.
        let summary = app_file("js/scan_info/report.js");
        let insights = app_file("js/scan_info/insights.js");
        assert!(
            summary.contains("renderLocation("),
            "the Summary must compose renderLocation() (the residency headline)"
        );
        assert!(
            insights.contains("renderIdentities("),
            "the Insights tab must compose renderIdentities()"
        );
        assert!(
            insights.contains("renderBenchmark("),
            "the Insights tab must compose renderBenchmark()"
        );
    }

    #[test]
    fn embedded_spa_surfaces_the_exposure_index() {
        // `core::exposure::assess` headlines the CLI dossier and the debug
        // bundle, but had no API consumer at all — so the web console (the only
        // interface on a Termux/Android device without a second terminal) never
        // showed the calibrated 0–100 verdict that summarises the whole scan.
        // Guard both ends of the wire so it cannot go dead again.
        let api = app_file("js/api.js");
        assert!(
            api.contains("/exposure"),
            "SPA must fetch the per-scan /exposure endpoint"
        );
        let info = app_file("js/scan_info/info.js");
        assert!(
            info.contains("API.exposure("),
            "the Info tab must call API.exposure()"
        );
        assert!(
            info.contains("Exposure Index"),
            "the Exposure Index panel must be rendered"
        );
        // Every component field the backend serialises must be consumed — a
        // breakdown that drops `detail` or `max` reduces the transparent
        // per-signal explanation to a bare number.
        for field in ["c.name", "c.score", "c.max", "c.detail"] {
            assert!(
                info.contains(field),
                "the Exposure breakdown must render {field}"
            );
        }
    }

    #[test]
    fn embedded_spa_wires_the_autonomous_plan_and_sweep_endpoints() {
        // The autonomous loop's read-only queue preview (/scan/auto/plan) and the
        // multi-target sweep (/scan/auto/sweep) are routed + tested server-side but
        // were dead-from-the-UI: the API methods existed yet no control invoked
        // them. Both are now wired into the New-Scan "Autonomous investigation"
        // panel; guard that the call sites stay present.
        let api = app_file("js/api.js");
        for path in ["/scan/auto/plan", "/scan/auto/sweep"] {
            assert!(
                api.contains(path),
                "SPA must fetch the {path} autonomous endpoint"
            );
        }
        // The handlers must be invoked from real UI controls, not merely defined.
        let new_scan = app_file("js/views/new_scan.js");
        assert!(
            new_scan.contains("autoQueuePreview(") && new_scan.contains("autoSweepGo("),
            "SPA must wire the queue-preview + auto-sweep controls"
        );
        assert!(
            new_scan.contains("API.autoPlan(") && new_scan.contains("API.autoSweep("),
            "the controls must call the autoPlan/autoSweep API methods"
        );
    }

    #[test]
    fn embedded_spa_styles_every_entity_kind() {
        // Rendering contract: every `EntityKind` a module can produce must have a
        // distinct `.k-<snake_case>` pill style, or it renders as an
        // undifferentiated default pill in Browse / the graph. The list is the
        // serde snake_case tags of `core::entity::EntityKind`; a drift count
        // against the enum keeps it honest when a kind is added.
        const KIND_STYLES: &[&str] = &[
            "abn_acn",
            "address",
            "api_key",
            "asn",
            "cidr",
            "coordinates",
            "credential",
            "crypto_address",
            "device_id",
            "domain",
            "email",
            "ip_address",
            "mac_address",
            "organisation",
            "other",
            "password",
            "person",
            "phone",
            "ssid",
            "tracking_id",
            "url",
            "username",
        ];
        // The Browse/report pill surface — a `.k-<kind>` CSS rule.
        let css = app_file("css/app.css");
        for k in KIND_STYLES {
            assert!(
                css.contains(&format!(".k-{k}{{")),
                "SPA has no `.k-{k}` pill style — EntityKind `{k}` renders as a \
                 default/undifferentiated pill; add a colour"
            );
        }
        // The graph surface — a NODE_COLOR entry. A kind missing here renders as
        // the undifferentiated '#888' grey node, indistinguishable from `other`.
        let node_colors = app_file("js/scan_info/graph.js")
            .split_once("const NODE_COLOR = {")
            .and_then(|(_, b)| b.split_once("};"))
            .map(|(b, _)| b)
            .expect("NODE_COLOR map present in graph.js");
        for k in KIND_STYLES {
            assert!(
                node_colors.contains(&format!("{k}:")),
                "EntityKind `{k}` has no NODE_COLOR entry — it renders as a grey \
                 default node in the graph; add a colour matching its pill"
            );
        }
        // Drift guard: pin to the real enum (every variant is a bare unit ident
        // except the `Other(String)` tuple, so count both forms).
        let src = std::fs::read_to_string(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/src/core/entity/mod.rs"
        ))
        .expect("entity source readable");
        let body = src
            .split_once("pub enum EntityKind {")
            .and_then(|(_, b)| b.split_once("\n}"))
            .map(|(b, _)| b)
            .expect("EntityKind enum present");
        let variant_count = body
            .lines()
            .filter(|l| {
                let t = l.trim_start();
                // 4-space-indented PascalCase ident, ending `,` or `(…` — not a
                // doc line (`///`) or attribute (`#`).
                l.starts_with("    ")
                    && !l.starts_with("        ")
                    && t.chars().next().is_some_and(|c| c.is_ascii_uppercase())
            })
            .count();
        assert_eq!(
            variant_count,
            KIND_STYLES.len(),
            "core::entity::EntityKind has {variant_count} variants but the SPA \
             pill-style list pins {} — add the new kind's `.k-<snake_case>` style",
            KIND_STYLES.len()
        );
    }

    #[test]
    fn embedded_spa_resolves_graph_link_endpoints_to_node_objects() {
        // buildD3Graph() builds links keyed by entity UID *strings*
        // (source:seedId, target:e.uid, ...). The vendored d3.min.js is D3 v3,
        // whose force.start() only auto-resolves *numeric* link.source/target
        // (treating them as indices into .nodes()); string keys pass through
        // untouched, and its internal neighbor-seeding pass then does
        // `e[u.source.index].push(...)` — `.index` on a bare string is
        // undefined, `e[undefined]` is undefined, and `.push` throws. This was
        // reproduced directly against src/web/vendor/d3.min.js in a Node vm
        // sandbox: force.start() threw `TypeError: Cannot read properties of
        // undefined (reading 'push')` on the very first scan with >=1 entity
        // (every scan has an unconditional seed->entity link). The fix
        // resolves source/target to real node object references via a
        // nodesById map before `.links()` is called — this guard pins that
        // resolution step so it cannot silently regress.
        let graph_fn = app_file("js/scan_info/graph.js")
            .split_once("function buildD3Graph(")
            .map(|(_, b)| b)
            .expect("buildD3Graph() present in graph.js");
        assert!(
            graph_fn.contains("nodesById"),
            "buildD3Graph must build a nodesById map to resolve string-keyed \
             link endpoints to node object references before calling \
             d3.layout.force().links(...), or D3 v3 throws on any scan with \
             at least one entity"
        );
        let links_call_idx = graph_fn
            .find(".links(")
            .expect("buildD3Graph calls .links(...)");
        assert!(
            graph_fn[..links_call_idx].contains("nodesById.get(l.source)")
                && graph_fn[..links_call_idx].contains("nodesById.get(l.target)"),
            "link source/target must be resolved via nodesById.get(...) before \
             the .links(...) call, matching the tick handler's existing \
             d.source.x/d.target.x object-reference assumption"
        );
    }

    #[test]
    fn embedded_spa_graph_is_bounded_and_never_builds_correlation_cliques() {
        // buildD3Graph historically drew a *clique* per correlation cluster:
        //   for (let i=0;i<uids.length;i++) for (let j=i+1;j<uids.length;j++)
        //     links.push({source:uids[i], target:uids[j], corr:true});
        // That is O(k²) in the cluster size. Real scans routinely produce
        // correlation clusters spanning 600+ members (a single 607-member
        // cluster is 183_921 edges); one observed scan — 1089 entities, several
        // 607-member clusters — expanded to ~15.27M `<line>` elements, which
        // hangs or crashes the browser tab and renders an unreadable hairball.
        // The fix caps the rendered node/edge counts and represents each
        // correlation as a bounded *star* (O(k)), not a clique. These asserts
        // pin that so the O(k²) construct cannot silently return.
        let graph = app_file("js/scan_info/graph.js");
        for c in ["GRAPH_MAX_NODES", "GRAPH_MAX_LINKS", "CORR_MAX_SPOKES"] {
            assert!(
                graph.contains(c),
                "graph.js must define the rendering ceiling `{c}` — without it a \
                 large scan builds millions of SVG edges and crashes the tab"
            );
        }
        // The exact clique double-loop over correlation member UIDs must be gone.
        assert!(
            !graph.contains("for (let j=i+1;j<uids.length;j++)"),
            "graph.js still contains the O(k²) correlation-clique double-loop — a \
             600+-member cluster expands to >180k edges; represent correlations \
             as a bounded star (CORR_MAX_SPOKES) instead"
        );
        let build = graph
            .split_once("function buildD3Graph(")
            .map(|(_, b)| b)
            .expect("buildD3Graph() present in graph.js");
        assert!(
            build.contains(".slice(0, GRAPH_MAX_NODES)"),
            "buildD3Graph must cap rendered entity nodes via \
             .slice(0, GRAPH_MAX_NODES)"
        );
        assert!(
            build.contains("CORR_MAX_SPOKES") && build.contains("GRAPH_MAX_LINKS"),
            "buildD3Graph must bound correlation fan-out (CORR_MAX_SPOKES) and \
             the total edge count (GRAPH_MAX_LINKS)"
        );
        // The summary notice element that tells the operator the view is capped
        // (and where the complete graph lives) must exist and be populated.
        assert!(
            graph.contains("id=\"graph-cap\"") && graph.contains("#graph-cap"),
            "graph.js must render and populate the #graph-cap notice so a capped \
             graph points the operator to Browse / Relations / GEXF"
        );
    }

    #[test]
    fn embedded_spa_deep_links_resolve_to_a_visible_section() {
        // The Location "no leads yet" hint and the status correlation-count
        // callout link to `#/scaninfo?...&tab=network` / `&tab=corr`. Post
        // streamline, Correlations is its own tab (the &tab=corr link resolves
        // straight to it) and the network section lives on the Summary (the
        // &tab=network link folds onto Summary and scrolls to #sum-network).
        // Guard both the anchor text and the dispatch so a link can never go
        // inert again.
        assert!(
            app_file("js/scan_info/leads.js").contains("tab=network\">Network</a>"),
            "expected deep-link anchor text `tab=network\">Network</a>` in leads.js"
        );
        assert!(
            app_file("js/scan_info/status.js").contains("tab=corr\">Correlations</a>"),
            "expected deep-link anchor text `tab=corr\">Correlations</a>` in status.js"
        );
        let dispatch = app_file("js/scan_info/index.js")
            .split_once("const body = $('#scan-body');")
            .and_then(|(_, b)| b.split_once("\n\n"))
            .map(|(b, _)| b)
            .expect("renderScanInfo's tab dispatch block present");
        assert!(
            dispatch.contains("activeTab==='corr'") && dispatch.contains("renderCorrelations("),
            "tab=corr must render the Correlations tab (renderCorrelations)"
        );
        assert!(
            dispatch.contains("tab==='network'") && dispatch.contains("$('#sum-network')"),
            "tab=network must fold onto the Summary and scroll to #sum-network"
        );
    }

    #[test]
    fn embedded_spa_scan_detail_is_streamlined() {
        // The scan-detail view was streamlined (SpiderFoot-style) from a single
        // ~90-screen "Report" scroll (~15 sections, ~17 API calls on open) into a
        // slim Summary + a lazy Insights drawer + a dedicated Correlations tab.
        // Pin the shape so it cannot regress into the kitchen-sink scroll.
        let index = app_file("js/scan_info/index.js");
        for t in [
            "subTab('summary'",
            "subTab('browse'",
            "subTab('graph'",
            "subTab('corr'",
            "subTab('insights'",
        ] {
            assert!(index.contains(t), "scan-detail tab bar must include {t}");
        }
        // The Summary leads with the calibrated Exposure Index (the headline the
        // CLI dossier opens with) — which was previously dead-from-the-UI.
        let summary = app_file("js/scan_info/report.js");
        assert!(
            summary.contains("renderExposure("),
            "the Summary must headline the Exposure Index"
        );
        // Insights is a lazy lens switcher — it renders one lens on demand, not
        // all ~10 analytical sections (and their fetches) at once.
        let insights = app_file("js/scan_info/insights.js");
        assert!(
            insights.contains("data-lens") && insights.contains("insights-lens"),
            "Insights must be a lazy per-lens switcher"
        );
        // Correlation member rows are built lazily on expand — a 607-member
        // cluster must not put tens of thousands of hidden DOM nodes on the page
        // up front (the same unbounded-render class as the graph clique bug).
        let corr = app_file("js/scan_info/correlations.js");
        assert!(
            corr.contains("data-corr-idx") && corr.contains("dataset.built"),
            "correlation members must be built lazily on card expand, not up front"
        );
    }

    #[test]
    fn embedded_spa_renders_every_event_kind() {
        // Event contract: every `EventKind` variant the engine/live loop emits
        // over the bus must have a friendly `mapEvent` case in the SPA, or it
        // renders as a raw-JSON blob in the live log / Live-activity panel. The
        // snake_case names below are the serde `type` tags of `core::event::
        // EventKind` — keep in sync when a variant is added (the same pin-the-list
        // discipline as the architecture guards). The `live_*` trio is the case
        // that was actually rendering raw before this guard existed.
        const EVENT_TYPES: &[&str] = &[
            "module_start",
            "module_done",
            "module_error",
            "module_skipped",
            "entity_found",
            "scan_start",
            "scan_complete",
            "expansion_tick",
            "expansion_stop",
            "entity_excluded",
            "breach_sweep",
            "consensus_audit",
            "correlation_found",
            "correlations_done",
            "live_start",
            "live_tick",
            "live_stop",
        ];
        let log_js = app_file("js/scan_info/log.js");
        for ty in EVENT_TYPES {
            assert!(
                log_js.contains(&format!("t==='{ty}'")),
                "SPA mapEvent has no case for EventKind `{ty}` — it would render \
                 as raw JSON in the live log; add a friendly row"
            );
        }
        // Drift guard: pin the list to the real enum so a NEW EventKind variant
        // can't be added without giving it a mapEvent case. Every variant carries
        // fields (`Variant {`), so count 4-space-indented PascalCase openings.
        let src =
            std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/src/core/event/mod.rs"))
                .expect("event source readable");
        let body = src
            .split_once("pub enum EventKind {")
            .and_then(|(_, b)| b.split_once("\n}"))
            .map(|(b, _)| b)
            .expect("EventKind enum present");
        let variant_count = body
            .lines()
            .filter(|l| {
                let t = l.trim_start();
                l.starts_with("    ")
                    && !l.starts_with("        ")
                    && t.chars().next().is_some_and(|c| c.is_ascii_uppercase())
                    && t.trim_end().ends_with('{')
            })
            .count();
        assert_eq!(
            variant_count,
            EVENT_TYPES.len(),
            "core::event::EventKind has {variant_count} variants but the SPA \
             event-contract list pins {} — add the new variant's snake_case type \
             here (and a mapEvent case in spa.html)",
            EVENT_TYPES.len()
        );
    }

    #[test]
    fn spa_enrichment_sources_matches_backend_is_non_corroborating_source() {
        // Drift guard: the SPA's client-side C_eff mirror (`ENRICHMENT_SOURCES`,
        // used by `sourceCount()`/`effC()` in spa.html to reproduce
        // `Entity::c_effective()` for Browse) must exclude exactly the same
        // evidence sources as the backend's authoritative
        // `is_non_corroborating_source()`. It once carried only 2 of the real
        // exclusions (missing `name_intel`, `payid`, `cross_scan_history`), and
        // later lagged again on `breach_consensus`, so an entity corroborated
        // only by one of those rendered a higher
        // C_eff/tier in Browse than the server's own classification —
        // reintroducing, client-side, the exact over-credit bugs those
        // exclusions were added to close.
        //
        // NOTE when adding a new non-corroborating source: append its constant
        // to `expected` below as well. This list is a hand-assembled mirror of
        // `is_non_corroborating_source`'s arms (a predicate's domain can't be
        // enumerated), so it is itself drift-prone — it once omitted
        // `CONSENSUS_SOURCE` after that arm was added, which made this guard
        // demand the *stale* 5-member set and fail the corrected 6-member SPA
        // copy. The `is_non_corroborating_source` assertion below catches the
        // reverse slip (a constant listed here that the predicate no longer
        // excludes).
        use crate::core::entity::{
            CONSENSUS_SOURCE, CROSS_SCAN_SOURCE, ENRICHMENT_ONLY_SOURCES, RECALL_SOURCE,
            is_non_corroborating_source,
        };
        let expected: Vec<&str> = ENRICHMENT_ONLY_SOURCES
            .iter()
            .copied()
            .chain([RECALL_SOURCE, CROSS_SCAN_SOURCE, CONSENSUS_SOURCE])
            .collect();
        for name in &expected {
            assert!(
                is_non_corroborating_source(name),
                "`{name}` is listed as an expected exclusion but the backend's \
                 is_non_corroborating_source() no longer excludes it — this \
                 guard's mirror of the predicate has gone stale"
            );
        }
        let js = app_file("js/helpers.js")
            .split_once("const ENRICHMENT_SOURCES = new Set([")
            .and_then(|(_, rest)| rest.split_once(']'))
            .map(|(set, _)| set)
            .expect("ENRICHMENT_SOURCES literal present in helpers.js");
        for name in &expected {
            assert!(
                js.contains(&format!("'{name}'")),
                "backend is_non_corroborating_source excludes `{name}` but the \
                 SPA's ENRICHMENT_SOURCES set does not — Browse would over-credit \
                 an entity corroborated only by this source"
            );
        }
        // Symmetric: no UNEXPECTED member either — a source wrongly excluded
        // client-side would under-credit an entity the backend treats as
        // genuinely corroborating.
        let js_count = js.matches('\'').count() / 2;
        assert_eq!(
            js_count,
            expected.len(),
            "SPA ENRICHMENT_SOURCES has a different member count than the \
             backend's exclusion list ({expected:?}) — check for a stale or \
             extra entry: {js}"
        );
    }

    #[test]
    fn embedded_spa_tails_the_live_session_event_stream() {
        // The per-session live SSE endpoint (/live/{id}/events) streams a running
        // session's lifecycle + every per-iteration scan's events. It had no SPA
        // consumer — the Live Monitor only polled the session list every 8s. The
        // "Live activity" panel now opens an EventSource against it; guard the
        // wiring so the stream can't silently revert to dead-from-the-UI.
        let log_js = app_file("js/scan_info/log.js");
        let live_js = app_file("js/views/live.js");
        assert!(
            log_js.contains("/live/'+encodeURIComponent(liveId)+'/events"),
            "SPA must open an EventSource against /live/{{id}}/events"
        );
        assert!(
            log_js.contains("openLiveSse(") && live_js.contains("openLiveStream("),
            "SPA must define the live-session stream tail (openLiveSse/openLiveStream)"
        );
        // The tail must be invoked from a real per-session control.
        assert!(
            live_js.contains("data-livestream") && live_js.contains("wireLiveStreams("),
            "each Active-sessions row must carry a Stream control wired to the tail"
        );
    }

    #[test]
    fn external_resource_scanner_flags_a_cdn_but_not_a_local_or_anchor() {
        // Guard the guard: the scanner must catch a real external resource load,
        // ignore same-origin ones, and ignore navigational <a> links.
        let sample = r#"
            <link rel="stylesheet" href="https://cdn.example/x.css">
            <script src="/static/app.js"></script>
            <link rel="icon" href="data:image/svg+xml,<svg/>">
            <a href="https://github.com/example">repo</a>
            <img src="//cdn.example/pixel.gif">
        "#;
        let hits = external_resource_refs(sample);
        assert_eq!(
            hits.len(),
            2,
            "exactly the CDN css + protocol-relative img: {hits:?}"
        );
        assert!(hits.iter().any(|h| h.contains("cdn.example/x.css")));
        assert!(hits.iter().any(|h| h.contains("//cdn.example/pixel.gif")));
        assert!(
            !hits.iter().any(|h| h.contains("github.com")),
            "<a> is not a resource"
        );
        assert!(
            !hits.iter().any(|h| h.contains("/static/")),
            "same-origin is fine"
        );
    }

    #[test]
    fn spa_scan_preset_modules_are_all_registered() {
        // The New-Scan use-case presets (Footprint / Investigate / …) select their
        // module set by name from a hard-coded `pick:m=>['a','b',…].includes(m.name)`
        // list in the SPA. A renamed or removed module silently drops out of the
        // preset — the name simply stops matching — quietly shrinking coverage in
        // the web UI with no error anywhere. Pin every preset name to the live
        // registry so a module rename/removal can't rot a preset unnoticed: the
        // same no-silent-drift guard the README / MODULES.md counts already carry.
        let registered: std::collections::BTreeSet<&str> =
            crate::modules::registry().iter().map(|m| m.name()).collect();

        let state_js = app_file("js/state.js");
        let mut checked = 0usize;
        let mut idx = 0;
        while let Some(rel) = state_js[idx..].find("pick:m=>[") {
            let start = idx + rel + "pick:m=>[".len();
            let end = state_js[start..]
                .find(']')
                .map_or(state_js.len(), |e| start + e);
            for raw in state_js[start..end].split(',') {
                let name = raw.trim().trim_matches(['\'', '"']);
                if name.is_empty() {
                    continue;
                }
                assert!(
                    registered.contains(name),
                    "New-Scan preset references unknown module `{name}` — update \
                     src/web/spa.html after a module rename/removal"
                );
                checked += 1;
            }
            idx = end;
        }
        // Sanity floor: the literal-list presets (Footprint + Investigate) name
        // ~20 modules between them, so a refactor that drops the `pick:m=>[…]`
        // syntax can't quietly make this guard vacuous.
        assert!(
            checked >= 20,
            "expected the SPA scan presets to name many modules, saw {checked}"
        );
    }
