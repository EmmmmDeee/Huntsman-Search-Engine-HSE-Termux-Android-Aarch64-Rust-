//! The serve page's contracts that hold without a browser: its colours meet WCAG AA in both
//! themes (text 4.5:1, the graph's node colours 3:1), its light theme follows the system until the
//! toggle picks one, every scan call carries the lookup header, provider text reaches the page only
//! as text, it keeps nothing of a scan in the browser, a returning tab asks only for health unless
//! a scan is running, and it stays within its weight budget. CI also drives the page in a
//! phone-sized browser (`tools/web-ui-check`), and the last test here keeps that job in place.

use std::collections::BTreeMap;
use std::fs;

const PAGE: &str = include_str!("../src/web_ui.html");
/// The most the page may weigh. It is read from loopback on a phone, but every byte is parsed on
/// the phone's CPU each time the tab loads. Spiderfoot's own UI loads about 1 MiB of scripts and
/// styles for the same views; this page is one file with no library.
const PAGE_BUDGET: usize = 96 * 1024;
/// WCAG 2.2 AA for text under 18.66 px bold or 24 px: the page has none larger.
const AA: f64 = 4.5;
/// WCAG 2.2 AA for a graphical object a reader must see (1.4.11), such as a graph node.
const NON_TEXT: f64 = 3.0;

/// The text between `<tag>` and `</tag>`.
fn inline(tag: &str) -> &'static str {
    let open = format!("<{tag}>");
    let start = PAGE.find(&open).expect("open tag") + open.len();
    let end = PAGE.find(&format!("</{tag}>")).expect("close tag");
    &PAGE[start..end]
}

/// The declarations of the first rule that opens with `selector{`.
fn rule<'a>(style: &'a str, selector: &str) -> &'a str {
    let open = format!("{selector}{{");
    let start = style
        .find(&open)
        .unwrap_or_else(|| panic!("no rule {open}"))
        + open.len();
    let end = style[start..].find('}').expect("rule end") + start;
    &style[start..end]
}

fn tokens(declarations: &str) -> BTreeMap<String, String> {
    declarations
        .split(';')
        .filter_map(|declaration| declaration.trim().split_once(':'))
        .filter(|(name, _)| name.starts_with("--"))
        .map(|(name, value)| (name.to_owned(), value.trim().to_owned()))
        .collect()
}

/// `#rgb`, `#rrggbb` or `rgba(r,g,b,a)` as sRGB channels in 0..=1 and an alpha.
fn colour(value: &str) -> ([f64; 3], f64) {
    if let Some(hex) = value.strip_prefix('#') {
        let hex: String = if hex.len() == 3 {
            hex.chars().flat_map(|c| [c, c]).collect()
        } else {
            hex.to_owned()
        };
        assert_eq!(hex.len(), 6, "{value}");
        let channel =
            |i: usize| f64::from(u8::from_str_radix(&hex[i..i + 2], 16).expect(value)) / 255.0;
        return ([channel(0), channel(2), channel(4)], 1.0);
    }
    let inner = value
        .strip_prefix("rgba(")
        .and_then(|rest| rest.strip_suffix(')'))
        .unwrap_or_else(|| panic!("not a colour: {value}"));
    let parts: Vec<f64> = inner
        .split(',')
        .map(|p| p.trim().parse().expect(value))
        .collect();
    assert_eq!(parts.len(), 4, "{value}");
    (
        [parts[0] / 255.0, parts[1] / 255.0, parts[2] / 255.0],
        parts[3],
    )
}

fn luminance([r, g, b]: [f64; 3]) -> f64 {
    let linear = |c: f64| {
        if c <= 0.040_45 {
            c / 12.92
        } else {
            ((c + 0.055) / 1.055).powf(2.4)
        }
    };
    0.2126 * linear(r) + 0.7152 * linear(g) + 0.0722 * linear(b)
}

fn contrast(a: [f64; 3], b: [f64; 3]) -> f64 {
    let (la, lb) = (luminance(a), luminance(b));
    (la.max(lb) + 0.05) / (la.min(lb) + 0.05)
}

/// `top` laid over `under`, as the browser composites a translucent background.
fn over(top: ([f64; 3], f64), under: [f64; 3]) -> [f64; 3] {
    let ([r, g, b], a) = top;
    [
        r * a + under[0] * (1.0 - a),
        g * a + under[1] * (1.0 - a),
        b * a + under[2] * (1.0 - a),
    ]
}

/// The dark tokens, and the dark tokens with the light theme's laid over them.
fn themes() -> [(&'static str, BTreeMap<String, String>); 2] {
    let style = inline("style");
    let dark = tokens(rule(style, ":root"));
    let mut light = dark.clone();
    light.extend(tokens(rule(style, ":root.light")));
    [("dark", dark), ("light", light)]
}

#[test]
fn every_text_colour_meets_wcag_aa_in_both_themes() {
    let style = inline("style");
    // The pairs below are the ones the page draws: a chip is muted text on the hover surface, and
    // the primary button is --acct on --acc.
    assert!(style.contains(".label{display:inline-block;padding:2px 7px;border-radius:3px;background:var(--hover);color:var(--muted);"));
    assert!(
        style.contains(
            ".btn-primary{background:var(--acc);border-color:var(--acc);color:var(--acct);"
        )
    );
    let mut failures = Vec::new();
    for (theme, t) in themes() {
        let solid = |name: &str| {
            let (rgb, alpha) = colour(&t[name]);
            assert!(
                (alpha - 1.0).abs() < f64::EPSILON,
                "{theme} {name} must be opaque"
            );
            rgb
        };
        let mut need = |text: &str, ground: &str, rgb_text: [f64; 3], rgb_ground: [f64; 3]| {
            let ratio = contrast(rgb_text, rgb_ground);
            if ratio < AA {
                failures.push(format!("{theme}: {text} on {ground} is {ratio:.2}:1"));
            }
        };
        for surface in ["--bg", "--el", "--el2"] {
            for text in [
                "--fg", "--muted", "--dim", "--acc", "--ok", "--warn", "--bad",
            ] {
                need(text, surface, solid(text), solid(surface));
            }
            // A status chip or alert: the colour on its own tint, over the surface it sits on.
            for (text, tint) in [
                ("--ok", "--okd"),
                ("--warn", "--warnd"),
                ("--bad", "--badd"),
                ("--acc", "--accd"),
            ] {
                let ground = over(colour(&t[tint]), solid(surface));
                need(text, &format!("{tint} over {surface}"), solid(text), ground);
            }
        }
        need("--acct", "--acc", solid("--acct"), solid("--acc"));
        need("--muted", "--hover", solid("--muted"), solid("--hover"));
    }
    assert!(
        failures.is_empty(),
        "below {AA}:1:\n{}",
        failures.join("\n")
    );
}

#[test]
fn the_light_theme_follows_the_system_until_the_toggle_picks_one() {
    let style = inline("style");
    assert_eq!(
        rule(
            style,
            "@media (prefers-color-scheme:light){:root:not(.dark)"
        ),
        rule(style, ":root.light"),
        "the system's light theme and the chosen one must be the same tokens"
    );
    let script = inline("script");
    assert!(script.contains("const sys=matchMedia('(prefers-color-scheme: light)');"));
    assert!(script.contains("isLight=t?t==='light':sys.matches;"));
    assert!(script.contains(
        "root.classList.toggle('light',t==='light');root.classList.toggle('dark',t==='dark');"
    ));
    assert!(script.contains("if(sys.addEventListener)sys.addEventListener('change',theme);"));
    // The browser's own bar takes the app bar's colour (--el) in each theme.
    let bar = "$('themecolor').content=isLight?'";
    let start = script.find(bar).expect("theme-color update") + bar.len();
    let (light_bar, rest) = script[start..].split_once("':'").expect("light colour");
    let dark_bar = rest.split_once('\'').expect("dark colour").0;
    let [(_, dark), (_, light)] = themes();
    assert_eq!(colour(light_bar).0, colour(&light["--el"]).0);
    assert_eq!(colour(dark_bar).0, colour(&dark["--el"]).0);
    assert!(PAGE.contains(&format!(
        "<meta name=\"theme-color\" content=\"{dark_bar}\" id=\"themecolor\">"
    )));
}

#[test]
fn the_graph_nodes_stand_out_from_the_graph_in_both_themes() {
    let style = inline("style");
    assert!(style.contains(".graph{height:62vh;min-height:300px;margin:0 0 10px;background:var(--el);"));
    let mut failures = Vec::new();
    for (theme, t) in themes() {
        let ground = colour(&t["--el"]).0;
        for i in 0..10 {
            let name = format!("--g{i}");
            assert!(style.contains(&format!(".g{i}{{fill:var({name});")), "no .g{i} rule");
            let ratio = contrast(colour(&t[&name]).0, ground);
            if ratio < NON_TEXT {
                failures.push(format!("{theme}: {name} on --el is {ratio:.2}:1"));
            }
        }
    }
    assert!(
        failures.is_empty(),
        "below {NON_TEXT}:1:\n{}",
        failures.join("\n")
    );
}

#[test]
fn every_scan_call_carries_the_lookup_header_and_provider_text_stays_text() {
    let script = inline("script");
    // Scans spend egress and keys, so they go through api(), which always sends the header that
    // another origin cannot send without a preflight this server never approves.
    assert!(script.contains("const LH={'X-Huntsman-Lookup':'1'}"));
    assert!(script.contains("try{res=await call(path,LH,opts)}"));
    assert!(!script.contains("call('/api/scans"), "a scan call without the header");
    assert_eq!(script.matches("fetch(").count(), 2, "call() and the export");
    assert!(script.contains("await fetch(base()+'/export?'+p,{headers:headers(LH),cache:'no-store'})"));
    // Provider text reaches the page only as text.
    assert!(script.contains("function el(tag,cls,text){const e=document.createElement(tag);if(cls)e.className=cls;if(text!=null)e.textContent=String(text);return e}"));
    for sink in [
        "innerHTML",
        "outerHTML",
        "insertAdjacentHTML",
        "document.write",
        "eval(",
        "new Function",
    ] {
        assert!(!script.contains(sink), "the page uses {sink}");
    }
}

#[test]
fn scans_live_on_the_server_and_only_the_analysis_is_kept_for_the_tab() {
    let script = inline("script");
    assert!(script.contains("const store=keep(()=>localStorage),sess=keep(()=>sessionStorage);"));
    assert_eq!(
        script.matches("localStorage").count(),
        1,
        "one guarded accessor"
    );
    assert_eq!(
        script.matches("sessionStorage").count(),
        1,
        "one guarded accessor"
    );
    // A scan is saved by the server and named in the address (#/scan/ID/section), so a reload
    // finds it there. The tab keeps only the last analysis, which the server does not save.
    assert!(script.contains("showAnalysis(saved);sess.set('hse-analysis',JSON.stringify(saved));"));
    for call in script.split("sess.set(").skip(1) {
        assert!(call.starts_with("'hse-analysis'"), "sess.set({}", &call[..call.len().min(40)]);
    }
    assert!(script.contains("location.hash='#/scan/'+enc(r.id)+'/summary'"));
    // Local storage outlives the tab, so it holds a preference and a public bind's token, never a
    // result.
    for call in script.split("store.set(").skip(1) {
        assert!(
            call.starts_with("'hse-theme'") || call.starts_with("'hse-token'"),
            "store.set({}",
            &call[..call.len().min(40)]
        );
    }
}

#[test]
fn a_returning_tab_asks_only_for_health_unless_a_scan_is_running() {
    let script = inline("script");
    assert!(script.contains(
        "document.addEventListener('visibilitychange',()=>{if(!document.hidden){health();if(resume){clearTimeout(timer);resume()}}});"
    ));
    // A poll is set only while a scan runs, skipped while the tab is hidden, and dropped when the
    // view changes; a finished scan leaves nothing to resume.
    assert!(script.contains("function later(fn){clearTimeout(timer);const g=gen;resume=fn;timer=setTimeout(()=>{if(g===gen&&!document.hidden)fn()},5000)}"));
    assert!(script.contains("gen++;clearTimeout(timer);resume=null;view=v;"));
    assert!(script.contains("if(scans.some(s=>live(s.status)))later(loadScans);else resume=null;"));
    assert!(script.contains("if(running)later(()=>loadScan(false));else resume=null;"));
    let start = script.find("async function health(){").expect("health");
    let end = script.find("async function details(){").expect("details");
    let health = &script[start..end];
    assert!(!health.contains("/api/modules"), "{health}");
    assert!(!health.contains("/api/scans"), "{health}");
    assert_eq!(health.matches("/api/command").count(), 1, "{health}");
    assert!(health.contains("call('/api/command',{},{method:'HEAD'})"));
    assert!(script.contains("else if(v==='about'&&!detailed)details();"));
}

#[test]
fn the_page_stays_within_its_budget() {
    assert!(
        PAGE.len() <= PAGE_BUDGET,
        "the page is {} bytes; its budget is {PAGE_BUDGET}",
        PAGE.len()
    );
}

#[test]
fn ci_drives_the_page_in_a_phone_browser() {
    let ci = fs::read_to_string(".github/workflows/ci.yml").expect("ci.yml");
    for required in [
        "  web-ui:\n",
        "working-directory: tools/web-ui-check",
        "run: npm install --no-package-lock --ignore-scripts",
        "run: cargo build --locked --bin huntsman-recon",
        "node tools/web-ui-check/check.cjs target/debug/huntsman-recon",
    ] {
        assert!(ci.contains(required), "ci.yml must contain {required:?}");
    }
    let check = fs::read_to_string("tools/web-ui-check/check.cjs").expect("check.cjs");
    assert!(check.contains(&format!(
        "const PAGE_BUDGET = {} * 1024;",
        PAGE_BUDGET / 1024
    )));
    let manifest: serde_json::Value = serde_json::from_str(
        &fs::read_to_string("tools/web-ui-check/package.json").expect("package.json"),
    )
    .expect("package.json is JSON");
    let dependencies = manifest["dependencies"].as_object().expect("dependencies");
    assert_eq!(
        dependencies.keys().map(String::as_str).collect::<Vec<_>>(),
        ["axe-core", "playwright-core"]
    );
    for (name, version) in dependencies {
        let version = version.as_str().expect("version");
        assert!(
            version.split('.').count() == 3
                && version.chars().all(|c| c.is_ascii_digit() || c == '.'),
            "{name} must be pinned to an exact version, not {version:?}"
        );
    }
}
