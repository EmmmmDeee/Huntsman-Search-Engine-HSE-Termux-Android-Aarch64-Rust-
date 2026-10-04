# Legacy expected outputs: M D's 764ce8e

`*_cases.json` are the inputs. `*_expected.json` are what the **legacy** code produced for
them. They were recorded before the port and are not edited by hand.

- Legacy code: the old tree `restore/md-stolen-tax-crtsh` at `4d5db3dc`. That is
  `1dfb5c9d` ("restore: M D's stolen.tax v2 + crtsh changes (from lost local commit
  764ce8e)") merged with `98c77fd`. The uncommitted blank-name/host guard is excluded,
  so these files show the pre-guard behaviour. The stale v1 copies under `legacy/`
  were not used.
- How: the harness below was appended (scratch clone only) to
  `src/modules/{stolen_tax,crtsh}/mod.rs`. It runs the module's own decode →
  normalise → `build_entities` → `dedup_merge_entities` → partial-marking steps on
  each case, without a network. The capture ran on 2026-10-03 (AEST), built with
  `-j 1`:

      LEGACY_CAPTURE_DIR=$PWD/tests/fixtures/legacy_764ce8e \
        cargo +1.98.0 test -j 1 --lib -- legacy_capture --test-threads=1

- Checked by `src/stolen_tax/differential.rs` and `src/crtsh/differential.rs`. crt.sh
  must match exactly; ordering within a confidence tie follows each crate's uid.
  stolen.tax must match except for the guard: no `breach:osintcat`/`stealer:unknown`
  placeholder markers, and no `unknown` stand-in facts in evidence text.

The stealer IPs in `stolen_tax_cases.json` are RFC 5737 documentation addresses
(`192.0.2.***`, `198.51.100.**`, `203.0.113.***`, masked as the provider masks them).
They replaced routable-looking prefixes (`27.56.`, `103.196.`, `1.2.`), and
`stolen_tax_expected.json` was re-captured from the same legacy tree with the same
harness on the new inputs (2026-10-03 AEST); the only change in the output is the
`ip=` text in four stealer evidence summaries.

The crt.sh case with `"generate_unrelated": N` adds one entry whose `name_value` is
`host{i}.other-{i}.net` for `i` in `0..N`, joined by newlines.

## One-key 429 retry: `stolen_tax_single_key_expected.json`

Derived, not recorded directly. The source is a second legacy capture on the same old
tree (`4d5db3dc`), recorded 2026-10-03 (AEST) and kept out of the repository: the
module's real `process()` and `util::http::keyed_cascade_json`, with the provider
served on loopback and a two-key setup (the environment key, logged as `first`, plus
one pooled key, logged as `second`). Nine scenarios (the first key answering 429 with
`Retry-After: 0`, 401, 403, an auth-shaped 400, an in-body dead key, an in-body quota
error, 500; and both keys answering 429 or an in-body dead key) were run over the 13
`stolen_tax_cases.json` cases, logging every request as `{path, key, status}`. The
keys were throwaway per-case labels, and neither the log nor this fixture carries a
key: keys appear only as the labels `first`/`second`. Besides labels and statuses, the
fixture holds the nine synthetic `first_key_answer` responses (status, headers and
body) the loopback provider was scripted to send, and three `legacy_error` strings in
which the monolith quoted those bodies. None of them is a secret or a real stolen.tax
response.

Derivation (the script below, run on that capture):

- `attempts[path]` is the run of requests legacy sent on the first key for that path
  before it asked the pool for another key. With a one-key pool there is no other
  key: `next_pooled_key` returns `None` and `keyed_cascade_json` returns the last
  attempt's error, so the path fails after exactly these attempts. The script
  checks that all 13 cases agree and that the first key is never used again on a
  path after the second key was asked.
- `paths_captured_with_one_key` are the paths that really ran with one usable key
  (the pooled key already burned, or never asked for): `osintcat` and `hudsonrock`
  in `all_keys_429` (3 × 429 each) and `all_keys_in_body_dead` (1 request each),
  and every path in the 500 scenario.
- `legacy_error` is the module error when every case failed with one text
  (`all_keys_*` and 500, where every key reached answered as the one key does);
  otherwise `null`, because the second key rescued the lookup.

`src/stolen_tax/differential.rs` (`single_key_attempts_match_the_legacy_cascade_with_one_key`)
replays each scenario's first-key answer to the port with one key and requires the
same attempts in the same order, a failed lookup, the status (or the provider's own
words for an in-body error) in the failure, and no key in any error text.

```python
# Derive the one-key retry fixture from the legacy two-key rotation capture.
import json, sys
cap = sys.argv[1]
cases = json.load(open(f"{cap}/stolen_tax_rotation_cases.json"))
exp = json.load(open(f"{cap}/stolen_tax_rotation_expected.json"))
PATHS = ["snusbase", "osintcat", "hudsonrock"]
out = []
for scen_in, scen in zip(cases, exp["scenarios"]):
    assert scen_in["name"] == scen["name"]
    per_case = []
    for c in scen["cases"]:
        attempts = {}
        for p in PATHS:
            reqs = [r for r in c["requests"] if r["path"] == p]
            prefix = []
            for r in reqs:
                if r["key"] != "first":
                    break
                prefix.append(r["status"])
            # Nothing on the first key after the second key was asked.
            assert all(r["key"] != "first" for r in reqs[len(prefix):]), (scen["name"], p)
            attempts[p] = prefix
        per_case.append(attempts)
    # The first key's answer does not depend on the case: every case agrees.
    assert all(a == per_case[0] for a in per_case), scen["name"]
    attempts = per_case[0]
    # Where the second key was never asked for a path, legacy ran that path with a
    # one-key pool (the second key was burned or never needed): its error is captured.
    one_key_paths = [
        p for p in PATHS
        if all(r["key"] == "first" for r in scen["cases"][0]["requests"] if r["path"] == p)
    ]
    # The module error, where every case failed with one text: then every key the
    # paths reached answered exactly as the one key does (all_keys_*, 500).
    errors = {c["error"] for c in scen["cases"]}
    error = errors.pop() if len(errors) == 1 and None not in errors else None
    out.append({
        "name": scen["name"],
        "first_key_answer": scen_in["first_key"],
        "attempts": attempts,
        "paths_captured_with_one_key": one_key_paths,
        "legacy_error": error,
    })
doc = {
    "derived_from": "stolen_tax_rotation_expected.json: " + exp["captured_from"]
    + "; two-key run (env key 'first' + pooled key 'second'), see CAPTURE.md",
    "rule": "attempts[path] = the requests legacy sent on the first key for that path "
    "before asking the pool for another key; with a one-key pool there is no other key, "
    "so the path fails after them (keyed_cascade_json: next_pooled_key -> None -> Err)",
    "scenarios": out,
}
print(json.dumps(doc, indent=2))
```

## Harness (diff against `4d5db3dc`)

```diff
diff --git a/src/modules/crtsh/mod.rs b/src/modules/crtsh/mod.rs
index af13ee08..b83bd8da 100644
--- a/src/modules/crtsh/mod.rs
+++ b/src/modules/crtsh/mod.rs
@@ -436,3 +436,101 @@ async fn fetch_crt_json_with_transient_retry<T: serde::de::DeserializeOwned>(
 mod tests {
     include!("tests.rs");
 }
+
+/// Differential capture only (scratch clone): runs M D's 764ce8e crt.sh logic over
+/// shared fixtures and writes the observed output. Not part of any committed tree.
+#[cfg(test)]
+mod legacy_capture {
+    use super::*;
+    use serde_json::Value;
+
+    fn entity_json(e: &Entity) -> Value {
+        let mut tags = e.tags.clone();
+        tags.sort();
+        let evidence: Vec<Value> = e
+            .evidence
+            .iter()
+            .map(|ev| serde_json::json!({"source": ev.source, "summary": ev.summary, "attributes": ev.attributes}))
+            .collect();
+        serde_json::json!({
+            "kind": format!("{:?}", e.kind),
+            "value": e.value,
+            "raw_value": e.raw_value,
+            "confidence": e.confidence,
+            "tags": tags,
+            "evidence": evidence,
+        })
+    }
+
+    fn kind(s: &str) -> TargetKind {
+        match s {
+            "domain" => TargetKind::Domain,
+            "email" => TargetKind::Email,
+            "url" => TargetKind::Url,
+            "username" => TargetKind::Username,
+            other => panic!("kind {other}"),
+        }
+    }
+
+    #[tokio::test]
+    async fn capture() {
+        let dir = std::env::var("LEGACY_CAPTURE_DIR").expect("LEGACY_CAPTURE_DIR");
+        let cases: Vec<Value> = serde_json::from_str(
+            &std::fs::read_to_string(format!("{dir}/crtsh_cases.json")).expect("read"),
+        )
+        .expect("cases");
+        let mut out = Vec::new();
+        for case in &cases {
+            let k = kind(case["seed_kind"].as_str().expect("kind"));
+            let seed = case["seed"].as_str().expect("seed");
+            let mut raw = case["entries"].as_array().expect("entries").clone();
+            if let Some(n) = case["generate_unrelated"].as_u64() {
+                let sans: Vec<String> = (0..n).map(|i| format!("host{i}.other-{i}.net")).collect();
+                raw.push(serde_json::json!({"name_value": sans.join("\n")}));
+            }
+            let entries: Vec<CrtEntry> = serde_json::from_value(Value::Array(raw)).expect("entries");
+            let base = apex_base(k, seed);
+            let ents = build_entities(&entries, &base, "fixture-scan");
+            let mut sorted: Vec<Value> = ents.iter().map(entity_json).collect();
+            sorted.sort_by(|a, b| {
+                (a["kind"].as_str(), a["value"].as_str()).cmp(&(b["kind"].as_str(), b["value"].as_str()))
+            });
+            out.push(serde_json::json!({
+                "name": case["name"],
+                "query": build_query(k, seed),
+                "apex_base": base,
+                "emitted_count": ents.len(),
+                "first_value": ents.first().map(|e| e.value.clone()),
+                "confidence_non_increasing": ents.windows(2).all(|w| w[0].confidence >= w[1].confidence),
+                "entities": sorted,
+            }));
+        }
+        let mut retry = Vec::new();
+        for code in [400u16, 401, 403, 404, 408, 429, 500, 502, 503, 504] {
+            let e = crate::util::http::http_status_error(
+                SRC,
+                reqwest::Response::from(
+                    http::Response::builder()
+                        .status(code)
+                        .body(String::from("upstream says no"))
+                        .expect("response"),
+                ),
+            )
+            .await;
+            retry.push(serde_json::json!({"status": code, "retry": is_transient_crt_error(&e)}));
+        }
+        let doc = serde_json::json!({
+            "captured_from": "M D 764ce8e restore (old tree 4d5db3dc = 1dfb5c9d + 98c77fd), src/modules/crtsh/mod.rs",
+            "max_timeout_ms": CrtSh.max_timeout_ms(),
+            "transient_attempts": TRANSIENT_ATTEMPTS,
+            "transient_pause_ms": u64::try_from(TRANSIENT_PAUSE.as_millis()).expect("ms"),
+            "retry_by_status": retry,
+            "cases": out,
+        });
+        std::fs::write(
+            format!("{dir}/crtsh_expected.json"),
+            serde_json::to_string_pretty(&doc).expect("json") + "\n",
+        )
+        .expect("write");
+    }
+}
diff --git a/src/modules/stolen_tax/mod.rs b/src/modules/stolen_tax/mod.rs
index 3e60b046..3226c974 100644
--- a/src/modules/stolen_tax/mod.rs
+++ b/src/modules/stolen_tax/mod.rs
@@ -1289,3 +1289,93 @@ mod tests {
         assert_eq!(clear_email_login("not-email"), None);
     }
 }
+
+/// Differential capture only (scratch clone): runs M D's 764ce8e normalisers over
+/// shared fixtures and writes the observed output. Not part of any committed tree.
+#[cfg(test)]
+mod legacy_capture {
+    use super::*;
+
+    fn entity_json(e: &Entity) -> Value {
+        let mut tags = e.tags.clone();
+        tags.sort();
+        let evidence: Vec<Value> = e
+            .evidence
+            .iter()
+            .map(|ev| serde_json::json!({"source": ev.source, "summary": ev.summary, "attributes": ev.attributes}))
+            .collect();
+        serde_json::json!({
+            "kind": format!("{:?}", e.kind),
+            "value": e.value,
+            "raw_value": e.raw_value,
+            "confidence": e.confidence,
+            "tags": tags,
+            "evidence": evidence,
+        })
+    }
+
+    #[test]
+    fn capture() {
+        let dir = std::env::var("LEGACY_CAPTURE_DIR").expect("LEGACY_CAPTURE_DIR");
+        let cases: Vec<Value> = serde_json::from_str(
+            &std::fs::read_to_string(format!("{dir}/stolen_tax_cases.json")).expect("read"),
+        )
+        .expect("cases");
+        let mut out = Vec::new();
+        for case in &cases {
+            let query = case["query"].as_str().expect("query");
+            let mut merged = StolenTaxData::default();
+            let mut hard_failure: Option<Error> = None;
+            let mut failed_paths: Vec<&str> = Vec::new();
+            for step in case["paths"].as_array().expect("paths") {
+                let path = step[0].as_str().expect("path");
+                let path: &'static str = PATHS.iter().copied().find(|p| *p == path).expect("known path");
+                let attempt = serde_json::from_value::<StolenTaxResponse>(step[1].clone())
+                    .map_err(|e| Error::module(SRC, format!("decode: {e}")))
+                    .and_then(accepted)
+                    .and_then(|r| match r.data {
+                        Some(data) => normalize_path(path, &data),
+                        None => Ok(StolenTaxData::default()),
+                    });
+                match attempt {
+                    Ok(chunk) => merge_data(&mut merged, chunk),
+                    Err(e) => {
+                        failed_paths.push(path);
+                        hard_failure.get_or_insert(e);
+                    }
+                }
+            }
+            let mut result = ModuleResult::new();
+            result.entities = build_entities(&merged, query, "fixture-scan");
+            crate::core::entity::dedup_merge_entities(&mut result.entities);
+            declare_partial_cascade(&mut result, &failed_paths);
+            let truncation = result.truncation.clone();
+            let (entities, error) = match result.or_hard_failure(hard_failure) {
+                Ok(r) => (r.entities, None),
+                Err(e) => (Vec::new(), Some(e.to_string())),
+            };
+            let mut ents: Vec<Value> = entities.iter().map(entity_json).collect();
+            ents.sort_by(|a, b| {
+                (a["kind"].as_str(), a["value"].as_str()).cmp(&(b["kind"].as_str(), b["value"].as_str()))
+            });
+            out.push(serde_json::json!({
+                "name": case["name"],
+                "failed_paths": failed_paths,
+                "truncation": truncation,
+                "error": error,
+                "entities": ents,
+            }));
+        }
+        let doc = serde_json::json!({
+            "captured_from": "M D 764ce8e restore (old tree 4d5db3dc = 1dfb5c9d + 98c77fd), src/modules/stolen_tax/mod.rs",
+            "max_timeout_ms": StolenTax.max_timeout_ms(),
+            "api_urls": PATHS.iter().map(|p| api_url(p)).collect::<Vec<_>>(),
+            "cases": out,
+        });
+        std::fs::write(
+            format!("{dir}/stolen_tax_expected.json"),
+            serde_json::to_string_pretty(&doc).expect("json") + "\n",
+        )
+        .expect("write");
+    }
+}
```
