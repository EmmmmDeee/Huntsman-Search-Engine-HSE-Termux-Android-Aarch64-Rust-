# Public account exposure assessment

Huntsman includes an **offline, read-only** defensive classification of a supplied source-backed public entity graph.

```sh
huntsman-recon privacy-audit /path/to/public-graph.json > privacy-report.json
```

No network requests, provider keys, runtime LLM, elevated permissions or Android root access are required. Input is limited to **1 MiB**, 5,000 nodes and 10,000 edges. The reader refuses symlinks and the assessor refuses missing or unknown source IDs, duplicate node IDs and dangling edges. A malformed input fails rather than receiving a clean bill of health.

The JSON input is an object with `nodes`, `edges` and `source_definitions`. Each node has `id`, `type` and a non-empty `sources` array. Each edge has `from`, `to`, `predicate` and non-empty `sources`. Source IDs must be keys in `source_definitions`.

Example (fictional, no private information):

```json
{
  "source_definitions": { "S1": { "url": "https://example.org/profile" } },
  "nodes": [
    { "id": "hub", "type": "link_hub", "sources": ["S1"] },
    { "id": "social", "type": "social_profile", "sources": ["S1"] },
    { "id": "pay", "type": "payment_handle", "sources": ["S1"] }
  ],
  "edges": [
    { "from": "hub", "to": "social", "predicate": "publicly_links_to", "sources": ["S1"] },
    { "from": "hub", "to": "pay", "predicate": "publicly_links_to", "sources": ["S1"] }
  ]
}
```

Results classify **public cross-account links, payment aliases, geographic statements, fundraisers, public imagery, and self-reported social statements**. They propose appropriate owner-authorized privacy controls. No finding proves identity, financial transactions, compromise or physical location. Absent findings and unassessed intelligence disciplines never certify safety. The command does not remediate any external account or verify control changes.

This is deliberately separate from `exposure`, the existing breach-provider command. A public profile link is not evidence of a stolen credential. The existing embedded web UI and network lookup APIs are untouched; browser upload support is not claimed by this addition.
