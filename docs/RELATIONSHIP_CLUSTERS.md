# Known-only relationship cluster analysis

This command produces a deterministic, full-URL-cited graph over records an authorised operator has already reviewed. It performs no remote searches, reads no credential dumps, and never infers a relationship from matching names, addresses or breach appearances.

## Execute

    cargo run -- breach-ci clusters docs/relationship-clusters-example.json
    huntsman-recon breach-ci clusters /private/path/source-cited-case.json

The example is ENTIRELY SYNTHETIC: Jordan Avery Example, Jane Mary Example and Example Organisation are test labels. Its example.org and example.net source links are illustrative, not evidence.

## Case schema

The input is one UTF-8 JSON object with exactly two fields: nodes and links. See the complete, copyable schema at [relationship-clusters-example.json](relationship-clusters-example.json).

Every node has an opaque unique id (1-64 bytes: ASCII letters, digits, hyphen, underscore, dot or colon); kind (person, organisation, domain, ip_address, asn, netblock, public_account, document); and complete label (maximum 160 bytes). A person requires a valid full name of at least two meaningful alphabetic tokens. Identical names may refer to different nodes and are never automatically merged. IP and network selectors must be public. Public-account labels must be full HTTPS URLs.

Every link must declare two distinct known node IDs (from_id, to_id), a relation type, full source_url, original source_root, and the booleans primary_record, exact_identifier, temporal_consistency and contradicted. Recognised relation types are documented_association, published_together, director_of, member_of, uses, owns, named_in and reported_link. Use only a source-supported type: co-occurrence alone is not proof of association.

Source URLs are preserved in full, including path and ordinary query parameters. Only public HTTPS domains are accepted; userinfo and secret-bearing query parameters are refused. Original source-root IDs identify the original dataset, not each mirror, platform, search index or scanning agent.

All booleans and claimed original roots are operator-supplied metadata, not external verification or proof of independence.

## Deterministic recursive graph construction

1. Reject invalid schema, unknown fields, missing nodes, self-links and uncited or unsafe URLs.
2. Deduplicate identical observations, retaining every distinct complete source URL and original-root ID.
3. Group explicit directed relations by endpoints and relation type. Never collapse different people based on name similarity.
4. Keep contradicted relation groups in disputed_relations, but do not let them connect clusters.
5. Compute connected components over remaining source-claimed links. Starting at the lowest stable node ID, breadth-first traverse every known link, recording the exact parent, relation and hop for each reached node. Traversal is undirected for exploration only: recorded relation direction remains unchanged.
6. Rank components by their highest constituent Confidence Index (CI), descending, with stable ID tie-breaks. Include all node names, source URLs, evidence details, recursive paths and explicit uncertainties.

The existing breach CI heuristic is an uncalibrated evidence-review priority, not a probability or verification verdict. No two-hop path is converted into a new direct relationship. An isolated name has no link CI. Different websites republishing one dataset are not independent corroboration.

Limits: 256 KiB input, 128 nodes, 256 link observations, at most eight claimed original roots per relation group. No network access, name-to-email inference, leak searches or automatic identity merges. For known-only infrastructure follow-up planning, the separate breach-ci enrich command processes a completed recursive report without performing further queries.

## Synthetic example network

    Jordan Avery Example [person-a]
      --member_of--> Example Organisation [organisation-b]
                         --documented_association--> Jane Mary Example [person-c]

    Jane Mary Example [namesake-d]    [isolated, no cited relationship]

The expected output has a three-node component and a distinct namesake singleton. None of these labels or source URLs constitutes a real-world finding.

## Acceptance

    cargo fmt --all -- --check
    cargo clippy --workspace --all-targets --locked -- -D warnings
    cargo test --locked known_relationship_clusters
    cargo test --locked --test breach_ci_cli
    cargo test --workspace --locked

Do not merge or claim production readiness until compilation, tests and Android AArch64 acceptance pass. GitHub Actions previously failed before jobs executed; that blocker must be resolved independently. A missing edge or empty graph is unknown coverage, not proof of no real-world association.
