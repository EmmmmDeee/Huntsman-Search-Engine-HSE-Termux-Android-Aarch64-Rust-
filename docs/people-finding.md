# People-Finding From a Fragment

Version r13 · 2026-10-09. Terminology and intent unchanged.
Engine notes at the end are the only addition.

Vendor names below are stable. Vendor prices, endpoints, and rate limits are not verified and may be wrong. Every figure marked [verify] must be checked against the vendor's own pricing page and API docs before budget is committed.

The chain, grading, disambiguation, OPSEC, escalation, and deliverable sections are an analytical framework, not empirical findings.

## Scope

Lawful, client-authorized people-finding. Skip tracing, fraud investigation, due diligence, journalistic attribution, litigation support, lawful assistance to authorities. Not harassment, stalking, or private harm.

## The shape of the problem

People-finding is a chain, not a search.

Fragment → pivot → pivot → anchor

A fragment is what you have. A pivot is a transformation. An anchor is an identity ender: legal name, address, phone tied to a real account, billing info.

The dominant failure mode is not "not enough data." It is "wrong person, confidently named."

## Pivot strength grading

Grade every hop before trusting the chain through it.

Grade A, near-decisive: reuse of a distinctive password; a leaked session cookie matched to a specific person; a unique HWID or developer API key matched to a real account; a phone number matching an anchor record.

Grade B, strong but not decisive: reuse of a common password; an email to a username appearing on multiple platforms with the same rare string; an infostealer infection whose logged-in accounts include both the fragment and a real-named account.

Grade C, suggestive: the same username on two platforms where the name is common; the same email pattern without a confirming pivot; a Discord handle linked to a Steam handle with no identifier in common.

Grade D, not evidence: matching first names; shared geography; similar interests or posting times.

An anchor is only as strong as the weakest A-or-B pivot connecting it to the original fragment. A C or D hop means a hypothesis, not a finding.

## Fragment to first source

Do not improvise the first move. Username: password-breach search. Email: stealer-log search, then anchor lookup. Phone: direct anchor lookup. Plaintext password: password-reuse search. Password hash: hash lookup, then pivot. Session cookie: stealer-log search. Discord, Steam, or Xbox: social graph search. IP address: stealer-log search, honeypot telemetry. HWID or device ID: stealer-log search, NHI search. Domain: domain-level credential leak.

The first move is usually free. Reach for paid only when the free tier stalls.

## Source classes

Class 1, direct anchors: phone, name, address. Examples: DeHashed, Leak-Lookup.

Class 2, pivots that reach anchors: stealer logs and password reuse. Stealer examples: Hudson Rock, LeaksAPI v2, LeakRadar, NiamonX, BlurSec, OsintCat. Password examples: ProxyNova, Snusbase, LeakCheck.

Class 3, conditional pivots: HWID, NHI, honeypot telemetry, domain leaks. Examples: RelayShield, NordStellar, BlackDome, ProjectDiscovery.

Class 4, social graph: Discord, Steam, Xbox, Roblox. Example: OathNet. Pseudonymous unless a handle touches a real-world identifier.

Class 5, verification only: breach presence. Examples: HIBP, XposedOrNot, LeakCheck, CheckLeaked. Rarely produce an anchor on their own.

## Disambiguation

Two independent sources for the same anchor. One is a candidate. Two is a finding. A location, employer, or age contradiction ends the hypothesis. Time-align the anchor. Prefer a distinctive fragment. Do not chain through a weak link.

## Parallel hypotheses

Keep two or three live hypotheses, each from a distinct fragment. A new fragment supports or contradicts them. Drop a hypothesis when it contradicts a grade A or B pivot. A distinctive password outweighs ten weak username matches.

## Stop conditions

Three pivot hops produced no new fragment. The chain depends on one source silent on every fragment. The only reachable anchors require guesses. Case value does not justify another paid query. Two anchors contradict and cannot be resolved. The time budget is exhausted without a grade A or B anchor.

## Time budget

Hour 1: free-tier pivots. Hours 2–3: chain extension. Hours 4–6: paid queries on the strongest remaining fragment. Hours 7–8: corroboration. Hour 9: the deliverable. Beyond that, only a specific lead justifies it.

## OPSEC

Prefer passive sources. Do not use infrastructure the target controls without a clear legal basis. Query paid sources on the strongest fragment. Rate-limit queries. State the lawful basis in one sentence before starting. If it cannot be stated, stop.

## Escalation ladder

Move up only when the previous rung stalls. One source per node class.

Rung 0, free tier. Examples: Hudson Rock, ProxyNova, BlurSec, BlackDome, Leak-Lookup, HIBP, XposedOrNot, ProjectDiscovery. Cost: $0 [verify].

Rung 1, direct anchors. Examples: DeHashed pay-as-you-go, Leak-Lookup paid. Cost: [verify].

Rung 2, stealer depth, and only if stealer logs produced anchors. Pick one. Examples: LeaksAPI v2, LeakRadar, NiamonX. Cost: [verify].

Rung 3, password reuse, and only if reuse bridged. Examples: Snusbase, LeakCheck. Cost: [verify].

Rung 4, social graph, and only if rungs 0–3 failed. Example: OathNet paid. Cost: [verify].

Rung 5, enterprise, and only if chain-of-custody is required or the node class exists only there. Examples: Constella, SpyCloud, Recorded Future. Cost: [verify].

## Redundancy and economics

A second source in the same class adds roughly half the first. A third adds roughly a quarter. Beyond that, near zero. Value is the probability the source holds the bridge, times case value. A source whose bridge probability is near zero has zero expected value.

## Deliverable

Fragment statement. Chain, with grade on every hop. Weakest link named. Anchor cited to two independent sources. Contradicting evidence not buried. Confidence high for A, medium for B, low for C. No finding at D. Lawful basis in one sentence. Sources appendix with URLs and query strings. If it cannot be written at A or B, the output is unresolved and why.

## Measurement

The only number that improves this file is bridge yield per source. On five to ten hard cases, record unique nodes, whether any node was an anchor, and which source produced the resolving anchor.

## What to ignore

Throughput math. Rate-raising strategy. Enterprise platforms at solo scale. DeHashed Professional when pay-as-you-go is the same data. Intelligence X higher tiers when the individual tier covers the use.

## Vendor reference

Names only. Prices and endpoints must be verified.

Free or free-tier: Hudson Rock Cavalier, ProxyNova COMB, BlurSec MCP, BlackDome MCP, Leak-Lookup, HIBP, XposedOrNot, ProjectDiscovery Cloud, OathNet free tier.

Low-cost paid: DeHashed pay-as-you-go, LeaksAPI v2, HIBP paid, RelayShield MCP, Enzoic, Snusbase, LeakCheck, CheckLeaked.

Mid-tier: OSINTLeak, LeakRadar, NiamonX, Intelligence X, NordStellar, WhiteIntel, OsintCat, Breachsense.

Enterprise, reject at solo scale: Constella, SpyCloud, Recorded Future, Cybersixgill, ZeroFox, DarkOwl, Intel 471, Flashpoint, Kalir, SpiderSilk, CloudSEK XVigil, Webz.io Scale.

## Legal line

The output is a person, not a record. Query, do not bulk-ingest. Do not retain plaintext credentials longer than needed. Document the lawful basis. Get counsel review before breach data goes into a client deliverable. Stay inside client authorization. API-mediated access is safer than raw file ingestion.

## Week one

Deploy every free source. Run every fragment through them. Then measure bridge yield on five to ten cases. Add rung 1 if the free tier stalled, rung 2 if stealer logs bridged, rung 3 if reuse bridged. Stop unless a case demands rung 4 or 5.

r13 is terminal pending measurement. Further editorial revision of the grades does not improve it.

## Engine note, 2026-10-09

This note does not change a grade or a rung.

`src/core/pivot_grade.rs` implements the grades. A distinctive password, session cookie, HWID, or phone anchor is A. A common password, rare username, or stealer account list is B. A common username, email pattern, or bare handle link is C. Anything else, including a shared name, is D. `weakest` takes the lowest hop. A or B is a finding. The two unit tests passed. The grader is not yet called from every module.

SeekNow is class 2 and class 4. `effective_plan` orders that matrix by ROI before credits are spent. One stealer source, not several. DeHashed and LeakIX are class 1 names and are not called without a key. HIBP is class 5. A keyless breach list returned 200. XposedOrNot `/v1` returned 404. Epieos is a dead route and is marked truncated, not a clean miss. Shodan InternetDB is a host record, not an anchor: `8.8.8.8` returned ports 53 and 443.

No price in this file was verified.
