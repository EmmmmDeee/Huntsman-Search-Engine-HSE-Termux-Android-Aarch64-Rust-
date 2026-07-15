# THE RULE

**Nothing ships unless it is backed by verifiable evidence from an authoritative source.**

That is the whole rule. It is binding on every change to this repository — code,
tests, docs, data, and any finding the engine emits. Everything below only
explains how to obey it. It adds nothing new.

---

## Why this is the one rule

HSE is an evidentiary OSINT/GEOINT/NETINT engine. Its only product is a claim an
operator will act on. A false claim that *looks* true is worse than a missing
one, because it is trusted. Every other quality — speed, coverage, ergonomics —
is worthless if the output cannot be trusted. So the project has exactly one
non-negotiable rule, and this is it.

## What it forbids

- **No fabricated findings.** Never emit an entity, evidence record, or
  correlation the code did not actually observe.
- **No assumed API contracts.** Never call an endpoint, pass a parameter, or
  parse a response field you have not confirmed exists in the provider's
  authoritative specification or in a real response. An API you *expect* to
  behave a certain way is a guess until the provider says otherwise.
- **No synthetic, mocked, or placeholder data dressed up as real.** Test
  fixtures must be labelled fixtures. A mock may prove *logic*; it may never
  stand in as *evidence* that a live service behaves a given way.
- **No speculative conclusions.** "Probably", "should", and "I assume" are not
  evidence. If the code depends on it, verify it or do not depend on it.

## The test you must pass before committing

For every external fact the change relies on — every endpoint path, query
parameter, response field, status-code meaning, quota, and auth scheme — you
must be able to point at **at least one** of:

1. the provider's **authoritative documentation** (its OpenAPI/Swagger spec, its
   official API reference), or
2. a **real, observed response** captured from the live service, or
3. a **reproducible run** of this code that exercises the path.

If you can point at none of the three, you do not have evidence. You have a
guess, and a guess does not ship.

## When you cannot verify

Say so, plainly, in the same change. Mark the unverified part as unverified in a
comment, do not present it as fact, and do not let anything downstream treat it
as confirmed. "I could not reach the service to confirm this" is an acceptable,
honest state. Silently shipping the guess as though it were confirmed is the one
thing this rule exists to stop.

## The cautionary case (why this rule is not abstract)

The WiGLE integration once asked `/api/v2/network/search?type=cell` and
`type=bluetooth` to fetch cell-tower and Bluetooth observations. WiGLE's own
API specification lists **no `type` parameter on `/network/search`** — cell and
Bluetooth live under separate endpoints (`/api/v2/cell/search`,
`/api/v2/bluetooth/search`). A parameter the server never reads is silently
ignored, so those calls returned Wi-Fi data that the engine then labelled as
cell and Bluetooth intelligence: a fabricated finding, produced not by malice
but by an **unverified assumption about an API contract**. One look at the
authoritative spec would have caught it. That look is now mandatory.

---

**Follow the rule. If a change cannot satisfy it, the change is not ready.**
