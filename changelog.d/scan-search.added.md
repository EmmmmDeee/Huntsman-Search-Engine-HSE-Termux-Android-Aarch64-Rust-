- `scans search VALUE [ID...]`, `GET /api/scans/search?value=V[&type=T][&ids=A,B]` and a search
  box on the console's Scans page find elements in every saved scan at once, which Spiderfoot's
  page cannot do: each hit carries its scan and opens that scan's Browse. A query reads as
  Spiderfoot's search box reads it, `/regex/` anywhere, a `*wildcard*` as the whole value or text
  anywhere, regardless of case, over each element's data, its source element's data and its
  module; `type` alone lists one type in every scan.
