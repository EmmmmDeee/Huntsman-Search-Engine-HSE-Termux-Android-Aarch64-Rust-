- `domain` no longer reports "no subdomains" from sub.md when sub.md answers with an error page,
  a JSON error or a sentence: any line that is not a host name makes the answer a decode failure,
  reported as such. Certificate wildcards (`*.example.com`), service labels (`_dmarc`) and a
  trailing root dot are still read as host names. A test sends every indicator leg a 401, 403,
  429, 500 and an HTML 200 and requires each to be reported as a failure (a 429 as rate-limited),
  never as an answer, so no leg can mistake a refusal for a clean result.
