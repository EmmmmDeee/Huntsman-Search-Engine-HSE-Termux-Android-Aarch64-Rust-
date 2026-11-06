- The Spiderfoot export types a link on the target's own domain as internal even when the host is
  written with a trailing root dot (`ftp://example.com./pub` against `example.com`). It used to
  call that link external.
  - **Who is affected.** Only links that canonical form cannot read: `http` and `https` links
    already lost the dot when they were canonicalised.
  - **One reader.** Five functions read a URL's host by different rules; two of them cut an IPv6
    literal at its first colon. `circuit::host_of`, the breakers' reader, is now the only one.
    The Spiderfoot export, web meta-search and the hosted-on relation read through it.
  - **Nothing else changes.** The cut IPv6 host changed no output.
