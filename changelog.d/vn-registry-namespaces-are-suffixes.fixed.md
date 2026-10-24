- A name under one of the eight Vietnamese registry namespaces (`com.vn`, `gov.vn`, `edu.vn`,
  `ac.vn`, `org.vn`, `biz.vn`, `net.vn`, `name.vn`) is registered one label below the namespace,
  as `example.com.au` is under `com.au`. Such names used to be read as registered under the
  namespace itself: `domain example.com.vn` never tagged a look-alike it found, such as
  `examp1e.com.vn`, as `lookalike`, and a Spiderfoot scan of `example.com.vn` that found
  `mail.example.com.vn` reported a `DOMAIN_NAME_PARENT` of `com.vn`. The look-alike is now
  tagged, and the scan reports `DOMAIN_NAME` `example.com.vn`. Where the IANA bootstrap names an
  RDAP service for `.vn`, the RDAP leg now asks about `example.com.vn` instead of `com.vn`.
