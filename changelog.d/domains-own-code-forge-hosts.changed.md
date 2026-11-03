- The code forges whose bare host is noise as a `Domain` pivot (GitHub, GitLab, Bitbucket,
  Codeberg, SourceHut — a link there is already a `Url`) are listed once, `domains::CODE_FORGES`
  with `domains::is_code_forge_host`, instead of three private copies in the crates.io, Docker Hub
  and npm author legs. The npm leg keeps its own exclusion of the registry's hosts (`npmjs.com`,
  `npmjs.org`) beside the shared list, and now also drops a Codeberg or SourceHut link's host as the
  other two legs always did. The shared rule has its own test.
