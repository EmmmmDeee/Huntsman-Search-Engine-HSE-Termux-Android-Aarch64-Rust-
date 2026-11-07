- A `--depth` scan no longer lets one kind of pivot crowd out the rest. No kind may take more
  than half of a generation, and the next generation is followed one kind at a time, in turn.
  On `telstra.com.au` at depth 1, the domain's thousands of certificate-log subdomains filled the
  whole frontier, so its addresses, emails and numbers were never looked up before the entity
  budget ran out.
