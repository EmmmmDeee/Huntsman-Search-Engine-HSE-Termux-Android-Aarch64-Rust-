- Wayback's CDX query still keeps only HTTP 200 captures before it collapses rows by URL, so an
  early redirect cannot hide a later good capture. When that query gets no first byte in time,
  one unfiltered query runs in its place. Its non-200 rows are dropped locally and counted, and
  the outcome says that collapsing may have hidden later good captures. Other failures are not
  retried.
