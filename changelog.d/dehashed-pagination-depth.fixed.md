- DeHashed pages follow DeHashed's documented limits. Before, a page past them was sent anyway,
  and the exposure leg read too little per credit.
  - **Depth.** A search where page × size is over 10,000 results is refused before it is sent
    (exit 65), so no request goes on an answer DeHashed would refuse.
  - **Page size.** `dehashed search --size` may go up to 10,000, the documented maximum.
  - **Exposure.** The leg reads 1,000 records per search, not 100. One search costs one credit
    whatever its size.
  - **Transport.** DeHashed has its own (16 MiB, 60 s), so a large page is read whole rather than
    cut and lost.
  - **Later pages.** `--save-artifact --page N` no longer marks a complete later page partial:
    only records past the page do.
