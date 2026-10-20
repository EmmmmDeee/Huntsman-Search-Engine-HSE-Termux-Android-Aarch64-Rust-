- Refuse graph task dispatch when the cumulative resource cost overflows, including
  policies with a `u64::MAX` budget. Exact-fit work remains admissible; excess work
  is blocked before its handler runs, with exact retained resource accounting.
