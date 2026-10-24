- `run-history record --from-stdin` refuses test output whose `test result:` counts add up past
  the largest count it can store. Two summary lines of `18446744073709551615 passed` and
  `1 passed` made a debug build crash and a release build wrap the total around to 0, record
  `passed=0` and report a regression or a baseline of 0. The command now exits 65 with
  `no usable 'test result:' totals in stdin`, which is also the message, reworded from
  `no 'test result:' line found in stdin`, for input with no summary line at all. Real test
  output never reaches these counts.
