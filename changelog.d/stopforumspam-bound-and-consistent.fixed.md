- StopForumSpam answers are checked before they count. One whose echoed value is not the queried
  address or IP is refused, as is one whose `appears` and `frequency` counters contradict each
  other, so neither becomes a finding or a valid zero. A confidence outside 0 to 100 now fails the
  decode instead of being recorded. The public live-canary job also runs for changes to
  `src/stopforumspam.rs` and checks this adapter against the reserved example address.
