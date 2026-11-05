- A source whose answer contradicts its own count is now treated as unanswered everywhere, not
  only in the scan API: an empty success, or a zero that reports results. It is no longer
  counted as answered in the HTML report or its gap list, it is logged and counted as a scan
  error with `outcome_count_conflict=true`, and it is not saved as accepted evidence. Duolingo
  answers that mix named accounts with blank rows are schema drift instead of a partial
  success. An all-blank reply still reads as one account whose profile is withheld.
