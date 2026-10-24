- A saved scan or JSON report whose outcome rows carry a kind label this build does not know
  now opens, and reads that row as `inconclusive`, which is never counted as an answer. Before,
  one unknown label made the whole scan's results unreadable. This lets a later build add a kind
  without making its saved scans unreadable to this one. No output changes.
