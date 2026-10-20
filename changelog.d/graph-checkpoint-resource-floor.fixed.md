- Reject graph checkpoints whose consumed-resource counter is below the checked
  minimum cost of their recorded attempted tasks, or whose minimum cost overflows.
  Invalid histories fail before dispatch; conservative extra reservations remain
  valid. This checks internal accounting consistency, not checkpoint authenticity.
