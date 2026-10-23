- `serve` writes every response by a deadline: 10 seconds, and a second more for each 16 KiB it
  holds (an inspection's answer keeps the 90 seconds its upload had). Before, only an
  inspection's answer had one, so a client that read a few bytes every few seconds held its
  connection for as long as it liked, and 32 such clients, no token needed, had every other
  request answered `503` for as long as they kept on.
