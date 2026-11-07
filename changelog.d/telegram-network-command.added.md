- New `telegram-network HANDLE [--depth 1-3] [--max 1-50]` command: a bounded, keyless map of
  the public Telegram channels around one channel. It reads each channel's public page and post
  preview and follows the names its posts forward from or link to, breadth first. It lists every
  channel read (kind, title, size, newest post), every edge with how often it was seen, and the
  most-amplified names. Names left unread because a bound was reached are listed. Edges are leads,
  never proof of affiliation. Only public pages are read.
