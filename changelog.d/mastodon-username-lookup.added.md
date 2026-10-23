- `username` (and `scan -k username`, `/api/lookup` and the New Scan page's `mastodon_user`
  module) looks the handle up on Mastodon through `mastodon.social`'s public account lookup,
  keyless: the account's username, profile URL, display name as a person when it has two words or
  more, and the e-mail addresses and links in its bio. Only the server's own `Record not found`
  answer is a zero; a block page, a rate limit or a bare 404 is not taken for absence, and a
  handle with `.` or `-`, which no Mastodon username can hold, sends nothing and is inconclusive.
