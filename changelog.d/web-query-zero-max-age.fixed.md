- Web search no longer caches an engine's answer whose `Cache-Control` writes a zero max-age
  with spaces, quotes or extra zeros (`max-age = 0`, `max-age="0"`, `max-age=000`). Only the
  exact `max-age=0` was recognised before.
