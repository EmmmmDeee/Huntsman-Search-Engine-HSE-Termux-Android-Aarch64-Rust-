- The regular-expression engine for correlation rules is now tested on 20,000 generated patterns.
  They are built from its own syntax, including lookahead and backreferences (which it refuses),
  huge repetition counts, stray brackets and non-ASCII text, and each is compiled
  case-sensitively and not. Every pattern either compiles and then matches text without a panic,
  or is refused. The test was checked by planting a panic on a trailing backslash, which it
  caught.
