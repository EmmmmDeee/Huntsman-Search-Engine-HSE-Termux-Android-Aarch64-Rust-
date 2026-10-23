- The YAML reader for correlation rule files is now tested against hostile input:
  - 20,000 generated documents built from YAML's own syntax: flow and anchor characters, block
    scalars, quotes, byte-order marks and emoji;
  - nesting far past the 64-level limit, whether by indentation or 50,000 levels on one line.
  Every document is read or refused with a line number; none panics or exhausts the stack.
