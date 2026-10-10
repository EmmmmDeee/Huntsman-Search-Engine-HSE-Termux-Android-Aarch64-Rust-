#!/usr/bin/env python3
"""Judges the red result of each failing generated test binary, one log at a time.

Usage: red_class.py LOG [LOG ...]

Each LOG is the cargo test output of one generated test binary that failed on untouched
main. Each log is judged on its own, and the red is valid only when every log is valid.
A valid red is one of these classes:

  missing-symbol    the build failed, and every compile error is a `cannot find`
  assertion-failed  the test ran, and every panic is an assertion macro's default message

The default messages begin with "assertion `left" (assert_eq!, assert_ne!) or with
"assertion failed" (assert!). A custom message on assert! replaces that text and is
refused. A custom message on assert_eq! or assert_ne! is added after it and is accepted.
Anything else is rejected: a build failure on another error, a parse error, a panic that
is not an assertion (unwrap() on an Err, expect()), and a failure with no panic (a test
that returns Err).

Prints one line per log, `NAME: CLASS`, or `NAME: rejected (REASON)`, and exits 0 only
when every log is valid. Run it with -I, as every Python call in the plan stage is run.
"""
import re
import sys
from pathlib import Path

DEFAULT_MESSAGES = ("assertion `left", "assertion failed")
PANIC_MARK = "panicked at "
BUILD_FAILED = "error: could not compile "
ERROR_LINE = re.compile(r"^error(\[E\d+\])?: ")


def compile_errors(lines):
    """The rustc error lines of a failed build. The cargo summary line is not an error."""
    errors = []
    for line in lines:
        if ERROR_LINE.match(line) and not line.startswith(BUILD_FAILED):
            errors.append(line)
    return errors


def panic_messages(lines):
    """The message of each panic. Rust 1.73 and later put the message on the line after
    `panicked at FILE:LINE:COL:`. Earlier Rust quotes it on the same line."""
    messages = []
    for index, line in enumerate(lines):
        at = line.find(PANIC_MARK)
        if at < 0:
            continue
        rest = line[at + len(PANIC_MARK) :]
        if rest.startswith("'"):
            messages.append(rest[1:])
        elif index + 1 < len(lines):
            messages.append(lines[index + 1].strip())
        else:
            messages.append("")
    return messages


def classify(text):
    """Returns (class, reason) for one log. The class is missing-symbol, assertion-failed,
    or rejected. The reason is empty unless the class is rejected."""
    lines = text.splitlines()
    # GUARD: a log whose build failed is judged by its compile errors alone. Panic text in
    # the same log never makes a failed build a red.
    if any(line.startswith(BUILD_FAILED) for line in lines):
        errors = compile_errors(lines)
        if any("expected one of" in error for error in errors):
            return "rejected", "the generated test does not parse"
        if errors and all("cannot find" in error for error in errors):
            return "missing-symbol", ""
        return "rejected", "the build failed on an error other than a missing symbol"
    messages = panic_messages(lines)
    if not messages:
        return "rejected", "the test failed without an assertion panic"
    for message in messages:
        if not message.startswith(DEFAULT_MESSAGES):
            return "rejected", f"a panic that is not an assertion: {message}"
    return "assertion-failed", ""


def main(argv):
    if not argv:
        print("usage: red_class.py LOG [LOG ...]", file=sys.stderr)
        return 2
    valid = True
    for log in argv:
        path = Path(log)
        kind, reason = classify(path.read_text(encoding="utf-8", errors="replace"))
        if kind == "rejected":
            valid = False
            print(f"{path.stem}: rejected ({reason})")
        else:
            print(f"{path.stem}: {kind}")
    return 0 if valid else 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
