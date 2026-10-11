"""The paths a unified diff touches, read from every header a patch can carry.

A pure rename or copy has no ---/+++ lines, so those alone miss it. Every path a git
header names is returned. A `diff --git` header this module cannot split, such as one
whose path contains a space, raises PatchError, so the caller refuses the patch.
"""


class PatchError(ValueError):
    pass


def _strip(name: str) -> str:
    if name == "/dev/null":
        return ""
    if name.startswith(("a/", "b/")):
        return name[2:]
    return name


def patch_paths(diff: str) -> set[str]:
    paths: set[str] = set()
    for line in diff.splitlines():
        if line.startswith("diff --git "):
            parts = line[len("diff --git ") :].split(" ")
            if len(parts) != 2 or not parts[0].startswith("a/") or not parts[1].startswith("b/"):
                raise PatchError(f"cannot read the paths in: {line}")
            paths.update({_strip(parts[0]), _strip(parts[1])})
        elif line.startswith(("--- ", "+++ ")):
            name = _strip(line[4:].split("\t", 1)[0].strip())
            if name:
                paths.add(name)
        elif line.startswith(("rename from ", "rename to ", "copy from ", "copy to ")):
            paths.add(line.split(" ", 2)[2])
    paths.discard("")
    return paths
