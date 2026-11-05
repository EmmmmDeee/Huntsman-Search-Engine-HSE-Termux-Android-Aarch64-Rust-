- `doctor` no longer counts symlinks toward the build cache's size. It now adds only regular
  files: before, each link's own length was counted. It never descends into a linked
  directory, and a cache directory that is itself a link reads as 0 MiB rather than being
  measured through the link.
