- `artifacts::ArtifactPayload` and `artifacts::PipelineArtifacts` no longer implement `Serialize`
  and `Deserialize`. Nothing serialised them, and the internally tagged `Ready(Vec<u8>)` variant
  could not be serialised. No output changes.
