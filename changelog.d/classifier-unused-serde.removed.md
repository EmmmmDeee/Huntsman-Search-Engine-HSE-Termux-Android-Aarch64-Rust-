- `classifier::Classified` no longer implements `Serialize` and `Deserialize`. Nothing serialised
  a classification, and its `&'static str` signal could not be deserialised from ordinary input.
  No output changes.
