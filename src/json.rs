//! Stable, canonical JSON helpers with optional byte-exact export budgets.

use std::io::{self, Write};

use serde::ser::{Serialize, SerializeMap, Serializer};
use serde_json::Value;

/// A value whose object members serialize in ascending key order. Sorting is
/// explicit even when another dependency changes JSON object iteration order.
struct Canonical<'a>(&'a Value);

impl Serialize for Canonical<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        match self.0 {
            Value::Object(map) => {
                let mut members = map.iter().collect::<Vec<_>>();
                members.sort_unstable_by(|left, right| left.0.cmp(right.0));
                let mut out = serializer.serialize_map(Some(members.len()))?;
                for (key, value) in members {
                    out.serialize_entry(key, &Canonical(value))?;
                }
                out.end()
            }
            Value::Array(items) => serializer.collect_seq(items.iter().map(Canonical)),
            scalar => scalar.serialize(serializer),
        }
    }
}

/// Compact JSON with every object's keys in ascending order.
///
/// # Errors
/// Returns the underlying serialization failure.
pub fn to_canonical_string(value: &Value) -> serde_json::Result<String> {
    serde_json::to_string(&Canonical(value))
}

#[derive(Debug)]
struct BoundedWriter {
    bytes: Vec<u8>,
    limit: usize,
    required_bytes: usize,
}

impl BoundedWriter {
    fn new(limit: usize) -> Self {
        Self {
            bytes: Vec::new(),
            limit,
            required_bytes: 0,
        }
    }

    fn finish(self) -> Result<Vec<u8>, usize> {
        if self.required_bytes > self.limit {
            Err(self.required_bytes)
        } else {
            Ok(self.bytes)
        }
    }
}

impl Write for BoundedWriter {
    fn write(&mut self, input: &[u8]) -> io::Result<usize> {
        self.required_bytes = self.required_bytes.saturating_add(input.len());
        if self.required_bytes <= self.limit {
            self.bytes.extend_from_slice(input);
        }
        Ok(input.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

/// Serialize in canonical key order, retaining no more than the byte limit.
/// The error variant inside the successful serialization result reports the
/// full required byte count, so callers can omit the whole document.
///
/// # Errors
/// Returns the underlying serialization failure.
pub fn to_canonical_bounded(
    value: &Value,
    limit: usize,
) -> serde_json::Result<Result<Vec<u8>, usize>> {
    let mut writer = BoundedWriter::new(limit);
    serde_json::to_writer(&mut writer, &Canonical(value))?;
    Ok(writer.finish())
}

/// Serialize any Rust value to compact or pretty JSON without retaining more
/// bytes than the requested limit. Serialization still traverses the source to
/// report its full encoded size, but an over-budget document is never returned.
///
/// Existing callers that need canonical object order can keep using
/// [`to_canonical_bounded`]; persistence respects the same serde representation
/// as the original to_vec and to_vec_pretty calls.
///
/// # Errors
/// Returns serialization failures from serde_json.
pub fn to_bounded_json<T: Serialize>(
    value: &T,
    limit: usize,
    pretty: bool,
) -> serde_json::Result<Result<Vec<u8>, usize>> {
    let mut writer = BoundedWriter::new(limit);
    if pretty {
        serde_json::to_writer_pretty(&mut writer, value)?;
    } else {
        serde_json::to_writer(&mut writer, value)?;
    }
    Ok(writer.finish())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nested_objects_sort_by_key() {
        let value = serde_json::json!({"b":1,"a":{"z":1,"y":2}});
        assert_eq!(
            to_canonical_string(&value).unwrap(),
            r#"{"a":{"y":2,"z":1},"b":1}"#
        );
    }

    #[test]
    fn byte_budget_preserves_canonical_output_and_reports_escaped_size() {
        let value = serde_json::json!({
            "z": [{"note": "café 🌐 \n \"quoted\""}],
            "a": {"nested": [true, false, null], "count": 42}
        });
        let text = to_canonical_string(&value).unwrap();
        assert_eq!(
            to_canonical_bounded(&value, text.len()).unwrap(),
            Ok(text.as_bytes().to_vec())
        );
        assert_eq!(
            to_canonical_bounded(&value, text.len() - 1).unwrap(),
            Err(text.len())
        );
        assert_eq!(to_canonical_bounded(&value, 0).unwrap(), Err(text.len()));
    }

    #[test]
    fn bounded_compact_and_pretty_match_serde_exactly() {
        let value = serde_json::json!({"greeting":"café 🌐", "items":[1, null, true]});
        for pretty in [false, true] {
            let original = if pretty {
                serde_json::to_vec_pretty(&value).unwrap()
            } else {
                serde_json::to_vec(&value).unwrap()
            };
            assert_eq!(
                to_bounded_json(&value, original.len(), pretty).unwrap(),
                Ok(original.clone())
            );
            assert_eq!(
                to_bounded_json(&value, original.len() - 1, pretty).unwrap(),
                Err(original.len())
            );
            assert_eq!(
                to_bounded_json(&value, 0, pretty).unwrap(),
                Err(original.len())
            );
        }
    }

    #[test]
    fn bounded_writer_does_not_retain_data_after_budget_exceeded() {
        let mut writer = BoundedWriter::new(4);
        writer.write_all(b"abcd").unwrap();
        writer.write_all(b"efgh").unwrap();
        assert_eq!(writer.bytes.len(), 4);
        assert_eq!(writer.required_bytes, 8);
        assert_eq!(writer.finish(), Err(8));
    }
}
