//! Reject duplicate JSON members before they can silently replace evidence fields.

use std::fmt;

use serde::de::{Deserialize, Deserializer, Error, MapAccess, SeqAccess, Visitor};
use serde_json::{Map, Value};

struct Checked(Value);

impl<'de> Deserialize<'de> for Checked {
    fn deserialize<D: Deserializer<'de>>(input: D) -> Result<Self, D::Error> {
        input.deserialize_any(CheckedVisitor).map(Self)
    }
}

struct CheckedVisitor;

impl<'de> Visitor<'de> for CheckedVisitor {
    type Value = Value;

    fn expecting(&self, out: &mut fmt::Formatter<'_>) -> fmt::Result {
        out.write_str("JSON without duplicate object members")
    }

    fn visit_bool<E: Error>(self, value: bool) -> Result<Value, E> {
        Ok(value.into())
    }

    fn visit_i64<E: Error>(self, value: i64) -> Result<Value, E> {
        Ok(value.into())
    }

    fn visit_u64<E: Error>(self, value: u64) -> Result<Value, E> {
        Ok(value.into())
    }

    fn visit_f64<E: Error>(self, value: f64) -> Result<Value, E> {
        Ok(value.into())
    }

    fn visit_str<E: Error>(self, value: &str) -> Result<Value, E> {
        Ok(value.into())
    }

    fn visit_string<E: Error>(self, value: String) -> Result<Value, E> {
        Ok(value.into())
    }

    fn visit_unit<E: Error>(self) -> Result<Value, E> {
        Ok(Value::Null)
    }

    fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Value, A::Error> {
        let mut items = Vec::new();
        while let Some(Checked(item)) = seq.next_element()? {
            items.push(item);
        }
        Ok(Value::Array(items))
    }

    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Value, A::Error> {
        let mut fields = Map::new();
        while let Some((key, Checked(value))) = map.next_entry()? {
            if fields.insert(key, value).is_some() {
                return Err(A::Error::custom("duplicate JSON object member"));
            }
        }
        Ok(Value::Object(fields))
    }
}

pub(super) fn parse(raw: &[u8]) -> serde_json::Result<Value> {
    serde_json::from_slice(raw).map(|Checked(value)| value)
}
