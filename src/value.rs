//! Typed values produced by the parser and consumed by the model layer.

use std::collections::HashMap;
use std::fmt;

/// A value in the DSL. Numbers are stored as `f64` but integer accessors are
/// provided since protocol sequence numbers are integral. `Bytes` carries
/// raw binary data (from `hex = "..."`), allowing binary wire messages.
#[derive(Debug, Clone, PartialEq)]
pub enum Value {
    Null,
    Bool(bool),
    Number(f64),
    String(String),
    Bytes(Vec<u8>),
    Array(Vec<Value>),
    Object(HashMap<String, Value>),
}

impl Value {
    pub fn as_bool(&self) -> Option<bool> {
        match self {
            Value::Bool(b) => Some(*b),
            _ => None,
        }
    }

    pub fn as_str(&self) -> Option<&str> {
        match self {
            Value::String(s) => Some(s.as_str()),
            _ => None,
        }
    }

    /// Access raw bytes if this is a [`Value::Bytes`].
    pub fn as_bytes(&self) -> Option<&[u8]> {
        match self {
            Value::Bytes(b) => Some(b),
            _ => None,
        }
    }

    pub fn as_i64(&self) -> Option<i64> {
        match self {
            Value::Number(n)
                if n.is_finite()
                    && n.fract() == 0.0
                    && *n >= i64::MIN as f64
                    && *n < 9_223_372_036_854_775_808.0 =>
            {
                Some(*n as i64)
            }
            _ => None,
        }
    }

    pub fn as_u64(&self) -> Option<u64> {
        match self {
            Value::Number(n)
                if n.is_finite()
                    && n.fract() == 0.0
                    && *n >= 0.0
                    && *n < 18_446_744_073_709_551_616.0 =>
            {
                Some(*n as u64)
            }
            _ => None,
        }
    }

    pub fn as_u32(&self) -> Option<u32> {
        self.as_u64().and_then(|n| u32::try_from(n).ok())
    }

    pub fn as_array(&self) -> Option<&[Value]> {
        match self {
            Value::Array(a) => Some(a),
            _ => None,
        }
    }

    pub fn as_object(&self) -> Option<&HashMap<String, Value>> {
        match self {
            Value::Object(o) => Some(o),
            _ => None,
        }
    }

    /// Collect an array of strings (e.g. `depends_on = ["a", "b"]`).
    pub fn as_string_array(&self) -> Option<Vec<String>> {
        match self {
            Value::Array(a) => {
                let mut out = Vec::with_capacity(a.len());
                for v in a {
                    out.push(v.as_str()?.to_string());
                }
                Some(out)
            }
            _ => None,
        }
    }

    /// Render for human-friendly display (used in `plan` output).
    pub fn to_display(&self) -> String {
        match self {
            Value::Null => "null".to_string(),
            Value::Bool(b) => b.to_string(),
            Value::Number(n) => {
                if n.fract() == 0.0 {
                    format!("{}", *n as i64)
                } else {
                    format!("{n}")
                }
            }
            Value::String(s) => format!("{s:?}"),
            Value::Bytes(b) => format!("hex:\"{}\"", bytes_to_hex(b)),
            Value::Array(a) => {
                let items: Vec<String> = a.iter().map(|v| v.to_display()).collect();
                format!("[{}]", items.join(", "))
            }
            Value::Object(o) => {
                let items: Vec<String> = o
                    .iter()
                    .map(|(k, v)| format!("{k} = {}", v.to_display()))
                    .collect();
                format!("{{ {} }}", items.join(", "))
            }
        }
    }
}

impl fmt::Display for Value {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.to_display())
    }
}

/// Parse a hex string into bytes. Accepts an optional `0x` prefix and
/// ignores embedded whitespace. An odd number of hex digits is an error.
///
/// `"4500003c"`, `"0x4500003c"`, `"45 00 00 3c"` all parse to
/// `[0x45, 0x00, 0x00, 0x3c]`.
pub fn parse_hex(s: &str) -> Result<Vec<u8>, String> {
    let cleaned: String = s
        .strip_prefix("0x")
        .unwrap_or(s)
        .chars()
        .filter(|c| !c.is_whitespace())
        .collect();
    if !cleaned.len().is_multiple_of(2) {
        return Err(format!(
            "hex string has odd number of digits ({}): {cleaned:?}",
            cleaned.len()
        ));
    }
    let mut out = Vec::with_capacity(cleaned.len() / 2);
    let bytes = cleaned.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        let hi = hex_digit(bytes[i])?;
        let lo = hex_digit(bytes[i + 1])?;
        out.push((hi << 4) | lo);
        i += 2;
    }
    Ok(out)
}

fn hex_digit(b: u8) -> Result<u8, String> {
    match b {
        b'0'..=b'9' => Ok(b - b'0'),
        b'a'..=b'f' => Ok(b - b'a' + 10),
        b'A'..=b'F' => Ok(b - b'A' + 10),
        _ => Err(format!("invalid hex digit: {:#?}", b as char)),
    }
}

/// Render bytes as a lowercase hex string (no prefix). Used for display and
/// interpolation of `Value::Bytes` into `${var}` contexts.
pub fn bytes_to_hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}
