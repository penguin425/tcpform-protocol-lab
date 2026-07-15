//! Wire-level primitives: the [`Message`] that travels over the simulated
//! transport and the matching logic for [`Expect`].

use crate::model::Expect;
use crate::value::Value;
use std::collections::HashMap;

/// A message on the simulated wire.
#[derive(Debug, Clone)]
pub struct Message {
    pub from: String,
    pub flags: Vec<String>,
    pub seq: i64,
    pub ack: i64,
    pub payload: String,
    /// Raw binary payload (from `hex = "..."`). When non-empty, takes
    /// precedence over `payload` for matching and length calculations.
    pub raw: Vec<u8>,
    /// Flow-control advertisement (TCP window). 0 when unspecified.
    pub window: i64,
    /// Multiplexing stream id. `None` means the default stream.
    pub stream: Option<i64>,
    /// Structured message fields (key→value), traveling on the wire.
    pub fields: HashMap<String, Value>,
}

impl Message {
    pub fn flags_str(&self) -> String {
        if self.flags.is_empty() {
            "-".into()
        } else {
            self.flags.join(",")
        }
    }

    /// The effective payload length: `raw.len()` if binary, else `payload.len()`.
    pub fn payload_len(&self) -> usize {
        if !self.raw.is_empty() {
            self.raw.len()
        } else {
            self.payload.len()
        }
    }
}

impl Expect {
    /// True if `msg` satisfies this expectation.
    /// `from`: if set, the message must originate from that role.
    /// `flags`: every expected flag must be present in the message (subset
    /// match, so `["SYN"]` matches `["SYN","ACK"]`).
    /// `payload`: if set, must equal the message payload exactly.
    pub fn matches(&self, msg: &Message) -> bool {
        if let Some(from) = &self.from {
            if !from.is_empty() && *from != msg.from {
                return false;
            }
        }
        for f in &self.flags {
            if !msg.flags.iter().any(|g| g == f) {
                return false;
            }
        }
        if let Some(p) = &self.payload {
            if *p != msg.payload {
                return false;
            }
        }
        // Binary payload exact match
        if let Some(hx) = &self.hex {
            if msg.raw != *hx {
                return false;
            }
        }
        // Binary payload substring match
        if let Some(needle) = &self.hex_contains {
            if needle.is_empty() {
                return false;
            }
            if !msg
                .raw
                .windows(needle.len())
                .any(|w| w == needle.as_slice())
            {
                return false;
            }
        }
        if let Some(w) = self.window {
            if w != msg.window {
                return false;
            }
        }
        if let Some(s) = self.stream {
            if Some(s) != msg.stream {
                return false;
            }
        }
        // Structured field matching: only the named fields are checked (partial
        // match). Each field uses its operator (Equal/Contains/Min/Max/Range).
        for (key, matcher) in &self.fields {
            match msg.fields.get(key) {
                Some(actual) => {
                    if !matcher.matches(actual) {
                        return false;
                    }
                }
                None => return false,
            }
        }
        true
    }
}
