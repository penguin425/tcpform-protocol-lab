//! Generic HCL-like block tree. The parser produces `Vec<Block>` (top-level
//! blocks of a file). The model layer interprets `protocol` blocks.

use crate::value::Value;
use std::collections::HashMap;

/// A block: `name ["label"]* { attributes... sub-blocks... }`.
#[derive(Debug, Clone, PartialEq)]
pub struct Block {
    pub name: String,
    pub labels: Vec<String>,
    pub attributes: HashMap<String, Value>,
    pub blocks: Vec<Block>,
    pub source: Option<String>,
    pub line: usize,
    pub column: usize,
}

impl Block {
    pub fn new(name: impl Into<String>) -> Self {
        Block {
            name: name.into(),
            labels: Vec::new(),
            attributes: HashMap::new(),
            blocks: Vec::new(),
            source: None,
            line: 0,
            column: 0,
        }
    }

    /// Look up an attribute by key.
    pub fn attr(&self, key: &str) -> Option<&Value> {
        self.attributes.get(key)
    }

    /// Look up a string attribute by key.
    pub fn attr_str(&self, key: &str) -> Option<&str> {
        self.attr(key).and_then(|v| v.as_str())
    }

    /// First child block with the given name.
    pub fn child(&self, name: &str) -> Option<&Block> {
        self.blocks.iter().find(|b| b.name == name)
    }

    /// All child blocks with the given name.
    pub fn children(&self, name: &str) -> impl Iterator<Item = &Block> {
        let name = name.to_string();
        self.blocks.iter().filter(move |b| b.name == name)
    }
}
