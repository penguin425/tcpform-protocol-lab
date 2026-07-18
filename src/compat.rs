//! DSL version validation, deprecation diagnostics, and machine-readable schema.

use crate::Block;
use serde_json::json;

pub const DSL_VERSION: u32 = 2;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompatibilityReport {
    pub version: u32,
    pub explicit: bool,
    pub warnings: Vec<String>,
}

pub fn inspect_dsl(source: &str, blocks: &[Block]) -> Result<CompatibilityReport, String> {
    let declarations = blocks
        .iter()
        .filter(|block| block.name == "tcpform")
        .collect::<Vec<_>>();
    if declarations.len() > 1 {
        return Err("only one top-level `tcpform` metadata block is allowed".into());
    }
    let marker_version = legacy_marker_version(source);
    let (version, explicit) = if let Some(block) = declarations.first() {
        if !block.labels.is_empty() || !block.blocks.is_empty() {
            return Err("tcpform metadata must be an unlabeled attribute-only block".into());
        }
        if block.attributes.len() != 1 || !block.attributes.contains_key("dsl_version") {
            return Err("tcpform metadata accepts only `dsl_version`".into());
        }
        let version = block
            .attr("dsl_version")
            .and_then(|value| value.as_u32())
            .ok_or("tcpform.dsl_version must be a positive integer")?;
        (version, true)
    } else if let Some(version) = marker_version {
        (version, false)
    } else {
        (1, false)
    };
    if version == 0 {
        return Err("DSL version must be at least 1".into());
    }
    if version > DSL_VERSION {
        return Err(format!(
            "DSL version {version} is newer than supported version {DSL_VERSION}"
        ));
    }
    let mut warnings = Vec::new();
    if declarations.is_empty() {
        if marker_version.is_some() {
            warnings.push("deprecated version comment; run `tcpform migrate --write` to add a tcpform metadata block".into());
        } else {
            warnings.push("missing explicit DSL version; run `tcpform migrate --write`".into());
        }
    }
    for (needle, replacement) in [
        ("action = \"connect\"", "action = \"open\""),
        ("action=\"connect\"", "action = \"open\""),
        (
            "action = \"listen\"",
            "action = \"open\" with mode = \"passive\"",
        ),
        (
            "action=\"listen\"",
            "action = \"open\" with mode = \"passive\"",
        ),
        ("retries =", "retry ="),
        ("retries=", "retry ="),
        ("delay_ms =", "delay = \"...ms\""),
        ("delay_ms=", "delay = \"...ms\""),
        ("timeout_ms =", "timeout = \"...ms\""),
        ("timeout_ms=", "timeout = \"...ms\""),
    ] {
        if source.contains(needle) {
            warnings.push(format!("deprecated syntax `{needle}`; use `{replacement}`"));
        }
    }
    Ok(CompatibilityReport {
        version,
        explicit,
        warnings,
    })
}

fn legacy_marker_version(source: &str) -> Option<u32> {
    source.lines().find_map(|line| {
        line.trim()
            .strip_prefix("# tcpform-version:")
            .and_then(|value| value.trim().parse().ok())
    })
}

pub fn dsl_json_schema() -> serde_json::Value {
    json!({
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": "https://github.com/penguin425/tcpform-protocol-lab/schema/tcpf-v2.json",
        "title": "tcpform DSL v2 abstract syntax",
        "description": "Machine-readable constraints for parsed tcpform DSL documents.",
        "type": "object",
        "required": ["dsl_version", "protocols"],
        "properties": {
            "dsl_version": {"const": DSL_VERSION},
            "protocols": {"type":"array", "items":{"$ref":"#/$defs/protocol"}},
            "case_suites": {"type":"array", "items":{"$ref":"#/$defs/cases"}}
        },
        "$defs": {
            "step": {
                "type":"object", "required":["name","role","action"],
                "properties": {
                    "name":{"type":"string","minLength":1}, "role":{"type":"string","minLength":1},
                    "action":{"enum":["send","recv","send_raw","recv_raw","ack","nack","wait","open","close","reset","drop","duplicate","corrupt","assert","set","log","plugin"]},
                    "depends_on":{"type":"array","items":{"type":"string"}},
                    "requirements":{"type":"array","items":{"type":"string"}},
                    "retry":{"type":"integer","minimum":0}, "loop":{"type":"integer","minimum":0}
                }, "additionalProperties": true
            },
            "protocol": {
                "type":"object", "required":["name","steps"],
                "properties":{"name":{"type":"string","minLength":1},"description":{"type":["string","null"]},"steps":{"type":"array","items":{"$ref":"#/$defs/step"}}},
                "additionalProperties": true
            },
            "cases": {
                "type":"object", "required":["protocol","cases"],
                "properties":{"protocol":{"type":"string"},"cases":{"type":"array","items":{"type":"object","required":["name"],"additionalProperties":true}}},
                "additionalProperties": false
            }
        },
        "additionalProperties": false
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn explicit_versions_and_legacy_warnings_are_reported() {
        let current = "tcpform { dsl_version = 2 }\nprotocol \"p\" {}";
        let blocks = crate::parse_file(current).unwrap();
        assert_eq!(
            inspect_dsl(current, &blocks).unwrap(),
            CompatibilityReport {
                version: 2,
                explicit: true,
                warnings: vec![]
            }
        );
        let legacy = "protocol \"p\" {}";
        let blocks = crate::parse_file(legacy).unwrap();
        assert!(!inspect_dsl(legacy, &blocks).unwrap().warnings.is_empty());
    }
}
