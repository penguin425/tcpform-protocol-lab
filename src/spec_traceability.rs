//! Import normative prose into reviewable requirements and report execution coverage.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

const KEYWORDS: [&str; 9] = [
    "MUST NOT",
    "SHOULD NOT",
    "MUST",
    "SHOULD",
    "REQUIRED",
    "SHALL NOT",
    "SHALL",
    "MAY",
    "RECOMMENDED",
];

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RequirementCatalog {
    pub schema_version: String,
    pub source: String,
    pub generated_by: String,
    pub review_required: bool,
    pub requirements: Vec<Requirement>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Requirement {
    pub id: String,
    pub section: String,
    pub level: String,
    pub text: String,
    pub source: String,
    pub category: String,
    pub confidence: f64,
    pub inferred: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CoverageReport {
    pub schema_version: String,
    pub source: String,
    pub summary: CoverageSummary,
    pub requirements: Vec<RequirementCoverage>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CoverageSummary {
    pub total: usize,
    pub covered: usize,
    pub failed: usize,
    pub untested: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RequirementCoverage {
    pub id: String,
    pub status: String,
    pub steps: Vec<String>,
}

pub fn import_spec(text: &str, source: &str) -> Result<RequirementCatalog, String> {
    let mut section = "preamble".to_string();
    let mut candidates = Vec::new();
    let normalized = text.replace("\r\n", "\n");
    let mut paragraph = String::new();

    let flush = |paragraph: &mut String, section: &str, out: &mut Vec<(String, String)>| {
        if !paragraph.trim().is_empty() {
            out.push((
                section.to_string(),
                paragraph.split_whitespace().collect::<Vec<_>>().join(" "),
            ));
            paragraph.clear();
        }
    };
    for line in normalized.lines() {
        let trimmed = line.trim();
        if is_heading(trimmed) {
            flush(&mut paragraph, &section, &mut candidates);
            section = trimmed.to_string();
        } else if trimmed.is_empty() {
            flush(&mut paragraph, &section, &mut candidates);
        } else {
            if !paragraph.is_empty() {
                paragraph.push(' ');
            }
            paragraph.push_str(trimmed);
        }
    }
    flush(&mut paragraph, &section, &mut candidates);

    let mut requirements = Vec::new();
    for (section, paragraph) in candidates {
        for sentence in sentences(&paragraph) {
            if let Some(level) = normative_level(sentence) {
                let index = requirements.len() + 1;
                requirements.push(Requirement {
                    id: format!("REQ-{index:04}"),
                    section: section.clone(),
                    level: level.to_string(),
                    text: sentence.trim().to_string(),
                    source: source.to_string(),
                    category: infer_category(sentence).to_string(),
                    confidence: 0.85,
                    inferred: true,
                });
            }
        }
    }
    if requirements.is_empty() {
        return Err("no RFC 2119-style normative requirements found".to_string());
    }
    Ok(RequirementCatalog {
        schema_version: "1".to_string(),
        source: source.to_string(),
        generated_by: "tcpform spec import (heuristic RFC 2119 extraction)".to_string(),
        review_required: true,
        requirements,
    })
}

pub fn starter_dsl(catalog: &RequirementCatalog, protocol: &str) -> String {
    let mut out = format!(
        "# Generated proposal: review every inferred requirement before conformance use.\ntcpform {{ dsl_version = 2 }}\n\nprotocol \"{}\" {{\n  description = \"Requirements imported from {}\"\n",
        escape(protocol), escape(&catalog.source)
    );
    for requirement in &catalog.requirements {
        out.push_str(&format!(
            "  step \"requirement_{}\" {{\n    role = \"specification\"\n    action = \"log\"\n    requirements = [\"{}\"]\n    description = \"[{}; confidence {:.2}] {}\"\n    message = \"Review and replace this proposal with executable protocol steps\"\n    when = false\n  }}\n",
            requirement.id.trim_start_matches("REQ-").to_lowercase(),
            escape(&requirement.id), escape(&requirement.category), requirement.confidence,
            escape(&requirement.text)
        ));
    }
    out.push_str("}\n");
    out
}

pub fn coverage(
    catalog: &RequirementCatalog,
    trace: &serde_json::Value,
) -> Result<CoverageReport, String> {
    let events = trace
        .get("events")
        .and_then(|v| v.as_array())
        .or_else(|| trace.get("trace").and_then(|v| v.as_array()))
        .or_else(|| trace.as_array())
        .ok_or("trace JSON must be an array or contain an `events`/`trace` array")?;
    let mut seen: HashMap<String, (bool, Vec<String>)> = HashMap::new();
    for event in events {
        if event
            .get("detail")
            .and_then(|value| value.as_str())
            .is_some_and(|detail| detail.starts_with("skipped:"))
        {
            continue;
        }
        let ok = event.get("ok").and_then(|v| v.as_bool()).unwrap_or(false);
        let step = event
            .get("step")
            .and_then(|v| v.as_str())
            .unwrap_or("unknown")
            .to_string();
        if let Some(ids) = event.get("requirements").and_then(|v| v.as_array()) {
            for id in ids.iter().filter_map(|v| v.as_str()) {
                let entry = seen.entry(id.to_string()).or_insert((true, Vec::new()));
                entry.0 &= ok;
                if !entry.1.contains(&step) {
                    entry.1.push(step.clone());
                }
            }
        }
    }
    let requirements: Vec<_> = catalog
        .requirements
        .iter()
        .map(|req| {
            let (status, steps) = match seen.get(&req.id) {
                Some((true, steps)) => ("covered", steps.clone()),
                Some((false, steps)) => ("failed", steps.clone()),
                None => ("untested", Vec::new()),
            };
            RequirementCoverage {
                id: req.id.clone(),
                status: status.to_string(),
                steps,
            }
        })
        .collect();
    Ok(CoverageReport {
        schema_version: "1".to_string(),
        source: catalog.source.clone(),
        summary: CoverageSummary {
            total: requirements.len(),
            covered: requirements
                .iter()
                .filter(|r| r.status == "covered")
                .count(),
            failed: requirements.iter().filter(|r| r.status == "failed").count(),
            untested: requirements
                .iter()
                .filter(|r| r.status == "untested")
                .count(),
        },
        requirements,
    })
}

fn normative_level(text: &str) -> Option<&'static str> {
    let upper = text.to_ascii_uppercase();
    KEYWORDS
        .iter()
        .copied()
        .find(|keyword| contains_word(&upper, keyword))
}

fn contains_word(text: &str, needle: &str) -> bool {
    text.match_indices(needle).any(|(start, _)| {
        let end = start + needle.len();
        (start == 0 || !text.as_bytes()[start - 1].is_ascii_alphanumeric())
            && (end == text.len() || !text.as_bytes()[end].is_ascii_alphanumeric())
    })
}

fn is_heading(line: &str) -> bool {
    let first = line.split_whitespace().next().unwrap_or("");
    !first.is_empty()
        && first.chars().all(|c| c.is_ascii_digit() || c == '.')
        && line.len() < 120
        && line.chars().any(char::is_alphabetic)
}

fn sentences(paragraph: &str) -> Vec<&str> {
    paragraph
        .split_inclusive(['.', '!', '?'])
        .filter(|s| !s.trim().is_empty())
        .collect()
}

fn infer_category(text: &str) -> &'static str {
    let lower = text.to_ascii_lowercase();
    if lower.contains("error") || lower.contains("invalid") || lower.contains("reject") {
        "error-handling"
    } else if lower.contains("timer") || lower.contains("timeout") || lower.contains("retransmit") {
        "timer-retransmission"
    } else if lower.contains("state") || lower.contains("transition") {
        "state-transition"
    } else if lower.contains("not ") || lower.contains("never") {
        "negative"
    } else {
        "behavior"
    }
}

fn escape(value: &str) -> String {
    value
        .replace('\\', "\\\\")
        .replace('"', "\\\"")
        .replace(['\n', '\r'], " ")
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn imports_and_categorizes_normative_sentences() {
        let catalog = import_spec("1. Rules\nA peer MUST enter the ready state. It MUST NOT accept an invalid frame. A retry SHOULD use a timer.", "RFC-test").unwrap();
        assert_eq!(catalog.requirements.len(), 3);
        assert_eq!(catalog.requirements[0].section, "1. Rules");
        assert_eq!(catalog.requirements[1].category, "error-handling");
        assert!(starter_dsl(&catalog, "demo").contains("requirements = [\"REQ-0001\"]"));
    }

    #[test]
    fn reports_covered_failed_and_untested() {
        let catalog = import_spec(
            "A peer MUST connect. It SHOULD retry. It MAY close.",
            "spec",
        )
        .unwrap();
        let trace = json!({"events":[
            {"step":"connect", "ok":true, "requirements":["REQ-0001"]},
            {"step":"retry", "ok":false, "requirements":["REQ-0002"]}
        ]});
        let report = coverage(&catalog, &trace).unwrap();
        assert_eq!(
            (
                report.summary.covered,
                report.summary.failed,
                report.summary.untested
            ),
            (1, 1, 1)
        );
    }
}
