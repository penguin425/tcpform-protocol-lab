//! Local productivity features that do not require hosted services.

use crate::{Action, Protocol};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::HashSet;
use std::fs;
use std::path::Path;

#[derive(Debug, Clone, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct LintConfig {
    pub require_receive_timeout: bool,
    pub max_timeout_ms: u64,
    pub forbidden_actions: Vec<String>,
    pub step_name_pattern: String,
    pub report_unused_variables: bool,
    pub deny_warnings: bool,
}

impl Default for LintConfig {
    fn default() -> Self {
        Self {
            require_receive_timeout: true,
            max_timeout_ms: 30_000,
            forbidden_actions: Vec::new(),
            step_name_pattern: "^[a-z][a-z0-9_]*$".into(),
            report_unused_variables: true,
            deny_warnings: false,
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct LintDiagnostic {
    pub rule: &'static str,
    pub severity: &'static str,
    pub protocol: String,
    pub step: Option<String>,
    pub message: String,
}

pub fn lint_protocol(protocol: &Protocol, config: &LintConfig) -> Vec<LintDiagnostic> {
    let mut diagnostics = Vec::new();
    let name_pattern = match regex_lite::Regex::new(&config.step_name_pattern) {
        Ok(pattern) => Some(pattern),
        Err(error) => {
            diagnostics.push(diagnostic(
                "configuration",
                "error",
                protocol,
                None,
                &format!("invalid step_name_pattern: {error}"),
            ));
            None
        }
    };
    let names = protocol
        .steps
        .iter()
        .map(|step| step.name.as_str())
        .collect::<HashSet<_>>();
    for step in &protocol.steps {
        if name_pattern
            .as_ref()
            .is_some_and(|pattern| !pattern.is_match(&step.name))
        {
            diagnostics.push(diagnostic(
                "step-name",
                "warning",
                protocol,
                Some(&step.name),
                &format!("step name does not match `{}`", config.step_name_pattern),
            ));
        }
        if matches!(step.action, Action::Recv | Action::RecvRaw)
            && config.require_receive_timeout
            && step
                .timer
                .as_ref()
                .is_none_or(|timer| timer.timeout_ms == 0)
        {
            diagnostics.push(diagnostic(
                "receive-timeout",
                "warning",
                protocol,
                Some(&step.name),
                "receive step has no explicit timeout",
            ));
        }
        if let Some(timer) = &step.timer {
            if timer.timeout_ms > config.max_timeout_ms {
                diagnostics.push(diagnostic(
                    "maximum-timeout",
                    "warning",
                    protocol,
                    Some(&step.name),
                    &format!(
                        "timeout {}ms exceeds configured maximum {}ms",
                        timer.timeout_ms, config.max_timeout_ms
                    ),
                ));
            }
        }
        if config
            .forbidden_actions
            .iter()
            .any(|action| action == step.action.as_str())
        {
            diagnostics.push(diagnostic(
                "forbidden-action",
                "error",
                protocol,
                Some(&step.name),
                &format!("action `{}` is forbidden by policy", step.action.as_str()),
            ));
        }
        for dependency in &step.depends_on {
            if !names.contains(dependency.as_str()) {
                diagnostics.push(diagnostic(
                    "unknown-dependency",
                    "error",
                    protocol,
                    Some(&step.name),
                    &format!("dependency `{dependency}` does not exist"),
                ));
            }
        }
    }
    if config.report_unused_variables {
        let mut defined = HashSet::new();
        let mut used = HashSet::new();
        for step in &protocol.steps {
            if let Some(set) = &step.set {
                defined.extend(set.vars.keys().cloned());
            }
            if let Some(expect) = &step.expect {
                defined.extend(expect.capture.values().cloned());
            }
            if let Some(assertion) = &step.assert {
                used.extend(assertion.attrs.keys().cloned());
                for value in assertion.attrs.values() {
                    collect_references(value, &mut used);
                }
            }
            if let Some(segment) = &step.segment {
                for text in segment.payload.iter().chain(segment.hex.iter()) {
                    collect_text_references(text, &mut used);
                }
                for value in segment.fields.values() {
                    collect_references(value, &mut used);
                }
            }
            if let Some(value) = &step.when {
                collect_references(value, &mut used);
            }
        }
        for variable in defined.difference(&used) {
            diagnostics.push(diagnostic(
                "unused-variable",
                "warning",
                protocol,
                None,
                &format!("variable `{variable}` is assigned but never used"),
            ));
        }
    }
    diagnostics
}

fn collect_references(value: &crate::Value, output: &mut HashSet<String>) {
    match value {
        crate::Value::String(value) => collect_text_references(value, output),
        crate::Value::Array(values) => {
            for value in values {
                collect_references(value, output);
            }
        }
        crate::Value::Object(values) => {
            for value in values.values() {
                collect_references(value, output);
            }
        }
        _ => {}
    }
}

fn collect_text_references(value: &str, output: &mut HashSet<String>) {
    let mut remaining = value;
    while let Some((_, rest)) = remaining.split_once("${") {
        let Some((name, tail)) = rest.split_once('}') else {
            break;
        };
        if !name.is_empty() {
            output.insert(name.to_string());
        }
        remaining = tail;
    }
}

fn diagnostic(
    rule: &'static str,
    severity: &'static str,
    protocol: &Protocol,
    step: Option<&str>,
    message: &str,
) -> LintDiagnostic {
    LintDiagnostic {
        rule,
        severity,
        protocol: protocol.name.clone(),
        step: step.map(str::to_string),
        message: message.to_string(),
    }
}

pub fn har_to_tcpform(har: &Value, protocol: &str) -> Result<String, String> {
    let entries = har
        .pointer("/log/entries")
        .and_then(Value::as_array)
        .ok_or("HAR must contain log.entries")?;
    if entries.is_empty() {
        return Err("HAR contains no entries".into());
    }
    let mut steps = String::new();
    for (index, entry) in entries.iter().enumerate() {
        let request = entry.get("request").ok_or("HAR entry has no request")?;
        let response = entry.get("response").ok_or("HAR entry has no response")?;
        let method = request
            .get("method")
            .and_then(Value::as_str)
            .unwrap_or("GET");
        let url = request.get("url").and_then(Value::as_str).unwrap_or("/");
        let status = response.get("status").and_then(Value::as_i64).unwrap_or(0);
        let headers = |value: &Value| {
            value
                .get("headers")
                .and_then(Value::as_array)
                .into_iter()
                .flatten()
                .filter_map(|header| {
                    Some((
                        header.get("name")?.as_str()?.to_string(),
                        Value::String(header.get("value")?.as_str()?.to_string()),
                    ))
                })
                .collect::<serde_json::Map<_, _>>()
        };
        let request_line = escape(
            &serde_json::json!({
                "method":method,
                "url":url,
                "headers":headers(request),
                "body":request.pointer("/postData/text").and_then(Value::as_str).unwrap_or("")
            })
            .to_string(),
        );
        let response_line = escape(
            &serde_json::json!({
                "status":status,
                "headers":headers(response),
                "body":response.pointer("/content/text").and_then(Value::as_str).unwrap_or("")
            })
            .to_string(),
        );
        let dependency = if index == 0 {
            String::new()
        } else {
            format!(" depends_on = [\"response_{}\"]", index - 1)
        };
        steps.push_str(&format!(
            "  step \"request_{index}\" {{ role = \"client\" action = \"send\" to = \"server\"{dependency} segment {{ payload = \"{request_line}\" }} }}\n  step \"receive_{index}\" {{ role = \"server\" action = \"recv\" depends_on = [\"request_{index}\"] timer {{ timeout = \"5s\" }} expect {{ from = \"client\" payload = \"{request_line}\" }} }}\n  step \"response_{index}\" {{ role = \"server\" action = \"send\" to = \"client\" depends_on = [\"receive_{index}\"] segment {{ payload = \"{response_line}\" }} }}\n  step \"verify_{index}\" {{ role = \"client\" action = \"recv\" depends_on = [\"response_{index}\"] timer {{ timeout = \"5s\" }} expect {{ from = \"server\" payload = \"{response_line}\" }} }}\n"
        ));
    }
    Ok(format!(
        "tcpform {{ dsl_version = 2 }}\n\nprotocol \"{}\" {{\n  clock = \"virtual\"\n{} }}\n\ncases \"{}\" {{\n  case \"har_replay\" {{ expect = \"pass\" tags = [\"har\", \"import\"] }}\n}}\n",
        escape(protocol), steps, escape(protocol)
    ))
}

fn escape(value: &str) -> String {
    value
        .replace('\\', "\\\\")
        .replace('"', "\\\"")
        .replace('\n', "\\n")
        .replace('\r', "\\r")
}

pub fn create_tutorial(directory: &Path, force: bool) -> Result<Vec<String>, String> {
    if directory.exists() && !force {
        return Err(format!(
            "{} already exists; use --force",
            directory.display()
        ));
    }
    fs::create_dir_all(directory).map_err(|error| error.to_string())?;
    let files = [
        ("01-hello.tcpf", HELLO),
        ("02-assertions.tcpf", ASSERTIONS),
        ("03-faults.tcpf", FAULTS),
        ("README.md", TUTORIAL_README),
    ];
    for (name, contents) in files {
        fs::write(directory.join(name), contents).map_err(|error| error.to_string())?;
    }
    Ok(files.iter().map(|(name, _)| (*name).to_string()).collect())
}

const HELLO: &str = r#"tcpform { dsl_version = 2 }
protocol "hello" {
  clock = "virtual"
  step "request" { role = "client" action = "send" to = "server" segment { payload = "ping" } }
  step "receive" { role = "server" action = "recv" depends_on = ["request"] timer { timeout = "1s" } expect { payload = "ping" } }
}
cases "hello" { case "smoke" { expect = "pass" tags = ["tutorial"] } }
"#;

const ASSERTIONS: &str = r#"tcpform { dsl_version = 2 }
protocol "assertions" {
  clock = "virtual"
  step "value" { role = "client" action = "set" set { answer = 42 } }
  step "check" { role = "client" action = "assert" depends_on = ["value"] assert { answer = 42 } }
}
cases "assertions" { case "value_is_42" { expect = "pass" tags = ["tutorial"] } }
"#;

const FAULTS: &str = r#"tcpform { dsl_version = 2 }
protocol "faults" {
  clock = "virtual"
  transport { delay = "20ms" jitter = "5ms" seed = 42 }
  step "request" { role = "client" action = "send" to = "server" segment { payload = "ping" } }
  step "receive" { role = "server" action = "recv" depends_on = ["request"] timer { timeout = "1s" } expect { payload = "ping" } }
}
cases "faults" { case "delayed_delivery" { expect = "pass" tags = ["tutorial", "fault"] } }
"#;

const TUTORIAL_README: &str = r#"# tcpform interactive tutorial

Run each lesson in order:

```sh
tcpform test 01-hello.tcpf
tcpform test 02-assertions.tcpf
tcpform test 03-faults.tcpf
```

Edit payloads, assertions, and timeouts and rerun the commands to observe the diagnostics.
"#;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{model::interpret, parse_file};

    #[test]
    fn har_generates_runnable_dsl() {
        let har = serde_json::json!({"log":{"entries":[{"request":{"method":"QUERY","url":"https://example.test/items"},"response":{"status":200}}]}});
        let source = har_to_tcpform(&har, "api").unwrap();
        let blocks = parse_file(&source).unwrap();
        let protocol = interpret(&blocks).unwrap().remove(0);
        assert_eq!(protocol.steps.len(), 4);
        assert!(crate::Engine::new(protocol).unwrap().run().is_ok());
    }

    #[test]
    fn lint_policy_reports_timeouts_and_forbidden_actions() {
        let blocks = parse_file(r#"protocol "p" { step "r" { role="a" action="recv" } step "x" { role="a" action="reset" } }"#).unwrap();
        let protocol = interpret(&blocks).unwrap().remove(0);
        let config = LintConfig {
            forbidden_actions: vec!["reset".into()],
            ..Default::default()
        };
        let diagnostics = lint_protocol(&protocol, &config);
        assert_eq!(diagnostics.len(), 2);
    }

    #[test]
    fn lint_reports_naming_and_unused_variables() {
        let blocks = parse_file(
            r#"protocol "p" { step "Bad-Name" { role="a" action="set" set { unused = 1 } } }"#,
        )
        .unwrap();
        let protocol = interpret(&blocks).unwrap().remove(0);
        let diagnostics = lint_protocol(&protocol, &LintConfig::default());
        assert!(diagnostics.iter().any(|item| item.rule == "step-name"));
        assert!(diagnostics
            .iter()
            .any(|item| item.rule == "unused-variable"));
    }
}
