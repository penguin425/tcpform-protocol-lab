//! Process-isolated extension API using a small, versioned JSON-RPC protocol.
//!
//! Plugins are ordinary executables described by a JSON manifest. A fresh
//! process handles each request, which prevents plugin state and crashes from
//! contaminating the simulation engine.

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::io::{Read, Write};
use std::process::{Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

pub const PLUGIN_PROTOCOL_VERSION: &str = "1.0";

pub fn dsl_value_to_json(value: &crate::Value) -> Value {
    match value {
        crate::Value::Null => Value::Null,
        crate::Value::Bool(value) => Value::Bool(*value),
        crate::Value::Number(value) => serde_json::Number::from_f64(*value)
            .map(Value::Number)
            .unwrap_or(Value::Null),
        crate::Value::String(value) => Value::String(value.clone()),
        crate::Value::Bytes(value) => {
            Value::String(value.iter().map(|byte| format!("{byte:02x}")).collect())
        }
        crate::Value::Array(values) => Value::Array(values.iter().map(dsl_value_to_json).collect()),
        crate::Value::Object(values) => Value::Object(
            values
                .iter()
                .map(|(key, value)| (key.clone(), dsl_value_to_json(value)))
                .collect(),
        ),
    }
}

pub fn json_to_dsl_value(value: &Value) -> crate::Value {
    match value {
        Value::Null => crate::Value::Null,
        Value::Bool(value) => crate::Value::Bool(*value),
        Value::Number(value) => crate::Value::Number(value.as_f64().unwrap_or_default()),
        Value::String(value) => crate::Value::String(value.clone()),
        Value::Array(values) => crate::Value::Array(values.iter().map(json_to_dsl_value).collect()),
        Value::Object(values) => crate::Value::Object(
            values
                .iter()
                .map(|(key, value)| (key.clone(), json_to_dsl_value(value)))
                .collect(),
        ),
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct PluginCapabilities {
    #[serde(default)]
    pub actions: Vec<String>,
    #[serde(default)]
    pub matchers: Vec<String>,
    #[serde(default)]
    pub decoders: Vec<String>,
    #[serde(default)]
    pub reports: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PluginManifest {
    pub id: String,
    pub version: String,
    pub protocol_version: String,
    pub command: String,
    #[serde(default)]
    pub args: Vec<String>,
    #[serde(default)]
    pub capabilities: PluginCapabilities,
    #[serde(default = "default_timeout")]
    pub timeout_ms: u64,
    #[serde(default = "default_output")]
    pub max_output_bytes: usize,
}

fn default_timeout() -> u64 {
    5_000
}
fn default_output() -> usize {
    4 * 1024 * 1024
}

impl PluginManifest {
    pub fn validate(&self) -> Result<(), String> {
        validate_name("plugin id", &self.id)?;
        if self.version.trim().is_empty() {
            return Err("plugin version must not be empty".into());
        }
        if self.protocol_version != PLUGIN_PROTOCOL_VERSION {
            return Err(format!(
                "unsupported plugin protocol {}, expected {PLUGIN_PROTOCOL_VERSION}",
                self.protocol_version
            ));
        }
        if self.command.trim().is_empty() {
            return Err("plugin command must not be empty".into());
        }
        if self.timeout_ms == 0 || self.timeout_ms > 300_000 {
            return Err("plugin timeout_ms must be between 1 and 300000".into());
        }
        if self.max_output_bytes == 0 || self.max_output_bytes > 64 * 1024 * 1024 {
            return Err("plugin max_output_bytes must be between 1 and 67108864".into());
        }
        for name in self
            .capabilities
            .actions
            .iter()
            .chain(&self.capabilities.matchers)
            .chain(&self.capabilities.decoders)
            .chain(&self.capabilities.reports)
        {
            validate_name("capability", name)?;
        }
        Ok(())
    }

    fn supports(&self, kind: &str, name: &str) -> bool {
        let values = match kind {
            "action" => &self.capabilities.actions,
            "matcher" => &self.capabilities.matchers,
            "decoder" => &self.capabilities.decoders,
            "report" => &self.capabilities.reports,
            _ => return false,
        };
        values.iter().any(|value| value == name)
    }
}

fn validate_name(context: &str, value: &str) -> Result<(), String> {
    if value.is_empty()
        || !value
            .chars()
            .all(|character| character.is_ascii_alphanumeric() || matches!(character, '_' | '-'))
    {
        return Err(format!(
            "{context} `{value}` must contain only ASCII letters, digits, `_` or `-`"
        ));
    }
    Ok(())
}

/// Invoke one declared capability and return its JSON result.
pub fn invoke_plugin(
    manifest: &PluginManifest,
    kind: &str,
    name: &str,
    input: Value,
) -> Result<Value, String> {
    manifest.validate()?;
    validate_name("capability", name)?;
    if !manifest.supports(kind, name) {
        return Err(format!(
            "plugin `{}` does not declare {kind} `{name}`",
            manifest.id
        ));
    }
    let request = json!({
        "jsonrpc":"2.0","id":1,
        "method":format!("tcpform.{kind}"),
        "params":{"name":name,"input":input,"protocol_version":PLUGIN_PROTOCOL_VERSION}
    });
    let mut child = Command::new(&manifest.command)
        .args(&manifest.args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|error| format!("cannot start plugin `{}`: {error}", manifest.id))?;
    let mut stdin = child.stdin.take().ok_or("plugin stdin is unavailable")?;
    serde_json::to_writer(&mut stdin, &request).map_err(|error| error.to_string())?;
    stdin.write_all(b"\n").map_err(|error| error.to_string())?;
    drop(stdin);
    let mut stdout = child.stdout.take().ok_or("plugin stdout is unavailable")?;
    let limit = manifest.max_output_bytes;
    let reader = thread::spawn(move || {
        let mut bytes = Vec::new();
        stdout
            .by_ref()
            .take(limit.saturating_add(1) as u64)
            .read_to_end(&mut bytes)
            .map(|_| bytes)
            .map_err(|error| error.to_string())
    });
    let started = Instant::now();
    loop {
        if let Some(status) = child.try_wait().map_err(|error| error.to_string())? {
            if !status.success() {
                return Err(format!("plugin `{}` exited with {status}", manifest.id));
            }
            break;
        }
        if started.elapsed() >= Duration::from_millis(manifest.timeout_ms) {
            let _ = child.kill();
            let _ = child.wait();
            return Err(format!(
                "plugin `{}` exceeded timeout_ms={}",
                manifest.id, manifest.timeout_ms
            ));
        }
        thread::sleep(Duration::from_millis(5));
    }
    let bytes = reader
        .join()
        .map_err(|_| "plugin output reader panicked".to_string())??;
    if bytes.len() > manifest.max_output_bytes {
        return Err(format!(
            "plugin `{}` exceeded max_output_bytes={}",
            manifest.id, manifest.max_output_bytes
        ));
    }
    let response: Value = serde_json::from_slice(&bytes)
        .map_err(|error| format!("plugin `{}` returned invalid JSON: {error}", manifest.id))?;
    if response.get("jsonrpc").and_then(Value::as_str) != Some("2.0")
        || response.get("id").and_then(Value::as_u64) != Some(1)
    {
        return Err(format!(
            "plugin `{}` returned an invalid JSON-RPC envelope",
            manifest.id
        ));
    }
    if let Some(error) = response.get("error") {
        return Err(format!("plugin `{}` error: {error}", manifest.id));
    }
    response
        .get("result")
        .cloned()
        .ok_or_else(|| format!("plugin `{}` response has no result", manifest.id))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn manifest() -> PluginManifest {
        PluginManifest {
            id: "example".into(),
            version: "1.0.0".into(),
            protocol_version: PLUGIN_PROTOCOL_VERSION.into(),
            command: "/bin/sh".into(),
            args: vec![
                "-c".into(),
                "read request; printf '%s\\n' '{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{\"matched\":true}}'"
                    .into(),
            ],
            capabilities: PluginCapabilities {
                matchers: vec!["custom".into()],
                ..PluginCapabilities::default()
            },
            timeout_ms: 1_000,
            max_output_bytes: 4096,
        }
    }

    #[test]
    #[cfg(unix)]
    fn manifest_validation_and_json_rpc_invocation_work() {
        let result = invoke_plugin(&manifest(), "matcher", "custom", json!({"actual":1})).unwrap();
        assert_eq!(result["matched"], true);
        assert!(invoke_plugin(&manifest(), "action", "missing", Value::Null).is_err());
    }
}
