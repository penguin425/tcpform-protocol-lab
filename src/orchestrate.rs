use serde::Deserialize;
use std::collections::HashMap;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Scenario {
    pub processes: Vec<ProcessSpec>,
    #[serde(default = "default_timeout")]
    pub timeout_ms: u64,
    #[serde(default)]
    pub capture: Option<CaptureSpec>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProcessSpec {
    pub name: String,
    pub command: Vec<String>,
    #[serde(default)]
    pub cwd: Option<PathBuf>,
    #[serde(default)]
    pub env: HashMap<String, String>,
    #[serde(default)]
    pub namespace: bool,
    #[serde(default)]
    pub allow_failure: bool,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CaptureSpec {
    pub output: PathBuf,
    #[serde(default = "default_interface")]
    pub interface: String,
    #[serde(default)]
    pub filter: Vec<String>,
    #[serde(default = "default_tcpdump")]
    pub command: String,
}

fn default_timeout() -> u64 {
    30_000
}
fn default_interface() -> String {
    "any".into()
}
fn default_tcpdump() -> String {
    "tcpdump".into()
}

impl Scenario {
    pub fn validate(&self) -> Result<(), String> {
        if self.processes.is_empty() {
            return Err("orchestration requires at least one process".into());
        }
        if self.timeout_ms == 0 {
            return Err("timeout_ms must be greater than zero".into());
        }
        let mut names = std::collections::HashSet::new();
        for process in &self.processes {
            if process.name.trim().is_empty() {
                return Err("process name must not be empty".into());
            }
            if !names.insert(&process.name) {
                return Err(format!("duplicate process name `{}`", process.name));
            }
            if process.command.is_empty() || process.command[0].is_empty() {
                return Err(format!("process `{}` has no command", process.name));
            }
            if let Some(cwd) = &process.cwd {
                if !cwd.is_dir() {
                    return Err(format!(
                        "process `{}` cwd does not exist: {}",
                        process.name,
                        cwd.display()
                    ));
                }
            }
        }
        if let Some(capture) = &self.capture {
            if capture.interface.is_empty() || capture.command.is_empty() {
                return Err("capture command and interface must not be empty".into());
            }
            if let Some(parent) = capture.output.parent() {
                if !parent.as_os_str().is_empty() && !parent.is_dir() {
                    return Err(format!(
                        "capture output directory does not exist: {}",
                        parent.display()
                    ));
                }
            }
        }
        Ok(())
    }

    pub fn plan(&self) -> serde_json::Value {
        serde_json::json!({
            "timeout_ms": self.timeout_ms,
            "capture": self.capture.as_ref().map(capture_command),
            "processes": self.processes.iter().map(process_command).collect::<Vec<_>>()
        })
    }
}

fn process_command(spec: &ProcessSpec) -> Vec<String> {
    if spec.namespace {
        let mut value = vec![
            "unshare".into(),
            "--net".into(),
            "--mount-proc".into(),
            "--".into(),
        ];
        value.extend(spec.command.clone());
        value
    } else {
        spec.command.clone()
    }
}

fn capture_command(spec: &CaptureSpec) -> Vec<String> {
    let mut value = vec![
        spec.command.clone(),
        "-U".into(),
        "-n".into(),
        "-i".into(),
        spec.interface.clone(),
        "-w".into(),
        spec.output.to_string_lossy().into_owned(),
    ];
    value.extend(spec.filter.clone());
    value
}

struct ManagedChild {
    name: String,
    allow_failure: bool,
    child: Child,
}

fn terminate(children: &mut [ManagedChild], capture: &mut Option<Child>) {
    for process in children.iter_mut() {
        let _ = process.child.kill();
        let _ = process.child.wait();
    }
    if let Some(process) = capture {
        let _ = process.kill();
        let _ = process.wait();
    }
}

pub fn run(scenario: &Scenario) -> Result<serde_json::Value, String> {
    scenario.validate()?;
    let mut capture = if let Some(spec) = &scenario.capture {
        let command = capture_command(spec);
        Some(
            Command::new(&command[0])
                .args(&command[1..])
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::inherit())
                .spawn()
                .map_err(|e| format!("cannot start capture: {e}"))?,
        )
    } else {
        None
    };
    let mut children = Vec::new();
    for spec in &scenario.processes {
        let command = process_command(spec);
        let mut builder = Command::new(&command[0]);
        builder
            .args(&command[1..])
            .envs(&spec.env)
            .stdin(Stdio::null())
            .stdout(Stdio::inherit())
            .stderr(Stdio::inherit());
        if let Some(cwd) = &spec.cwd {
            builder.current_dir(cwd);
        }
        match builder.spawn() {
            Ok(child) => children.push(ManagedChild {
                name: spec.name.clone(),
                allow_failure: spec.allow_failure,
                child,
            }),
            Err(error) => {
                terminate(&mut children, &mut capture);
                return Err(format!("cannot start process `{}`: {error}", spec.name));
            }
        }
    }
    let deadline = Instant::now() + Duration::from_millis(scenario.timeout_ms);
    let mut results = Vec::new();
    loop {
        let mut active = 0;
        for process in &mut children {
            if results
                .iter()
                .any(|value: &serde_json::Value| value["name"] == process.name)
            {
                continue;
            }
            match process.child.try_wait().map_err(|e| e.to_string())? {
                Some(status) => results.push(serde_json::json!({"name":process.name,"success":status.success(),"code":status.code(),"allowed_failure":process.allow_failure})),
                None => active += 1,
            }
        }
        if active == 0 {
            break;
        }
        if Instant::now() >= deadline {
            terminate(&mut children, &mut capture);
            return Err(format!(
                "orchestration timed out after {}ms",
                scenario.timeout_ms
            ));
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    if let Some(process) = &mut capture {
        let _ = process.kill();
        let _ = process.wait();
    }
    let failed = results
        .iter()
        .filter(|value| value["success"] == false && value["allowed_failure"] == false)
        .count();
    let report = serde_json::json!({"passed":failed==0,"processes":results,"capture":scenario.capture.as_ref().map(|value| &value.output)});
    if failed == 0 {
        Ok(report)
    } else {
        Err(format!(
            "{failed} orchestrated process(es) failed\n{report}"
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn validates_and_builds_namespace_and_capture_plan() {
        let value = r#"{"processes":[{"name":"server","command":["echo","ok"],"namespace":true}],"capture":{"output":"trace.pcapng","filter":["tcp","port","80"]}}"#;
        let scenario: Scenario = serde_json::from_str(value).unwrap();
        scenario.validate().unwrap();
        let plan = scenario.plan();
        assert_eq!(plan["processes"][0][0], "unshare");
        assert_eq!(plan["capture"][0], "tcpdump");
    }
    #[test]
    fn rejects_duplicate_process_names() {
        let value =
            r#"{"processes":[{"name":"x","command":["true"]},{"name":"x","command":["true"]}]}"#;
        let scenario: Scenario = serde_json::from_str(value).unwrap();
        assert!(scenario.validate().unwrap_err().contains("duplicate"));
    }
}
