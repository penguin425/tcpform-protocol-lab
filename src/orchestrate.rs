use serde::Deserialize;
use std::collections::HashMap;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Scenario {
    pub processes: Vec<ProcessSpec>,
    #[serde(default)]
    pub nodes: Vec<NodeSpec>,
    #[serde(default)]
    pub links: Vec<LinkSpec>,
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
    #[serde(default = "default_node")]
    pub node: String,
    #[serde(default)]
    pub roles: Vec<String>,
    #[serde(default)]
    pub start_after: Vec<String>,
    #[serde(default)]
    pub startup_delay_ms: u64,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NodeSpec {
    pub name: String,
    #[serde(default = "default_executor")]
    pub executor: String,
    #[serde(default)]
    pub host: Option<String>,
    #[serde(default)]
    pub user: Option<String>,
    #[serde(default)]
    pub port: Option<u16>,
    #[serde(default)]
    pub ssh_options: Vec<String>,
}

#[derive(Debug, Deserialize, serde::Serialize)]
#[serde(deny_unknown_fields)]
pub struct LinkSpec {
    pub from: String,
    pub to: String,
    #[serde(default)]
    pub latency_ms: u64,
    #[serde(default)]
    pub loss_rate: f64,
    #[serde(default)]
    pub bandwidth_bps: u64,
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
fn default_node() -> String {
    "local".into()
}
fn default_executor() -> String {
    "local".into()
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
        let mut roles = std::collections::HashSet::new();
        let mut nodes = std::collections::HashSet::from(["local".to_string()]);
        for node in &self.nodes {
            if node.name.trim().is_empty() || !nodes.insert(node.name.clone()) {
                return Err(format!("duplicate or empty node name `{}`", node.name));
            }
            if !matches!(node.executor.as_str(), "local" | "ssh") {
                return Err(format!(
                    "node `{}` executor must be local or ssh",
                    node.name
                ));
            }
            if node.executor == "ssh"
                && node.host.as_ref().is_none_or(|host| host.trim().is_empty())
            {
                return Err(format!("ssh node `{}` requires host", node.name));
            }
            if node.executor == "ssh"
                && (node
                    .host
                    .as_ref()
                    .is_some_and(|host| host.starts_with('-') || host.contains(['\n', '\r']))
                    || node.user.as_ref().is_some_and(|user| {
                        user.is_empty() || user.starts_with('-') || user.contains(['\n', '\r', '@'])
                    }))
            {
                return Err(format!(
                    "ssh node `{}` has an unsafe host or user",
                    node.name
                ));
            }
            if node.executor == "local"
                && (node.host.is_some()
                    || node.user.is_some()
                    || node.port.is_some()
                    || !node.ssh_options.is_empty())
            {
                return Err(format!(
                    "local node `{}` cannot define ssh settings",
                    node.name
                ));
            }
        }
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
            if !nodes.contains(&process.node) {
                return Err(format!(
                    "process `{}` references unknown node `{}`",
                    process.name, process.node
                ));
            }
            for role in &process.roles {
                if role.trim().is_empty() || !roles.insert(role) {
                    return Err(format!("role `{role}` is empty or assigned more than once"));
                }
            }
            for key in process.env.keys() {
                if key.is_empty()
                    || !key.chars().enumerate().all(|(index, character)| {
                        character == '_'
                            || character.is_ascii_alphabetic()
                            || (index > 0 && character.is_ascii_digit())
                    })
                {
                    return Err(format!(
                        "process `{}` has invalid environment name `{key}`",
                        process.name
                    ));
                }
            }
            let remote = self
                .nodes
                .iter()
                .any(|node| node.name == process.node && node.executor == "ssh");
            if !remote {
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
        }
        let process_names: std::collections::HashSet<_> = self
            .processes
            .iter()
            .map(|process| process.name.as_str())
            .collect();
        for process in &self.processes {
            for dependency in &process.start_after {
                if dependency == &process.name || !process_names.contains(dependency.as_str()) {
                    return Err(format!(
                        "process `{}` has invalid start_after `{dependency}`",
                        process.name
                    ));
                }
            }
        }
        startup_order(&self.processes)?;
        for link in &self.links {
            if !nodes.contains(&link.from) || !nodes.contains(&link.to) || link.from == link.to {
                return Err(format!(
                    "invalid topology link {} -> {}",
                    link.from, link.to
                ));
            }
            if !(0.0..=1.0).contains(&link.loss_rate) || !link.loss_rate.is_finite() {
                return Err(format!(
                    "link {} -> {} loss_rate must be 0.0–1.0",
                    link.from, link.to
                ));
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
            "nodes": std::iter::once(serde_json::json!({"name":"local","executor":"local","host":null})).chain(self.nodes.iter().map(|node| serde_json::json!({"name":node.name,"executor":node.executor,"host":node.host}))).collect::<Vec<_>>(),
            "links": self.links,
            "startup_order": startup_order(&self.processes).unwrap_or_default().iter().map(|process| process.name.as_str()).collect::<Vec<_>>(),
            "processes": self.processes.iter().map(|process| serde_json::json!({"name":process.name,"node":process.node,"roles":process.roles,"start_after":process.start_after,"command":self.process_command(process)})).collect::<Vec<_>>()
        })
    }

    fn process_command(&self, spec: &ProcessSpec) -> Vec<String> {
        let mut command = local_process_command(spec);
        let node = self.nodes.iter().find(|node| node.name == spec.node);
        if let Some(node) = node.filter(|node| node.executor == "ssh") {
            let mut ssh = vec!["ssh".to_string()];
            if let Some(port) = node.port {
                ssh.extend(["-p".into(), port.to_string()]);
            }
            ssh.extend(node.ssh_options.clone());
            let destination = match &node.user {
                Some(user) => format!("{user}@{}", node.host.as_deref().unwrap()),
                None => node.host.clone().unwrap(),
            };
            ssh.push(destination);
            let mut environment = spec.env.clone();
            environment.insert("TCPFORM_NODE".into(), spec.node.clone());
            environment.insert("TCPFORM_ROLES".into(), spec.roles.join(","));
            environment.insert(
                "TCPFORM_TOPOLOGY_LINKS".into(),
                serde_json::to_string(&self.links).expect("links serialize"),
            );
            ssh.push(shell_command(&command, spec.cwd.as_ref(), &environment));
            command = ssh;
        }
        command
    }
}

fn local_process_command(spec: &ProcessSpec) -> Vec<String> {
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

fn shell_quote(value: &str) -> String {
    format!("'{}'", value.replace('\'', "'\\''"))
}

fn shell_command(
    command: &[String],
    cwd: Option<&PathBuf>,
    env: &HashMap<String, String>,
) -> String {
    let mut parts = Vec::new();
    if let Some(cwd) = cwd {
        parts.push(format!("cd {} &&", shell_quote(&cwd.to_string_lossy())));
    }
    let mut environment: Vec<_> = env.iter().collect();
    environment.sort_by_key(|(key, _)| *key);
    for (key, value) in environment {
        parts.push(format!("{}={}", key, shell_quote(value)));
    }
    parts.extend(command.iter().map(|value| shell_quote(value)));
    parts.join(" ")
}

fn startup_order(processes: &[ProcessSpec]) -> Result<Vec<&ProcessSpec>, String> {
    let mut remaining: std::collections::HashSet<_> = processes
        .iter()
        .map(|process| process.name.as_str())
        .collect();
    let mut started = std::collections::HashSet::new();
    let mut ordered = Vec::new();
    while !remaining.is_empty() {
        let mut progress = false;
        for process in processes {
            if remaining.contains(process.name.as_str())
                && process
                    .start_after
                    .iter()
                    .all(|dependency| started.contains(dependency.as_str()))
            {
                remaining.remove(process.name.as_str());
                started.insert(process.name.as_str());
                ordered.push(process);
                progress = true;
            }
        }
        if !progress {
            return Err(format!(
                "process start_after cycle involving: {}",
                remaining.into_iter().collect::<Vec<_>>().join(", ")
            ));
        }
    }
    Ok(ordered)
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
    node: String,
    roles: Vec<String>,
    started: Instant,
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
    let link_json = serde_json::to_string(&scenario.links).map_err(|error| error.to_string())?;
    for spec in startup_order(&scenario.processes)? {
        let command = scenario.process_command(spec);
        let mut builder = Command::new(&command[0]);
        builder
            .args(&command[1..])
            .envs(&spec.env)
            .env("TCPFORM_NODE", &spec.node)
            .env("TCPFORM_ROLES", spec.roles.join(","))
            .env("TCPFORM_TOPOLOGY_LINKS", &link_json)
            .stdin(Stdio::null())
            .stdout(Stdio::inherit())
            .stderr(Stdio::inherit());
        let remote = scenario
            .nodes
            .iter()
            .any(|node| node.name == spec.node && node.executor == "ssh");
        if !remote {
            if let Some(cwd) = &spec.cwd {
                builder.current_dir(cwd);
            }
        }
        match builder.spawn() {
            Ok(child) => children.push(ManagedChild {
                name: spec.name.clone(),
                node: spec.node.clone(),
                roles: spec.roles.clone(),
                started: Instant::now(),
                allow_failure: spec.allow_failure,
                child,
            }),
            Err(error) => {
                terminate(&mut children, &mut capture);
                return Err(format!("cannot start process `{}`: {error}", spec.name));
            }
        }
        if spec.startup_delay_ms > 0 {
            std::thread::sleep(Duration::from_millis(spec.startup_delay_ms));
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
                Some(status) => results.push(serde_json::json!({"name":process.name,"node":process.node,"roles":process.roles,"success":status.success(),"code":status.code(),"allowed_failure":process.allow_failure,"duration_ms":process.started.elapsed().as_millis()})),
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
    let nodes = std::iter::once("local")
        .chain(scenario.nodes.iter().map(|node| node.name.as_str()))
        .collect::<Vec<_>>();
    let report = serde_json::json!({"passed":failed==0,"nodes":nodes,"links":scenario.links,"processes":results,"capture":scenario.capture.as_ref().map(|value| &value.output)});
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
        assert_eq!(plan["processes"][0]["command"][0], "unshare");
        assert_eq!(plan["capture"][0], "tcpdump");
    }
    #[test]
    fn rejects_duplicate_process_names() {
        let value =
            r#"{"processes":[{"name":"x","command":["true"]},{"name":"x","command":["true"]}]}"#;
        let scenario: Scenario = serde_json::from_str(value).unwrap();
        assert!(scenario.validate().unwrap_err().contains("duplicate"));
    }

    #[test]
    fn plans_remote_nodes_roles_links_and_start_order() {
        let value = r#"{
          "nodes":[{"name":"edge","executor":"ssh","host":"lab.example","user":"runner","port":2222}],
          "links":[{"from":"local","to":"edge","latency_ms":25,"loss_rate":0.01,"bandwidth_bps":1000000}],
          "processes":[
            {"name":"server","node":"edge","roles":["server"],"command":["tcpform","run","server.tcpf"],"cwd":"/srv/lab","env":{"MODE":"test"}},
            {"name":"client","roles":["client"],"start_after":["server"],"command":["tcpform","run","client.tcpf"]}
          ]
        }"#;
        let scenario: Scenario = serde_json::from_str(value).unwrap();
        scenario.validate().unwrap();
        let plan = scenario.plan();
        assert_eq!(
            plan["startup_order"],
            serde_json::json!(["server", "client"])
        );
        assert_eq!(plan["processes"][0]["command"][0], "ssh");
        assert_eq!(plan["processes"][0]["command"][2], "2222");
        let remote = plan["processes"][0]["command"]
            .as_array()
            .unwrap()
            .last()
            .unwrap()
            .as_str()
            .unwrap();
        assert!(remote.contains("TCPFORM_NODE='edge'"));
        assert!(remote.contains("cd '/srv/lab' &&"));
        assert_eq!(plan["links"][0]["latency_ms"], 25);
    }

    #[test]
    fn rejects_start_cycles_and_duplicate_role_placements() {
        let cycle = r#"{"processes":[{"name":"a","command":["true"],"start_after":["b"]},{"name":"b","command":["true"],"start_after":["a"]}]}"#;
        let scenario: Scenario = serde_json::from_str(cycle).unwrap();
        assert!(scenario.validate().unwrap_err().contains("cycle"));
        let duplicate = r#"{"processes":[{"name":"a","command":["true"],"roles":["peer"]},{"name":"b","command":["true"],"roles":["peer"]}]}"#;
        let scenario: Scenario = serde_json::from_str(duplicate).unwrap();
        assert!(scenario
            .validate()
            .unwrap_err()
            .contains("assigned more than once"));
    }
}
