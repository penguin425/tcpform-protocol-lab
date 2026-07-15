//! Project and host diagnostics used by `tcpform doctor`.

use crate::platform::PluginLock;
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum CheckStatus {
    Pass,
    Warn,
    Fail,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DoctorCheck {
    pub name: String,
    pub status: CheckStatus,
    pub message: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DoctorReport {
    pub schema_version: String,
    pub tcpform_version: String,
    pub dsl_version: u32,
    pub project: String,
    pub checks: Vec<DoctorCheck>,
}

impl DoctorReport {
    pub fn healthy(&self) -> bool {
        !self
            .checks
            .iter()
            .any(|check| check.status == CheckStatus::Fail)
    }
}

pub fn diagnose(project: &Path) -> DoctorReport {
    let root = project
        .canonicalize()
        .unwrap_or_else(|_| project.to_path_buf());
    let mut checks = vec![version_check(), raw_socket_check(), docker_check()];
    checks.push(formatter_check(&root));
    let sources = tcpf_files(&root);
    checks.push(import_check(&sources));
    checks.push(plugin_signature_check(&root, &sources));
    checks.push(github_actions_check(&root));
    DoctorReport {
        schema_version: "1.0".into(),
        tcpform_version: env!("CARGO_PKG_VERSION").into(),
        dsl_version: crate::compat::DSL_VERSION,
        project: root.display().to_string(),
        checks,
    }
}

fn check(name: &str, status: CheckStatus, message: impl Into<String>) -> DoctorCheck {
    DoctorCheck {
        name: name.into(),
        status,
        message: message.into(),
    }
}

fn version_check() -> DoctorCheck {
    check(
        "version",
        CheckStatus::Pass,
        format!(
            "tcpform {}, DSL v{}",
            env!("CARGO_PKG_VERSION"),
            crate::compat::DSL_VERSION
        ),
    )
}

#[cfg(target_os = "linux")]
fn raw_socket_check() -> DoctorCheck {
    let effective = fs::read_to_string("/proc/self/status")
        .ok()
        .and_then(|status| {
            status
                .lines()
                .find_map(|line| line.strip_prefix("CapEff:\t"))
                .and_then(|value| u64::from_str_radix(value.trim(), 16).ok())
        });
    let has_cap_net_raw = effective.is_some_and(|caps| caps & (1 << 13) != 0);
    // SAFETY: geteuid has no arguments and cannot invalidate memory.
    let root = unsafe { libc::geteuid() == 0 };
    if root || has_cap_net_raw {
        check(
            "raw_socket",
            CheckStatus::Pass,
            if root {
                "available through effective root privileges"
            } else {
                "CAP_NET_RAW is effective"
            },
        )
    } else {
        check(
            "raw_socket",
            CheckStatus::Warn,
            "unavailable; run as root or grant CAP_NET_RAW when raw mode is needed",
        )
    }
}

#[cfg(not(target_os = "linux"))]
fn raw_socket_check() -> DoctorCheck {
    check(
        "raw_socket",
        CheckStatus::Warn,
        "raw socket mode is supported only on Linux",
    )
}

fn command_works(program: &str, args: &[&str]) -> bool {
    Command::new(program)
        .args(args)
        .output()
        .is_ok_and(|output| output.status.success())
}

fn docker_check() -> DoctorCheck {
    if !command_works("docker", &["version", "--format", "{{.Server.Version}}"]) {
        return check(
            "docker",
            CheckStatus::Warn,
            "Docker Engine is unavailable or the daemon is not reachable",
        );
    }
    if !command_works("docker", &["compose", "version"]) {
        return check(
            "docker",
            CheckStatus::Warn,
            "Docker Engine is available, but Compose v2 is unavailable",
        );
    }
    check(
        "docker",
        CheckStatus::Pass,
        "Docker Engine and Compose v2 are available",
    )
}

fn formatter_check(root: &Path) -> DoctorCheck {
    let path = root.join(".tcpformfmt.json");
    if !path.exists() {
        return check(
            "formatter",
            CheckStatus::Warn,
            ".tcpformfmt.json was not found; formatter defaults will be used",
        );
    }
    match fs::read_to_string(&path)
        .map_err(|error| error.to_string())
        .and_then(|source| {
            serde_json::from_str::<crate::tooling::FormatOptions>(&source)
                .map_err(|error| error.to_string())
        }) {
        Ok(_) => check(
            "formatter",
            CheckStatus::Pass,
            format!("valid configuration at {}", path.display()),
        ),
        Err(error) => check(
            "formatter",
            CheckStatus::Fail,
            format!("invalid {}: {error}", path.display()),
        ),
    }
}

fn tcpf_files(root: &Path) -> Vec<PathBuf> {
    let mut found = Vec::new();
    visit(root, &mut found);
    found.sort();
    found
}

fn visit(path: &Path, found: &mut Vec<PathBuf>) {
    if path.is_file() {
        if path.extension().and_then(|value| value.to_str()) == Some("tcpf") {
            found.push(path.to_path_buf());
        }
        return;
    }
    let Ok(entries) = fs::read_dir(path) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir()
            && matches!(
                path.file_name().and_then(|value| value.to_str()),
                Some(".git" | "target" | "node_modules")
            )
        {
            continue;
        }
        visit(&path, found);
    }
}

fn import_check(files: &[PathBuf]) -> DoctorCheck {
    if files.is_empty() {
        return check("imports", CheckStatus::Warn, "no .tcpf files were found");
    }
    let errors = files
        .iter()
        .filter_map(|path| {
            crate::load_blocks(path)
                .err()
                .map(|error| format!("{}: {error}", path.display()))
        })
        .collect::<Vec<_>>();
    if errors.is_empty() {
        check(
            "imports",
            CheckStatus::Pass,
            format!("{} DSL file(s) and their imports resolved", files.len()),
        )
    } else {
        check("imports", CheckStatus::Fail, errors.join("; "))
    }
}

#[derive(Deserialize)]
#[serde(untagged)]
enum PluginLocks {
    List(Vec<PluginLock>),
    Object { plugins: Vec<PluginLock> },
}

fn plugin_signature_check(root: &Path, files: &[PathBuf]) -> DoctorCheck {
    let plugin_used = files.iter().any(|path| {
        fs::read_to_string(path).is_ok_and(|source| {
            source.contains("action = \"plugin\"") || source.contains("action=\"plugin\"")
        })
    });
    let path = root.join(".tcpform/plugins.lock.json");
    if !path.exists() {
        return if plugin_used {
            check(
                "plugin_signatures",
                CheckStatus::Warn,
                "plugins are referenced but .tcpform/plugins.lock.json was not found",
            )
        } else {
            check(
                "plugin_signatures",
                CheckStatus::Pass,
                "no plugins are referenced",
            )
        };
    }
    let parsed = fs::read_to_string(&path)
        .map_err(|error| error.to_string())
        .and_then(|source| {
            serde_json::from_str::<PluginLocks>(&source).map_err(|error| error.to_string())
        });
    let locks = match parsed {
        Ok(PluginLocks::List(locks) | PluginLocks::Object { plugins: locks }) => locks,
        Err(error) => {
            return check(
                "plugin_signatures",
                CheckStatus::Fail,
                format!("invalid {}: {error}", path.display()),
            )
        }
    };
    if locks.is_empty() {
        return check(
            "plugin_signatures",
            CheckStatus::Warn,
            "plugin lock file contains no entries",
        );
    }
    let incomplete = locks
        .iter()
        .filter(|lock| lock.signature_hex.is_empty() || lock.public_key_hex.is_empty())
        .map(|lock| lock.id.as_str())
        .collect::<Vec<_>>();
    let malformed = locks
        .iter()
        .filter(|lock| {
            if lock.signature_hex.is_empty() || lock.public_key_hex.is_empty() {
                return false;
            }
            crate::parse_hex(&lock.signature_hex).map_or(true, |value| value.len() != 64)
                || crate::parse_hex(&lock.public_key_hex).map_or(true, |value| value.len() != 32)
        })
        .map(|lock| lock.id.as_str())
        .collect::<Vec<_>>();
    if !malformed.is_empty() {
        return check(
            "plugin_signatures",
            CheckStatus::Fail,
            format!(
                "malformed plugin signature or public key: {}",
                malformed.join(", ")
            ),
        );
    }
    if incomplete.is_empty() {
        check(
            "plugin_signatures",
            CheckStatus::Pass,
            format!(
                "{} plugin lock(s) include signatures and public keys",
                locks.len()
            ),
        )
    } else {
        check(
            "plugin_signatures",
            CheckStatus::Warn,
            format!(
                "unsigned or incomplete plugin lock(s): {}",
                incomplete.join(", ")
            ),
        )
    }
}

fn github_actions_check(root: &Path) -> DoctorCheck {
    let directory = root.join(".github/workflows");
    let workflows = fs::read_dir(&directory)
        .ok()
        .into_iter()
        .flatten()
        .flatten()
        .filter(|entry| {
            matches!(
                entry.path().extension().and_then(|value| value.to_str()),
                Some("yml" | "yaml")
            )
        })
        .filter_map(|entry| fs::read_to_string(entry.path()).ok())
        .collect::<Vec<_>>();
    if workflows.is_empty() {
        return check(
            "github_actions",
            CheckStatus::Warn,
            "no GitHub Actions workflow was found",
        );
    }
    if workflows
        .iter()
        .any(|workflow| workflow.contains("tcpform"))
    {
        check(
            "github_actions",
            CheckStatus::Pass,
            "a GitHub Actions workflow invokes tcpform",
        )
    } else {
        check(
            "github_actions",
            CheckStatus::Warn,
            "workflows exist, but none invoke tcpform",
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn temporary_project() -> PathBuf {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path = std::env::temp_dir().join(format!("tcpform-doctor-{unique}"));
        fs::create_dir_all(&path).unwrap();
        path
    }

    #[test]
    fn healthy_project_reports_required_checks() {
        let root = temporary_project();
        fs::write(root.join("main.tcpf"), "tcpform { dsl_version = 2 }").unwrap();
        fs::write(root.join(".tcpformfmt.json"), "{\"indent_width\":2}").unwrap();
        fs::create_dir_all(root.join(".github/workflows")).unwrap();
        fs::write(
            root.join(".github/workflows/ci.yml"),
            "run: tcpform validate main.tcpf",
        )
        .unwrap();
        let report = diagnose(&root);
        for name in [
            "version",
            "raw_socket",
            "docker",
            "formatter",
            "imports",
            "plugin_signatures",
            "github_actions",
        ] {
            assert!(report.checks.iter().any(|check| check.name == name));
        }
        assert!(report.healthy());
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn broken_import_is_fatal() {
        let root = temporary_project();
        fs::write(root.join("main.tcpf"), "import \"missing.tcpf\"").unwrap();
        let report = diagnose(&root);
        assert!(!report.healthy());
        assert!(report
            .checks
            .iter()
            .any(|check| check.name == "imports" && check.status == CheckStatus::Fail));
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn malformed_plugin_signatures_are_fatal() {
        let root = temporary_project();
        fs::write(root.join("main.tcpf"), "tcpform { dsl_version = 2 }").unwrap();
        fs::create_dir_all(root.join(".tcpform")).unwrap();
        fs::write(
            root.join(".tcpform/plugins.lock.json"),
            r#"[{"id":"demo","version":"1.0.0","sha256":"00","capabilities":[],"signature_hex":"00","public_key_hex":"00"}]"#,
        )
        .unwrap();
        let report = diagnose(&root);
        assert!(!report.healthy());
        assert!(report.checks.iter().any(|check| {
            check.name == "plugin_signatures" && check.status == CheckStatus::Fail
        }));
        fs::remove_dir_all(root).unwrap();
    }
}
