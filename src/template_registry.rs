//! Pinned and signed external template registry support.

use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs;
use std::path::{Component, Path, PathBuf};
use std::process::Command;

pub const DEFAULT_REGISTRY: &str = ".tcpform/template-registry.json";
pub const DEFAULT_LOCK: &str = ".tcpform/templates.lock.json";

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Registry {
    pub schema_version: String,
    #[serde(default)]
    pub trusted_owners: Vec<String>,
    #[serde(default)]
    pub templates: Vec<RegistryEntry>,
}

#[derive(Debug, Clone, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct RegistryEntry {
    pub name: String,
    pub version: String,
    pub repository: String,
    pub revision: String,
    pub path: String,
    pub sha256: String,
    pub signature_hex: String,
    pub public_key_hex: String,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct LockFile {
    pub schema_version: String,
    pub templates: Vec<LockedTemplate>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct LockedTemplate {
    #[serde(flatten)]
    pub entry: RegistryEntry,
    pub cache: String,
}

pub fn read_registry(path: &Path) -> Result<Registry, String> {
    let registry: Registry = serde_json::from_str(
        &fs::read_to_string(path)
            .map_err(|error| format!("cannot read registry {}: {error}", path.display()))?,
    )
    .map_err(|error| format!("invalid registry {}: {error}", path.display()))?;
    if registry.schema_version != "1.0" {
        return Err(format!(
            "unsupported template registry schema `{}`",
            registry.schema_version
        ));
    }
    Ok(registry)
}

pub fn search(registry: &Registry, query: &str) -> Vec<RegistryEntry> {
    let query = query.to_ascii_lowercase();
    registry
        .templates
        .iter()
        .filter(|entry| {
            entry.name.to_ascii_lowercase().contains(&query)
                || entry.version.to_ascii_lowercase().contains(&query)
        })
        .cloned()
        .collect()
}

pub fn add(root: &Path, registry_path: &Path, name: &str) -> Result<LockedTemplate, String> {
    let registry = read_registry(registry_path)?;
    let entry = registry
        .templates
        .iter()
        .find(|entry| entry.name == name)
        .cloned()
        .ok_or_else(|| format!("template `{name}` not found in {}", registry_path.display()))?;
    validate_entry(&entry, &registry.trusted_owners)?;
    let temporary = std::env::temp_dir().join(format!(
        "tcpform-template-{}-{}",
        std::process::id(),
        &entry.sha256[..12]
    ));
    if temporary.exists() {
        fs::remove_dir_all(&temporary).map_err(|error| error.to_string())?;
    }
    run_git(
        &[
            "clone",
            "--quiet",
            "--no-checkout",
            "--filter=blob:none",
            &entry.repository,
        ],
        None,
        Some(&temporary),
    )?;
    run_git(
        &["checkout", "--quiet", "--detach", &entry.revision],
        Some(&temporary),
        None,
    )?;
    let actual_revision = git_output(&["rev-parse", "HEAD"], &temporary)?;
    if actual_revision != entry.revision.to_ascii_lowercase() {
        let _ = fs::remove_dir_all(&temporary);
        return Err("repository did not resolve to the pinned revision".into());
    }
    let relative = safe_relative_path(&entry.path)?;
    let bytes = fs::read(temporary.join(relative))
        .map_err(|error| format!("cannot read template `{}`: {error}", entry.path))?;
    verify(&entry, &bytes)?;
    let cache_relative = PathBuf::from(".tcpform/templates").join(format!("{}.tcpf", entry.sha256));
    let cache = root.join(&cache_relative);
    if let Some(parent) = cache.parent() {
        fs::create_dir_all(parent).map_err(|error| error.to_string())?;
    }
    fs::write(&cache, &bytes)
        .map_err(|error| format!("cannot write {}: {error}", cache.display()))?;
    let locked = LockedTemplate {
        entry,
        cache: cache_relative.to_string_lossy().replace('\\', "/"),
    };
    write_lock(root, locked.clone())?;
    let _ = fs::remove_dir_all(temporary);
    Ok(locked)
}

pub fn load_locked(root: &Path, name: &str) -> Result<String, String> {
    let path = root.join(DEFAULT_LOCK);
    let lock: LockFile = serde_json::from_str(&fs::read_to_string(&path).map_err(|error| {
        format!(
            "cannot read template lock {}: {error}; run `tcpform template add {name}`",
            path.display()
        )
    })?)
    .map_err(|error| format!("invalid template lock {}: {error}", path.display()))?;
    if lock.schema_version != "1.0" {
        return Err(format!(
            "unsupported template lock schema `{}`",
            lock.schema_version
        ));
    }
    let locked = lock
        .templates
        .iter()
        .find(|item| item.entry.name == name)
        .ok_or_else(|| {
            format!("template `{name}` is not locked; run `tcpform template add {name}`")
        })?;
    let registry = read_registry(&root.join(DEFAULT_REGISTRY))?;
    validate_entry(&locked.entry, &registry.trusted_owners)?;
    if !registry
        .templates
        .iter()
        .any(|entry| entry == &locked.entry)
    {
        return Err(format!(
            "locked template `{name}` does not match the trusted registry; run `tcpform template add {name}`"
        ));
    }
    let cache = safe_relative_path(&locked.cache)?;
    let bytes = fs::read(root.join(cache))
        .map_err(|error| format!("cannot read cached template `{name}`: {error}"))?;
    verify(&locked.entry, &bytes)?;
    String::from_utf8(bytes).map_err(|_| format!("template `{name}` is not UTF-8"))
}

fn validate_entry(entry: &RegistryEntry, trusted: &[String]) -> Result<(), String> {
    let owner = entry
        .name
        .split_once('/')
        .map(|value| value.0)
        .ok_or_else(|| "external template names must use `owner/name`".to_string())?;
    if !trusted.iter().any(|candidate| candidate == owner) {
        return Err(format!(
            "template owner `{owner}` is not trusted by this registry"
        ));
    }
    if entry.version.trim().is_empty() {
        return Err("template version must be pinned".into());
    }
    if entry.revision.len() != 40 || !entry.revision.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err("template revision must be a full 40-character Git commit".into());
    }
    if entry.sha256.len() != 64 || !entry.sha256.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err("template SHA256 must contain 64 hexadecimal characters".into());
    }
    safe_relative_path(&entry.path)?;
    Ok(())
}

fn verify(entry: &RegistryEntry, bytes: &[u8]) -> Result<(), String> {
    let actual = crate::bytes_to_hex(&Sha256::digest(bytes));
    if actual != entry.sha256.to_ascii_lowercase() {
        return Err(format!("SHA256 mismatch for `{}`", entry.name));
    }
    let key: [u8; 32] = hex(&entry.public_key_hex)?
        .try_into()
        .map_err(|_| "Ed25519 public key must be 32 bytes".to_string())?;
    let signature: [u8; 64] = hex(&entry.signature_hex)?
        .try_into()
        .map_err(|_| "Ed25519 signature must be 64 bytes".to_string())?;
    VerifyingKey::from_bytes(&key)
        .map_err(|error| error.to_string())?
        .verify(bytes, &Signature::from_bytes(&signature))
        .map_err(|_| format!("signature verification failed for `{}`", entry.name))
}

fn write_lock(root: &Path, locked: LockedTemplate) -> Result<(), String> {
    let path = root.join(DEFAULT_LOCK);
    let mut lock = if path.exists() {
        serde_json::from_str::<LockFile>(
            &fs::read_to_string(&path).map_err(|error| error.to_string())?,
        )
        .map_err(|error| format!("invalid template lock {}: {error}", path.display()))?
    } else {
        LockFile {
            schema_version: "1.0".into(),
            templates: Vec::new(),
        }
    };
    lock.templates
        .retain(|item| item.entry.name != locked.entry.name);
    lock.templates.push(locked);
    lock.templates
        .sort_by(|left, right| left.entry.name.cmp(&right.entry.name));
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|error| error.to_string())?;
    }
    fs::write(
        &path,
        format!("{}\n", serde_json::to_string_pretty(&lock).unwrap()),
    )
    .map_err(|error| format!("cannot write {}: {error}", path.display()))
}

fn safe_relative_path(value: &str) -> Result<PathBuf, String> {
    let path = Path::new(value);
    if path.as_os_str().is_empty()
        || path.is_absolute()
        || path
            .components()
            .any(|part| !matches!(part, Component::Normal(_)))
    {
        return Err(format!("unsafe template path `{value}`"));
    }
    Ok(path.to_path_buf())
}

fn hex(value: &str) -> Result<Vec<u8>, String> {
    crate::parse_hex(value).map_err(|error| error.to_string())
}

fn run_git(args: &[&str], cwd: Option<&Path>, destination: Option<&Path>) -> Result<(), String> {
    let mut command = Command::new("git");
    command.args(args);
    if let Some(path) = destination {
        command.arg(path);
    }
    if let Some(path) = cwd {
        command.current_dir(path);
    }
    let output = command
        .output()
        .map_err(|error| format!("cannot run git: {error}"))?;
    if output.status.success() {
        Ok(())
    } else {
        Err(format!(
            "git failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        ))
    }
}

fn git_output(args: &[&str], cwd: &Path) -> Result<String, String> {
    let output = Command::new("git")
        .args(args)
        .current_dir(cwd)
        .output()
        .map_err(|error| error.to_string())?;
    if !output.status.success() {
        return Err(String::from_utf8_lossy(&output.stderr).trim().to_string());
    }
    Ok(String::from_utf8_lossy(&output.stdout)
        .trim()
        .to_ascii_lowercase())
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};
    use std::time::{SystemTime, UNIX_EPOCH};

    fn git(args: &[&str], cwd: &Path) {
        assert!(Command::new("git")
            .args(args)
            .current_dir(cwd)
            .status()
            .unwrap()
            .success());
    }

    #[test]
    fn signed_pinned_template_is_cached_locked_and_reverified() {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let base = std::env::temp_dir().join(format!("tcpform-template-registry-{unique}"));
        let repository = base.join("repository");
        let project = base.join("project");
        fs::create_dir_all(&repository).unwrap();
        fs::create_dir_all(&project).unwrap();
        let source = b"tcpform { dsl_version=2 }\nprotocol \"{{name}}\" { step \"send\" { role=\"client\" action=\"send\" } }\n";
        fs::write(repository.join("template.tcpf"), source).unwrap();
        git(&["init", "--quiet"], &repository);
        git(&["config", "user.name", "tcpform test"], &repository);
        git(
            &["config", "user.email", "test@example.invalid"],
            &repository,
        );
        git(&["add", "template.tcpf"], &repository);
        git(&["commit", "--quiet", "-m", "template"], &repository);
        let revision = git_output(&["rev-parse", "HEAD"], &repository).unwrap();
        let signing = SigningKey::from_bytes(&[9u8; 32]);
        let registry = json_document(&repository, source, &revision, &signing);
        let registry_path = project.join(DEFAULT_REGISTRY);
        fs::create_dir_all(registry_path.parent().unwrap()).unwrap();
        fs::write(
            &registry_path,
            serde_json::to_string_pretty(&registry).unwrap(),
        )
        .unwrap();
        let locked = add(&project, &registry_path, "owner/mqtt").unwrap();
        assert_eq!(locked.entry.revision, revision);
        assert!(project.join(DEFAULT_LOCK).exists());
        assert_eq!(
            search(&read_registry(&registry_path).unwrap(), "MQTT").len(),
            1
        );
        let loaded = load_locked(&project, "owner/mqtt").unwrap();
        assert!(loaded.contains("{{name}}"));
        let generated = base.join("generated");
        crate::templates::init_project_with_source(
            &generated,
            "broker-test",
            "owner/mqtt",
            &loaded,
            false,
        )
        .unwrap();
        assert!(fs::read_to_string(generated.join("protocol.tcpf"))
            .unwrap()
            .contains("protocol \"broker_test\""));
        fs::write(project.join(&locked.cache), b"tampered").unwrap();
        assert!(load_locked(&project, "owner/mqtt")
            .unwrap_err()
            .contains("SHA256"));
        fs::remove_dir_all(base).unwrap();
    }

    fn json_document(
        repository: &Path,
        source: &[u8],
        revision: &str,
        signing: &SigningKey,
    ) -> serde_json::Value {
        let signature = signing.sign(source);
        serde_json::json!({
            "schema_version":"1.0",
            "trusted_owners":["owner"],
            "templates":[{
                "name":"owner/mqtt", "version":"1.2.3",
                "repository":repository, "revision":revision, "path":"template.tcpf",
                "sha256":crate::bytes_to_hex(&Sha256::digest(source)),
                "signature_hex":crate::bytes_to_hex(&signature.to_bytes()),
                "public_key_hex":crate::bytes_to_hex(&signing.verifying_key().to_bytes())
            }]
        })
    }

    #[test]
    fn untrusted_owners_and_unsafe_paths_are_rejected() {
        let entry = RegistryEntry {
            name: "stranger/demo".into(),
            version: "1".into(),
            repository: "repo".into(),
            revision: "0".repeat(40),
            path: "../template.tcpf".into(),
            sha256: "0".repeat(64),
            signature_hex: String::new(),
            public_key_hex: String::new(),
        };
        assert!(validate_entry(&entry, &["owner".into()]).is_err());
        let mut trusted = entry;
        trusted.name = "owner/demo".into();
        assert!(validate_entry(&trusted, &["owner".into()])
            .unwrap_err()
            .contains("unsafe"));
    }
}
