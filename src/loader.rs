//! Recursive `.tcpf` loader with relative imports and cycle detection.

use crate::ast::Block;
use crate::parser::parse_file_named;
use std::collections::HashMap;
use std::collections::HashSet;
use std::fs;
use std::path::{Path, PathBuf};

/// Load and parse a file plus all of its `import "..."` dependencies.
/// Import paths are resolved relative to the importing file and each
/// canonical file is included once.
pub fn load_blocks(path: impl AsRef<Path>) -> Result<Vec<Block>, String> {
    let mut loaded = HashSet::new();
    let mut stack = Vec::new();
    load_recursive(path.as_ref(), &mut loaded, &mut stack, "root")
}

/// Load a browser-provided bundle without writing it to disk. Paths use `/`
/// separators, must be relative, and imports are resolved relative to the
/// importing source exactly like filesystem imports.
pub fn load_blocks_from_sources(
    root: &str,
    sources: &HashMap<String, String>,
) -> Result<Vec<Block>, String> {
    let normalized = sources
        .iter()
        .map(|(path, source)| Ok((normalize_virtual_path("", path)?, source.clone())))
        .collect::<Result<HashMap<_, _>, String>>()?;
    let root = normalize_virtual_path("", root)?;
    let mut loaded = HashSet::new();
    let mut stack = Vec::new();
    load_virtual_recursive(&root, &normalized, &mut loaded, &mut stack, "root")
}

fn normalize_virtual_path(base: &str, path: &str) -> Result<String, String> {
    let joined = if base.is_empty() {
        path.to_string()
    } else {
        format!("{base}/{path}")
    };
    let normalized = joined.replace('\\', "/");
    let mut parts = Vec::new();
    for part in normalized.split('/') {
        match part {
            "" | "." => {}
            ".." => {
                if parts.pop().is_none() {
                    return Err(format!("import path escapes bundle: `{path}`"));
                }
            }
            value if value.contains(':') => return Err(format!("invalid bundle path `{path}`")),
            value => parts.push(value),
        }
    }
    if parts.is_empty() {
        Err("bundle path must not be empty".to_string())
    } else {
        Ok(parts.join("/"))
    }
}

fn load_virtual_recursive(
    path: &str,
    sources: &HashMap<String, String>,
    loaded: &mut HashSet<(String, String)>,
    stack: &mut Vec<String>,
    instance: &str,
) -> Result<Vec<Block>, String> {
    if let Some(start) = stack.iter().position(|item| item == path) {
        let mut cycle = stack[start..].to_vec();
        cycle.push(path.to_string());
        return Err(format!("import cycle: {}", cycle.join(" -> ")));
    }
    if !loaded.insert((path.to_string(), instance.to_string())) {
        return Ok(Vec::new());
    }
    let source = sources
        .get(path)
        .ok_or_else(|| format!("import `{path}` is not present in uploaded bundle"))?;
    let blocks = parse_file_named(source, Some(path)).map_err(|error| error.to_string())?;
    stack.push(path.to_string());
    let base = path.rsplit_once('/').map_or("", |(base, _)| base);
    let result = expand_virtual_imports(blocks, base, sources, loaded, stack, path);
    stack.pop();
    result
}

fn expand_virtual_imports(
    blocks: Vec<Block>,
    base: &str,
    sources: &HashMap<String, String>,
    loaded: &mut HashSet<(String, String)>,
    stack: &mut Vec<String>,
    source: &str,
) -> Result<Vec<Block>, String> {
    let mut out = Vec::new();
    for mut block in blocks {
        if block.name == "import" {
            let imported = block
                .labels
                .first()
                .ok_or_else(|| format!("{source}: import needs a path"))?;
            for key in block.attributes.keys() {
                if !matches!(key.as_str(), "as" | "only") {
                    return Err(format!("{source}: unknown import attribute `{key}`"));
                }
            }
            let only = import_only(&block, source)?;
            let alias = block
                .attributes
                .get("as")
                .and_then(ValueExt::string)
                .map(str::to_string)
                .or_else(|| block.labels.get(1).cloned());
            let instance = import_instance(alias.as_deref(), only.as_ref());
            let target = normalize_virtual_path(base, imported)?;
            let mut imported_blocks =
                load_virtual_recursive(&target, sources, loaded, stack, &instance)?;
            if let Some(only) = &only {
                imported_blocks.retain(|candidate| {
                    !matches!(candidate.name.as_str(), "protocol" | "cases")
                        || candidate
                            .labels
                            .first()
                            .is_some_and(|name| only.contains(name))
                });
            }
            if let Some(alias) = alias {
                if alias.is_empty() {
                    return Err(format!("{source}: import alias must not be empty"));
                }
                imported_blocks = vec![Block {
                    name: "module".into(),
                    labels: vec![alias],
                    attributes: Default::default(),
                    blocks: imported_blocks,
                    source: Some(source.into()),
                    line: block.line,
                    column: block.column,
                }];
            }
            out.extend(imported_blocks);
        } else {
            block.blocks =
                expand_virtual_imports(block.blocks, base, sources, loaded, stack, source)?;
            out.push(block);
        }
    }
    Ok(out)
}

trait ValueExt {
    fn string(&self) -> Option<&str>;
}
impl ValueExt for crate::Value {
    fn string(&self) -> Option<&str> {
        self.as_str()
    }
}

fn import_only(block: &Block, source: &str) -> Result<Option<HashSet<String>>, String> {
    match block.attributes.get("only") {
        None => Ok(None),
        Some(crate::Value::Array(values)) => values
            .iter()
            .map(|value| {
                value
                    .as_str()
                    .map(str::to_string)
                    .ok_or_else(|| format!("{source}: import only must contain strings"))
            })
            .collect::<Result<HashSet<_>, _>>()
            .map(Some),
        Some(_) => Err(format!("{source}: import only must be an array of strings")),
    }
}
fn import_instance(alias: Option<&str>, only: Option<&HashSet<String>>) -> String {
    let mut names = only
        .map(|items| items.iter().cloned().collect::<Vec<_>>())
        .unwrap_or_default();
    names.sort();
    format!("alias={};only={}", alias.unwrap_or(""), names.join(","))
}

fn load_recursive(
    path: &Path,
    loaded: &mut HashSet<(PathBuf, String)>,
    stack: &mut Vec<PathBuf>,
    instance: &str,
) -> Result<Vec<Block>, String> {
    let canonical = path
        .canonicalize()
        .map_err(|e| format!("cannot resolve {}: {e}", path.display()))?;
    if let Some(start) = stack.iter().position(|p| p == &canonical) {
        let mut cycle: Vec<String> = stack[start..]
            .iter()
            .map(|p| p.display().to_string())
            .collect();
        cycle.push(canonical.display().to_string());
        return Err(format!("import cycle: {}", cycle.join(" -> ")));
    }
    if !loaded.insert((canonical.clone(), instance.to_string())) {
        return Ok(Vec::new());
    }

    let src = fs::read_to_string(&canonical)
        .map_err(|e| format!("cannot read {}: {e}", canonical.display()))?;
    let source_name = canonical.display().to_string();
    let blocks = parse_file_named(&src, Some(&source_name)).map_err(|e| e.to_string())?;
    stack.push(canonical.clone());
    let base = canonical.parent().unwrap_or_else(|| Path::new("."));
    let out = expand_imports(blocks, base, loaded, stack, &canonical)?;
    stack.pop();
    Ok(out)
}

fn expand_imports(
    blocks: Vec<Block>,
    base: &Path,
    loaded: &mut HashSet<(PathBuf, String)>,
    stack: &mut Vec<PathBuf>,
    source: &Path,
) -> Result<Vec<Block>, String> {
    let mut out = Vec::new();
    for mut block in blocks {
        if block.name == "import" {
            let imported = block
                .labels
                .first()
                .ok_or_else(|| format!("{}: import needs a path", source.display()))?;
            for key in block.attributes.keys() {
                if !matches!(key.as_str(), "as" | "only") {
                    return Err(format!(
                        "{}: unknown import attribute `{key}`",
                        source.display()
                    ));
                }
            }
            let only = match block.attributes.get("only") {
                None => None,
                Some(crate::Value::Array(values)) => {
                    let mut names = HashSet::new();
                    for value in values {
                        let name = value.as_str().ok_or_else(|| {
                            format!("{}: import only must contain strings", source.display())
                        })?;
                        names.insert(name.to_string());
                    }
                    Some(names)
                }
                Some(_) => {
                    return Err(format!(
                        "{}: import only must be an array of strings",
                        source.display()
                    ))
                }
            };
            let alias = block
                .attributes
                .get("as")
                .and_then(|value| value.as_str())
                .map(str::to_string)
                .or_else(|| block.labels.get(1).cloned());
            let instance = format!(
                "alias={};only={}",
                alias.as_deref().unwrap_or(""),
                only.as_ref()
                    .map(|names| {
                        let mut names: Vec<_> = names.iter().cloned().collect();
                        names.sort();
                        names.join(",")
                    })
                    .unwrap_or_default()
            );
            let mut imported_blocks =
                load_recursive(&base.join(imported), loaded, stack, &instance)?;
            if let Some(only) = &only {
                imported_blocks.retain(|candidate| {
                    !matches!(candidate.name.as_str(), "protocol" | "cases")
                        || candidate
                            .labels
                            .first()
                            .is_some_and(|name| only.contains(name))
                });
            }
            if let Some(alias) = alias {
                if alias.is_empty() {
                    return Err(format!(
                        "{}: import alias must not be empty",
                        source.display()
                    ));
                }
                imported_blocks = vec![Block {
                    name: "module".to_string(),
                    labels: vec![alias],
                    attributes: Default::default(),
                    blocks: imported_blocks,
                    source: Some(source.display().to_string()),
                    line: block.line,
                    column: block.column,
                }];
            }
            out.extend(imported_blocks);
        } else {
            block.blocks = expand_imports(block.blocks, base, loaded, stack, source)?;
            out.push(block);
        }
    }
    Ok(out)
}
