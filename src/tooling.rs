use serde_json::{json, Value as JsonValue};
use std::collections::HashMap;
use std::io::{BufRead, Write};

#[derive(Debug, Clone, serde::Deserialize)]
#[serde(default)]
pub struct FormatOptions {
    pub indent_width: usize,
    pub align_attributes: bool,
    pub preserve_inline_blocks: bool,
}

impl Default for FormatOptions {
    fn default() -> Self {
        Self {
            indent_width: 2,
            align_attributes: false,
            preserve_inline_blocks: true,
        }
    }
}

pub fn format_dsl(source: &str) -> String {
    format_dsl_with_options(source, &FormatOptions::default())
}

pub fn format_dsl_with_options(source: &str, options: &FormatOptions) -> String {
    let expanded;
    let source = if options.preserve_inline_blocks {
        source
    } else {
        expanded = expand_inline_blocks(source);
        &expanded
    };
    let mut level = 0usize;
    let mut output = Vec::new();
    for raw in source.replace("\r\n", "\n").lines() {
        let trimmed = raw.trim();
        if trimmed.is_empty() {
            if output.last().is_some_and(|line: &String| !line.is_empty()) {
                output.push(String::new());
            }
            continue;
        }
        if trimmed.starts_with('}') {
            level = level.saturating_sub(1);
        }
        let formatted = if trimmed.starts_with('#') || trimmed.starts_with("//") {
            trimmed.to_string()
        } else {
            normalize_equals(trimmed)
        };
        output.push(format!(
            "{}{}",
            " ".repeat(options.indent_width.saturating_mul(level)),
            formatted
        ));
        let (opens, closes) = brace_counts(trimmed);
        if trimmed.starts_with('}') {
            level += opens.saturating_sub(closes.saturating_sub(1));
        } else {
            level += opens.saturating_sub(closes);
        }
    }
    while output.last().is_some_and(String::is_empty) {
        output.pop();
    }
    if options.align_attributes {
        align_attribute_groups(&mut output);
    }
    format!("{}\n", output.join("\n"))
}

pub fn expand_inline_blocks(source: &str) -> String {
    let characters = source.chars().collect::<Vec<_>>();
    let mut output = String::new();
    let mut quoted = false;
    let mut escaped = false;
    let mut square_depth = 0usize;
    let mut curly_depth = 0usize;
    let mut index = 0usize;
    while index < characters.len() {
        let character = characters[index];
        if quoted {
            output.push(character);
            if escaped {
                escaped = false;
            } else if character == '\\' {
                escaped = true;
            } else if character == '"' {
                quoted = false;
            }
            index += 1;
            continue;
        }
        match character {
            '"' => {
                quoted = true;
                output.push(character);
            }
            '[' => {
                square_depth += 1;
                output.push(character);
            }
            ']' => {
                square_depth = square_depth.saturating_sub(1);
                output.push(character);
            }
            '{' => {
                curly_depth += 1;
                output.push('{');
                push_newline(&mut output);
            }
            '}' => {
                curly_depth = curly_depth.saturating_sub(1);
                trim_horizontal(&mut output);
                push_newline(&mut output);
                output.push('}');
                if characters.get(index + 1).is_some_and(|next| *next != '\n') {
                    push_newline(&mut output);
                }
            }
            value if value.is_whitespace() && value != '\n' => {
                let mut next = index + 1;
                while characters
                    .get(next)
                    .is_some_and(|value| value.is_whitespace() && *value != '\n')
                {
                    next += 1;
                }
                if curly_depth > 0
                    && square_depth == 0
                    && looks_like_attribute(&characters, next)
                    && output
                        .rsplit('\n')
                        .next()
                        .is_some_and(|line| line.contains('='))
                {
                    trim_horizontal(&mut output);
                    push_newline(&mut output);
                } else if !output.ends_with([' ', '\n']) {
                    output.push(' ');
                }
                index = next.saturating_sub(1);
            }
            _ => output.push(character),
        }
        index += 1;
    }
    output
}

fn looks_like_attribute(characters: &[char], mut index: usize) -> bool {
    if !characters
        .get(index)
        .is_some_and(|value| value.is_alphabetic() || *value == '_')
    {
        return false;
    }
    index += 1;
    while characters
        .get(index)
        .is_some_and(|value| value.is_alphanumeric() || matches!(value, '_' | '-'))
    {
        index += 1;
    }
    while characters
        .get(index)
        .is_some_and(|value| value.is_whitespace())
    {
        index += 1;
    }
    characters.get(index) == Some(&'=')
}

fn trim_horizontal(output: &mut String) {
    while output.ends_with([' ', '\t']) {
        output.pop();
    }
}

fn push_newline(output: &mut String) {
    if !output.ends_with('\n') {
        output.push('\n');
    }
}

pub fn format_dsl_range(
    source: &str,
    start_line: usize,
    end_line: usize,
    options: &FormatOptions,
) -> String {
    let lines = source.lines().collect::<Vec<_>>();
    if lines.is_empty() || start_line >= lines.len() || start_line > end_line {
        return source.to_string();
    }
    let start = start_line.min(lines.len() - 1);
    let end = end_line.min(lines.len() - 1);
    let fragment = format_dsl_with_options(&lines[start..=end].join("\n"), options);
    let mut result = Vec::new();
    result.extend(lines[..start].iter().copied());
    result.extend(fragment.trim_end_matches('\n').lines());
    result.extend(lines[end + 1..].iter().copied());
    let trailing = source.ends_with('\n');
    format!("{}{}", result.join("\n"), if trailing { "\n" } else { "" })
}

fn align_attribute_groups(lines: &mut [String]) {
    let mut start = 0;
    while start < lines.len() {
        let indent = lines[start].len() - lines[start].trim_start().len();
        let eligible = |line: &str| {
            line.len() - line.trim_start().len() == indent
                && unquoted_equals(line).len() == 1
                && !line.contains('{')
                && !line.trim_start().starts_with(['#', '/'])
        };
        if !eligible(&lines[start]) {
            start += 1;
            continue;
        }
        let mut end = start + 1;
        while end < lines.len() && eligible(&lines[end]) {
            end += 1;
        }
        let column = lines[start..end]
            .iter()
            .filter_map(|line| unquoted_equals(line).first().copied())
            .max()
            .unwrap_or(0);
        for line in &mut lines[start..end] {
            if let Some(index) = unquoted_equals(line).first().copied() {
                if index < column {
                    line.insert_str(index, &" ".repeat(column - index));
                }
            }
        }
        start = end;
    }
}

fn unquoted_equals(line: &str) -> Vec<usize> {
    let mut quoted = false;
    let mut escaped = false;
    let mut positions = Vec::new();
    for (index, character) in line.char_indices() {
        if quoted {
            if escaped {
                escaped = false;
            } else if character == '\\' {
                escaped = true;
            } else if character == '"' {
                quoted = false;
            }
        } else if character == '"' {
            quoted = true;
        } else if character == '=' {
            positions.push(index);
        }
    }
    positions
}

fn normalize_equals(line: &str) -> String {
    let mut out = String::new();
    let mut chars = line.chars().peekable();
    let mut quoted = false;
    let mut escaped = false;
    while let Some(character) = chars.next() {
        if quoted {
            out.push(character);
            if escaped {
                escaped = false;
            } else if character == '\\' {
                escaped = true;
            } else if character == '"' {
                quoted = false;
            }
            continue;
        }
        if character == '"' {
            quoted = true;
            out.push(character);
        } else if character == '=' {
            while out.ends_with([' ', '\t']) {
                out.pop();
            }
            out.push_str(" = ");
            while chars.peek().is_some_and(|next| next.is_whitespace()) {
                chars.next();
            }
        } else {
            out.push(character);
        }
    }
    out
}

fn brace_counts(line: &str) -> (usize, usize) {
    let mut quoted = false;
    let mut escaped = false;
    let mut opens = 0;
    let mut closes = 0;
    for character in line.chars() {
        if quoted {
            if escaped {
                escaped = false;
            } else if character == '\\' {
                escaped = true;
            } else if character == '"' {
                quoted = false;
            }
        } else if character == '"' {
            quoted = true;
        } else if character == '{' {
            opens += 1;
        } else if character == '}' {
            closes += 1;
        }
    }
    (opens, closes)
}

pub const DSL_VERSION: u32 = crate::compat::DSL_VERSION;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MigrationResult {
    pub source: String,
    pub from_version: u32,
    pub to_version: u32,
    pub changes: Vec<String>,
}

/// Upgrade legacy syntax to the current DSL version. The version marker is a
/// comment so migrated files remain readable by older parsers.
pub fn migrate_dsl(source: &str) -> Result<MigrationResult, String> {
    let marker = regex_lite::Regex::new(r"(?m)^\s*#\s*tcpform-version:\s*(\d+)\s*$")
        .map_err(|error| error.to_string())?;
    let metadata =
        regex_lite::Regex::new(r"(?s)\btcpform\s*\{[^}]*\bdsl_version\s*=\s*(\d+)[^}]*\}")
            .map_err(|error| error.to_string())?;
    let from_version = metadata
        .captures(source)
        .and_then(|capture| capture.get(1))
        .and_then(|value| value.as_str().parse::<u32>().ok())
        .or_else(|| {
            marker
                .captures(source)
                .and_then(|capture| capture.get(1))
                .and_then(|value| value.as_str().parse::<u32>().ok())
        })
        .unwrap_or(1);
    if from_version > DSL_VERSION {
        return Err(format!(
            "DSL version {from_version} is newer than supported version {DSL_VERSION}"
        ));
    }
    let mut migrated = source.to_string();
    let mut changes = Vec::new();
    let replacements = [
        (
            r#"\baction\s*=\s*"connect""#,
            r#"action = "open""#,
            "connect action → open",
        ),
        (
            r#"\baction\s*=\s*"listen""#,
            r#"action = "open" mode = "passive""#,
            "listen action → passive open",
        ),
        (r"\bretries\s*=", "retry =", "retries → retry"),
        (r"\bsrc_port\s*=", "source_port =", "src_port → source_port"),
        (
            r"\bdst_port\s*=",
            "destination_port =",
            "dst_port → destination_port",
        ),
    ];
    for (pattern, replacement, description) in replacements {
        let regex = regex_lite::Regex::new(pattern).map_err(|error| error.to_string())?;
        if regex.is_match(&migrated) {
            migrated = regex.replace_all(&migrated, replacement).into_owned();
            changes.push(description.to_string());
        }
    }
    for (pattern, replacement, description) in [
        (
            r"\bdelay_ms\s*=\s*(\d+)",
            "delay = \"${1}ms\"",
            "delay_ms → delay duration",
        ),
        (
            r"\btimeout_ms\s*=\s*(\d+)",
            "timeout = \"${1}ms\"",
            "timeout_ms → timeout duration",
        ),
    ] {
        let regex = regex_lite::Regex::new(pattern).map_err(|error| error.to_string())?;
        if regex.is_match(&migrated) {
            migrated = regex.replace_all(&migrated, replacement).into_owned();
            changes.push(description.to_string());
        }
    }
    if metadata.is_match(&migrated) {
        let version_attribute = regex_lite::Regex::new(r"\bdsl_version\s*=\s*\d+")
            .map_err(|error| error.to_string())?;
        migrated = version_attribute
            .replace(&migrated, format!("dsl_version = {DSL_VERSION}").as_str())
            .into_owned();
    } else {
        migrated = marker.replace(&migrated, "").into_owned();
        migrated = format!(
            "tcpform {{ dsl_version = {DSL_VERSION} }}\n\n{}",
            migrated.trim_start()
        );
        changes.push("added tcpform DSL metadata".to_string());
    }
    Ok(MigrationResult {
        source: migrated,
        from_version,
        to_version: DSL_VERSION,
        changes,
    })
}

pub fn run_lsp<R: BufRead, W: Write>(reader: &mut R, writer: &mut W) -> Result<(), String> {
    let mut documents = HashMap::<String, String>::new();
    while let Some(message) = read_lsp_message(reader)? {
        let method = message
            .get("method")
            .and_then(JsonValue::as_str)
            .unwrap_or("");
        let id = message.get("id").cloned();
        match method {
            "initialize" => respond(
                writer,
                id,
                json!({"capabilities":{
                    "textDocumentSync":1,"completionProvider":{"triggerCharacters":[" ","\""]},
                    "definitionProvider":true,"referencesProvider":true,"renameProvider":true,
                    "hoverProvider":true,"documentSymbolProvider":true,"workspaceSymbolProvider":true,
                    "documentFormattingProvider":true,"documentRangeFormattingProvider":true,
                    "codeActionProvider":true,"inlayHintProvider":true,
                    "semanticTokensProvider":{"legend":{"tokenTypes":["keyword","string","number","variable"],"tokenModifiers":[]},"full":true}
                }}),
            )?,
            "shutdown" => respond(writer, id, JsonValue::Null)?,
            "exit" => break,
            "textDocument/didOpen" => {
                if let Some(document) = message.pointer("/params/textDocument") {
                    let uri = document
                        .get("uri")
                        .and_then(JsonValue::as_str)
                        .unwrap_or("");
                    let text = document
                        .get("text")
                        .and_then(JsonValue::as_str)
                        .unwrap_or("");
                    documents.insert(uri.to_string(), text.to_string());
                    publish_diagnostics(writer, uri, text)?;
                }
            }
            "textDocument/didChange" => {
                let uri = message
                    .pointer("/params/textDocument/uri")
                    .and_then(JsonValue::as_str)
                    .unwrap_or("");
                if let Some(text) = message
                    .pointer("/params/contentChanges/0/text")
                    .and_then(JsonValue::as_str)
                {
                    documents.insert(uri.to_string(), text.to_string());
                    publish_diagnostics(writer, uri, text)?;
                }
            }
            "textDocument/completion" => {
                respond(writer, id, completion_items_for(&message, &documents))?
            }
            "textDocument/hover" => respond(
                writer,
                id,
                hover_request(&message, &documents).unwrap_or(JsonValue::Null),
            )?,
            "textDocument/definition" => {
                let result =
                    location_request(&message, &documents, false).unwrap_or(JsonValue::Null);
                respond(writer, id, result)?;
            }
            "textDocument/rename" => {
                let result =
                    rename_request(&message, &documents).unwrap_or_else(|| json!({"changes":{}}));
                respond(writer, id, result)?;
            }
            "textDocument/references" => {
                respond(writer, id, references_request(&message, &documents))?;
            }
            "textDocument/documentSymbol" => {
                respond(writer, id, document_symbols(&message, &documents))?;
            }
            "workspace/symbol" => respond(writer, id, workspace_symbols(&message, &documents))?,
            "textDocument/formatting" => {
                respond(writer, id, formatting_edits(&message, &documents, None))?;
            }
            "textDocument/rangeFormatting" => {
                let range = message.pointer("/params/range");
                respond(writer, id, formatting_edits(&message, &documents, range))?;
            }
            "textDocument/semanticTokens/full" => {
                respond(writer, id, semantic_tokens(&message, &documents))?;
            }
            "textDocument/codeAction" => respond(writer, id, code_actions())?,
            "textDocument/inlayHint" => respond(writer, id, inlay_hints(&message, &documents))?,
            _ if id.is_some() => respond_error(writer, id, -32601, "method not found")?,
            _ => {}
        }
    }
    Ok(())
}

fn read_lsp_message<R: BufRead>(reader: &mut R) -> Result<Option<JsonValue>, String> {
    let mut length = None;
    loop {
        let mut line = String::new();
        if reader.read_line(&mut line).map_err(|e| e.to_string())? == 0 {
            return Ok(None);
        }
        if line == "\r\n" || line == "\n" {
            break;
        }
        if let Some(value) = line.to_ascii_lowercase().strip_prefix("content-length:") {
            length = value.trim().parse::<usize>().ok();
        }
    }
    let length = length.ok_or("LSP message lacks Content-Length")?;
    let mut body = vec![0; length];
    reader.read_exact(&mut body).map_err(|e| e.to_string())?;
    serde_json::from_slice(&body)
        .map(Some)
        .map_err(|e| e.to_string())
}

fn send<W: Write>(writer: &mut W, value: &JsonValue) -> Result<(), String> {
    let body = value.to_string();
    write!(writer, "Content-Length: {}\r\n\r\n{}", body.len(), body).map_err(|e| e.to_string())?;
    writer.flush().map_err(|e| e.to_string())
}
fn respond<W: Write>(
    writer: &mut W,
    id: Option<JsonValue>,
    result: JsonValue,
) -> Result<(), String> {
    send(writer, &json!({"jsonrpc":"2.0","id":id,"result":result}))
}
fn respond_error<W: Write>(
    writer: &mut W,
    id: Option<JsonValue>,
    code: i64,
    message: &str,
) -> Result<(), String> {
    send(
        writer,
        &json!({"jsonrpc":"2.0","id":id,"error":{"code":code,"message":message}}),
    )
}

fn publish_diagnostics<W: Write>(writer: &mut W, uri: &str, source: &str) -> Result<(), String> {
    let diagnostics = match crate::parse_file_named(source, Some(uri)) {
        Err(error) => vec![diagnostic(error.line, error.column, error.message)],
        Ok(blocks) => match crate::model::interpret(&blocks) {
            Err(error) => vec![diagnostic(
                error.line.unwrap_or(1),
                error.column.unwrap_or(1),
                error.message,
            )],
            Ok(protocols) => protocols
                .into_iter()
                .filter_map(|protocol| crate::Engine::new(protocol).err())
                .map(|error| diagnostic(1, 1, error.to_string()))
                .collect(),
        },
    };
    send(
        writer,
        &json!({"jsonrpc":"2.0","method":"textDocument/publishDiagnostics","params":{"uri":uri,"diagnostics":diagnostics}}),
    )
}
fn diagnostic(line: usize, column: usize, message: String) -> JsonValue {
    json!({"range":{"start":{"line":line.saturating_sub(1),"character":column.saturating_sub(1)},"end":{"line":line.saturating_sub(1),"character":column}},"severity":1,"source":"tcpform","message":message})
}

fn completion_items() -> JsonValue {
    let actions = [
        "send",
        "send_raw",
        "recv",
        "recv_raw",
        "ack",
        "nack",
        "wait",
        "open",
        "close",
        "reset",
        "drop",
        "duplicate",
        "corrupt",
        "assert",
        "set",
        "log",
        "plugin",
    ];
    let attributes = [
        "role",
        "action",
        "to",
        "depends_on",
        "from_state",
        "to_state",
        "when",
        "retry",
        "loop",
        "retransmit",
        "segment",
        "expect",
        "timer",
        "plugin",
    ];
    JsonValue::Array(
        actions
            .into_iter()
            .map(|label| json!({"label":label,"kind":12}))
            .chain(
                attributes
                    .into_iter()
                    .map(|label| json!({"label":label,"kind":10})),
            )
            .collect(),
    )
}

fn completion_items_for(message: &JsonValue, documents: &HashMap<String, String>) -> JsonValue {
    let Some(uri) = message
        .pointer("/params/textDocument/uri")
        .and_then(JsonValue::as_str)
    else {
        return completion_items();
    };
    let Some(source) = documents.get(uri) else {
        return completion_items();
    };
    let line = message
        .pointer("/params/position/line")
        .and_then(JsonValue::as_u64)
        .unwrap_or(0) as usize;
    let character = message
        .pointer("/params/position/character")
        .and_then(JsonValue::as_u64)
        .unwrap_or(0) as usize;
    let prefix = source
        .lines()
        .nth(line)
        .map(|line| line.chars().take(character).collect::<String>())
        .unwrap_or_default();
    let pattern = if prefix.contains("depends_on") {
        Some(r#"step\s+\"([^\"]+)\""#)
    } else if ["role", "to", "from"]
        .iter()
        .any(|attribute| prefix.contains(attribute))
    {
        Some(r#"role\s*=\s*\"([^\"]+)\""#)
    } else if prefix.contains("action") {
        return completion_items();
    } else {
        None
    };
    let Some(pattern) = pattern else {
        return completion_items();
    };
    let regex = regex_lite::Regex::new(pattern).expect("static completion regex");
    JsonValue::Array(
        regex
            .captures_iter(source)
            .filter_map(|capture| capture.get(1).map(|value| value.as_str().to_string()))
            .collect::<std::collections::BTreeSet<_>>()
            .into_iter()
            .map(|label| json!({"label":label,"kind":12}))
            .collect(),
    )
}

fn request_word(
    message: &JsonValue,
    documents: &HashMap<String, String>,
) -> Option<(String, String)> {
    let uri = message.pointer("/params/textDocument/uri")?.as_str()?;
    let source = documents.get(uri)?;
    let position = message.pointer("/params/position")?;
    let word = word_at(
        source,
        position.get("line")?.as_u64()? as usize,
        position.get("character")?.as_u64()? as usize,
    )?;
    Some((uri.to_string(), word))
}

fn hover_request(message: &JsonValue, documents: &HashMap<String, String>) -> Option<JsonValue> {
    let (_, word) = request_word(message, documents)?;
    let description = match word.as_str() {
        "send" => "Send a structured segment to another role.",
        "send_raw" => "Encode and send explicit Ethernet/IP/TCP/UDP headers.",
        "recv" | "recv_raw" => "Wait for a matching inbound message; timer controls timeout.",
        "when" => "Boolean guard evaluated from case and role variables.",
        "depends_on" => "Names of steps that must complete before this step runs.",
        "retry" => "Maximum retries after an eligible step failure.",
        "transport" => "Protocol-wide loss, delay, jitter, bandwidth, MTU and fault policy.",
        "fault_when" => "Equality predicate restricting transport faults to a decoded field.",
        _ => return None,
    };
    Some(json!({"contents":{"kind":"markdown","value":format!("**`{word}`**\n\n{description}")}}))
}

fn references_request(message: &JsonValue, documents: &HashMap<String, String>) -> JsonValue {
    let Some((_, word)) = request_word(message, documents) else {
        return JsonValue::Array(Vec::new());
    };
    let mut locations = Vec::new();
    for (uri, source) in documents {
        for (offset, _) in source.match_indices(&word) {
            let before = source[..offset].chars().next_back();
            let after = source[offset + word.len()..].chars().next();
            if before.is_none_or(|value| !is_word(value))
                && after.is_none_or(|value| !is_word(value))
            {
                let (line, character) = offset_position(source, offset);
                locations.push(json!({"uri":uri,"range":{"start":{"line":line,"character":character},"end":{"line":line,"character":character+word.len()}}}));
            }
        }
    }
    JsonValue::Array(locations)
}

fn symbols_for_source(uri: &str, source: &str, query: Option<&str>) -> Vec<JsonValue> {
    let pattern = regex_lite::Regex::new(
        r#"(?m)^\s*(protocol|module|cases|step|header_schema)\s+\"([^\"]+)\""#,
    )
    .expect("static symbol regex");
    pattern
        .captures_iter(source)
        .filter_map(|capture| {
            let whole = capture.get(0)?;
            let kind = capture.get(1)?.as_str();
            let name = capture.get(2)?.as_str();
            if query.is_some_and(|query| !name.to_ascii_lowercase().contains(&query.to_ascii_lowercase())) {
                return None;
            }
            let offset = whole.start() + whole.as_str().find(name)?;
            let (line, character) = offset_position(source, offset);
            let symbol_kind = match kind { "module" => 2, "protocol" => 5, "cases" => 5, "step" => 12, _ => 23 };
            Some(json!({"name":name,"kind":symbol_kind,"location":{"uri":uri,"range":{"start":{"line":line,"character":character},"end":{"line":line,"character":character+name.len()}}},"range":{"start":{"line":line,"character":character},"end":{"line":line,"character":character+name.len()}},"selectionRange":{"start":{"line":line,"character":character},"end":{"line":line,"character":character+name.len()}}}))
        })
        .collect()
}

fn document_symbols(message: &JsonValue, documents: &HashMap<String, String>) -> JsonValue {
    let uri = message
        .pointer("/params/textDocument/uri")
        .and_then(JsonValue::as_str)
        .unwrap_or("");
    JsonValue::Array(
        documents
            .get(uri)
            .map(|source| symbols_for_source(uri, source, None))
            .unwrap_or_default(),
    )
}

fn workspace_symbols(message: &JsonValue, documents: &HashMap<String, String>) -> JsonValue {
    let query = message
        .pointer("/params/query")
        .and_then(JsonValue::as_str)
        .unwrap_or("");
    JsonValue::Array(
        documents
            .iter()
            .flat_map(|(uri, source)| symbols_for_source(uri, source, Some(query)))
            .collect(),
    )
}

fn formatting_edits(
    message: &JsonValue,
    documents: &HashMap<String, String>,
    range: Option<&JsonValue>,
) -> JsonValue {
    let Some(uri) = message
        .pointer("/params/textDocument/uri")
        .and_then(JsonValue::as_str)
    else {
        return JsonValue::Array(Vec::new());
    };
    let Some(source) = documents.get(uri) else {
        return JsonValue::Array(Vec::new());
    };
    let options = FormatOptions {
        indent_width: message
            .pointer("/params/options/tabSize")
            .and_then(JsonValue::as_u64)
            .unwrap_or(2) as usize,
        ..FormatOptions::default()
    };
    let (edit_range, new_text) = if let Some(range) = range {
        let start = range
            .pointer("/start/line")
            .and_then(JsonValue::as_u64)
            .unwrap_or(0) as usize;
        let end = range
            .pointer("/end/line")
            .and_then(JsonValue::as_u64)
            .unwrap_or(start as u64) as usize;
        let lines = source.lines().collect::<Vec<_>>();
        let fragment = if lines.is_empty() || start >= lines.len() {
            String::new()
        } else {
            format_dsl_with_options(
                &lines[start..=end.min(lines.len() - 1)].join("\n"),
                &options,
            )
        };
        (range.clone(), fragment)
    } else {
        let last_line = source.lines().count().saturating_sub(1);
        let last_character = source.lines().last().unwrap_or("").chars().count();
        (
            json!({"start":{"line":0,"character":0},"end":{"line":last_line,"character":last_character}}),
            format_dsl_with_options(source, &options),
        )
    };
    json!([{"range":edit_range,"newText":new_text}])
}

fn semantic_tokens(message: &JsonValue, documents: &HashMap<String, String>) -> JsonValue {
    let uri = message
        .pointer("/params/textDocument/uri")
        .and_then(JsonValue::as_str)
        .unwrap_or("");
    let Some(source) = documents.get(uri) else {
        return json!({"data":[]});
    };
    let pattern = regex_lite::Regex::new(
        r#"\b(protocol|module|cases|step|transport|segment|expect|timer|fault_when)\b"#,
    )
    .expect("static semantic regex");
    let mut tokens = Vec::new();
    let mut previous_line = 0usize;
    let mut previous_character = 0usize;
    for found in pattern.find_iter(source) {
        let (line, character) = offset_position(source, found.start());
        let delta_line = line - previous_line;
        let delta_character = if delta_line == 0 {
            character - previous_character
        } else {
            character
        };
        tokens.extend([delta_line, delta_character, found.as_str().len(), 0, 0]);
        previous_line = line;
        previous_character = character;
    }
    json!({"data":tokens})
}

fn code_actions() -> JsonValue {
    json!([{"title":"Format tcpform document","kind":"source.format","command":{"title":"Format tcpform document","command":"editor.action.formatDocument"}}])
}

fn inlay_hints(message: &JsonValue, documents: &HashMap<String, String>) -> JsonValue {
    let uri = message
        .pointer("/params/textDocument/uri")
        .and_then(JsonValue::as_str)
        .unwrap_or("");
    let Some(source) = documents.get(uri) else {
        return JsonValue::Array(Vec::new());
    };
    let mut hints = Vec::new();
    for (line, text) in source.lines().enumerate() {
        if text.contains("action") && text.contains("retry") {
            hints.push(json!({"position":{"line":line,"character":text.chars().count()},"label":" retry policy","kind":2,"paddingLeft":true}));
        }
    }
    JsonValue::Array(hints)
}

fn location_request(
    message: &JsonValue,
    documents: &HashMap<String, String>,
    _rename: bool,
) -> Option<JsonValue> {
    let uri = message.pointer("/params/textDocument/uri")?.as_str()?;
    let source = documents.get(uri)?;
    let position = message.pointer("/params/position")?;
    let line_index = position.get("line")?.as_u64()? as usize;
    let character_index = position.get("character")?.as_u64()? as usize;
    if let Some(line) = source.lines().nth(line_index) {
        let import = regex_lite::Regex::new(r#"import\s+\"([^\"]+)\""#).ok()?;
        if let Some(capture) = import.captures(line) {
            let path = capture.get(1)?;
            if (path.start()..=path.end()).contains(&character_index) {
                let target = resolve_import_uri(uri, path.as_str());
                if documents.contains_key(&target) {
                    return Some(
                        json!({"uri":target,"range":{"start":{"line":0,"character":0},"end":{"line":0,"character":0}}}),
                    );
                }
            }
        }
    }
    let word = word_at(source, line_index, character_index)?;
    let needle = format!("step \"{word}\"");
    let offset = source
        .find(&needle)
        .or_else(|| source.find(&format!("role = \"{word}\"")))?;
    let (line, character) = offset_position(source, offset);
    Some(
        json!({"uri":uri,"range":{"start":{"line":line,"character":character},"end":{"line":line,"character":character+word.len()}}}),
    )
}

fn resolve_import_uri(base: &str, relative: &str) -> String {
    let Some(index) = base.rfind('/') else {
        return relative.to_string();
    };
    let mut parts = base[..index]
        .split('/')
        .map(str::to_string)
        .collect::<Vec<_>>();
    for part in relative.split('/') {
        match part {
            "." | "" => {}
            ".." => {
                if parts.last().is_some_and(|value| !value.is_empty()) {
                    parts.pop();
                }
            }
            value => parts.push(value.to_string()),
        }
    }
    parts.join("/")
}

fn rename_request(message: &JsonValue, documents: &HashMap<String, String>) -> Option<JsonValue> {
    let uri = message.pointer("/params/textDocument/uri")?.as_str()?;
    let source = documents.get(uri)?;
    let position = message.pointer("/params/position")?;
    let word = word_at(
        source,
        position.get("line")?.as_u64()? as usize,
        position.get("character")?.as_u64()? as usize,
    )?;
    let new_name = message.pointer("/params/newName")?.as_str()?;
    let mut edits = Vec::new();
    for (offset, _) in source.match_indices(&word) {
        let before = source[..offset].chars().next_back();
        let after = source[offset + word.len()..].chars().next();
        if before.is_none_or(|c| !is_word(c)) && after.is_none_or(|c| !is_word(c)) {
            let (line, character) = offset_position(source, offset);
            edits.push(json!({"range":{"start":{"line":line,"character":character},"end":{"line":line,"character":character+word.len()}},"newText":new_name}));
        }
    }
    let mut changes = serde_json::Map::new();
    changes.insert(uri.to_string(), JsonValue::Array(edits));
    Some(json!({"changes":changes}))
}

fn word_at(source: &str, line: usize, character: usize) -> Option<String> {
    let text = source.lines().nth(line)?;
    let chars: Vec<char> = text.chars().collect();
    let mut start = character.min(chars.len());
    let mut end = start;
    while start > 0 && is_word(chars[start - 1]) {
        start -= 1;
    }
    while end < chars.len() && is_word(chars[end]) {
        end += 1;
    }
    (start < end).then(|| chars[start..end].iter().collect())
}
fn is_word(character: char) -> bool {
    character.is_alphanumeric() || matches!(character, '_' | '-')
}
fn offset_position(source: &str, offset: usize) -> (usize, usize) {
    let prefix = &source[..offset];
    (
        prefix.bytes().filter(|b| *b == b'\n').count(),
        prefix.rsplit('\n').next().unwrap_or("").chars().count(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn formatter_preserves_comments_and_is_idempotent() {
        let source = "protocol \"p\" {\n# note\nstep \"s\" { role=\"a\" action = \"log\" }\n}\n";
        let formatted = format_dsl(source);
        assert!(formatted.contains("  # note"));
        assert!(formatted.contains("role = \"a\""));
        assert_eq!(format_dsl(&formatted), formatted);
        let aligned = format_dsl_with_options(
            "protocol \"p\" {\n role=\"a\"\n description=\"x=y\"\n}\n",
            &FormatOptions {
                indent_width: 4,
                align_attributes: true,
                preserve_inline_blocks: true,
            },
        );
        let attribute_lines = aligned
            .lines()
            .filter(|line| line.contains("role") || line.contains("description"))
            .collect::<Vec<_>>();
        assert_eq!(attribute_lines[0].find('='), attribute_lines[1].find('='));
        assert!(aligned.contains("\"x=y\""));
        let expanded = format_dsl_with_options(
            "protocol \"p\" { step \"s\" { role=\"a\" action=\"log\" } }",
            &FormatOptions {
                preserve_inline_blocks: false,
                ..FormatOptions::default()
            },
        );
        assert!(expanded.contains("\n  step \"s\" {\n"));
        assert!(expanded.contains("\n    action = \"log\"\n"));
        crate::parse_file(&expanded).unwrap();
    }

    #[test]
    fn migration_upgrades_legacy_syntax_and_is_idempotent() {
        let legacy = r#"protocol "p" {
  transport { delay_ms=10 }
  step "open" { role="a" action="connect" retries=2 }
  step "listen" { role="b" action="listen" }
  step "recv" { role="b" action="recv" timer { timeout_ms=20 } }
}"#;
        let migrated = migrate_dsl(legacy).unwrap();
        assert_eq!(migrated.from_version, 1);
        assert!(migrated.source.starts_with("tcpform { dsl_version = 2 }\n"));
        assert!(migrated.source.contains("delay = \"10ms\""));
        assert!(migrated
            .source
            .contains("action = \"open\" mode = \"passive\""));
        assert!(migrated.source.contains("retry =2"));
        assert_eq!(
            migrate_dsl(&migrated.source).unwrap().source,
            migrated.source
        );
        crate::parse_file(&migrated.source).unwrap();
    }
    #[test]
    fn lsp_initializes_and_completes() {
        let first = json!({"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}).to_string();
        let second = json!({"jsonrpc":"2.0","id":2,"method":"textDocument/completion","params":{}})
            .to_string();
        let exit = json!({"jsonrpc":"2.0","method":"exit"}).to_string();
        let input = format!(
            "Content-Length: {}\r\n\r\n{}Content-Length: {}\r\n\r\n{}Content-Length: {}\r\n\r\n{}",
            first.len(),
            first,
            second.len(),
            second,
            exit.len(),
            exit
        );
        let mut reader = std::io::BufReader::new(input.as_bytes());
        let mut output = Vec::new();
        run_lsp(&mut reader, &mut output).unwrap();
        let text = String::from_utf8(output).unwrap();
        assert!(text.contains("completionProvider"));
        assert!(text.contains("send_raw"));
    }

    #[test]
    fn lsp_publishes_diagnostics_and_renames_references() {
        let uri = "file:///sample.tcpf";
        let source = "protocol \"p\" {\n  step \"first\" { role = \"a\" action = \"log\" }\n  step \"next\" { role = \"a\" action = \"log\" depends_on = [\"first\"] }\n}\n";
        let messages = [
            json!({"jsonrpc":"2.0","method":"textDocument/didOpen","params":{"textDocument":{"uri":uri,"text":source}}}),
            json!({"jsonrpc":"2.0","id":3,"method":"textDocument/definition","params":{"textDocument":{"uri":uri},"position":{"line":2,"character":70}}}),
            json!({"jsonrpc":"2.0","id":4,"method":"textDocument/rename","params":{"textDocument":{"uri":uri},"position":{"line":1,"character":10},"newName":"start"}}),
            json!({"jsonrpc":"2.0","id":5,"method":"textDocument/references","params":{"textDocument":{"uri":uri},"position":{"line":1,"character":10}}}),
            json!({"jsonrpc":"2.0","id":6,"method":"textDocument/hover","params":{"textDocument":{"uri":uri},"position":{"line":1,"character":43}}}),
            json!({"jsonrpc":"2.0","id":7,"method":"textDocument/documentSymbol","params":{"textDocument":{"uri":uri}}}),
            json!({"jsonrpc":"2.0","id":8,"method":"textDocument/formatting","params":{"textDocument":{"uri":uri},"options":{"tabSize":2,"insertSpaces":true}}}),
            json!({"jsonrpc":"2.0","id":9,"method":"textDocument/semanticTokens/full","params":{"textDocument":{"uri":uri}}}),
            json!({"jsonrpc":"2.0","method":"exit"}),
        ];
        let input = messages
            .iter()
            .map(|message| {
                let body = message.to_string();
                format!("Content-Length: {}\r\n\r\n{body}", body.len())
            })
            .collect::<String>();
        let mut reader = std::io::BufReader::new(input.as_bytes());
        let mut output = Vec::new();
        run_lsp(&mut reader, &mut output).unwrap();
        let text = String::from_utf8(output).unwrap();
        assert!(text.contains("publishDiagnostics"));
        assert!(text.contains("\"diagnostics\":[]"));
        assert!(text.contains("\"newText\":\"start\""));
        assert!(text.contains("\"name\":\"first\""));
        assert!(text.contains("\"data\":["));
    }

    #[test]
    fn lsp_resolves_imports_and_contextual_symbols() {
        assert_eq!(
            resolve_import_uri("file:///work/main.tcpf", "lib/common.tcpf"),
            "file:///work/lib/common.tcpf"
        );
        let mut documents = HashMap::new();
        documents.insert(
            "file:///work/main.tcpf".to_string(),
            "import \"lib.tcpf\"\nprotocol \"p\" {\n step \"first\" { role = \"client\" action = \"log\" }\n step \"next\" { role = \"client\" action = \"log\" depends_on = [\"\"] }\n}\n".to_string(),
        );
        documents.insert(
            "file:///work/lib.tcpf".to_string(),
            "protocol \"library\" {}\n".to_string(),
        );
        let definition = json!({"params":{"textDocument":{"uri":"file:///work/main.tcpf"},"position":{"line":0,"character":10}}});
        assert_eq!(
            location_request(&definition, &documents, false).unwrap()["uri"],
            "file:///work/lib.tcpf"
        );
        let completion = json!({"params":{"textDocument":{"uri":"file:///work/main.tcpf"},"position":{"line":3,"character":75}}});
        assert!(completion_items_for(&completion, &documents)
            .to_string()
            .contains("first"));
    }
}
