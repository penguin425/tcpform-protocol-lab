//! Built-in protocol templates and project scaffolding.

use std::fs;
use std::path::{Path, PathBuf};

pub const DEFAULT_TEMPLATE: &str = "tcp-handshake";

#[derive(Debug, Clone, Copy)]
pub struct ProtocolTemplate {
    pub name: &'static str,
    pub description: &'static str,
    pub source: &'static str,
}

const TCP_HANDSHAKE: &str = r#"tcpform { dsl_version = 2 }

protocol "{{name}}" {
  description = "TCP three-way handshake"

  step "syn" { role = "client" action = "send" segment { flags = ["SYN"] } }
  step "recv_syn" { role = "server" action = "recv" expect { flags = ["SYN"] } }
  step "syn_ack" { role = "server" action = "send" depends_on = ["recv_syn"] segment { flags = ["SYN", "ACK"] } }
  step "recv_syn_ack" { role = "client" action = "recv" depends_on = ["syn"] expect { flags = ["SYN", "ACK"] } }
  step "ack" { role = "client" action = "ack" depends_on = ["recv_syn_ack"] segment { flags = ["ACK"] } }
  step "recv_ack" { role = "server" action = "recv" depends_on = ["syn_ack"] expect { flags = ["ACK"] } }
}

cases "{{name}}" {
  case "handshake_completes" { tags = ["smoke"] expect = "pass" }
}
"#;

const DNS: &str = r#"tcpform { dsl_version = 2 }

protocol "{{name}}" {
  description = "DNS query and response model"
  step "query" { role = "client" action = "send" segment { fields = { id = 1 name = "example.com" type = "A" } } }
  step "recv_query" { role = "server" action = "recv" expect { fields = { name = "example.com" type = "A" } } }
  step "response" { role = "server" action = "send" depends_on = ["recv_query"] segment { fields = { id = 1 rcode = 0 address = "192.0.2.1" } } }
  step "recv_response" { role = "client" action = "recv" depends_on = ["query"] expect { fields = { rcode = 0 address = "192.0.2.1" } } }
}

cases "{{name}}" {
  case "a_record" { tags = ["smoke", "dns"] expect = "pass" }
}
"#;

const HTTP: &str = r#"tcpform { dsl_version = 2 }

protocol "{{name}}" {
  description = "HTTP request and response model"
  step "request" { role = "client" action = "send" segment { fields = { method = "GET" path = "/health" } } }
  step "recv_request" { role = "server" action = "recv" expect { fields = { method = "GET" path = "/health" } } }
  step "response" { role = "server" action = "send" depends_on = ["recv_request"] segment { fields = { status = 200 content_type = "application/json" } payload = "{\"ok\":true}" } }
  step "recv_response" { role = "client" action = "recv" depends_on = ["request"] expect { fields = { status = 200 } payload = "{\"ok\":true}" } }
}

cases "{{name}}" {
  case "health_check" { tags = ["smoke", "http"] expect = "pass" }
}
"#;

const WEBSOCKET: &str = r#"tcpform { dsl_version = 2 }

protocol "{{name}}" {
  description = "WebSocket-style bidirectional message exchange"
  step "client_message" { role = "client" action = "send" segment { fields = { opcode = "text" } payload = "hello" } }
  step "recv_client_message" { role = "server" action = "recv" expect { fields = { opcode = "text" } payload = "hello" } }
  step "server_message" { role = "server" action = "send" depends_on = ["recv_client_message"] segment { fields = { opcode = "text" } payload = "world" } }
  step "recv_server_message" { role = "client" action = "recv" depends_on = ["client_message"] expect { fields = { opcode = "text" } payload = "world" } }
}

cases "{{name}}" {
  case "text_round_trip" { tags = ["smoke", "websocket"] expect = "pass" }
}
"#;

const TLS: &str = r#"tcpform { dsl_version = 2 }

protocol "{{name}}" {
  description = "Simplified TLS handshake model"
  step "client_hello" { role = "client" action = "send" segment { fields = { record = "handshake" message = "client_hello" version = "1.3" } } }
  step "recv_client_hello" { role = "server" action = "recv" expect { fields = { message = "client_hello" version = "1.3" } } }
  step "server_hello" { role = "server" action = "send" depends_on = ["recv_client_hello"] segment { fields = { record = "handshake" message = "server_hello" version = "1.3" } } }
  step "recv_server_hello" { role = "client" action = "recv" depends_on = ["client_hello"] expect { fields = { message = "server_hello" version = "1.3" } } }
  step "finished" { role = "client" action = "send" depends_on = ["recv_server_hello"] segment { fields = { message = "finished" } } }
  step "recv_finished" { role = "server" action = "recv" depends_on = ["server_hello"] expect { fields = { message = "finished" } } }
}

cases "{{name}}" {
  case "tls13_handshake" { tags = ["smoke", "tls"] expect = "pass" }
}
"#;

pub const TEMPLATES: &[ProtocolTemplate] = &[
    ProtocolTemplate {
        name: "tcp-handshake",
        description: "TCP three-way handshake",
        source: TCP_HANDSHAKE,
    },
    ProtocolTemplate {
        name: "dns",
        description: "DNS query and response",
        source: DNS,
    },
    ProtocolTemplate {
        name: "http",
        description: "HTTP request and response",
        source: HTTP,
    },
    ProtocolTemplate {
        name: "websocket",
        description: "WebSocket-style bidirectional messages",
        source: WEBSOCKET,
    },
    ProtocolTemplate {
        name: "tls",
        description: "Simplified TLS 1.3 handshake",
        source: TLS,
    },
];

pub fn list_templates() -> &'static [ProtocolTemplate] {
    TEMPLATES
}

pub fn render_template(template: &str, protocol_name: &str) -> Result<String, String> {
    validate_name(protocol_name)?;
    let template = TEMPLATES
        .iter()
        .find(|candidate| candidate.name == template)
        .ok_or_else(|| format!("unknown template `{template}`; run `tcpform template list`"))?;
    Ok(template.source.replace("{{name}}", protocol_name))
}

pub fn init_project(
    directory: &Path,
    project_name: &str,
    template: &str,
    force: bool,
) -> Result<Vec<PathBuf>, String> {
    validate_name(project_name)?;
    if directory.exists()
        && !force
        && fs::read_dir(directory)
            .map_err(|error| error.to_string())?
            .next()
            .is_some()
    {
        return Err(format!(
            "{} is not empty; use --force to overwrite generated files",
            directory.display()
        ));
    }
    let protocol_name = project_name.replace('-', "_");
    let source = render_template(template, &protocol_name)?;
    let files = [
        (PathBuf::from("protocol.tcpf"), source),
        (PathBuf::from(".tcpformfmt.json"), "{\n  \"indent_width\": 2,\n  \"align_attributes\": false,\n  \"preserve_inline_blocks\": true\n}\n".to_string()),
        (PathBuf::from("README.md"), project_readme(project_name, template, &protocol_name)),
        (PathBuf::from(".github/workflows/tcpform.yml"), project_ci()),
    ];
    let mut written = Vec::new();
    for (relative, contents) in files {
        let path = directory.join(relative);
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)
                .map_err(|error| format!("cannot create {}: {error}", parent.display()))?;
        }
        if path.exists() && !force {
            return Err(format!(
                "{} already exists; use --force to overwrite",
                path.display()
            ));
        }
        fs::write(&path, contents)
            .map_err(|error| format!("cannot write {}: {error}", path.display()))?;
        written.push(path);
    }
    Ok(written)
}

fn validate_name(name: &str) -> Result<(), String> {
    if name.is_empty()
        || !name
            .chars()
            .all(|value| value.is_ascii_alphanumeric() || matches!(value, '-' | '_'))
    {
        return Err("names may contain only ASCII letters, numbers, `-`, and `_`".into());
    }
    Ok(())
}

fn project_readme(project: &str, template: &str, protocol: &str) -> String {
    format!("# {project}\n\nGenerated from tcpform's `{template}` template.\n\n```sh\ntcpform validate protocol.tcpf\ntcpform test protocol.tcpf {protocol}\ntcpform run protocol.tcpf {protocol}\n```\n\nThe smoke case is embedded in `protocol.tcpf`. Update it alongside protocol behavior.\n")
}

fn project_ci() -> String {
    r#"name: tcpform

on:
  pull_request:
  push:
    branches: [main]

permissions:
  contents: read
  pull-requests: write

jobs:
  validate:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v7
      - uses: dtolnay/rust-toolchain@stable
      - name: Install tcpform
        run: cargo install --git https://github.com/penguin425/tcpform-protocol-lab.git --locked tcpform
      - run: tcpform doctor .
      - run: tcpform validate protocol.tcpf
      - run: tcpform fmt --check protocol.tcpf
      - run: tcpform test --tag smoke protocol.tcpf
      - name: Create current snapshot
        if: github.event_name == 'pull_request'
        run: tcpform ci-snapshot --output current.json protocol.tcpf
      - name: Check out base revision
        if: github.event_name == 'pull_request'
        uses: actions/checkout@v7
        with:
          ref: ${{ github.event.pull_request.base.sha }}
          path: .tcpform-base
      - name: Create base snapshot
        if: github.event_name == 'pull_request'
        run: tcpform ci-snapshot --output base.json .tcpform-base/protocol.tcpf
      - name: Build differential report
        if: github.event_name == 'pull_request'
        run: tcpform ci-report base.json current.json --markdown tcpform-report.md --json tcpform-report.json
      - name: Create or update PR comment
        if: github.event_name == 'pull_request'
        uses: actions/github-script@v8
        with:
          script: |
            const fs = require('fs');
            const body = fs.readFileSync('tcpform-report.md', 'utf8');
            const marker = '<!-- tcpform-ci-report -->';
            const { owner, repo } = context.repo;
            const issue_number = context.issue.number;
            const comments = await github.paginate(github.rest.issues.listComments, { owner, repo, issue_number });
            const existing = comments.find(comment => comment.user.type === 'Bot' && comment.body.includes(marker));
            if (existing) {
              await github.rest.issues.updateComment({ owner, repo, comment_id: existing.id, body });
            } else {
              await github.rest.issues.createComment({ owner, repo, issue_number, body });
            }
      - name: Fail on regression
        if: github.event_name == 'pull_request'
        run: tcpform ci-report base.json current.json --fail-on-regression >/dev/null
"#.to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    #[test]
    fn every_template_parses_and_runs_its_smoke_case() {
        for template in TEMPLATES {
            let source = render_template(template.name, "example").unwrap();
            let blocks = crate::parse_file(&source).unwrap();
            let protocols = crate::model::interpret(&blocks).unwrap();
            let cases = crate::model::interpret_cases(&blocks).unwrap();
            let results = crate::Engine::new(protocols[0].clone())
                .unwrap()
                .run_cases(&cases[0].cases);
            assert!(
                results.iter().all(|result| result.passed),
                "{}: {results:?}",
                template.name
            );
        }
    }

    #[test]
    fn init_writes_a_complete_project_without_overwriting_it() {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let directory = std::env::temp_dir().join(format!("tcpform-init-{unique}"));
        let paths = init_project(&directory, "sample-project", "dns", false).unwrap();
        assert_eq!(paths.len(), 4);
        let protocol = fs::read_to_string(directory.join("protocol.tcpf")).unwrap();
        assert!(protocol.contains("tcpform { dsl_version = 2 }"));
        assert!(protocol.contains("protocol \"sample_project\""));
        let workflow = fs::read_to_string(directory.join(".github/workflows/tcpform.yml")).unwrap();
        assert!(workflow.contains("tcpform ci-report"));
        assert!(workflow.contains("pull-requests: write"));
        assert!(init_project(&directory, "sample-project", "dns", false).is_err());
        fs::remove_dir_all(directory).unwrap();
    }
}
