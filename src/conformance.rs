//! Protocol conformance reports derived from an external implementation trace.

use crate::{Protocol, TraceEvent};
use serde::Serialize;

#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct ConformanceReport {
    pub schema_version: &'static str,
    pub protocol: String,
    pub target: String,
    pub role: String,
    pub status: String,
    pub success_rate: f64,
    pub summary: ConformanceSummary,
    pub failure_kind: Option<String>,
    pub error: Option<String>,
    pub requirements: Vec<RequirementResult>,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct ConformanceSummary {
    pub total: usize,
    pub passed: usize,
    pub failed: usize,
    pub not_run: usize,
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub struct RequirementResult {
    pub step: String,
    pub action: String,
    pub description: Option<String>,
    pub status: String,
    pub observations: usize,
    pub detail: Option<String>,
}

pub fn build_report(
    protocol: &Protocol,
    role: &str,
    target: &str,
    trace: &[TraceEvent],
    failure: Option<(&str, &str)>,
) -> ConformanceReport {
    let mut requirements = Vec::new();
    for step in protocol.steps.iter().filter(|step| step.role == role) {
        let observations = trace
            .iter()
            .filter(|event| event.role == role && event.step == step.name)
            .collect::<Vec<_>>();
        let failed = observations.iter().find(|event| !event.ok);
        let status = if failed.is_some() {
            "fail"
        } else if observations.is_empty() {
            "not_run"
        } else {
            "pass"
        };
        let detail = failed
            .map(|event| event.detail.clone())
            .or_else(|| observations.last().map(|event| event.detail.clone()));
        requirements.push(RequirementResult {
            step: step.name.clone(),
            action: step.action.as_str().into(),
            description: step.description.clone(),
            status: status.into(),
            observations: observations.len(),
            detail,
        });
    }
    let passed = requirements
        .iter()
        .filter(|requirement| requirement.status == "pass")
        .count();
    let failed = requirements
        .iter()
        .filter(|requirement| requirement.status == "fail")
        .count();
    let not_run = requirements.len() - passed - failed;
    let total = requirements.len();
    let success_rate = if total == 0 {
        0.0
    } else {
        passed as f64 / total as f64
    };
    ConformanceReport {
        schema_version: "1.0",
        protocol: protocol.name.clone(),
        target: target.into(),
        role: role.into(),
        status: if failure.is_none() && failed == 0 && not_run == 0 && total > 0 {
            "conformant"
        } else {
            "nonconformant"
        }
        .into(),
        success_rate,
        summary: ConformanceSummary {
            total,
            passed,
            failed,
            not_run,
        },
        failure_kind: failure.map(|(kind, _)| kind.into()),
        error: failure.map(|(_, error)| error.into()),
        requirements,
    }
}

pub fn markdown(report: &ConformanceReport) -> String {
    let mut output = format!(
        "# tcpform protocol conformance report\n\n- Protocol: `{}`\n- Target: `{}`\n- Role: `{}`\n- Status: **{}**\n- Success rate: {:.2}%\n\n| Step | Action | Status | Observations | Detail |\n| --- | --- | --- | ---: | --- |\n",
        report.protocol,
        report.target,
        report.role,
        report.status,
        report.success_rate * 100.0
    );
    for requirement in &report.requirements {
        output.push_str(&format!(
            "| `{}` | `{}` | {} | {} | {} |\n",
            requirement.step.replace('|', "\\|"),
            requirement.action,
            requirement.status,
            requirement.observations,
            requirement
                .detail
                .as_deref()
                .unwrap_or("")
                .replace('|', "\\|")
                .replace('\n', " ")
        ));
    }
    if let Some(error) = &report.error {
        output.push_str(&format!("\n## Failure\n\n{}\n", error));
    }
    output
}

pub fn junit(report: &ConformanceReport) -> String {
    let mut cases = String::new();
    for requirement in &report.requirements {
        let failure = match requirement.status.as_str() {
            "fail" => format!(
                "<failure message=\"{}\"/>",
                xml(requirement
                    .detail
                    .as_deref()
                    .unwrap_or("requirement failed"))
            ),
            "not_run" => "<skipped message=\"not executed after an earlier failure\"/>".into(),
            _ => String::new(),
        };
        cases.push_str(&format!(
            "  <testcase classname=\"tcpform.conformance.{}\" name=\"{}\">{failure}</testcase>\n",
            xml(&report.protocol),
            xml(&requirement.step)
        ));
    }
    format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<testsuite name=\"tcpform conformance\" tests=\"{}\" failures=\"{}\" skipped=\"{}\">\n{cases}</testsuite>\n",
        report.summary.total, report.summary.failed, report.summary.not_run
    )
}

fn xml(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&apos;")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reports_pass_fail_and_not_run_requirements() {
        let source = r#"protocol "service" {
          clock="virtual"
          step "send" { role="client" action="send" to="server" segment { payload="ping" } }
          step "recv" { role="client" action="recv" timer { timeout="1ms" } expect { payload="pong" } }
          step "close" { role="client" action="close" }
          step "peer" { role="server" action="log" }
        }"#;
        let protocol = crate::model::interpret(&crate::parse_file(source).unwrap())
            .unwrap()
            .remove(0);
        let mut trace = crate::Engine::new(protocol.clone())
            .unwrap()
            .run()
            .unwrap_err();
        let events = match &mut trace {
            crate::EngineError::Runtime { trace, .. } => trace,
            _ => panic!("expected runtime failure"),
        };
        let report = build_report(
            &protocol,
            "client",
            "127.0.0.1:9000",
            events,
            Some(("timeout", "peer did not respond")),
        );
        assert_eq!(report.status, "nonconformant");
        assert_eq!(report.summary.total, 3);
        assert!(report.summary.failed > 0 || report.summary.not_run > 0);
        assert!(markdown(&report).contains("protocol conformance report"));
        assert!(junit(&report).contains("<testsuite"));
    }
}
