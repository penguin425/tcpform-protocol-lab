//! Bounded exhaustive exploration of DSL step schedules and protocol states.

use crate::graph;
use crate::model::{InvariantKind, Protocol};
use serde::Serialize;
use std::collections::{HashMap, HashSet, VecDeque};

#[derive(Debug, Clone, Serialize)]
pub struct ModelCheckReport {
    pub schema_version: &'static str,
    pub protocol: String,
    pub complete: bool,
    pub states_explored: usize,
    pub transitions_explored: usize,
    pub violations: Vec<Violation>,
    pub unreachable_steps: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct Violation {
    pub kind: String,
    pub invariant: Option<String>,
    pub message: String,
    pub counterexample: Vec<String>,
    pub role_states: HashMap<String, String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct State {
    completed: Vec<bool>,
    role_states: Vec<String>,
    reached_liveness: Vec<bool>,
    path: Vec<usize>,
}

pub fn check(protocol: &Protocol, max_states: usize) -> Result<ModelCheckReport, String> {
    if max_states == 0 {
        return Err("max_states must be at least 1".to_string());
    }
    let plan = graph::plan(protocol).map_err(|error| error.to_string())?;
    let roles = plan.roles.clone();
    let role_index: HashMap<_, _> = roles
        .iter()
        .enumerate()
        .map(|(i, role)| (role.clone(), i))
        .collect();
    for invariant in &protocol.invariants {
        if !role_index.contains_key(&invariant.role) {
            return Err(format!(
                "invariant `{}` references unknown role `{}`",
                invariant.name, invariant.role
            ));
        }
        if let Some(role) = &invariant.implies_role {
            if !role_index.contains_key(role) {
                return Err(format!(
                    "invariant `{}` references unknown role `{role}`",
                    invariant.name
                ));
            }
        }
    }
    let step_index: HashMap<_, _> = plan
        .order
        .iter()
        .enumerate()
        .map(|(i, step)| (step.step.name.clone(), i))
        .collect();
    let deps: Vec<Vec<usize>> = plan
        .order
        .iter()
        .map(|step| step.deps.iter().map(|name| step_index[name]).collect())
        .collect();
    let initial = State {
        completed: vec![false; plan.order.len()],
        role_states: vec!["initial".to_string(); roles.len()],
        reached_liveness: protocol
            .invariants
            .iter()
            .filter(|invariant| invariant.kind == InvariantKind::EventuallyState)
            .map(|invariant| invariant.state == "initial")
            .collect(),
        path: Vec::new(),
    };
    let mut queue = VecDeque::from([initial]);
    let mut visited: HashSet<(Vec<bool>, Vec<String>, Vec<bool>)> = HashSet::new();
    let mut reached_steps = HashSet::new();
    let mut violations = Vec::new();
    let mut violation_keys = HashSet::new();
    let mut transitions_explored = 0;
    let mut complete = true;

    while let Some(state) = queue.pop_front() {
        let key = (
            state.completed.clone(),
            state.role_states.clone(),
            state.reached_liveness.clone(),
        );
        if !visited.insert(key) {
            continue;
        }
        if visited.len() > max_states {
            complete = false;
            break;
        }
        check_safety(
            protocol,
            &roles,
            &state,
            &plan,
            &mut violations,
            &mut violation_keys,
        );
        let mut enabled = Vec::new();
        for (index, planned) in plan.order.iter().enumerate() {
            if state.completed[index] || !deps[index].iter().all(|dep| state.completed[*dep]) {
                continue;
            }
            let outcomes: &[bool] = match planned.step.when.as_ref() {
                Some(crate::Value::Bool(false)) => &[false],
                Some(crate::Value::Bool(true)) | None => &[true],
                Some(_) => &[false, true],
            };
            for execute in outcomes {
                let role = role_index[&planned.step.role];
                if !execute
                    || planned.step.from_state.as_ref().is_none_or(|required| {
                        required == "*" || required == &state.role_states[role]
                    })
                {
                    enabled.push((index, *execute));
                }
            }
        }
        if enabled.is_empty() {
            if state.completed.iter().all(|done| *done) {
                check_liveness(
                    protocol,
                    &roles,
                    &state,
                    &plan,
                    &mut violations,
                    &mut violation_keys,
                );
            } else {
                add_violation(
                    &mut violations,
                    &mut violation_keys,
                    (
                        "deadlock",
                        "no step is enabled before the protocol completes".to_string(),
                    ),
                    None,
                    &state,
                    &roles,
                    &plan,
                );
            }
            continue;
        }
        for (index, execute) in enabled {
            reached_steps.insert(index);
            transitions_explored += 1;
            let mut next = state.clone();
            next.completed[index] = true;
            let step = &plan.order[index].step;
            if execute {
                if let Some(target) = &step.to_state {
                    next.role_states[role_index[&step.role]] = target.clone();
                }
            }
            let mut liveness = 0;
            for invariant in &protocol.invariants {
                if invariant.kind == InvariantKind::EventuallyState {
                    if execute
                        && step.role == invariant.role
                        && step.to_state.as_ref() == Some(&invariant.state)
                    {
                        next.reached_liveness[liveness] = true;
                    }
                    liveness += 1;
                }
            }
            next.path.push(index);
            queue.push_back(next);
        }
    }
    let unreachable_steps = plan
        .order
        .iter()
        .enumerate()
        .filter(|(i, _)| !reached_steps.contains(i))
        .map(|(_, step)| step.step.name.clone())
        .collect();
    Ok(ModelCheckReport {
        schema_version: "1",
        protocol: protocol.name.clone(),
        complete,
        states_explored: visited.len().min(max_states),
        transitions_explored,
        violations,
        unreachable_steps,
    })
}

fn check_safety(
    protocol: &Protocol,
    roles: &[String],
    state: &State,
    plan: &graph::Plan,
    violations: &mut Vec<Violation>,
    keys: &mut HashSet<String>,
) {
    for invariant in &protocol.invariants {
        let role = roles.iter().position(|r| r == &invariant.role).unwrap();
        let failed = match invariant.kind {
            InvariantKind::NeverState => state.role_states[role] == invariant.state,
            InvariantKind::StateImplies => {
                state.role_states[role] == invariant.state && {
                    let other = roles
                        .iter()
                        .position(|r| Some(r) == invariant.implies_role.as_ref())
                        .unwrap();
                    state.role_states[other] != *invariant.implies_state.as_ref().unwrap()
                }
            }
            InvariantKind::EventuallyState => false,
        };
        if failed {
            add_violation(
                violations,
                keys,
                (
                    "invariant",
                    format!("invariant `{}` is false", invariant.name),
                ),
                Some(invariant.name.clone()),
                state,
                roles,
                plan,
            );
        }
    }
}

fn check_liveness(
    protocol: &Protocol,
    roles: &[String],
    state: &State,
    plan: &graph::Plan,
    violations: &mut Vec<Violation>,
    keys: &mut HashSet<String>,
) {
    for (liveness, invariant) in protocol
        .invariants
        .iter()
        .filter(|i| i.kind == InvariantKind::EventuallyState)
        .enumerate()
    {
        if !state.reached_liveness[liveness] {
            add_violation(
                violations,
                keys,
                (
                    "liveness",
                    format!(
                        "role `{}` never reaches `{}`",
                        invariant.role, invariant.state
                    ),
                ),
                Some(invariant.name.clone()),
                state,
                roles,
                plan,
            );
        }
    }
}

fn add_violation(
    violations: &mut Vec<Violation>,
    keys: &mut HashSet<String>,
    kind_message: (&str, String),
    invariant: Option<String>,
    state: &State,
    roles: &[String],
    plan: &graph::Plan,
) {
    let (kind, message) = kind_message;
    // Breadth-first exploration guarantees the first report is a shortest
    // counterexample. Keep one concise witness per property/type.
    let key = format!("{kind}:{invariant:?}");
    if !keys.insert(key) {
        return;
    }
    violations.push(Violation {
        kind: kind.to_string(),
        invariant,
        message,
        counterexample: state
            .path
            .iter()
            .map(|i| plan.order[*i].step.name.clone())
            .collect(),
        role_states: roles
            .iter()
            .cloned()
            .zip(state.role_states.iter().cloned())
            .collect(),
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{model::interpret, parse_file};

    fn protocol(source: &str) -> Protocol {
        interpret(&parse_file(source).unwrap()).unwrap().remove(0)
    }

    #[test]
    fn finds_invariant_counterexample_and_deadlock() {
        let p = protocol(
            r#"protocol "p" {
          invariant "safe" { kind="never_state" role="client" state="error" }
          step "bad" { role="client" action="log" from_state="initial" to_state="error" }
          step "blocked" { role="client" action="log" from_state="ready" }
        }"#,
        );
        let report = check(&p, 100).unwrap();
        assert!(report
            .violations
            .iter()
            .any(|v| v.invariant.as_deref() == Some("safe") && v.counterexample == ["bad"]));
        assert!(report.violations.iter().any(|v| v.kind == "deadlock"));
        assert_eq!(report.unreachable_steps, ["blocked"]);
    }

    #[test]
    fn skipped_steps_do_not_apply_state_transitions() {
        let p = protocol(
            r#"protocol "p" {
              invariant "safe" { kind="never_state" role="client" state="error" }
              step "disabled" { role="client" action="log" when=false to_state="error" }
            }"#,
        );
        let report = check(&p, 100).unwrap();
        assert!(report.complete);
        assert!(report.violations.is_empty());
    }
}
