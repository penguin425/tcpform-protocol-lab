//! Dependency graph: resolves step ordering, validates references and cycles,
//! and produces a topologically-sorted [`Plan`].
//!
//! Edges come from two sources:
//! 1. **explicit** `depends_on = [...]` on a step (cross-role synchronization);
//! 2. **implicit** ordering: each step depends on the previous step of the
//!    *same role* in declaration order (serializes a role's actions).
//!
//! This is what makes ordering "adjustable": reorder declarations or add
//! `depends_on` edges, then `plan`/`run` reflects the new order.

use crate::model::{Protocol, Step};
use std::collections::{HashMap, HashSet, VecDeque};
use std::fmt;

#[derive(Debug, Clone)]
pub struct PlanError {
    pub message: String,
    pub source: Option<String>,
    pub line: Option<usize>,
    pub column: Option<usize>,
}

impl fmt::Display for PlanError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if let (Some(source), Some(line), Some(column)) = (&self.source, self.line, self.column) {
            write!(f, "{source}:{line}:{column}: plan error: {}", self.message)
        } else {
            write!(f, "plan error: {}", self.message)
        }
    }
}

impl std::error::Error for PlanError {}

fn perr(msg: impl Into<String>) -> PlanError {
    PlanError {
        message: msg.into(),
        source: None,
        line: None,
        column: None,
    }
}

fn perr_at(step: &Step, msg: impl Into<String>) -> PlanError {
    PlanError {
        message: msg.into(),
        source: step.source.clone(),
        line: Some(step.line),
        column: Some(step.column),
    }
}

/// A step with its fully-resolved dependency set (explicit + implicit).
#[derive(Debug, Clone)]
pub struct PlannedStep {
    pub step: Step,
    pub deps: Vec<String>,
}

/// A resolved, validated, topologically-ordered execution plan.
#[derive(Debug, Clone)]
pub struct Plan {
    pub protocol_name: String,
    pub roles: Vec<String>,
    pub order: Vec<PlannedStep>,
}

/// Build and validate a plan for `protocol`.
pub fn plan(protocol: &Protocol) -> Result<Plan, PlanError> {
    // 1. name uniqueness + index
    let mut by_name: HashMap<String, usize> = HashMap::new();
    for (i, s) in protocol.steps.iter().enumerate() {
        if by_name.insert(s.name.clone(), i).is_some() {
            return Err(perr_at(
                s,
                format!(
                    "duplicate step name `{}` in protocol `{}`",
                    s.name, protocol.name
                ),
            ));
        }
    }

    // 2. resolve deps (explicit + implicit prev-in-role)
    let mut deps: HashMap<String, Vec<String>> = HashMap::new();
    let mut prev_in_role: HashMap<String, String> = HashMap::new();
    let mut roles_seen: Vec<String> = Vec::new();
    for s in &protocol.steps {
        if !prev_in_role.contains_key(&s.role) {
            roles_seen.push(s.role.clone());
        }
        let mut d: Vec<String> = Vec::new();
        if let Some(prev) = prev_in_role.get(&s.role) {
            d.push(prev.clone());
        }
        for e in &s.depends_on {
            if !d.contains(e) {
                d.push(e.clone());
            }
        }
        deps.insert(s.name.clone(), d);
        prev_in_role.insert(s.role.clone(), s.name.clone());
    }

    // 3. validate explicit depends_on references exist
    for s in &protocol.steps {
        for e in &s.depends_on {
            if !by_name.contains_key(e) {
                return Err(perr_at(
                    s,
                    format!("step `{}` depends on unknown step `{}`", s.name, e),
                ));
            }
        }
    }

    // 4. Kahn's topological sort (stable by declaration index)
    let mut indeg: HashMap<String, usize> = HashMap::new();
    let mut adj: HashMap<String, Vec<String>> = HashMap::new(); // dep -> dependents
    for s in &protocol.steps {
        indeg.entry(s.name.clone()).or_insert(0);
        adj.entry(s.name.clone()).or_default();
    }
    for (sname, dlist) in &deps {
        let n = dlist.len();
        indeg.insert(sname.clone(), n);
        for d in dlist {
            adj.entry(d.clone()).or_default().push(sname.clone());
        }
    }

    // priority queue ordered by declaration index for determinism
    let mut ready: VecDeque<usize> = {
        let mut idxs: Vec<usize> = protocol
            .steps
            .iter()
            .enumerate()
            .filter(|(_, s)| indeg[&s.name] == 0)
            .map(|(i, _)| i)
            .collect();
        idxs.sort();
        idxs.into()
    };

    let mut order: Vec<PlannedStep> = Vec::new();
    let mut done: HashSet<String> = HashSet::new();
    while let Some(i) = ready.pop_front() {
        let s = &protocol.steps[i];
        order.push(PlannedStep {
            step: s.clone(),
            deps: deps[&s.name].clone(),
        });
        done.insert(s.name.clone());
        for dependent in adj[&s.name].clone() {
            let e = indeg.entry(dependent.clone()).or_insert(0);
            *e = e.saturating_sub(1);
            if *e == 0 {
                ready.push_back(by_name[&dependent]);
            }
        }
        // keep ready sorted by declaration index for deterministic output
        let mut sorted: Vec<usize> = ready.drain(..).collect();
        sorted.sort();
        ready = sorted.into();
    }

    if order.len() != protocol.steps.len() {
        let remaining: Vec<String> = protocol
            .steps
            .iter()
            .filter(|s| !done.contains(&s.name))
            .map(|s| s.name.clone())
            .collect();
        let representative = protocol
            .steps
            .iter()
            .find(|step| remaining.contains(&step.name));
        return Err(representative.map_or_else(
            || {
                perr(format!(
                    "dependency cycle detected involving steps: [{}]",
                    remaining.join(", ")
                ))
            },
            |step| {
                perr_at(
                    step,
                    format!(
                        "dependency cycle detected involving steps: [{}]",
                        remaining.join(", ")
                    ),
                )
            },
        ));
    }

    Ok(Plan {
        protocol_name: protocol.name.clone(),
        roles: roles_seen,
        order,
    })
}
