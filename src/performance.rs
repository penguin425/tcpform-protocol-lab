//! Repeated protocol execution with latency, throughput, jitter and deadline gates.

use crate::{ClockMode, Engine, Protocol, TraceEvent};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Instant;

#[derive(Debug, Clone)]
pub struct PerformanceConfig {
    pub iterations: usize,
    pub warmup: usize,
    pub jobs: usize,
    pub deadline_us: Option<u64>,
    pub duration_ms: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PerformanceReport {
    pub schema_version: String,
    pub protocol: String,
    pub config: ReportConfig,
    pub metrics: PerformanceMetrics,
    pub step_intervals: BTreeMap<String, LatencyDistribution>,
    pub baseline: Option<BaselineComparison>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReportConfig {
    pub iterations: usize,
    pub warmup: usize,
    pub jobs: usize,
    pub deadline_us: Option<u64>,
    #[serde(default)]
    pub duration_ms: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PerformanceMetrics {
    pub successful_runs: usize,
    pub failed_runs: usize,
    pub success_rate: f64,
    pub throughput_runs_per_second: f64,
    pub deadline_misses: usize,
    pub latency_us: LatencyDistribution,
    pub scheduler_overhead_us: LatencyDistribution,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct LatencyDistribution {
    pub samples: usize,
    pub min: u64,
    pub mean: f64,
    pub p50: u64,
    pub p95: u64,
    pub p99: u64,
    pub max: u64,
    pub jitter_p99_p50: u64,
    #[serde(default)]
    pub values: Vec<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BaselineComparison {
    pub p95_change_percent: f64,
    pub throughput_change_percent: f64,
    pub latency_p_value: Option<f64>,
    pub statistically_significant: bool,
}

#[derive(Debug)]
struct RunSample {
    duration_us: u64,
    trace_duration_us: u64,
    success: bool,
    trace: Vec<TraceEvent>,
}

pub fn benchmark(
    protocol: &Protocol,
    config: &PerformanceConfig,
) -> Result<PerformanceReport, String> {
    if config.iterations == 0 {
        return Err("iterations must be at least 1".into());
    }
    if config.jobs == 0 {
        return Err("jobs must be at least 1".into());
    }
    if config.duration_ms == Some(0) {
        return Err("duration_ms must be at least 1".into());
    }
    let mut real_protocol = protocol.clone();
    real_protocol.clock = ClockMode::Real;
    for _ in 0..config.warmup {
        let _ = run_once(real_protocol.clone())?;
    }

    let protocol = Arc::new(real_protocol);
    let next = Arc::new(AtomicUsize::new(0));
    let samples = Arc::new(Mutex::new(Vec::with_capacity(config.iterations)));
    let started = Instant::now();
    let stop_at = config
        .duration_ms
        .map(|milliseconds| started + std::time::Duration::from_millis(milliseconds));
    let mut workers = Vec::new();
    for _ in 0..config.jobs.min(config.iterations) {
        let protocol = Arc::clone(&protocol);
        let next = Arc::clone(&next);
        let samples = Arc::clone(&samples);
        let iterations = config.iterations;
        workers.push(std::thread::spawn(move || -> Result<(), String> {
            loop {
                if next.load(Ordering::Relaxed) > 0
                    && stop_at.is_some_and(|deadline| Instant::now() >= deadline)
                {
                    break;
                }
                let index = next.fetch_add(1, Ordering::Relaxed);
                if index >= iterations {
                    break;
                }
                samples.lock().unwrap().push(run_once((*protocol).clone())?);
            }
            Ok(())
        }));
    }
    for worker in workers {
        worker.join().map_err(|_| "performance worker panicked")??;
    }
    let elapsed_seconds = started.elapsed().as_secs_f64().max(f64::EPSILON);
    let samples = Arc::try_unwrap(samples)
        .map_err(|_| "performance samples still shared")?
        .into_inner()
        .map_err(|_| "performance samples poisoned")?;
    let durations: Vec<_> = samples.iter().map(|sample| sample.duration_us).collect();
    let overhead: Vec<_> = samples
        .iter()
        .map(|sample| sample.duration_us.saturating_sub(sample.trace_duration_us))
        .collect();
    let successful_runs = samples.iter().filter(|sample| sample.success).count();
    let failed_runs = samples.len() - successful_runs;
    let deadline_misses = config.deadline_us.map_or(0, |deadline| {
        samples
            .iter()
            .filter(|sample| sample.duration_us > deadline)
            .count()
    });
    let mut step_samples: BTreeMap<String, Vec<u64>> = BTreeMap::new();
    for sample in &samples {
        let mut events = sample.trace.iter().collect::<Vec<_>>();
        events.sort_by_key(|event| event.seq);
        let mut previous_by_role = std::collections::HashMap::new();
        for event in events {
            let previous = previous_by_role
                .insert(event.role.clone(), event.timestamp_us)
                .unwrap_or(0);
            step_samples
                .entry(event.step.clone())
                .or_default()
                .push(event.timestamp_us.saturating_sub(previous));
        }
    }
    Ok(PerformanceReport {
        schema_version: "1".into(),
        protocol: protocol.name.clone(),
        config: ReportConfig {
            iterations: config.iterations,
            warmup: config.warmup,
            jobs: config.jobs,
            deadline_us: config.deadline_us,
            duration_ms: config.duration_ms,
        },
        metrics: PerformanceMetrics {
            successful_runs,
            failed_runs,
            success_rate: successful_runs as f64 / samples.len() as f64,
            throughput_runs_per_second: samples.len() as f64 / elapsed_seconds,
            deadline_misses,
            latency_us: distribution(&durations),
            scheduler_overhead_us: distribution(&overhead),
        },
        step_intervals: step_samples
            .into_iter()
            .map(|(step, samples)| (step, distribution(&samples)))
            .collect(),
        baseline: None,
    })
}

fn run_once(protocol: Protocol) -> Result<RunSample, String> {
    let started = Instant::now();
    let result = Engine::new(protocol)
        .map_err(|error| error.to_string())?
        .run();
    let duration_us = started.elapsed().as_micros().min(u128::from(u64::MAX)) as u64;
    let (success, trace) = match result {
        Ok(trace) => (true, trace),
        Err(crate::EngineError::Runtime { trace, .. }) => (false, trace),
        Err(crate::EngineError::Plan(message)) => return Err(message),
    };
    let trace_duration_us = trace
        .iter()
        .map(|event| event.timestamp_us)
        .max()
        .unwrap_or(0);
    Ok(RunSample {
        duration_us,
        trace_duration_us,
        success,
        trace,
    })
}

pub fn compare_baseline(report: &mut PerformanceReport, baseline: &PerformanceReport) {
    let percent = |current: f64, old: f64| {
        if old == 0.0 {
            if current == 0.0 {
                0.0
            } else {
                100.0
            }
        } else {
            (current - old) / old * 100.0
        }
    };
    let latency_p_value = welch_p_value(
        &report.metrics.latency_us.values,
        &baseline.metrics.latency_us.values,
    );
    report.baseline = Some(BaselineComparison {
        p95_change_percent: percent(
            report.metrics.latency_us.p95 as f64,
            baseline.metrics.latency_us.p95 as f64,
        ),
        throughput_change_percent: percent(
            report.metrics.throughput_runs_per_second,
            baseline.metrics.throughput_runs_per_second,
        ),
        latency_p_value,
        statistically_significant: latency_p_value.is_some_and(|value| value < 0.05),
    });
}

#[derive(Debug, Clone, Default)]
pub struct PerformanceGates {
    pub min_success_rate: f64,
    pub min_throughput: Option<f64>,
    pub max_p95_us: Option<u64>,
    pub max_jitter_us: Option<u64>,
    pub max_deadline_misses: usize,
    pub max_regression_percent: Option<f64>,
    pub max_p_value: Option<f64>,
}

pub fn gate(report: &PerformanceReport, gates: &PerformanceGates) -> Result<(), Vec<String>> {
    let mut failures = Vec::new();
    if report.metrics.success_rate < gates.min_success_rate {
        failures.push(format!(
            "success_rate {:.4} < {:.4}",
            report.metrics.success_rate, gates.min_success_rate
        ));
    }
    if gates
        .min_throughput
        .is_some_and(|minimum| report.metrics.throughput_runs_per_second < minimum)
    {
        failures.push(format!(
            "throughput {:.2} runs/s below minimum",
            report.metrics.throughput_runs_per_second
        ));
    }
    if gates
        .max_p95_us
        .is_some_and(|maximum| report.metrics.latency_us.p95 > maximum)
    {
        failures.push(format!(
            "p95 {}us exceeds maximum",
            report.metrics.latency_us.p95
        ));
    }
    if gates
        .max_jitter_us
        .is_some_and(|maximum| report.metrics.latency_us.jitter_p99_p50 > maximum)
    {
        failures.push(format!(
            "jitter {}us exceeds maximum",
            report.metrics.latency_us.jitter_p99_p50
        ));
    }
    if report.metrics.deadline_misses > gates.max_deadline_misses {
        failures.push(format!(
            "deadline misses {} exceed maximum {}",
            report.metrics.deadline_misses, gates.max_deadline_misses
        ));
    }
    if let (Some(maximum), Some(baseline)) = (gates.max_regression_percent, &report.baseline) {
        if baseline.p95_change_percent > maximum {
            failures.push(format!(
                "p95 regression {:.2}% exceeds maximum {maximum:.2}%",
                baseline.p95_change_percent
            ));
        }
        if baseline.throughput_change_percent < -maximum {
            failures.push(format!(
                "throughput regression {:.2}% exceeds maximum {maximum:.2}%",
                -baseline.throughput_change_percent
            ));
        }
    }
    if let (Some(maximum), Some(baseline)) = (gates.max_p_value, &report.baseline) {
        match baseline.latency_p_value {
            Some(value) if value <= maximum => {}
            Some(value) => failures.push(format!(
                "latency p-value {value:.6} exceeds maximum {maximum:.6}"
            )),
            None => failures.push(
                "latency significance requires at least two raw samples in both reports".into(),
            ),
        }
    }
    if failures.is_empty() {
        Ok(())
    } else {
        Err(failures)
    }
}

fn distribution(samples: &[u64]) -> LatencyDistribution {
    if samples.is_empty() {
        return LatencyDistribution::default();
    }
    let mut sorted = samples.to_vec();
    sorted.sort_unstable();
    let percentile = |percent: usize| {
        sorted[sorted
            .len()
            .saturating_mul(percent)
            .div_ceil(100)
            .saturating_sub(1)]
    };
    let p50 = percentile(50);
    let p99 = percentile(99);
    LatencyDistribution {
        samples: sorted.len(),
        min: sorted[0],
        mean: sorted.iter().map(|value| *value as f64).sum::<f64>() / sorted.len() as f64,
        p50,
        p95: percentile(95),
        p99,
        max: *sorted.last().unwrap(),
        jitter_p99_p50: p99.saturating_sub(p50),
        values: sorted,
    }
}

fn welch_p_value(current: &[u64], baseline: &[u64]) -> Option<f64> {
    if current.len() < 2 || baseline.len() < 2 {
        return None;
    }
    let stats = |values: &[u64]| {
        let mean = values.iter().map(|value| *value as f64).sum::<f64>() / values.len() as f64;
        let variance = values
            .iter()
            .map(|value| (*value as f64 - mean).powi(2))
            .sum::<f64>()
            / (values.len() - 1) as f64;
        (mean, variance)
    };
    let (current_mean, current_variance) = stats(current);
    let (baseline_mean, baseline_variance) = stats(baseline);
    let error = (current_variance / current.len() as f64
        + baseline_variance / baseline.len() as f64)
        .sqrt();
    if error == 0.0 {
        return Some(if current_mean == baseline_mean {
            1.0
        } else {
            0.0
        });
    }
    let z = ((current_mean - baseline_mean) / error).abs();
    Some((2.0 * (1.0 - normal_cdf(z))).clamp(0.0, 1.0))
}

fn normal_cdf(value: f64) -> f64 {
    let t = 1.0 / (1.0 + 0.231_641_9 * value.abs());
    let density = (-value * value / 2.0).exp() / (2.0 * std::f64::consts::PI).sqrt();
    let tail = density
        * t
        * (0.319_381_530
            + t * (-0.356_563_782
                + t * (1.781_477_937 + t * (-1.821_255_978 + t * 1.330_274_429))));
    if value >= 0.0 {
        1.0 - tail
    } else {
        tail
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn distributions_and_baseline_gates_are_deterministic() {
        let values = distribution(&[1, 2, 3, 4, 100]);
        assert_eq!(
            (values.p50, values.p95, values.p99, values.jitter_p99_p50),
            (3, 100, 100, 97)
        );
        let mut report = PerformanceReport {
            schema_version: "1".into(),
            protocol: "p".into(),
            config: ReportConfig {
                iterations: 1,
                warmup: 0,
                jobs: 1,
                deadline_us: None,
                duration_ms: None,
            },
            metrics: PerformanceMetrics {
                successful_runs: 1,
                failed_runs: 0,
                success_rate: 1.0,
                throughput_runs_per_second: 80.0,
                deadline_misses: 0,
                latency_us: distribution(&[120]),
                scheduler_overhead_us: distribution(&[1]),
            },
            step_intervals: BTreeMap::new(),
            baseline: None,
        };
        let mut baseline = report.clone();
        baseline.metrics.latency_us = distribution(&[100]);
        baseline.metrics.throughput_runs_per_second = 100.0;
        compare_baseline(&mut report, &baseline);
        assert!(gate(
            &report,
            &PerformanceGates {
                min_success_rate: 1.0,
                max_regression_percent: Some(10.0),
                ..PerformanceGates::default()
            }
        )
        .is_err());
        report.metrics.latency_us = distribution(&[120, 121, 122, 123, 124]);
        baseline.metrics.latency_us = distribution(&[100, 101, 102, 103, 104]);
        compare_baseline(&mut report, &baseline);
        assert!(report.baseline.as_ref().unwrap().statistically_significant);
        assert!(gate(
            &report,
            &PerformanceGates {
                min_success_rate: 1.0,
                max_p_value: Some(0.05),
                ..PerformanceGates::default()
            }
        )
        .is_ok());
    }
}
