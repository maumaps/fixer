use crate::adapters::{inspect_repo, resolve_repo_root};
use crate::capabilities::detect_capabilities;
use crate::config::FixerConfig;
use crate::models::{FindingInput, ObservedArtifact, PopularBinaryProfile};
use crate::storage::Store;
use crate::util::{
    command_exists, command_output, command_output_os, find_postgres_binary, hash_text,
    maybe_canonicalize, now_rfc3339,
};
use crate::workspace::resolve_installed_package_metadata;
use anyhow::Result;
use chrono::{DateTime, Duration as ChronoDuration, Utc};
use regex::Regex;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::ffi::OsStr;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::thread;
use std::time::Duration as StdDuration;

// Keep a slightly wider target window so a single unexpectedly hot daemon does not
// crowd out the next-most-interesting runaway candidate for the entire cycle.
const PERF_PROFILE_TARGET_LIMIT: usize = 5;
const PERF_TOP_HOTSPOTS_PER_TARGET: usize = 3;
const PERF_REPORT_LIMIT: usize = 12;
const RUNAWAY_INVESTIGATION_SUBSYSTEM: &str = "runaway-process";
const STUCK_PROCESS_INVESTIGATION_SUBSYSTEM: &str = "stuck-process";
const DESKTOP_RESUME_INVESTIGATION_SUBSYSTEM: &str = "desktop-resume";
const RUNAWAY_STRACE_EXCERPT_LIMIT: usize = 24;
const RUNAWAY_TOP_SYSCALL_LIMIT: usize = 6;
const RUNAWAY_SEQUENCE_WINDOW: usize = 3;
const STUCK_PROCESS_FD_TARGET_LIMIT: usize = 8;

#[derive(Debug, Default, Clone)]
pub struct CollectReport {
    pub capabilities_seen: usize,
    pub artifacts_seen: usize,
    pub findings_seen: usize,
}

pub fn collect_once(config: &FixerConfig, store: &Store) -> Result<CollectReport> {
    let capabilities = detect_capabilities();
    store.sync_capabilities(&capabilities)?;

    let mut report = CollectReport {
        capabilities_seen: capabilities.len(),
        ..CollectReport::default()
    };

    if config.service.collect_processes {
        report.artifacts_seen += collect_process_artifacts(store)?;
        report.findings_seen += collect_stuck_process_investigations(config, store)?;
    }
    report.artifacts_seen += collect_repos(&config.service.watched_repos, store)?;
    if config.service.collect_crashes {
        report.findings_seen += collect_crashes(config, store)?;
    }
    if config.service.collect_warnings {
        report.findings_seen += collect_warning_logs(config, store)?;
        report.findings_seen += collect_kernel_oom_kill_investigations(config, store)?;
        report.findings_seen += collect_desktop_resume_investigations(config, store)?;
        report.findings_seen += collect_kernel_warnings(config, store)?;
        report.findings_seen += collect_postgres_collation_mismatches(store)?;
    }
    if config.service.collect_perf {
        report.findings_seen += collect_perf_hotspots(config, store)?;
    }
    if config.service.collect_bpftrace {
        report.findings_seen += collect_bpftrace(config, store)?;
    }
    Ok(report)
}

fn collect_process_artifacts(store: &Store) -> Result<usize> {
    let cpu_percents = current_process_cpu_percents();
    let mut seen = BTreeMap::<PathBuf, ProcessArtifactStats>::new();
    for entry in fs::read_dir("/proc")? {
        let entry = entry?;
        let file_name = entry.file_name();
        let Some(name) = file_name.to_str() else {
            continue;
        };
        if !name.chars().all(|ch| ch.is_ascii_digit()) {
            continue;
        }
        let Ok(pid) = name.parse::<i32>() else {
            continue;
        };
        let exe_link = entry.path().join("exe");
        if let Ok(path) = fs::read_link(&exe_link) {
            let stats = seen.entry(path).or_default();
            stats.process_count += 1;
            let cpu_percent = cpu_percents.get(&pid).copied().unwrap_or_default();
            stats.total_cpu_percent += cpu_percent;
            stats.max_cpu_percent = stats.max_cpu_percent.max(cpu_percent);
        }
    }

    let total = seen.len();
    let current_paths = seen.keys().cloned().collect::<Vec<_>>();
    for (path, stats) in seen {
        let canonical = maybe_canonicalize(&path);
        let package_name = map_path_to_package(&canonical);
        let artifact = ObservedArtifact {
            kind: "binary".to_string(),
            name: canonical
                .file_name()
                .and_then(|x| x.to_str())
                .unwrap_or("binary")
                .to_string(),
            path: Some(canonical),
            package_name,
            repo_root: None,
            ecosystem: None,
            metadata: json!({
                "source": "proc",
                "process_count": stats.process_count,
                "total_cpu_percent": stats.total_cpu_percent,
                "max_cpu_percent": stats.max_cpu_percent,
                "collected_at": now_rfc3339(),
            }),
        };
        let _ = store.upsert_artifact(&artifact)?;
    }
    store.prune_proc_binary_artifacts(&current_paths)?;
    Ok(total)
}

#[derive(Debug, Default, Clone, Copy)]
struct ProcessArtifactStats {
    process_count: usize,
    total_cpu_percent: f64,
    max_cpu_percent: f64,
}

fn current_process_cpu_percents() -> HashMap<i32, f64> {
    let mut percents = HashMap::new();
    let output = match Command::new("ps")
        .env("LC_ALL", "C")
        .args(["-eo", "pid=,pcpu="])
        .output()
    {
        Ok(output) if output.status.success() => output,
        _ => return percents,
    };
    let raw = String::from_utf8_lossy(&output.stdout);
    for line in raw.lines() {
        let mut parts = line.split_whitespace();
        let Some(pid) = parts.next().and_then(|value| value.parse::<i32>().ok()) else {
            continue;
        };
        let Some(cpu_percent) = parts.next().and_then(|value| value.parse::<f64>().ok()) else {
            continue;
        };
        percents.insert(pid, cpu_percent.max(0.0));
    }
    percents
}

#[derive(Debug, Clone)]
struct StuckProcessSample {
    pid: i32,
    comm: String,
    executable: Option<PathBuf>,
    package_name: Option<String>,
    runtime_seconds: u64,
}

#[derive(Debug, Clone)]
struct StuckProcessGroup {
    name: String,
    executable: Option<PathBuf>,
    package_name: Option<String>,
    pids: Vec<i32>,
    sample_pid: i32,
    sample_runtime_seconds: u64,
    comm: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct KernelOomKillEvent {
    process_name: String,
    pid: i32,
    uid: u32,
    total_vm_kb: u64,
    anon_rss_kb: u64,
    file_rss_kb: u64,
    shmem_rss_kb: u64,
    oom_score_adj: i32,
    constraint: Option<String>,
    cpuset: Option<String>,
    task_memcg: Option<String>,
    cgroup_target: Option<String>,
    invoker: Option<String>,
    killed_line: String,
    oom_kill_line: Option<String>,
    invoker_line: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct DesktopResumeFailureEvent {
    driver: String,
    session_type: String,
    display_manager: String,
    crashed_processes: Vec<String>,
    gpu_error_lines: Vec<String>,
    session_error_lines: Vec<String>,
    suspend_line: Option<String>,
    resume_line: String,
    display_restart_line: Option<String>,
}

fn collect_stuck_process_investigations(config: &FixerConfig, store: &Store) -> Result<usize> {
    if !config.service.auto_investigate_stuck_processes {
        return Ok(0);
    }
    let groups = collect_stuck_process_groups(config)?;
    if groups.is_empty() {
        return Ok(0);
    }
    let investigations_dir = config.service.state_dir.join("investigations");
    fs::create_dir_all(&investigations_dir)?;
    prune_runaway_investigation_artifacts(
        &investigations_dir,
        config.service.hotspot_investigation_retention_days,
    )?;
    let richer_evidence_allowed = richer_evidence_enabled(config, store);
    let mut count = 0;
    let mut assessed_sources = Vec::new();
    let mut current_fingerprints = Vec::new();

    for group in groups
        .into_iter()
        .take(config.service.stuck_process_investigation_limit)
    {
        let source_fingerprint = stuck_process_source_fingerprint(&group);
        assessed_sources.push(source_fingerprint.clone());
        if let Some(outcome) = maybe_record_stuck_process_investigation(
            config,
            store,
            &investigations_dir,
            &group,
            &source_fingerprint,
            richer_evidence_allowed,
        )? {
            current_fingerprints.push(outcome.finding_fingerprint);
            if outcome.created {
                count += 1;
            }
        }
    }

    if !assessed_sources.is_empty() {
        assessed_sources.sort();
        assessed_sources.dedup();
        current_fingerprints.sort();
        current_fingerprints.dedup();
        store
            .prune_stuck_process_investigation_findings(&assessed_sources, &current_fingerprints)?;
    }
    Ok(count)
}

fn collect_stuck_process_groups(config: &FixerConfig) -> Result<Vec<StuckProcessGroup>> {
    let uptime_seconds = system_uptime_seconds();
    let clock_ticks_per_second = clock_ticks_per_second();
    let mut groups = BTreeMap::<String, Vec<StuckProcessSample>>::new();
    for entry in fs::read_dir("/proc")? {
        let entry = entry?;
        let file_name = entry.file_name();
        let Some(name) = file_name.to_str() else {
            continue;
        };
        let Ok(pid) = name.parse::<i32>() else {
            continue;
        };
        let process_dir = entry.path();
        let Some(status_raw) = fs::read_to_string(process_dir.join("status")).ok() else {
            continue;
        };
        let Some(state) = process_state_from_status(&status_raw) else {
            continue;
        };
        if !state.starts_with('D') {
            continue;
        }
        let runtime_seconds = process_runtime_seconds(pid, uptime_seconds, clock_ticks_per_second)
            .unwrap_or_default();
        if runtime_seconds < config.service.stuck_process_min_runtime_seconds {
            continue;
        }
        let executable = fs::read_link(process_dir.join("exe"))
            .ok()
            .map(|path| maybe_canonicalize(&path));
        let comm = status_raw
            .lines()
            .find_map(|line| {
                let (key, value) = line.split_once(':')?;
                (key.trim() == "Name").then(|| value.trim().to_string())
            })
            .or_else(|| process_comm(pid))
            .unwrap_or_else(|| "process".to_string());
        let package_name = executable.as_deref().and_then(map_path_to_package);
        let group_key = executable
            .as_ref()
            .map(|path| path.display().to_string())
            .unwrap_or_else(|| normalize_stuck_process_target_name(&comm));
        groups
            .entry(group_key)
            .or_default()
            .push(StuckProcessSample {
                pid,
                comm,
                executable,
                package_name,
                runtime_seconds,
            });
    }

    let mut result = groups
        .into_values()
        .filter_map(|mut samples| {
            samples.sort_by(|left, right| {
                right
                    .runtime_seconds
                    .cmp(&left.runtime_seconds)
                    .then_with(|| left.pid.cmp(&right.pid))
            });
            let sample = samples.first()?;
            let executable = sample.executable.clone();
            let name = executable
                .as_ref()
                .and_then(|path| path.file_name())
                .and_then(|value| value.to_str())
                .map(ToString::to_string)
                .unwrap_or_else(|| normalize_stuck_process_target_name(&sample.comm));
            Some(StuckProcessGroup {
                name,
                executable,
                package_name: sample.package_name.clone(),
                pids: samples.iter().map(|item| item.pid).collect(),
                sample_pid: sample.pid,
                sample_runtime_seconds: sample.runtime_seconds,
                comm: sample.comm.clone(),
            })
        })
        .collect::<Vec<_>>();
    result.sort_by(|left, right| {
        right
            .pids
            .len()
            .cmp(&left.pids.len())
            .then_with(|| {
                right
                    .sample_runtime_seconds
                    .cmp(&left.sample_runtime_seconds)
            })
            .then_with(|| left.name.cmp(&right.name))
    });
    Ok(result)
}

fn system_uptime_seconds() -> f64 {
    fs::read_to_string("/proc/uptime")
        .ok()
        .and_then(|raw| raw.split_whitespace().next()?.parse::<f64>().ok())
        .unwrap_or_default()
}

fn clock_ticks_per_second() -> f64 {
    command_output("getconf", &["CLK_TCK"])
        .ok()
        .and_then(|raw| raw.trim().parse::<f64>().ok())
        .filter(|value| *value > 0.0)
        .unwrap_or(100.0)
}

fn process_runtime_seconds(
    pid: i32,
    uptime_seconds: f64,
    clock_ticks_per_second: f64,
) -> Option<u64> {
    let raw = fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    let after_comm = raw.rsplit_once(") ")?.1;
    let fields = after_comm.split_whitespace().collect::<Vec<_>>();
    let start_ticks = fields.get(19)?.parse::<f64>().ok()?;
    let elapsed = uptime_seconds - (start_ticks / clock_ticks_per_second);
    (elapsed.is_finite() && elapsed >= 0.0).then_some(elapsed.floor() as u64)
}

fn stuck_process_source_fingerprint(group: &StuckProcessGroup) -> String {
    hash_text(format!(
        "stuck-process-source:{}:{}:{}",
        group
            .executable
            .as_ref()
            .map(|path| path.display().to_string())
            .unwrap_or_else(|| normalize_stuck_process_target_name(&group.name)),
        group.package_name.as_deref().unwrap_or("unknown"),
        normalize_stuck_process_target_name(&group.comm),
    ))
}

fn normalize_stuck_process_target_name(raw: &str) -> String {
    let trimmed = raw.trim();
    if !trimmed.starts_with("kworker") {
        return trimmed.to_string();
    }
    if let Some((_, suffix)) = trimmed.split_once('+') {
        let suffix = suffix.trim();
        if !suffix.is_empty() {
            return format!("kworker+{suffix}");
        }
    }
    "kworker".to_string()
}

fn collect_repos(repo_paths: &[PathBuf], store: &Store) -> Result<usize> {
    let mut count = 0;
    for repo in repo_paths {
        if !repo.exists() {
            continue;
        }
        let root = resolve_repo_root(repo);
        let root = maybe_canonicalize(&root);
        let insight = inspect_repo(&root);
        let name = insight
            .as_ref()
            .map(|x| x.display_name.clone())
            .unwrap_or_else(|| {
                root.file_name()
                    .and_then(|x| x.to_str())
                    .unwrap_or("repo")
                    .to_string()
            });
        let ecosystem = insight.as_ref().map(|x| x.ecosystem.clone());
        let metadata = insight
            .as_ref()
            .map(|x| {
                json!({
                    "owners": x.owners,
                    "summary": x.summary,
                    "upstream_url": x.upstream_url,
                    "bug_tracker_url": x.bug_tracker_url,
                    "validation": x.validation,
                    "metadata": x.metadata,
                })
            })
            .unwrap_or_else(|| json!({"summary": "Watched repo without detected adapter"}));
        let artifact = ObservedArtifact {
            kind: "repo".to_string(),
            name,
            path: Some(root.clone()),
            package_name: None,
            repo_root: Some(root.clone()),
            ecosystem: ecosystem.clone(),
            metadata,
        };
        let _ = store.upsert_artifact(&artifact)?;
        count += 1;

        if let Some(insight) = insight {
            if insight.upstream_url.is_none() {
                let finding = FindingInput {
                    kind: "repo".to_string(),
                    title: format!("Repo `{}` is missing upstream metadata", artifact.name),
                    severity: "low".to_string(),
                    fingerprint: hash_text(format!("repo-metadata-missing:{}", root.display())),
                    summary: "The watched repository does not expose an obvious upstream URL."
                        .to_string(),
                    details: json!({
                        "repo_root": root,
                        "ecosystem": insight.ecosystem,
                        "owners": insight.owners,
                    }),
                    artifact: Some(artifact.clone()),
                    repo_root: Some(root),
                    ecosystem,
                };
                let _ = store.record_finding(&finding)?;
            }
        }
    }
    Ok(count)
}

fn collect_crashes(config: &FixerConfig, store: &Store) -> Result<usize> {
    if !store.capability_available("coredumpctl")? {
        return Ok(0);
    }
    store.prune_stackless_crash_findings()?;
    let output = command_output(
        "coredumpctl",
        &[
            "list",
            "--json=short",
            "--no-pager",
            "-n",
            &config.service.coredump_limit.to_string(),
        ],
    )?;
    if output.trim().is_empty() {
        return Ok(0);
    }
    let events: Vec<Value> = serde_json::from_str(&output).unwrap_or_default();
    let mut count = 0;
    for event in events {
        let Some(pid) = event.get("pid").and_then(Value::as_i64) else {
            continue;
        };
        let info = command_output("coredumpctl", &["info", "--no-pager", &pid.to_string()])
            .unwrap_or_default();
        let Some(mut parsed) = parse_coredump_info(&info) else {
            continue;
        };
        let symbolization = improve_stack_symbols(&mut parsed);
        if parsed.primary_stack.is_empty() {
            continue;
        }

        let exe = parsed
            .executable
            .as_ref()
            .map(PathBuf::from)
            .or_else(|| event.get("exe").and_then(Value::as_str).map(PathBuf::from));
        let artifact = exe.as_ref().map(|path| ObservedArtifact {
            kind: "binary".to_string(),
            name: path
                .file_name()
                .and_then(|x| x.to_str())
                .unwrap_or("binary")
                .to_string(),
            path: Some(path.clone()),
            package_name: map_path_to_package(path),
            repo_root: None,
            ecosystem: None,
            metadata: json!({
                "source": "coredumpctl",
                "exe": path,
            }),
        });
        let process_name = parsed
            .process_name
            .clone()
            .or_else(|| {
                exe.as_ref()
                    .and_then(|x| x.file_name())
                    .and_then(|x| x.to_str())
                    .map(ToString::to_string)
            })
            .unwrap_or_else(|| "process".to_string());
        let title = format!("Crash with stack trace in {process_name}");
        let event_time = event
            .get("time")
            .and_then(Value::as_i64)
            .map(|value| value.to_string())
            .or_else(|| parsed.timestamp.clone())
            .unwrap_or_else(|| "unknown-time".to_string());
        let fingerprint = hash_text(format!(
            "{}:{}:{}:{}",
            parsed.executable.as_deref().unwrap_or("unknown"),
            parsed.pid.unwrap_or(pid),
            parsed.signal_number.unwrap_or_default(),
            event_time,
        ));
        let top_frame = parsed
            .primary_stack
            .iter()
            .find(|frame| frame_is_useful(frame))
            .cloned()
            .or_else(|| parsed.primary_stack.first().cloned())
            .unwrap_or_else(|| "stack trace available".to_string());
        let summary = if parsed.useful_stack_frame_count == 0 {
            format!(
                "Low-signal stack trace; unresolved frames: {}",
                symbolization.unresolved_frames
            )
        } else {
            format!("Top frame: {top_frame}")
        };
        let finding = FindingInput {
            kind: "crash".to_string(),
            title,
            severity: "high".to_string(),
            fingerprint,
            summary,
            details: json!({
                "coredumpctl_event": event,
                "process_name": parsed.process_name,
                "pid": parsed.pid,
                "signal_number": parsed.signal_number,
                "signal_name": parsed.signal_name,
                "timestamp": parsed.timestamp,
                "command_line": parsed.command_line,
                "executable": parsed.executable,
                "storage": parsed.storage,
                "stack_threads": parsed.stack_threads,
                "stack_thread_count": parsed.stack_thread_count,
                "total_stack_frame_count": parsed.total_stack_frame_count,
                "useful_stack_frame_count": parsed.useful_stack_frame_count,
                "primary_stack": parsed.primary_stack,
                "symbolization": symbolization,
                "raw_info_excerpt": info.lines().take(80).collect::<Vec<_>>().join("\n"),
            }),
            artifact,
            repo_root: None,
            ecosystem: None,
        };
        let _ = store.record_finding(&finding)?;
        count += 1;
    }
    Ok(count)
}

fn collect_warning_logs(config: &FixerConfig, store: &Store) -> Result<usize> {
    let mut count = 0;
    for path in &config.service.warning_logs {
        let Ok(raw) = fs::read_to_string(path) else {
            continue;
        };
        for line in raw.lines().rev().take(50) {
            if looks_like_warning(line) {
                let finding = FindingInput {
                    kind: "warning".to_string(),
                    title: format!("Warning in {}", path.display()),
                    severity: "medium".to_string(),
                    fingerprint: hash_text(format!("warning:{}:{}", path.display(), line.trim())),
                    summary: line.trim().to_string(),
                    details: json!({
                        "path": path,
                        "line": line.trim(),
                    }),
                    artifact: None,
                    repo_root: None,
                    ecosystem: None,
                };
                let _ = store.record_finding(&finding)?;
                count += 1;
            }
        }
    }
    Ok(count)
}

fn collect_kernel_warnings(config: &FixerConfig, store: &Store) -> Result<usize> {
    if !store.capability_available("journalctl")? {
        return Ok(0);
    }
    store.prune_low_signal_kernel_warning_findings()?;
    let journal_lines = config.service.journal_lines.to_string();
    let mut lines = Vec::new();
    let mut seen = BTreeSet::new();
    let warning_output = command_output(
        "journalctl",
        &[
            "-k",
            "-b",
            "-p",
            "warning",
            "-n",
            journal_lines.as_str(),
            "--no-pager",
        ],
    )
    .unwrap_or_default();
    extend_unique_log_lines(&mut lines, &mut seen, &warning_output);

    let apparmor_output = command_output(
        "journalctl",
        &[
            "-k",
            "-b",
            "-g",
            "apparmor=\"DENIED\"",
            "-n",
            journal_lines.as_str(),
            "--no-pager",
        ],
    )
    .unwrap_or_default();
    extend_unique_log_lines(&mut lines, &mut seen, &apparmor_output);

    let mut count = 0;
    for line in lines {
        if let Some(finding) = apparmor_finding_from_kernel_line(&line) {
            let _ = store.record_finding(&finding)?;
            count += 1;
            continue;
        }
        if is_low_signal_kernel_warning(&line) {
            continue;
        }
        let artifact = kernel_warning_artifact_from_line(&line);
        let mut details = serde_json::Map::new();
        details.insert("line".to_string(), json!(line));
        if let Some(artifact) = &artifact {
            details.insert("kernel_module".to_string(), json!(artifact.name));
            details.insert("kernel_module_path".to_string(), json!(artifact.path));
        }
        let finding = FindingInput {
            kind: "warning".to_string(),
            title: "Kernel warning".to_string(),
            severity: "medium".to_string(),
            fingerprint: hash_text(format!("kernel-warning:{line}")),
            summary: line.clone(),
            details: Value::Object(details),
            artifact,
            repo_root: None,
            ecosystem: None,
        };
        let _ = store.record_finding(&finding)?;
        count += 1;
    }
    Ok(count)
}

fn collect_kernel_oom_kill_investigations(config: &FixerConfig, store: &Store) -> Result<usize> {
    if !store.capability_available("journalctl")? {
        return Ok(0);
    }
    let journal_lines = config.service.journal_lines.saturating_mul(4).to_string();
    let output = command_output(
        "journalctl",
        &[
            "-k",
            "-b",
            "-g",
            "Out of memory: Killed process|oom-kill:|invoked oom-killer",
            "-n",
            journal_lines.as_str(),
            "--no-pager",
        ],
    )
    .unwrap_or_default();
    let mut count = 0;
    for event in parse_kernel_oom_kill_events(&output) {
        let package_name = event.package_name();
        let cgroup_target = event.cgroup_target.clone();
        let likely_external_root_cause = package_name.is_none();
        let finding = FindingInput {
            kind: "investigation".to_string(),
            title: format!("OOM kill investigation for {}", event.process_name),
            severity: "high".to_string(),
            fingerprint: hash_text(format!(
                "oom-kill:{}:{}:{}:{}",
                event.process_name,
                package_name.as_deref().unwrap_or("-"),
                cgroup_target.as_deref().unwrap_or("-"),
                event.constraint.as_deref().unwrap_or("-"),
            )),
            summary: event.public_summary(),
            details: json!({
                "subsystem": "oom-kill",
                "profile_target": {
                    "name": event.process_name.clone(),
                },
                "loop_classification": "kernel-oom-kill",
                "loop_confidence": 1.0,
                "loop_explanation": format!(
                    "The kernel OOM killer explicitly selected {} (pid {}) and logged its memory footprint at the kill site.",
                    event.process_name, event.pid
                ),
                "pid": event.pid,
                "uid": event.uid,
                "total_vm_kb": event.total_vm_kb,
                "anon_rss_kb": event.anon_rss_kb,
                "file_rss_kb": event.file_rss_kb,
                "shmem_rss_kb": event.shmem_rss_kb,
                "oom_score_adj": event.oom_score_adj,
                "constraint": event.constraint.clone(),
                "cpuset": event.cpuset.clone(),
                "task_memcg": event.task_memcg.clone(),
                "task_memcg_target": cgroup_target.clone(),
                "invoker": event.invoker.clone(),
                "killed_line": event.killed_line.clone(),
                "oom_kill_line": event.oom_kill_line.clone(),
                "invoker_line": event.invoker_line.clone(),
                "package_name": package_name.clone(),
                "likely_external_root_cause": likely_external_root_cause,
            }),
            artifact: Some(ObservedArtifact {
                kind: "binary".to_string(),
                name: event.process_name.clone(),
                path: None,
                package_name: package_name.clone(),
                repo_root: None,
                ecosystem: None,
                metadata: json!({
                    "source": "kernel-oom-kill",
                    "pid": event.pid,
                    "uid": event.uid,
                    "total_vm_kb": event.total_vm_kb,
                    "anon_rss_kb": event.anon_rss_kb,
                    "file_rss_kb": event.file_rss_kb,
                    "shmem_rss_kb": event.shmem_rss_kb,
                    "oom_score_adj": event.oom_score_adj,
                    "constraint": event.constraint.clone(),
                    "cpuset": event.cpuset.clone(),
                    "task_memcg": event.task_memcg.clone(),
                    "task_memcg_target": event.cgroup_target.clone(),
                }),
            }),
            repo_root: None,
            ecosystem: None,
        };
        let _ = store.record_finding(&finding)?;
        count += 1;
    }
    Ok(count)
}

fn collect_desktop_resume_investigations(config: &FixerConfig, store: &Store) -> Result<usize> {
    if !store.capability_available("journalctl")? {
        return Ok(0);
    }
    let journal_lines = config.service.journal_lines.saturating_mul(8).to_string();
    let output = command_output(
        "journalctl",
        &[
            "-b",
            "-g",
            "suspend|resume|radeon|amdgpu|drm|Xorg|kwin_x11|sddm|display server|kernel rejected CS|could not connect to display",
            "-n",
            journal_lines.as_str(),
            "--no-pager",
        ],
    )
    .unwrap_or_default();
    let Some(event) = parse_latest_desktop_resume_failure(&output) else {
        return Ok(0);
    };
    let package_name = event.package_name();
    let likely_external_root_cause = true;
    let finding = FindingInput {
        kind: "investigation".to_string(),
        title: format!(
            "Desktop resume failure investigation for {}",
            event.display_target()
        ),
        severity: "high".to_string(),
        fingerprint: hash_text(format!(
            "desktop-resume:{}:{}:{}:{}",
            event.driver,
            event.session_type,
            event.display_manager,
            event.crashed_processes.join("|"),
        )),
        summary: event.public_summary(),
        details: json!({
            "subsystem": DESKTOP_RESUME_INVESTIGATION_SUBSYSTEM,
            "profile_target": {
                "name": event.display_target(),
            },
            "loop_classification": "resume-display-failure",
            "loop_confidence": 0.99,
            "loop_explanation": format!(
                "After resume, the {} graphics stack reported GPU/display errors and {} restarted after {} crashed.",
                event.driver,
                event.display_manager,
                event.crashed_processes.join(", ")
            ),
            "driver": event.driver,
            "session_type": event.session_type,
            "display_manager": event.display_manager,
            "crashed_processes": event.crashed_processes,
            "gpu_error_lines": event.gpu_error_lines,
            "session_error_lines": event.session_error_lines,
            "suspend_line": event.suspend_line,
            "resume_line": event.resume_line,
            "display_restart_line": event.display_restart_line,
            "package_name": package_name,
            "likely_external_root_cause": likely_external_root_cause,
        }),
        artifact: Some(ObservedArtifact {
            kind: "display-stack".to_string(),
            name: event.display_target(),
            path: None,
            package_name: package_name.clone(),
            repo_root: None,
            ecosystem: None,
            metadata: json!({
                "source": "desktop-resume",
                "driver": event.driver,
                "session_type": event.session_type,
                "display_manager": event.display_manager,
                "crashed_processes": event.crashed_processes,
            }),
        }),
        repo_root: None,
        ecosystem: None,
    };
    let _ = store.record_finding(&finding)?;
    Ok(1)
}

fn collect_postgres_collation_mismatches(store: &Store) -> Result<usize> {
    if !store.capability_available("psql")? || !store.capability_available("pg_lsclusters")? {
        return Ok(0);
    }
    let output = command_output("pg_lsclusters", &["--json"]).unwrap_or_default();
    if output.trim().is_empty() {
        return Ok(0);
    }
    let clusters: Vec<PostgresClusterEntry> = serde_json::from_str(&output).unwrap_or_default();
    let mut count = 0;
    let mut assessed_clusters = Vec::new();
    let mut current_fingerprints = Vec::new();
    for cluster in clusters.into_iter().filter(|cluster| cluster.running != 0) {
        let Some((mismatches, warning_excerpt)) = postgres_collation_mismatches(&cluster) else {
            continue;
        };
        assessed_clusters.push((cluster.version.to_string(), cluster.cluster.clone()));
        for mismatch in mismatches {
            let (affected_index_candidates, candidate_warning_excerpt) =
                postgres_collation_index_candidates(&cluster, &mismatch.database_name);
            let package_name = Some(format!("postgresql-{}", cluster.version));
            let artifact = ObservedArtifact {
                kind: "postgres-cluster".to_string(),
                name: format!("{}/{}", cluster.version, cluster.cluster),
                path: cluster.configdir.as_ref().map(PathBuf::from),
                package_name,
                repo_root: None,
                ecosystem: Some("postgres".to_string()),
                metadata: json!({
                    "source": "postgres-collation-check",
                    "cluster": cluster.cluster,
                    "version": cluster.version,
                    "port": cluster.port,
                    "socketdir": cluster.socketdir,
                    "configdir": cluster.configdir,
                    "logfile": cluster.logfile,
                }),
            };
            let summary = format!(
                "Database `{}` on PostgreSQL cluster {}/{} stores collation version `{}` but the system now reports `{}`.",
                mismatch.database_name,
                cluster.version,
                cluster.cluster,
                mismatch.stored_collation_version,
                mismatch.actual_collation_version,
            );
            let fingerprint = hash_text(format!(
                "postgres-collation:{}:{}:{}:{}:{}",
                cluster.version,
                cluster.cluster,
                mismatch.database_name,
                mismatch.stored_collation_version,
                mismatch.actual_collation_version
            ));
            current_fingerprints.push(fingerprint.clone());
            let finding = FindingInput {
                kind: "warning".to_string(),
                title: format!(
                    "PostgreSQL collation mismatch in {} on {}/{}",
                    mismatch.database_name, cluster.version, cluster.cluster
                ),
                severity: "high".to_string(),
                fingerprint,
                summary,
                details: json!({
                    "subsystem": "postgres-collation",
                    "cluster_name": cluster.cluster,
                    "cluster_version": cluster.version,
                    "port": cluster.port,
                    "socketdir": cluster.socketdir,
                    "configdir": cluster.configdir,
                    "logfile": cluster.logfile,
                    "database_name": mismatch.database_name,
                    "stored_collation_version": mismatch.stored_collation_version,
                    "actual_collation_version": mismatch.actual_collation_version,
                    "affected_index_candidates": affected_index_candidates,
                    "pg_amcheck_path": find_postgres_binary("pg_amcheck")
                        .map(|path| path.display().to_string()),
                    "detection_warning_excerpt": candidate_warning_excerpt.or_else(|| warning_excerpt.clone()),
                    "detection_query": POSTGRES_COLLATION_QUERY,
                    "psql_connect_command": format!("psql -p {} -U postgres -d {}", cluster.port, mismatch.database_name),
                    "affected_indexes_query": POSTGRES_AFFECTED_INDEXES_QUERY,
                    "refresh_collation_command": format!("ALTER DATABASE {} REFRESH COLLATION VERSION;", sql_ident(&mismatch.database_name)),
                    "recommended_order": [
                        "List collation-dependent btree indexes in the affected database.",
                        "Run pg_amcheck first if it is available to catch obvious index failures.",
                        "Reindex the affected indexes instead of the whole database.",
                        "Refresh the recorded collation version with ALTER DATABASE ... REFRESH COLLATION VERSION.",
                        "Retest application queries that depend on locale-sensitive ordering."
                    ],
                }),
                artifact: Some(artifact),
                repo_root: None,
                ecosystem: Some("postgres".to_string()),
            };
            let _ = store.record_finding(&finding)?;
            count += 1;
        }
    }
    if !assessed_clusters.is_empty() {
        store.prune_postgres_collation_findings(&assessed_clusters, &current_fingerprints)?;
    }
    Ok(count)
}

const POSTGRES_COLLATION_QUERY: &str = "SELECT datname, COALESCE(datcollversion, ''), COALESCE(pg_database_collation_actual_version(oid), '') FROM pg_database WHERE datallowconn AND datcollversion IS DISTINCT FROM pg_database_collation_actual_version(oid) ORDER BY datname";

const POSTGRES_AFFECTED_INDEXES_QUERY: &str = "SELECT DISTINCT indrelid::regclass::text, indexrelid::regclass::text, collname, pg_get_indexdef(indexrelid) FROM (SELECT indexrelid, indrelid, indcollation[i] coll FROM pg_index, generate_subscripts(indcollation, 1) g(i)) s JOIN pg_class index_class ON index_class.oid = indexrelid JOIN pg_am am ON am.oid = index_class.relam JOIN pg_collation c ON coll = c.oid WHERE am.amname = 'btree' AND collprovider IN ('d', 'c') AND collname NOT IN ('C', 'POSIX') ORDER BY 1, 2";

fn postgres_collation_mismatches(
    cluster: &PostgresClusterEntry,
) -> Option<(Vec<PostgresCollationMismatch>, Option<String>)> {
    if command_exists("runuser") {
        if let Some((stdout, stderr)) =
            postgres_query_via_runuser(cluster.port.as_str(), POSTGRES_COLLATION_QUERY)
        {
            return Some((
                parse_postgres_collation_mismatch_rows(&stdout),
                trimmed_nonempty(stderr),
            ));
        }
    }
    if let Some((stdout, stderr)) =
        postgres_query_direct(cluster.port.as_str(), POSTGRES_COLLATION_QUERY)
    {
        return Some((
            parse_postgres_collation_mismatch_rows(&stdout),
            trimmed_nonempty(stderr),
        ));
    }
    None
}

fn postgres_collation_index_candidates(
    cluster: &PostgresClusterEntry,
    database_name: &str,
) -> (Vec<PostgresIndexCandidate>, Option<String>) {
    if command_exists("runuser") {
        if let Some((stdout, stderr)) = postgres_query_via_runuser_for_db(
            cluster.port.as_str(),
            database_name,
            POSTGRES_AFFECTED_INDEXES_QUERY,
        ) {
            return (
                parse_postgres_index_candidate_rows(&stdout),
                trimmed_nonempty(stderr),
            );
        }
    }
    if let Some((stdout, stderr)) = postgres_query_direct_for_db(
        cluster.port.as_str(),
        database_name,
        POSTGRES_AFFECTED_INDEXES_QUERY,
    ) {
        return (
            parse_postgres_index_candidate_rows(&stdout),
            trimmed_nonempty(stderr),
        );
    }
    (Vec::new(), None)
}

fn postgres_query_via_runuser(port: &str, query: &str) -> Option<(String, String)> {
    postgres_query_via_runuser_for_db(port, "postgres", query)
}

fn postgres_query_via_runuser_for_db(
    port: &str,
    database_name: &str,
    query: &str,
) -> Option<(String, String)> {
    let output = Command::new("runuser")
        .args([
            "-u",
            "postgres",
            "--",
            "psql",
            "-p",
            port,
            "-d",
            database_name,
            "-A",
            "-t",
            "-F",
            "\t",
            "-c",
            query,
        ])
        .output()
        .ok()?;
    if output.status.success() {
        Some((
            String::from_utf8_lossy(&output.stdout).to_string(),
            String::from_utf8_lossy(&output.stderr).to_string(),
        ))
    } else {
        None
    }
}

fn postgres_query_direct(port: &str, query: &str) -> Option<(String, String)> {
    postgres_query_direct_for_db(port, "postgres", query)
}

fn postgres_query_direct_for_db(
    port: &str,
    database_name: &str,
    query: &str,
) -> Option<(String, String)> {
    let output = Command::new("psql")
        .args([
            "-p",
            port,
            "-U",
            "postgres",
            "-d",
            database_name,
            "-A",
            "-t",
            "-F",
            "\t",
            "-c",
            query,
        ])
        .output()
        .ok()?;
    if output.status.success() {
        Some((
            String::from_utf8_lossy(&output.stdout).to_string(),
            String::from_utf8_lossy(&output.stderr).to_string(),
        ))
    } else {
        None
    }
}

fn parse_postgres_collation_mismatch_rows(output: &str) -> Vec<PostgresCollationMismatch> {
    output
        .lines()
        .filter_map(|line| {
            let mut parts = line.split('\t');
            let database_name = parts.next()?.trim();
            let stored_collation_version = parts.next()?.trim();
            let actual_collation_version = parts.next()?.trim();
            if database_name.is_empty()
                || stored_collation_version.is_empty()
                || actual_collation_version.is_empty()
                || stored_collation_version == actual_collation_version
            {
                return None;
            }
            Some(PostgresCollationMismatch {
                database_name: database_name.to_string(),
                stored_collation_version: stored_collation_version.to_string(),
                actual_collation_version: actual_collation_version.to_string(),
            })
        })
        .collect()
}

fn parse_postgres_index_candidate_rows(output: &str) -> Vec<PostgresIndexCandidate> {
    output
        .lines()
        .filter_map(|line| {
            let mut parts = line.split('\t');
            Some(PostgresIndexCandidate {
                table_name: parts.next()?.trim().to_string(),
                index_name: parts.next()?.trim().to_string(),
                collation_name: parts.next()?.trim().to_string(),
                index_definition: parts.next()?.trim().to_string(),
            })
        })
        .filter(|candidate| {
            !candidate.table_name.is_empty()
                && !candidate.index_name.is_empty()
                && !candidate.index_definition.is_empty()
        })
        .collect()
}

fn trimmed_nonempty(raw: String) -> Option<String> {
    let trimmed = raw.trim();
    (!trimmed.is_empty()).then(|| trimmed.to_string())
}

fn sql_ident(name: &str) -> String {
    format!("\"{}\"", name.replace('"', "\"\""))
}

fn extend_unique_log_lines(lines: &mut Vec<String>, seen: &mut BTreeSet<String>, output: &str) {
    for line in output
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
    {
        if seen.insert(line.to_string()) {
            lines.push(line.to_string());
        }
    }
}

fn kernel_warning_artifact_from_line(line: &str) -> Option<ObservedArtifact> {
    if !command_exists("modinfo") {
        return None;
    }
    for module in kernel_warning_module_candidates(line) {
        for lookup_name in kernel_module_lookup_names(&module) {
            let Ok(output) = command_output("modinfo", &["-n", &lookup_name]) else {
                continue;
            };
            let Some(path_line) = output.lines().next().map(str::trim) else {
                continue;
            };
            let module_path = PathBuf::from(path_line);
            if !module_path.exists() {
                continue;
            }
            return Some(ObservedArtifact {
                kind: "kernel-module".to_string(),
                name: module.clone(),
                path: Some(module_path.clone()),
                package_name: map_kernel_module_to_package(&module_path, &module),
                repo_root: None,
                ecosystem: None,
                metadata: json!({
                    "source": "kernel-warning",
                    "module": module,
                    "lookup_name": lookup_name,
                }),
            });
        }
    }
    None
}

fn map_kernel_module_to_package(module_path: &Path, module: &str) -> Option<String> {
    map_path_to_package(module_path)
        .or_else(|| dkms_module_package(module_path, module))
        .or_else(|| kernel_module_package_hint(module_path, module))
}

fn dkms_module_package(module_path: &Path, module: &str) -> Option<String> {
    let path_text = module_path.to_string_lossy();
    if !path_text.contains("/updates/dkms/") {
        return None;
    }
    let release = kernel_module_release(module_path)?;
    let module_names = dkms_module_names(module_path, module);
    if let Some((module_name, version)) = dkms_status_version(&module_names, &release) {
        if let Some(package_name) = map_dkms_source_to_package(&module_name, &version) {
            return Some(package_name);
        }
    }
    let version = command_output_os(
        "modinfo",
        &[
            OsStr::new("-F"),
            OsStr::new("version"),
            module_path.as_os_str(),
        ],
    )
    .ok()?;
    for module_name in module_names {
        if let Some(package_name) = map_dkms_source_to_package(&module_name, version.trim()) {
            return Some(package_name);
        }
    }
    None
}

fn dkms_status_version(module_names: &[String], release: &str) -> Option<(String, String)> {
    if !command_exists("dkms") {
        return None;
    }
    let output = command_output("dkms", &["status"]).ok()?;
    output
        .lines()
        .filter_map(parse_dkms_status_line)
        .find(|entry| {
            entry.kernel_release == release
                && module_names
                    .iter()
                    .any(|module_name| module_name == &entry.module_name)
        })
        .map(|entry| (entry.module_name, entry.version))
}

fn parse_dkms_status_line(line: &str) -> Option<DkmsStatusEntry> {
    let (prefix, rest) = line.split_once(',')?;
    let (module_name, version) = prefix.trim().split_once('/')?;
    let (kernel_release, status_section) = rest.trim().split_once(',')?;
    let status = status_section
        .split_once(':')
        .map(|(_, status)| status.trim())
        .unwrap_or_else(|| status_section.trim());
    Some(DkmsStatusEntry {
        module_name: module_name.trim().to_string(),
        version: version.trim().to_string(),
        kernel_release: kernel_release.trim().to_string(),
        status: status.to_string(),
    })
}

fn map_dkms_source_to_package(module_name: &str, version: &str) -> Option<String> {
    let source_tree = Path::new("/usr/src").join(format!("{module_name}-{version}"));
    if !source_tree.exists() {
        return None;
    }
    map_path_to_package(&source_tree)
}

fn dkms_module_names(module_path: &Path, module: &str) -> Vec<String> {
    let mut names = kernel_module_lookup_names(module);
    if let Some(file_hint) = stripped_module_file_name(module_path) {
        names.push(file_hint);
    }
    dedupe_preserve_order(names)
}

fn stripped_module_file_name(module_path: &Path) -> Option<String> {
    let file_name = module_path.file_name()?.to_str()?;
    let uncompressed = file_name
        .strip_suffix(".xz")
        .or_else(|| file_name.strip_suffix(".zst"))
        .unwrap_or(file_name);
    let module_name = uncompressed.strip_suffix(".ko").unwrap_or(uncompressed);
    if module_name.is_empty() {
        None
    } else {
        Some(module_name.to_string())
    }
}

fn kernel_module_package_hint(module_path: &Path, module: &str) -> Option<String> {
    let path_text = module_path.to_string_lossy();
    if path_text.contains("/updates/dkms/") {
        if module.starts_with("nvidia") || path_text.contains("/nvidia-current") {
            return Some("nvidia-kernel-dkms".to_string());
        }
        return None;
    }
    if module.starts_with("nvidia") || path_text.contains("/nvidia-current") {
        return Some("nvidia-driver".to_string());
    }
    let release = kernel_module_release(module_path);
    release.map(|release| format!("linux-image-{release}"))
}

fn kernel_module_release(module_path: &Path) -> Option<String> {
    module_path
        .components()
        .collect::<Vec<_>>()
        .windows(3)
        .find_map(|window| match window {
            [a, b, c]
                if a.as_os_str() == OsStr::new("lib") && b.as_os_str() == OsStr::new("modules") =>
            {
                c.as_os_str().to_str().map(ToString::to_string)
            }
            _ => None,
        })
}

fn kernel_warning_module_candidates(line: &str) -> Vec<String> {
    let message = line
        .split_once(" kernel: ")
        .map(|(_, message)| message)
        .unwrap_or(line)
        .trim();
    let mut candidates = Vec::new();
    if message.starts_with("NVRM:") {
        candidates.push("nvidia".to_string());
    }
    if let Some(module) = bracketed_kernel_module_name(message) {
        candidates.push(module);
    }
    if let Some(first_token) = message.split_whitespace().next() {
        let candidate = first_token.trim_end_matches(':');
        if is_plausible_kernel_module_name(candidate) {
            candidates.push(candidate.to_string());
        }
    }
    dedupe_preserve_order(candidates)
}

fn kernel_module_lookup_names(module: &str) -> Vec<String> {
    let mut names = vec![module.to_string()];
    if module == "nvidia" {
        names.push("nvidia-current".to_string());
    } else if let Some(suffix) = module.strip_prefix("nvidia_") {
        names.push(format!("nvidia-current-{suffix}"));
    }
    dedupe_preserve_order(names)
}

fn bracketed_kernel_module_name(message: &str) -> Option<String> {
    let start = message.rfind('[')?;
    let end = message.rfind(']')?;
    if end <= start + 1 {
        return None;
    }
    let candidate = &message[start + 1..end];
    if is_plausible_kernel_module_name(candidate) {
        Some(candidate.to_string())
    } else {
        None
    }
}

fn is_plausible_kernel_module_name(candidate: &str) -> bool {
    !candidate.is_empty()
        && candidate
            .chars()
            .all(|ch| ch.is_ascii_lowercase() || ch.is_ascii_digit() || ch == '_' || ch == '-')
}

fn dedupe_preserve_order(values: Vec<String>) -> Vec<String> {
    let mut seen = BTreeSet::new();
    let mut result = Vec::new();
    for value in values {
        if seen.insert(value.clone()) {
            result.push(value);
        }
    }
    result
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct DkmsStatusEntry {
    module_name: String,
    version: String,
    kernel_release: String,
    status: String,
}

#[derive(Debug, Clone, Deserialize)]
struct PostgresClusterEntry {
    cluster: String,
    version: i64,
    port: String,
    running: i64,
    socketdir: Option<String>,
    configdir: Option<String>,
    logfile: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct PostgresCollationMismatch {
    database_name: String,
    stored_collation_version: String,
    actual_collation_version: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
struct PostgresIndexCandidate {
    table_name: String,
    index_name: String,
    collation_name: String,
    index_definition: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ParsedAppArmorDenial {
    profile: String,
    comm: Option<String>,
    operation: Option<String>,
    class: Option<String>,
    info: Option<String>,
    name: Option<String>,
    family: Option<String>,
    sock_type: Option<String>,
    requested: Option<String>,
    denied: Option<String>,
    pid: Option<i64>,
}

impl ParsedAppArmorDenial {
    fn actor_display_name(&self) -> String {
        profile_display_name(&self.profile)
            .or_else(|| self.comm.clone())
            .unwrap_or_else(|| self.profile.clone())
    }

    fn mediated_actor_display_name(&self) -> String {
        let actor = self.actor_display_name();
        match self.comm.as_deref() {
            Some(comm) if !comm.trim().is_empty() && comm != actor => format!("{actor} via {comm}"),
            _ => actor,
        }
    }

    fn executable_path(&self) -> Option<PathBuf> {
        resolve_profile_or_command_path(&self.profile, self.comm.as_deref())
    }

    fn summary(&self) -> String {
        let actor = self.mediated_actor_display_name();
        let operation = self.operation.as_deref().unwrap_or("access");
        if let Some(name) = &self.name {
            return format!("AppArmor denied {actor}: {operation} {name}");
        }
        if let Some(class) = &self.class {
            let mut summary = format!("AppArmor denied {actor}: {operation} {class}");
            if let Some(family) = &self.family {
                summary.push(' ');
                summary.push_str(family);
            }
            if let Some(sock_type) = &self.sock_type {
                summary.push('/');
                summary.push_str(sock_type);
            }
            return summary;
        }
        if let Some(info) = &self.info {
            return format!("AppArmor denied {actor}: {operation} ({info})");
        }
        format!("AppArmor denied {actor}: {operation}")
    }
}

impl KernelOomKillEvent {
    fn package_name(&self) -> Option<String> {
        self.cgroup_target
            .as_ref()
            .filter(|value| !value.trim().is_empty() && *value != &self.process_name)
            .cloned()
    }

    fn public_summary(&self) -> String {
        let anon_mib = kib_to_mib(self.anon_rss_kb);
        let total_vm_gib = kib_to_gib(self.total_vm_kb);
        let scope = self
            .cgroup_target
            .as_deref()
            .map(|target| format!(" in `{target}`"))
            .unwrap_or_default();
        format!(
            "{} was killed by the kernel OOM killer after reaching about {:.0} MiB anonymous RSS ({:.1} GiB virtual memory){}.",
            self.process_name, anon_mib, total_vm_gib, scope
        )
    }
}

impl DesktopResumeFailureEvent {
    fn display_target(&self) -> String {
        format!(
            "{} {} desktop",
            self.driver,
            self.session_type.to_uppercase()
        )
    }

    fn package_name(&self) -> Option<String> {
        Some(current_kernel_image_package_name())
    }

    fn public_summary(&self) -> String {
        let crashes = self.crashed_processes.join(", ");
        format!(
            "After suspend/resume, the {} {} session hit GPU/display failures, {} crashed, and {} restarted the display stack.",
            self.driver,
            self.session_type.to_uppercase(),
            crashes,
            self.display_manager
        )
    }
}

fn parse_kernel_oom_kill_events(raw: &str) -> Vec<KernelOomKillEvent> {
    let killed_re = Regex::new(
        r"Out of memory: Killed process (?P<pid>\d+) \((?P<task>[^)]+)\) total-vm:(?P<total_vm>\d+)kB, anon-rss:(?P<anon_rss>\d+)kB, file-rss:(?P<file_rss>\d+)kB, shmem-rss:(?P<shmem_rss>\d+)kB, UID:(?P<uid>\d+) .* oom_score_adj:(?P<oom_score_adj>-?\d+)",
    )
    .expect("valid oom kill regex");
    let detail_re = Regex::new(
        r"oom-kill:constraint=(?P<constraint>[^,]+).*cpuset=(?P<cpuset>[^,]+).*task_memcg=(?P<task_memcg>[^,]+),task=(?P<task>[^,]+),pid=(?P<pid>\d+),uid=(?P<uid>\d+)",
    )
    .expect("valid oom detail regex");
    let invoker_re =
        Regex::new(r"^(?P<invoker>.+?) invoked oom-killer:").expect("valid oom invoker regex");

    let mut details_by_pid =
        HashMap::<i32, (Option<String>, Option<String>, Option<String>, String)>::new();
    let mut invoker_lines = Vec::<(String, String)>::new();

    for line in raw.lines() {
        let message = strip_kernel_log_prefix(line);
        if let Some(captures) = detail_re.captures(&message) {
            let Some(pid) = captures
                .name("pid")
                .and_then(|value| value.as_str().parse::<i32>().ok())
            else {
                continue;
            };
            let constraint = captures
                .name("constraint")
                .map(|value| value.as_str().to_string());
            let cpuset = captures
                .name("cpuset")
                .map(|value| value.as_str().to_string());
            let task_memcg = captures
                .name("task_memcg")
                .map(|value| value.as_str().to_string());
            details_by_pid.insert(pid, (constraint, cpuset, task_memcg, line.to_string()));
            continue;
        }
        if let Some(captures) = invoker_re.captures(&message) {
            let invoker = captures
                .name("invoker")
                .map(|value| value.as_str().trim().to_string())
                .unwrap_or_default();
            if !invoker.is_empty() {
                invoker_lines.push((invoker, line.to_string()));
            }
        }
    }

    let mut events = Vec::new();
    for line in raw.lines() {
        let message = strip_kernel_log_prefix(line);
        let Some(captures) = killed_re.captures(&message) else {
            continue;
        };
        let Some(pid) = captures
            .name("pid")
            .and_then(|value| value.as_str().parse::<i32>().ok())
        else {
            continue;
        };
        let process_name = captures
            .name("task")
            .map(|value| value.as_str().to_string())
            .unwrap_or_else(|| "process".to_string());
        let total_vm_kb = captures
            .name("total_vm")
            .and_then(|value| value.as_str().parse::<u64>().ok())
            .unwrap_or_default();
        let anon_rss_kb = captures
            .name("anon_rss")
            .and_then(|value| value.as_str().parse::<u64>().ok())
            .unwrap_or_default();
        let file_rss_kb = captures
            .name("file_rss")
            .and_then(|value| value.as_str().parse::<u64>().ok())
            .unwrap_or_default();
        let shmem_rss_kb = captures
            .name("shmem_rss")
            .and_then(|value| value.as_str().parse::<u64>().ok())
            .unwrap_or_default();
        let uid = captures
            .name("uid")
            .and_then(|value| value.as_str().parse::<u32>().ok())
            .unwrap_or_default();
        let oom_score_adj = captures
            .name("oom_score_adj")
            .and_then(|value| value.as_str().parse::<i32>().ok())
            .unwrap_or_default();
        let (constraint, cpuset, task_memcg, oom_kill_line) = details_by_pid
            .get(&pid)
            .cloned()
            .unwrap_or((None, None, None, String::new()));
        let task_memcg = task_memcg.filter(|value| !value.trim().is_empty());
        let cgroup_target = task_memcg
            .as_deref()
            .and_then(normalize_oom_task_memcg_target);
        let nearest_invoker = invoker_lines
            .iter()
            .find(|(_, invoker_line)| {
                let invoker_time = invoker_line.split(" kernel: ").next().unwrap_or_default();
                let event_time = line.split(" kernel: ").next().unwrap_or_default();
                invoker_time <= event_time
            })
            .cloned();

        events.push(KernelOomKillEvent {
            process_name,
            pid,
            uid,
            total_vm_kb,
            anon_rss_kb,
            file_rss_kb,
            shmem_rss_kb,
            oom_score_adj,
            constraint,
            cpuset: cpuset.filter(|value| !value.trim().is_empty()),
            task_memcg,
            cgroup_target,
            invoker: nearest_invoker.as_ref().map(|(invoker, _)| invoker.clone()),
            killed_line: line.to_string(),
            oom_kill_line: (!oom_kill_line.trim().is_empty()).then_some(oom_kill_line),
            invoker_line: nearest_invoker.map(|(_, raw)| raw),
        });
    }
    events
}

fn parse_latest_desktop_resume_failure(raw: &str) -> Option<DesktopResumeFailureEvent> {
    let lines = raw
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .map(ToString::to_string)
        .collect::<Vec<_>>();
    let resume_index = lines.iter().rposition(|line| {
        line.contains("PM: suspend exit")
            || line.contains("System returned from sleep operation 'suspend")
            || line.contains("Waking up from system sleep state S3")
    })?;
    let start_index = lines[..=resume_index]
        .iter()
        .rposition(|line| {
            line.contains("PM: suspend entry")
                || line.contains("The system will suspend")
                || line.contains("Performing sleep operation 'suspend'")
        })
        .unwrap_or_else(|| resume_index.saturating_sub(40));
    let end_index = (resume_index + 120).min(lines.len().saturating_sub(1));
    let window = &lines[start_index..=end_index];

    let driver = desktop_resume_driver(window)?;
    let mut crashed_processes = Vec::new();
    let mut seen_processes = BTreeSet::new();
    let mut gpu_error_lines = Vec::new();
    let mut gpu_seen = BTreeSet::new();
    let mut session_error_lines = Vec::new();
    let mut session_seen = BTreeSet::new();
    let suspend_line = window
        .iter()
        .find(|line| is_suspend_entry_line(line))
        .cloned();
    let resume_line = window
        .iter()
        .find(|line| is_resume_exit_line(line))
        .cloned()
        .unwrap_or_else(|| lines[resume_index].clone());
    let display_restart_line = window
        .iter()
        .find(|line| is_display_restart_line(line))
        .cloned();

    let coredump_re =
        Regex::new(r"Process (?:\d+ \()?(?P<process>[A-Za-z0-9_.-]+)\)? .* terminated abnormally")
            .expect("valid desktop resume coredump regex");

    for line in window {
        if is_resume_gpu_error_line(line) {
            if gpu_seen.insert(line.clone()) {
                gpu_error_lines.push(line.clone());
            }
        }
        if is_display_restart_line(line) || is_desktop_resume_session_error_line(line) {
            if session_seen.insert(line.clone()) {
                session_error_lines.push(line.clone());
            }
        }
        if let Some(captures) = coredump_re.captures(line) {
            if let Some(process) = captures
                .name("process")
                .map(|value| value.as_str().to_string())
            {
                if seen_processes.insert(process.clone()) {
                    crashed_processes.push(process);
                }
            }
        }
    }

    if gpu_error_lines.is_empty() || crashed_processes.is_empty() {
        return None;
    }
    crashed_processes.sort();

    Some(DesktopResumeFailureEvent {
        driver,
        session_type: desktop_resume_session_type(window),
        display_manager: desktop_resume_display_manager(window),
        crashed_processes,
        gpu_error_lines,
        session_error_lines,
        suspend_line,
        resume_line,
        display_restart_line,
    })
}

fn normalize_oom_task_memcg_target(raw: &str) -> Option<String> {
    let trailing_digits_re = Regex::new(r"-\d+$").expect("valid oom scope regex");
    for segment in raw.split('/') {
        if let Some(app) = segment.strip_prefix("app-") {
            let decoded = decode_systemd_unit_component(app);
            if let Some(service) = decoded.strip_suffix(".service") {
                let base = service
                    .split_once('@')
                    .map(|(head, _)| head)
                    .unwrap_or(service)
                    .trim();
                if !base.is_empty() {
                    return Some(base.to_string());
                }
            }
            if let Some(scope) = decoded.strip_suffix(".scope") {
                let normalized = trailing_digits_re.replace(scope, "").to_string();
                if !normalized.is_empty() {
                    return Some(normalized);
                }
            }
        }
    }
    None
}

fn decode_systemd_unit_component(raw: &str) -> String {
    let mut decoded = String::with_capacity(raw.len());
    let bytes = raw.as_bytes();
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'\\'
            && index + 3 < bytes.len()
            && bytes[index + 1] == b'x'
            && bytes[index + 2].is_ascii_hexdigit()
            && bytes[index + 3].is_ascii_hexdigit()
        {
            let hex = &raw[index + 2..index + 4];
            if let Ok(value) = u8::from_str_radix(hex, 16) {
                decoded.push(value as char);
                index += 4;
                continue;
            }
        }
        decoded.push(bytes[index] as char);
        index += 1;
    }
    decoded
}

fn strip_kernel_log_prefix(raw: &str) -> String {
    raw.split_once(" kernel: ")
        .map(|(_, message)| message.trim().to_string())
        .unwrap_or_else(|| raw.trim().to_string())
}

fn is_suspend_entry_line(line: &str) -> bool {
    line.contains("PM: suspend entry")
        || line.contains("The system will suspend")
        || line.contains("Performing sleep operation 'suspend'")
}

fn is_resume_exit_line(line: &str) -> bool {
    line.contains("PM: suspend exit")
        || line.contains("System returned from sleep operation 'suspend")
        || line.contains("Waking up from system sleep state S3")
}

fn is_resume_gpu_error_line(line: &str) -> bool {
    let lower = line.to_ascii_lowercase();
    (lower.contains("radeon") || lower.contains("amdgpu") || lower.contains("[drm"))
        && (lower.contains("gpu lockup")
            || lower.contains("ring 0 stalled")
            || lower.contains("fence wait failed")
            || lower.contains("failed testing ib")
            || lower.contains("ib ring test failed")
            || lower.contains("kernel rejected cs")
            || lower.contains("could not connect to display")
            || lower.contains("failed to read display number"))
}

fn is_display_restart_line(line: &str) -> bool {
    line.contains("Display server stopping")
        || line.contains("Display server stopped")
        || line.contains("Display server starting")
        || line.contains("Adding new display")
        || line.contains("Attempt 1 starting the Display server")
        || line.contains("Failed to read display number from pipe")
}

fn is_desktop_resume_session_error_line(line: &str) -> bool {
    line.contains("could not connect to display")
        || line.contains("Could not load the Qt platform plugin \"xcb\"")
        || line.contains(
            "This application failed to start because no Qt platform plugin could be initialized",
        )
}

fn desktop_resume_driver(lines: &[String]) -> Option<String> {
    if lines
        .iter()
        .any(|line| line.to_ascii_lowercase().contains("radeon"))
    {
        return Some("radeon".to_string());
    }
    if lines
        .iter()
        .any(|line| line.to_ascii_lowercase().contains("amdgpu"))
    {
        return Some("amdgpu".to_string());
    }
    None
}

fn desktop_resume_session_type(lines: &[String]) -> String {
    if lines
        .iter()
        .any(|line| line.contains("kwin_x11") || line.contains("Starting X11 session"))
    {
        return "x11".to_string();
    }
    if lines
        .iter()
        .any(|line| line.to_ascii_lowercase().contains("wayland"))
    {
        return "wayland".to_string();
    }
    "desktop".to_string()
}

fn desktop_resume_display_manager(lines: &[String]) -> String {
    if lines.iter().any(|line| line.contains("sddm")) {
        return "sddm".to_string();
    }
    if lines.iter().any(|line| line.contains("lightdm")) {
        return "lightdm".to_string();
    }
    "display-manager".to_string()
}

fn current_kernel_image_package_name() -> String {
    let release = command_output("uname", &["-r"])
        .ok()
        .map(|raw| raw.trim().to_string())
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| "unknown".to_string());
    format!("linux-image-{release}")
}

fn kib_to_mib(value: u64) -> f64 {
    value as f64 / 1024.0
}

fn kib_to_gib(value: u64) -> f64 {
    value as f64 / (1024.0 * 1024.0)
}

fn apparmor_finding_from_kernel_line(line: &str) -> Option<FindingInput> {
    let denial = parse_apparmor_denial(line)?;
    let executable_path = denial.executable_path();
    let artifact = executable_path.as_ref().map(|path| ObservedArtifact {
        kind: "binary".to_string(),
        name: denial.actor_display_name(),
        path: Some(path.clone()),
        package_name: map_path_to_package(path),
        repo_root: None,
        ecosystem: None,
        metadata: json!({
            "source": "journalctl",
            "profile": denial.profile,
            "comm": denial.comm,
        }),
    });
    let fingerprint = hash_text(format!(
        "apparmor-warning:{}:{}:{}:{}:{}:{}:{}:{}:{}",
        denial.profile,
        denial.comm.as_deref().unwrap_or(""),
        denial.operation.as_deref().unwrap_or(""),
        denial.class.as_deref().unwrap_or(""),
        denial.name.as_deref().unwrap_or(""),
        denial.family.as_deref().unwrap_or(""),
        denial.sock_type.as_deref().unwrap_or(""),
        denial.requested.as_deref().unwrap_or(""),
        denial.denied.as_deref().unwrap_or(""),
    ));
    Some(FindingInput {
        kind: "warning".to_string(),
        title: format!("AppArmor denial in {}", denial.actor_display_name()),
        severity: "medium".to_string(),
        fingerprint,
        summary: denial.summary(),
        details: json!({
            "line": line,
            "subsystem": "apparmor",
            "profile": denial.profile,
            "comm": denial.comm,
            "operation": denial.operation,
            "class": denial.class,
            "info": denial.info,
            "name": denial.name,
            "family": denial.family,
            "sock_type": denial.sock_type,
            "requested": denial.requested,
            "denied": denial.denied,
            "pid": denial.pid,
        }),
        artifact,
        repo_root: None,
        ecosystem: None,
    })
}

fn parse_apparmor_denial(line: &str) -> Option<ParsedAppArmorDenial> {
    if !line.contains("apparmor=\"DENIED\"") {
        return None;
    }
    let kernel_message = line
        .split_once(" kernel: ")
        .map(|(_, message)| message)
        .unwrap_or(line);
    let fields = parse_key_value_fields(kernel_message);
    if fields.get("apparmor").map(String::as_str) != Some("DENIED") {
        return None;
    }
    let profile = fields.get("profile")?.to_string();
    Some(ParsedAppArmorDenial {
        profile,
        comm: fields.get("comm").cloned(),
        operation: fields.get("operation").cloned(),
        class: fields.get("class").cloned(),
        info: fields.get("info").cloned(),
        name: fields.get("name").cloned(),
        family: fields.get("family").cloned(),
        sock_type: fields.get("sock_type").cloned(),
        requested: fields
            .get("requested")
            .or_else(|| fields.get("requested_mask"))
            .cloned(),
        denied: fields
            .get("denied")
            .or_else(|| fields.get("denied_mask"))
            .cloned(),
        pid: fields
            .get("pid")
            .and_then(|value| value.parse::<i64>().ok()),
    })
}

fn parse_key_value_fields(raw: &str) -> HashMap<String, String> {
    let mut fields = HashMap::new();
    let bytes = raw.as_bytes();
    let mut index = 0usize;
    while index < bytes.len() {
        while index < bytes.len() && bytes[index].is_ascii_whitespace() {
            index += 1;
        }
        if index >= bytes.len() {
            break;
        }
        let key_start = index;
        while index < bytes.len() && bytes[index] != b'=' && !bytes[index].is_ascii_whitespace() {
            index += 1;
        }
        if index >= bytes.len() || bytes[index] != b'=' {
            while index < bytes.len() && !bytes[index].is_ascii_whitespace() {
                index += 1;
            }
            continue;
        }
        let key = raw[key_start..index].trim();
        index += 1;
        if index >= bytes.len() {
            break;
        }
        let value = if bytes[index] == b'"' {
            index += 1;
            let value_start = index;
            while index < bytes.len() && bytes[index] != b'"' {
                index += 1;
            }
            let value = raw[value_start..index].to_string();
            if index < bytes.len() {
                index += 1;
            }
            value
        } else {
            let value_start = index;
            while index < bytes.len() && !bytes[index].is_ascii_whitespace() {
                index += 1;
            }
            raw[value_start..index].to_string()
        };
        if !key.is_empty() {
            fields.insert(key.to_string(), value);
        }
    }
    fields
}

fn is_low_signal_kernel_warning(line: &str) -> bool {
    (line.contains("kauditd_printk_skb:") && line.contains("callbacks suppressed"))
        || ((line.contains("show_signal:") || line.contains("show_signal_msg:"))
            && line.contains("callbacks suppressed"))
}

fn profile_display_name(profile: &str) -> Option<String> {
    let path = Path::new(profile);
    if path.is_absolute() {
        path.file_name()
            .and_then(|value| value.to_str())
            .map(ToString::to_string)
    } else if !profile.trim().is_empty() {
        Some(profile.to_string())
    } else {
        None
    }
}

fn resolve_profile_or_command_path(profile: &str, comm: Option<&str>) -> Option<PathBuf> {
    let mut candidates = Vec::new();
    if Path::new(profile).is_absolute() {
        candidates.push(PathBuf::from(profile));
    }
    if let Some(name) = profile_display_name(profile) {
        candidates.push(Path::new("/usr/sbin").join(&name));
        candidates.push(Path::new("/usr/bin").join(&name));
        candidates.push(Path::new("/sbin").join(&name));
        candidates.push(Path::new("/bin").join(&name));
        candidates.push(Path::new("/usr/libexec").join(&name));
    }
    if let Some(comm) = comm.filter(|value| !value.trim().is_empty()) {
        candidates.push(Path::new("/usr/sbin").join(comm));
        candidates.push(Path::new("/usr/bin").join(comm));
        candidates.push(Path::new("/sbin").join(comm));
        candidates.push(Path::new("/bin").join(comm));
        candidates.push(Path::new("/usr/libexec").join(comm));
    }
    candidates.into_iter().find(|candidate| candidate.exists())
}

fn collect_perf_hotspots(config: &FixerConfig, store: &Store) -> Result<usize> {
    if !store.capability_available("perf")? {
        return Ok(0);
    }
    let targets = store.list_popular_binary_profiles(PERF_PROFILE_TARGET_LIMIT * 2)?;
    if targets.is_empty() {
        return Ok(0);
    }
    let perf_dir = config.service.state_dir.join("perf");
    let investigations_dir = config.service.state_dir.join("investigations");
    fs::create_dir_all(&perf_dir)?;
    fs::create_dir_all(&investigations_dir)?;
    prune_runaway_investigation_artifacts(
        &investigations_dir,
        config.service.hotspot_investigation_retention_days,
    )?;
    let richer_evidence_allowed = richer_evidence_enabled(config, store);
    let strace_available = store.capability_available("strace")?;
    let mut count = 0;
    let mut assessed_targets = Vec::new();
    let mut current_fingerprints = Vec::new();
    let mut assessed_investigation_sources = Vec::new();
    let mut current_investigation_fingerprints = Vec::new();
    let mut investigation_budget = config.service.hotspot_investigation_limit;

    let mut profiled_targets = 0usize;
    for target in targets.into_iter().filter(is_profile_candidate) {
        if profiled_targets >= PERF_PROFILE_TARGET_LIMIT {
            break;
        }
        let sampled_pids = running_pids_for_binary(&target.path);
        if sampled_pids.is_empty() {
            continue;
        }
        let Some(profile) = profile_popular_binary(config, &perf_dir, &target, &sampled_pids)?
        else {
            continue;
        };
        profiled_targets += 1;
        let target_path = target.path.to_string_lossy().to_string();
        assessed_targets.push(target_path);
        for (index, hot_path) in profile
            .hot_paths
            .iter()
            .take(PERF_TOP_HOTSPOTS_PER_TARGET)
            .enumerate()
        {
            let artifact_path = hot_path
                .dso_path
                .clone()
                .unwrap_or_else(|| target.path.clone());
            let artifact = ObservedArtifact {
                kind: "binary".to_string(),
                name: artifact_path
                    .file_name()
                    .and_then(|value| value.to_str())
                    .unwrap_or(&target.name)
                    .to_string(),
                path: Some(artifact_path.clone()),
                package_name: hot_path
                    .package_name
                    .clone()
                    .or_else(|| target.package_name.clone()),
                repo_root: None,
                ecosystem: None,
                metadata: json!({
                    "source": "perf",
                    "profile_target_name": target.name,
                    "profile_target_path": target.path,
                    "profile_target_package_name": target.package_name,
                    "process_count": target.process_count,
                    "total_cpu_percent": target.total_cpu_percent,
                    "max_cpu_percent": target.max_cpu_percent,
                    "sampled_pids": profile.sampled_pids,
                }),
            };
            let dso_display = hot_path
                .dso_path
                .as_ref()
                .map(|path| path.display().to_string())
                .unwrap_or_else(|| hot_path.dso.clone());
            let title = format!(
                "CPU hotspot in {}: {}",
                target.name,
                summarize_hot_symbol(&hot_path.symbol)
            );
            let summary = format!(
                "{:.2}% of sampled CPU in {} went through {} ({})",
                hot_path.percent, target.name, hot_path.symbol, dso_display
            );
            let fingerprint = hash_text(format!(
                "perf-hotspot:{}:{}:{}",
                target.path.display(),
                hot_path
                    .dso_path
                    .as_ref()
                    .unwrap_or(&PathBuf::from(&hot_path.dso))
                    .display(),
                hot_path.symbol
            ));
            current_fingerprints.push(fingerprint.clone());
            let finding = FindingInput {
                kind: "hotspot".to_string(),
                title,
                severity: "medium".to_string(),
                fingerprint,
                summary,
                details: json!({
                    "subsystem": "perf-hotspot",
                    "profile_scope": "popular-binary",
                    "profile_duration_seconds": config.service.perf_duration_seconds,
                    "perf_data": profile.data_path,
                    "profile_target": {
                        "name": target.name,
                        "path": target.path,
                        "package_name": target.package_name,
                        "process_count": target.process_count,
                        "total_cpu_percent": target.total_cpu_percent,
                        "max_cpu_percent": target.max_cpu_percent,
                    },
                    "sampled_pids": profile.sampled_pids,
                    "sampled_pid_count": profile.sampled_pids.len(),
                    "hot_path_rank": index + 1,
                    "hot_path_percent": hot_path.percent,
                    "hot_path_comm": hot_path.comm,
                    "hot_path_symbol": hot_path.symbol,
                    "hot_path_dso": hot_path.dso,
                    "hot_path_dso_path": hot_path.dso_path,
                    "hot_path_package_name": hot_path.package_name,
                    "hot_paths": profile.hot_paths,
                }),
                artifact: Some(artifact),
                repo_root: None,
                ecosystem: None,
            };
            let _ = store.record_finding(&finding)?;
            count += 1;
        }
        if config.service.auto_investigate_hotspots && strace_available && investigation_budget > 0
        {
            let Some(primary_hot_path) = profile.hot_paths.first() else {
                continue;
            };
            let source_profile_fingerprint = runaway_investigation_source_fingerprint(&target);
            assessed_investigation_sources.push(source_profile_fingerprint.clone());
            if let Some(outcome) = maybe_record_runaway_investigation(
                config,
                store,
                &investigations_dir,
                &target,
                &profile,
                primary_hot_path,
                &source_profile_fingerprint,
                richer_evidence_allowed,
            )? {
                current_investigation_fingerprints.push(outcome.finding_fingerprint);
                if outcome.created {
                    count += 1;
                    investigation_budget = investigation_budget.saturating_sub(1);
                }
            }
        }
    }
    if !assessed_targets.is_empty() {
        store.prune_perf_hotspot_findings(&assessed_targets, &current_fingerprints)?;
    }
    if !assessed_investigation_sources.is_empty() {
        assessed_investigation_sources.sort();
        assessed_investigation_sources.dedup();
        current_investigation_fingerprints.sort();
        current_investigation_fingerprints.dedup();
        store.prune_runaway_investigation_findings(
            &assessed_investigation_sources,
            &current_investigation_fingerprints,
        )?;
    }
    Ok(count)
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
struct PerfHotPath {
    percent: f64,
    comm: String,
    dso: String,
    dso_path: Option<PathBuf>,
    package_name: Option<String>,
    symbol: String,
}

#[derive(Debug, Clone)]
struct PerfProfileCapture {
    data_path: PathBuf,
    sampled_pids: Vec<i32>,
    hot_paths: Vec<PerfHotPath>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct RunawayInvestigationCheckpoint {
    captured_at: String,
    finding_fingerprint: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
struct RunawaySyscallStat {
    name: String,
    count: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
struct RunawayHypothesis {
    classification: String,
    confidence: f64,
    explanation: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
struct RunawayPackageMetadata {
    package_name: String,
    source_package: Option<String>,
    installed_version: Option<String>,
    candidate_version: Option<String>,
    homepage: Option<String>,
    report_url: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
struct RunawayInvestigationSummary {
    sampled_pid: i32,
    sampled_pid_count: usize,
    command_line: Option<String>,
    executable: Option<String>,
    process_state: Option<String>,
    wchan: Option<String>,
    top_hot_symbols: Vec<String>,
    top_syscalls: Vec<RunawaySyscallStat>,
    dominant_sequence: Vec<String>,
    strace_line_count: usize,
    strace_excerpt: Vec<String>,
    status_excerpt: Option<String>,
    sched_excerpt: Option<String>,
    stack_excerpt: Option<String>,
    hypothesis: RunawayHypothesis,
    raw_artifacts: BTreeMap<String, String>,
    package_metadata: Option<RunawayPackageMetadata>,
}

#[derive(Debug, Clone)]
struct RunawayInvestigationOutcome {
    finding_fingerprint: String,
    created: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
struct StuckProcessInvestigationSummary {
    sampled_pid: i32,
    sampled_pid_count: usize,
    sampled_pids: Vec<i32>,
    command_line: Option<String>,
    executable: Option<String>,
    process_state: Option<String>,
    runtime_seconds: u64,
    wchan: Option<String>,
    cwd: Option<String>,
    root: Option<String>,
    fd_targets: Vec<String>,
    io_excerpt: Option<String>,
    status_excerpt: Option<String>,
    sched_excerpt: Option<String>,
    stack_excerpt: Option<String>,
    hypothesis: RunawayHypothesis,
    likely_external_root_cause: bool,
    raw_artifacts: BTreeMap<String, String>,
    package_metadata: Option<RunawayPackageMetadata>,
}

#[derive(Debug, Clone)]
struct StraceCapture {
    raw_log: String,
    stderr: Option<String>,
    log_path: PathBuf,
}

fn maybe_record_runaway_investigation(
    config: &FixerConfig,
    store: &Store,
    investigations_dir: &Path,
    target: &PopularBinaryProfile,
    profile: &PerfProfileCapture,
    hot_path: &PerfHotPath,
    source_profile_fingerprint: &str,
    include_richer_evidence: bool,
) -> Result<Option<RunawayInvestigationOutcome>> {
    let state_key = runaway_investigation_state_key(source_profile_fingerprint);
    if let Some(checkpoint) = store.get_local_state::<RunawayInvestigationCheckpoint>(&state_key)? {
        if investigation_cooldown_active(
            &checkpoint.captured_at,
            config.service.hotspot_investigation_cooldown_seconds,
        ) {
            return Ok(Some(RunawayInvestigationOutcome {
                finding_fingerprint: checkpoint.finding_fingerprint,
                created: false,
            }));
        }
    }

    let Some(sampled_pid) = sampled_pid_for_hot_path(profile, hot_path) else {
        return Ok(None);
    };
    let capture_timestamp = now_rfc3339();
    let capture_dir = investigations_dir.join(format!(
        "{}-{}-{}",
        capture_timestamp.replace(':', "-"),
        safe_perf_name(&target.name),
        abbreviated_hash(source_profile_fingerprint)
    ));
    fs::create_dir_all(&capture_dir)?;

    let proc_snapshot = collect_proc_snapshot(sampled_pid, &capture_dir)?;
    let strace_capture = capture_strace_sample(
        sampled_pid,
        config.service.hotspot_investigation_strace_seconds,
        &capture_dir.join("strace.log"),
    )?;
    let top_hot_symbols = investigation_hot_symbol_summaries(profile);
    let strace_lines = strace_capture
        .as_ref()
        .map(|capture| normalized_strace_lines(&capture.raw_log))
        .unwrap_or_default();
    let syscall_names = parse_strace_syscall_names(&strace_lines);
    let top_syscalls = summarize_top_syscalls(&syscall_names);
    let dominant_sequence = dominant_syscall_sequence(&syscall_names);
    let hypothesis = classify_runaway_loop(&strace_lines, &top_syscalls, &top_hot_symbols);
    let package_name = target.package_name.clone();
    let package_metadata = package_name
        .as_deref()
        .and_then(resolve_installed_package_metadata_for_investigation);
    let implicated_package_names = profile
        .hot_paths
        .iter()
        .filter_map(|path| path.package_name.clone())
        .filter(|name| Some(name.as_str()) != target.package_name.as_deref())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect::<Vec<_>>();

    let investigation = build_runaway_investigation_summary(
        sampled_pid,
        profile,
        &top_hot_symbols,
        &top_syscalls,
        &dominant_sequence,
        &hypothesis,
        &proc_snapshot,
        strace_capture.as_ref(),
        package_metadata,
        include_richer_evidence,
    );
    let fingerprint = runaway_investigation_fingerprint(
        target,
        &investigation.top_hot_symbols,
        &investigation.top_syscalls,
        &investigation.dominant_sequence,
        &investigation.hypothesis,
    );
    let summary = runaway_investigation_summary_line(target, hot_path, &investigation);
    let artifact = ObservedArtifact {
        kind: "binary".to_string(),
        name: target.name.clone(),
        path: Some(target.path.clone()),
        package_name,
        repo_root: None,
        ecosystem: None,
        metadata: json!({
            "source": "runaway-process-investigation",
            "profile_target_name": target.name,
            "profile_target_path": target.path,
            "profile_target_package_name": target.package_name,
            "sampled_pids": profile.sampled_pids,
        }),
    };
    let details = json!({
        "subsystem": RUNAWAY_INVESTIGATION_SUBSYSTEM,
        "source_profile_fingerprint": source_profile_fingerprint,
        "source_hotspot_kind": "perf-profile",
        "profile_duration_seconds": config.service.perf_duration_seconds,
        "strace_duration_seconds": config.service.hotspot_investigation_strace_seconds,
        "profile_target": {
            "name": target.name,
            "path": target.path,
            "package_name": target.package_name,
            "process_count": target.process_count,
            "total_cpu_percent": target.total_cpu_percent,
            "max_cpu_percent": target.max_cpu_percent,
        },
        "sampled_pids": profile.sampled_pids,
        "sampled_pid_count": profile.sampled_pids.len(),
        "sampled_pid": sampled_pid,
        "hot_path_symbol": hot_path.symbol,
        "hot_path_dso": hot_path.dso,
        "hot_path_percent": hot_path.percent,
        "implicated_package_names": implicated_package_names,
        "top_hot_symbols": investigation.top_hot_symbols,
        "top_syscalls": investigation.top_syscalls,
        "dominant_sequence": investigation.dominant_sequence,
        "strace_line_count": investigation.strace_line_count,
        "process_state": investigation.process_state,
        "wchan": investigation.wchan,
        "loop_classification": investigation.hypothesis.classification,
        "loop_confidence": investigation.hypothesis.confidence,
        "loop_explanation": investigation.hypothesis.explanation,
        "package_metadata": investigation.package_metadata,
        "richer_evidence_included": include_richer_evidence,
        "command_line": investigation.command_line,
        "executable": investigation.executable,
        "strace_excerpt": investigation.strace_excerpt,
        "status_excerpt": investigation.status_excerpt,
        "sched_excerpt": investigation.sched_excerpt,
        "stack_excerpt": investigation.stack_excerpt,
        "raw_artifacts": investigation.raw_artifacts,
    });
    let finding = FindingInput {
        kind: "investigation".to_string(),
        title: format!("Runaway CPU investigation for {}", target.name),
        severity: "high".to_string(),
        fingerprint: fingerprint.clone(),
        summary,
        details,
        artifact: Some(artifact),
        repo_root: None,
        ecosystem: None,
    };
    let _ = store.record_finding(&finding)?;
    store.set_local_state(
        &state_key,
        &RunawayInvestigationCheckpoint {
            captured_at: capture_timestamp,
            finding_fingerprint: fingerprint.clone(),
        },
    )?;
    Ok(Some(RunawayInvestigationOutcome {
        finding_fingerprint: fingerprint,
        created: true,
    }))
}

fn maybe_record_stuck_process_investigation(
    config: &FixerConfig,
    store: &Store,
    investigations_dir: &Path,
    group: &StuckProcessGroup,
    source_process_fingerprint: &str,
    include_richer_evidence: bool,
) -> Result<Option<RunawayInvestigationOutcome>> {
    let state_key = stuck_process_investigation_state_key(source_process_fingerprint);
    if let Some(checkpoint) = store.get_local_state::<RunawayInvestigationCheckpoint>(&state_key)? {
        if investigation_cooldown_active(
            &checkpoint.captured_at,
            config.service.stuck_process_investigation_cooldown_seconds,
        ) {
            return Ok(Some(RunawayInvestigationOutcome {
                finding_fingerprint: checkpoint.finding_fingerprint,
                created: false,
            }));
        }
    }

    let capture_timestamp = now_rfc3339();
    let capture_dir = investigations_dir.join(format!(
        "{}-{}-{}",
        capture_timestamp.replace(':', "-"),
        safe_perf_name(&group.name),
        abbreviated_hash(source_process_fingerprint)
    ));
    fs::create_dir_all(&capture_dir)?;

    let proc_snapshot = collect_proc_snapshot(group.sample_pid, &capture_dir)?;
    let hypothesis = classify_stuck_process(
        proc_snapshot.stack_excerpt.as_deref(),
        proc_snapshot.wchan.as_deref(),
        &proc_snapshot.fd_targets,
    );
    let package_metadata = group
        .package_name
        .as_deref()
        .and_then(resolve_installed_package_metadata_for_investigation);
    let investigation = build_stuck_process_investigation_summary(
        group,
        &proc_snapshot,
        &hypothesis,
        package_metadata,
        include_richer_evidence,
    );
    let fingerprint = stuck_process_investigation_fingerprint(group, &investigation);
    let summary = stuck_process_investigation_summary_line(group, &investigation);
    let artifact = ObservedArtifact {
        kind: "binary".to_string(),
        name: group.name.clone(),
        path: group.executable.clone(),
        package_name: group.package_name.clone(),
        repo_root: None,
        ecosystem: None,
        metadata: json!({
            "source": "stuck-process-investigation",
            "profile_target_name": group.name,
            "sampled_pids": group.pids.clone(),
        }),
    };
    let details = json!({
        "subsystem": STUCK_PROCESS_INVESTIGATION_SUBSYSTEM,
        "source_process_fingerprint": source_process_fingerprint,
        "blocked_process_kind": "uninterruptible-sleep",
        "profile_target": {
            "name": group.name,
            "path": group.executable.as_ref().map(|path| path.display().to_string()),
            "package_name": group.package_name.clone(),
            "process_count": group.pids.len(),
        },
        "sampled_pids": investigation.sampled_pids,
        "sampled_pid_count": investigation.sampled_pid_count,
        "sampled_pid": group.sample_pid,
        "runtime_seconds": investigation.runtime_seconds,
        "process_state": investigation.process_state,
        "wchan": investigation.wchan,
        "cwd": investigation.cwd,
        "root": investigation.root,
        "fd_targets": investigation.fd_targets,
        "io_excerpt": investigation.io_excerpt,
        "stack_excerpt": investigation.stack_excerpt,
        "status_excerpt": investigation.status_excerpt,
        "sched_excerpt": investigation.sched_excerpt,
        "loop_classification": investigation.hypothesis.classification,
        "loop_confidence": investigation.hypothesis.confidence,
        "loop_explanation": investigation.hypothesis.explanation,
        "likely_external_root_cause": investigation.likely_external_root_cause,
        "package_metadata": investigation.package_metadata,
        "richer_evidence_included": include_richer_evidence,
        "command_line": investigation.command_line,
        "executable": investigation.executable,
        "raw_artifacts": investigation.raw_artifacts,
    });
    let finding = FindingInput {
        kind: "investigation".to_string(),
        title: format!("Stuck D-state investigation for {}", group.name),
        severity: "high".to_string(),
        fingerprint: fingerprint.clone(),
        summary,
        details,
        artifact: Some(artifact),
        repo_root: None,
        ecosystem: None,
    };
    let _ = store.record_finding(&finding)?;
    store.set_local_state(
        &state_key,
        &RunawayInvestigationCheckpoint {
            captured_at: capture_timestamp,
            finding_fingerprint: fingerprint.clone(),
        },
    )?;
    Ok(Some(RunawayInvestigationOutcome {
        finding_fingerprint: fingerprint,
        created: true,
    }))
}

fn richer_evidence_enabled(config: &FixerConfig, store: &Store) -> bool {
    if !config.privacy.require_secondary_opt_in_for_richer_evidence {
        return true;
    }
    store
        .load_participation_state()
        .ok()
        .flatten()
        .map(|state| state.richer_evidence_allowed)
        .unwrap_or(config.participation.richer_evidence_allowed)
}

fn runaway_investigation_state_key(source_hotspot_fingerprint: &str) -> String {
    format!("runaway-investigation:{source_hotspot_fingerprint}")
}

fn stuck_process_investigation_state_key(source_process_fingerprint: &str) -> String {
    format!("stuck-process-investigation:{source_process_fingerprint}")
}

fn investigation_cooldown_active(captured_at: &str, cooldown_seconds: u64) -> bool {
    let Ok(parsed) = DateTime::parse_from_rfc3339(captured_at) else {
        return false;
    };
    Utc::now() - parsed.with_timezone(&Utc) < ChronoDuration::seconds(cooldown_seconds as i64)
}

fn abbreviated_hash(fingerprint: &str) -> &str {
    fingerprint.get(..12).unwrap_or(fingerprint)
}

fn sampled_pid_for_hot_path(profile: &PerfProfileCapture, hot_path: &PerfHotPath) -> Option<i32> {
    profile
        .sampled_pids
        .iter()
        .copied()
        .find(|pid| process_comm(*pid).as_deref() == Some(hot_path.comm.as_str()))
        .or_else(|| profile.sampled_pids.first().copied())
}

fn process_comm(pid: i32) -> Option<String> {
    fs::read_to_string(format!("/proc/{pid}/comm"))
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
}

#[derive(Debug, Clone)]
struct ProcSnapshot {
    command_line: Option<String>,
    executable: Option<String>,
    process_state: Option<String>,
    wchan: Option<String>,
    cwd: Option<String>,
    root: Option<String>,
    fd_targets: Vec<String>,
    io_excerpt: Option<String>,
    status_excerpt: Option<String>,
    sched_excerpt: Option<String>,
    stack_excerpt: Option<String>,
    raw_artifacts: BTreeMap<String, String>,
}

fn collect_proc_snapshot(pid: i32, capture_dir: &Path) -> Result<ProcSnapshot> {
    let mut raw_artifacts = BTreeMap::new();
    let command_line = read_proc_cmdline(pid);
    if let Some(value) = &command_line {
        let path = capture_dir.join("cmdline.txt");
        fs::write(&path, value)?;
        raw_artifacts.insert("cmdline".to_string(), path.display().to_string());
    }

    let executable = fs::read_link(format!("/proc/{pid}/exe"))
        .ok()
        .map(|path| path.display().to_string());
    if let Some(value) = &executable {
        let path = capture_dir.join("exe.txt");
        fs::write(&path, value)?;
        raw_artifacts.insert("exe".to_string(), path.display().to_string());
    }

    let cwd = fs::read_link(format!("/proc/{pid}/cwd"))
        .ok()
        .map(|path| path.display().to_string());
    if let Some(value) = &cwd {
        let path = capture_dir.join("cwd.txt");
        fs::write(&path, value)?;
        raw_artifacts.insert("cwd".to_string(), path.display().to_string());
    }

    let root = fs::read_link(format!("/proc/{pid}/root"))
        .ok()
        .map(|path| path.display().to_string());
    if let Some(value) = &root {
        let path = capture_dir.join("root.txt");
        fs::write(&path, value)?;
        raw_artifacts.insert("root".to_string(), path.display().to_string());
    }

    let status_raw = fs::read_to_string(format!("/proc/{pid}/status")).ok();
    if let Some(raw) = &status_raw {
        let path = capture_dir.join("status.txt");
        fs::write(&path, raw)?;
        raw_artifacts.insert("status".to_string(), path.display().to_string());
    }

    let sched_raw = fs::read_to_string(format!("/proc/{pid}/sched")).ok();
    if let Some(raw) = &sched_raw {
        let path = capture_dir.join("sched.txt");
        fs::write(&path, raw)?;
        raw_artifacts.insert("sched".to_string(), path.display().to_string());
    }

    let io_raw = fs::read_to_string(format!("/proc/{pid}/io")).ok();
    if let Some(raw) = &io_raw {
        let path = capture_dir.join("io.txt");
        fs::write(&path, raw)?;
        raw_artifacts.insert("io".to_string(), path.display().to_string());
    }

    let stack_raw = fs::read_to_string(format!("/proc/{pid}/stack")).ok();
    if let Some(raw) = &stack_raw {
        let path = capture_dir.join("stack.txt");
        fs::write(&path, raw)?;
        raw_artifacts.insert("stack".to_string(), path.display().to_string());
    }

    let wchan = fs::read_to_string(format!("/proc/{pid}/wchan"))
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty());
    if let Some(value) = &wchan {
        let path = capture_dir.join("wchan.txt");
        fs::write(&path, value)?;
        raw_artifacts.insert("wchan".to_string(), path.display().to_string());
    }

    let fd_targets = collect_fd_targets(pid, STUCK_PROCESS_FD_TARGET_LIMIT);
    if !fd_targets.is_empty() {
        let path = capture_dir.join("fd-targets.txt");
        fs::write(&path, fd_targets.join("\n"))?;
        raw_artifacts.insert("fd_targets".to_string(), path.display().to_string());
    }

    Ok(ProcSnapshot {
        command_line,
        executable,
        process_state: status_raw
            .as_deref()
            .and_then(process_state_from_status)
            .map(ToString::to_string),
        wchan,
        cwd,
        root,
        fd_targets,
        io_excerpt: io_raw
            .as_deref()
            .map(|raw| excerpt_lines(raw, RUNAWAY_STRACE_EXCERPT_LIMIT)),
        status_excerpt: status_raw
            .as_deref()
            .map(|raw| excerpt_lines(raw, RUNAWAY_STRACE_EXCERPT_LIMIT)),
        sched_excerpt: sched_raw
            .as_deref()
            .map(|raw| excerpt_lines(raw, RUNAWAY_STRACE_EXCERPT_LIMIT)),
        stack_excerpt: stack_raw
            .as_deref()
            .map(|raw| excerpt_lines(raw, RUNAWAY_STRACE_EXCERPT_LIMIT)),
        raw_artifacts,
    })
}

fn collect_fd_targets(pid: i32, limit: usize) -> Vec<String> {
    let mut targets = BTreeSet::new();
    let Ok(entries) = fs::read_dir(format!("/proc/{pid}/fd")) else {
        return Vec::new();
    };
    for entry in entries.flatten() {
        let Ok(target) = fs::read_link(entry.path()) else {
            continue;
        };
        let target = target.display().to_string();
        if target.starts_with("anon_inode:")
            || target.starts_with("socket:[")
            || target.starts_with("pipe:[")
        {
            continue;
        }
        targets.insert(target);
        if targets.len() >= limit {
            break;
        }
    }
    targets.into_iter().collect()
}

fn read_proc_cmdline(pid: i32) -> Option<String> {
    let raw = fs::read(format!("/proc/{pid}/cmdline")).ok()?;
    let text = raw
        .split(|byte| *byte == 0)
        .filter(|part| !part.is_empty())
        .map(|part| String::from_utf8_lossy(part).to_string())
        .collect::<Vec<_>>()
        .join(" ");
    (!text.trim().is_empty()).then_some(text)
}

fn capture_strace_sample(
    pid: i32,
    duration_seconds: u64,
    output_path: &Path,
) -> Result<Option<StraceCapture>> {
    let mut child = match Command::new("strace")
        .env("LC_ALL", "C")
        .args([
            "-ttT",
            "-f",
            "-s",
            "160",
            "-o",
            output_path.to_string_lossy().as_ref(),
            "-p",
            &pid.to_string(),
        ])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
    {
        Ok(child) => child,
        Err(_) => return Ok(None),
    };

    thread::sleep(StdDuration::from_secs(duration_seconds.max(1)));
    let _ = child.kill();
    let output = child.wait_with_output()?;
    let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
    let raw_log = fs::read_to_string(output_path).unwrap_or_default();
    if raw_log.trim().is_empty() {
        return Ok(None);
    }
    Ok(Some(StraceCapture {
        raw_log,
        stderr: (!stderr.is_empty()).then_some(stderr),
        log_path: output_path.to_path_buf(),
    }))
}

fn normalized_strace_lines(raw: &str) -> Vec<String> {
    raw.lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .filter(|line| !line.starts_with("strace:"))
        .map(ToString::to_string)
        .collect()
}

fn parse_strace_syscall_names(lines: &[String]) -> Vec<String> {
    lines
        .iter()
        .filter_map(|line| parse_strace_syscall_name(line))
        .collect()
}

fn parse_strace_syscall_name(line: &str) -> Option<String> {
    let mut text = line.trim();
    loop {
        if let Some(rest) = text.strip_prefix("[pid ") {
            text = rest.split_once(']')?.1.trim_start();
            continue;
        }
        if let Some((prefix, rest)) = text.split_once(' ') {
            if prefix
                .chars()
                .all(|ch| ch.is_ascii_digit() || ch == ':' || ch == '.')
            {
                text = rest.trim_start();
                continue;
            }
        }
        break;
    }
    let name_end = text.find('(')?;
    let name = text[..name_end].trim();
    (!name.is_empty()).then(|| name.to_string())
}

fn summarize_top_syscalls(syscalls: &[String]) -> Vec<RunawaySyscallStat> {
    let mut counts = HashMap::<String, usize>::new();
    for syscall in syscalls {
        *counts.entry(syscall.clone()).or_insert(0) += 1;
    }
    let mut items = counts
        .into_iter()
        .map(|(name, count)| RunawaySyscallStat { name, count })
        .collect::<Vec<_>>();
    items.sort_by(|left, right| {
        right
            .count
            .cmp(&left.count)
            .then_with(|| left.name.cmp(&right.name))
    });
    items.truncate(RUNAWAY_TOP_SYSCALL_LIMIT);
    items
}

fn dominant_syscall_sequence(syscalls: &[String]) -> Vec<String> {
    if syscalls.len() < RUNAWAY_SEQUENCE_WINDOW {
        return syscalls.to_vec();
    }
    let mut counts = HashMap::<Vec<String>, usize>::new();
    for window in syscalls.windows(RUNAWAY_SEQUENCE_WINDOW) {
        let key = window.to_vec();
        *counts.entry(key).or_insert(0) += 1;
    }
    counts
        .into_iter()
        .max_by(|left, right| {
            left.1
                .cmp(&right.1)
                .then_with(|| right.0.join(">").cmp(&left.0.join(">")))
        })
        .map(|(sequence, _)| sequence)
        .unwrap_or_default()
}

fn classify_runaway_loop(
    strace_lines: &[String],
    top_syscalls: &[RunawaySyscallStat],
    top_hot_symbols: &[String],
) -> RunawayHypothesis {
    let lower_lines = strace_lines.join("\n").to_ascii_lowercase();
    let lower_symbols = top_hot_symbols.join("\n").to_ascii_lowercase();
    let top_names = top_syscalls
        .iter()
        .map(|item| item.name.as_str())
        .collect::<Vec<_>>();

    if lower_lines.contains("/run/dbus")
        || lower_lines.contains("org.freedesktop")
        || lower_symbols.contains("qdbus")
        || lower_symbols.contains("dbus")
    {
        return RunawayHypothesis {
            classification: "dbus-spin".to_string(),
            confidence: 0.9,
            explanation:
                "The trace is dominated by DBus-style socket activity and DBus-related symbols, which looks like a message-loop spin."
                    .to_string(),
        };
    }
    if top_names.iter().any(|name| {
        matches!(
            *name,
            "poll" | "ppoll" | "epoll_wait" | "select" | "pselect6"
        )
    }) {
        return RunawayHypothesis {
            classification: "busy-poll".to_string(),
            confidence: 0.78,
            explanation:
                "The trace repeatedly returns to a poll-family syscall without meaningful blocking, which suggests a busy event-loop wakeup."
                    .to_string(),
        };
    }
    if top_names.iter().any(|name| {
        matches!(
            *name,
            "recvmsg" | "sendmsg" | "recvfrom" | "sendto" | "connect" | "socket" | "getsockopt"
        )
    }) {
        return RunawayHypothesis {
            classification: "socket-churn".to_string(),
            confidence: 0.72,
            explanation:
                "The trace is dominated by socket syscalls, which suggests the process is rapidly retrying or churning through network or IPC work."
                    .to_string(),
        };
    }
    if top_names.iter().any(|name| {
        matches!(
            *name,
            "timerfd_settime" | "timerfd_gettime" | "clock_nanosleep" | "nanosleep"
        )
    }) || lower_symbols.contains("timer")
    {
        return RunawayHypothesis {
            classification: "timer-churn".to_string(),
            confidence: 0.68,
            explanation:
                "Timer-related syscalls or symbols dominate the sample, which suggests a wakeup timer is firing too aggressively."
                    .to_string(),
        };
    }
    if lower_lines.contains("enoent")
        && top_names.iter().any(|name| {
            matches!(
                *name,
                "openat" | "openat2" | "access" | "faccessat2" | "statx" | "newfstatat"
            )
        })
    {
        return RunawayHypothesis {
            classification: "file-not-found-retry".to_string(),
            confidence: 0.84,
            explanation:
                "The trace keeps retrying file lookups that fail with ENOENT, which suggests a missing-file retry loop."
                    .to_string(),
        };
    }
    RunawayHypothesis {
        classification: "unknown-userspace-loop".to_string(),
        confidence: 0.42,
        explanation:
            "The process is demonstrably CPU-hot, but the current syscall and symbol sample does not point to a single dominant loop family yet."
                .to_string(),
    }
}

fn classify_stuck_process(
    stack_excerpt: Option<&str>,
    wchan: Option<&str>,
    fd_targets: &[String],
) -> RunawayHypothesis {
    let stack = stack_excerpt.unwrap_or_default().to_ascii_lowercase();
    let wchan = wchan.unwrap_or_default().to_ascii_lowercase();
    let fd_targets = fd_targets.join("\n").to_ascii_lowercase();

    if stack.contains("fuse") || wchan.contains("fuse") {
        return RunawayHypothesis {
            classification: "fuse-wait".to_string(),
            confidence: 0.91,
            explanation:
                "The kernel stack and wait channel point to FUSE request handling, so the process is likely blocked behind a userspace filesystem response."
                    .to_string(),
        };
    }
    if stack.contains("nfs") || stack.contains("sunrpc") || wchan.contains("nfs") {
        return RunawayHypothesis {
            classification: "nfs-wait".to_string(),
            confidence: 0.88,
            explanation:
                "The kernel stack points to NFS or RPC wait paths, which suggests the process is blocked on remote filesystem I/O."
                    .to_string(),
        };
    }
    if stack.contains("overlay") || wchan.contains("overlay") {
        return RunawayHypothesis {
            classification: "overlayfs-wait".to_string(),
            confidence: 0.77,
            explanation:
                "The kernel stack references overlayfs paths, which suggests the process is blocked on layered filesystem metadata or backing-store I/O."
                    .to_string(),
        };
    }
    if stack.contains("ext4")
        || stack.contains("xfs")
        || stack.contains("btrfs")
        || wchan.contains("io_schedule")
        || stack.contains("submit_bio")
        || stack.contains("blk_")
    {
        return RunawayHypothesis {
            classification: "filesystem-io-wait".to_string(),
            confidence: 0.73,
            explanation:
                "The kernel stack points to block or filesystem wait paths, so the process appears to be stuck below user space waiting for storage I/O."
                    .to_string(),
        };
    }
    if fd_targets.contains("/mnt/")
        || fd_targets.contains("/media/")
        || fd_targets.contains("/run/user/")
    {
        return RunawayHypothesis {
            classification: "mount-io-wait".to_string(),
            confidence: 0.58,
            explanation:
                "The process is blocked in `D` state while holding file descriptors on a mount-like path, which suggests a stuck filesystem or mount backend."
                    .to_string(),
        };
    }
    RunawayHypothesis {
        classification: "unknown-uninterruptible-wait".to_string(),
        confidence: 0.38,
        explanation:
            "The process is stuck in `D` state, but the current `/proc` evidence does not yet isolate which kernel or filesystem path is blocking it."
                .to_string(),
    }
}

fn resolve_installed_package_metadata_for_investigation(
    package_name: &str,
) -> Option<RunawayPackageMetadata> {
    let metadata = resolve_installed_package_metadata(package_name).ok()?;
    Some(RunawayPackageMetadata {
        package_name: metadata.package_name,
        source_package: Some(metadata.source_package),
        installed_version: metadata.installed_version,
        candidate_version: metadata.candidate_version,
        homepage: metadata.homepage,
        report_url: metadata.report_url,
    })
}

fn build_runaway_investigation_summary(
    sampled_pid: i32,
    profile: &PerfProfileCapture,
    top_hot_symbols: &[String],
    top_syscalls: &[RunawaySyscallStat],
    dominant_sequence: &[String],
    hypothesis: &RunawayHypothesis,
    proc_snapshot: &ProcSnapshot,
    strace_capture: Option<&StraceCapture>,
    package_metadata: Option<RunawayPackageMetadata>,
    include_richer_evidence: bool,
) -> RunawayInvestigationSummary {
    let mut raw_artifacts = proc_snapshot.raw_artifacts.clone();
    if let Some(strace_capture) = strace_capture {
        raw_artifacts.insert(
            "strace".to_string(),
            strace_capture.log_path.display().to_string(),
        );
        if let Some(stderr) = &strace_capture.stderr {
            let stderr_path = strace_capture.log_path.with_extension("stderr.txt");
            let _ = fs::write(&stderr_path, stderr);
            raw_artifacts.insert(
                "strace_stderr".to_string(),
                stderr_path.display().to_string(),
            );
        }
    }
    let excerpt = strace_capture
        .map(|capture| excerpt_list(&capture.raw_log, RUNAWAY_STRACE_EXCERPT_LIMIT))
        .unwrap_or_default();
    RunawayInvestigationSummary {
        sampled_pid,
        sampled_pid_count: profile.sampled_pids.len(),
        command_line: include_richer_evidence
            .then(|| proc_snapshot.command_line.clone())
            .flatten(),
        executable: include_richer_evidence
            .then(|| proc_snapshot.executable.clone())
            .flatten(),
        process_state: proc_snapshot.process_state.clone(),
        wchan: proc_snapshot.wchan.clone(),
        top_hot_symbols: top_hot_symbols.to_vec(),
        top_syscalls: top_syscalls.to_vec(),
        dominant_sequence: dominant_sequence.to_vec(),
        strace_line_count: strace_capture
            .map(|capture| normalized_strace_lines(&capture.raw_log).len())
            .unwrap_or_default(),
        strace_excerpt: if include_richer_evidence {
            excerpt
        } else {
            Vec::new()
        },
        status_excerpt: if include_richer_evidence {
            proc_snapshot.status_excerpt.clone()
        } else {
            None
        },
        sched_excerpt: if include_richer_evidence {
            proc_snapshot.sched_excerpt.clone()
        } else {
            None
        },
        stack_excerpt: if include_richer_evidence {
            proc_snapshot.stack_excerpt.clone()
        } else {
            None
        },
        hypothesis: hypothesis.clone(),
        raw_artifacts: if include_richer_evidence {
            raw_artifacts
        } else {
            BTreeMap::new()
        },
        package_metadata,
    }
}

fn build_stuck_process_investigation_summary(
    group: &StuckProcessGroup,
    proc_snapshot: &ProcSnapshot,
    hypothesis: &RunawayHypothesis,
    package_metadata: Option<RunawayPackageMetadata>,
    include_richer_evidence: bool,
) -> StuckProcessInvestigationSummary {
    StuckProcessInvestigationSummary {
        sampled_pid: group.sample_pid,
        sampled_pid_count: group.pids.len(),
        sampled_pids: group.pids.clone(),
        command_line: include_richer_evidence
            .then(|| proc_snapshot.command_line.clone())
            .flatten(),
        executable: include_richer_evidence
            .then(|| proc_snapshot.executable.clone())
            .flatten(),
        process_state: proc_snapshot.process_state.clone(),
        runtime_seconds: group.sample_runtime_seconds,
        wchan: proc_snapshot.wchan.clone(),
        cwd: if include_richer_evidence {
            proc_snapshot.cwd.clone()
        } else {
            None
        },
        root: if include_richer_evidence {
            proc_snapshot.root.clone()
        } else {
            None
        },
        fd_targets: if include_richer_evidence {
            proc_snapshot.fd_targets.clone()
        } else {
            Vec::new()
        },
        io_excerpt: if include_richer_evidence {
            proc_snapshot.io_excerpt.clone()
        } else {
            None
        },
        status_excerpt: if include_richer_evidence {
            proc_snapshot.status_excerpt.clone()
        } else {
            None
        },
        sched_excerpt: if include_richer_evidence {
            proc_snapshot.sched_excerpt.clone()
        } else {
            None
        },
        stack_excerpt: if include_richer_evidence {
            proc_snapshot.stack_excerpt.clone()
        } else {
            None
        },
        hypothesis: hypothesis.clone(),
        likely_external_root_cause: !matches!(
            hypothesis.classification.as_str(),
            "unknown-uninterruptible-wait"
        ),
        raw_artifacts: if include_richer_evidence {
            proc_snapshot.raw_artifacts.clone()
        } else {
            BTreeMap::new()
        },
        package_metadata,
    }
}

fn stuck_process_investigation_fingerprint(
    group: &StuckProcessGroup,
    investigation: &StuckProcessInvestigationSummary,
) -> String {
    hash_text(format!(
        "stuck-process:{}:{}:{}:{}",
        group
            .executable
            .as_ref()
            .map(|path| path.display().to_string())
            .unwrap_or_else(|| normalize_stuck_process_target_name(&group.name)),
        investigation.hypothesis.classification,
        investigation.wchan.as_deref().unwrap_or("unknown"),
        investigation
            .stack_excerpt
            .as_deref()
            .and_then(|excerpt| excerpt.lines().next())
            .unwrap_or("no-stack"),
    ))
}

fn stuck_process_investigation_summary_line(
    group: &StuckProcessGroup,
    investigation: &StuckProcessInvestigationSummary,
) -> String {
    let wait_point = investigation
        .wchan
        .as_deref()
        .unwrap_or("an unknown wait point");
    format!(
        "{} has {} process(es) stuck in `D` state for at least {}s, likely blocked in {} via {}.",
        group.name,
        investigation.sampled_pid_count,
        investigation.runtime_seconds,
        investigation.hypothesis.classification.replace('-', " "),
        wait_point,
    )
}

fn runaway_investigation_source_fingerprint(target: &PopularBinaryProfile) -> String {
    hash_text(format!(
        "runaway-process-source:{}:{}:{}",
        target.name,
        target.path.display(),
        target.package_name.as_deref().unwrap_or("unknown"),
    ))
}

fn runaway_investigation_fingerprint(
    target: &PopularBinaryProfile,
    top_hot_symbols: &[String],
    top_syscalls: &[RunawaySyscallStat],
    dominant_sequence: &[String],
    hypothesis: &RunawayHypothesis,
) -> String {
    hash_text(format!(
        "runaway-process:{}:{}:{}:{}:{}:{}:{}",
        target.name,
        target.path.display(),
        target.package_name.as_deref().unwrap_or("unknown"),
        top_hot_symbols
            .iter()
            .take(3)
            .cloned()
            .collect::<Vec<_>>()
            .join("|"),
        top_syscalls
            .iter()
            .take(3)
            .map(|item| item.name.as_str())
            .collect::<Vec<_>>()
            .join("|"),
        dominant_sequence.join(">"),
        hypothesis.classification,
    ))
}

fn runaway_investigation_summary_line(
    target: &PopularBinaryProfile,
    hot_path: &PerfHotPath,
    investigation: &RunawayInvestigationSummary,
) -> String {
    let syscall_summary = if investigation.top_syscalls.is_empty() {
        "no dominant syscall sample was captured".to_string()
    } else {
        investigation
            .top_syscalls
            .iter()
            .take(3)
            .map(|item| format!("{} x{}", item.name, item.count))
            .collect::<Vec<_>>()
            .join(", ")
    };
    format!(
        "{} is stuck in a likely {} loop: {:.2}% of sampled CPU passed through {}, with repeated {}.",
        target.name,
        investigation.hypothesis.classification.replace('-', " "),
        hot_path.percent,
        summarize_hot_symbol(&hot_path.symbol),
        syscall_summary,
    )
}

fn investigation_hot_symbol_summaries(profile: &PerfProfileCapture) -> Vec<String> {
    profile
        .hot_paths
        .iter()
        .take(5)
        .map(|hot_path| {
            let dso = hot_path
                .dso_path
                .as_ref()
                .and_then(|path| path.file_name())
                .and_then(|value| value.to_str())
                .unwrap_or(&hot_path.dso);
            format!("{} ({:.2}% in {})", hot_path.symbol, hot_path.percent, dso)
        })
        .collect()
}

fn process_state_from_status(status: &str) -> Option<&str> {
    status.lines().find_map(|line| {
        let (key, value) = line.split_once(':')?;
        (key.trim() == "State").then(|| value.trim())
    })
}

fn excerpt_lines(raw: &str, line_limit: usize) -> String {
    excerpt_list(raw, line_limit).join("\n")
}

fn excerpt_list(raw: &str, line_limit: usize) -> Vec<String> {
    raw.lines()
        .take(line_limit)
        .map(ToString::to_string)
        .collect()
}

fn prune_runaway_investigation_artifacts(root: &Path, retention_days: u64) -> Result<()> {
    if retention_days == 0 || !root.exists() {
        return Ok(());
    }
    let cutoff = std::time::SystemTime::now()
        .checked_sub(StdDuration::from_secs(
            retention_days.saturating_mul(24 * 60 * 60),
        ))
        .unwrap_or(std::time::SystemTime::UNIX_EPOCH);
    for entry in fs::read_dir(root)? {
        let entry = entry?;
        let path = entry.path();
        if !path.is_dir() {
            continue;
        }
        let Ok(metadata) = entry.metadata() else {
            continue;
        };
        let Ok(modified_at) = metadata.modified() else {
            continue;
        };
        if modified_at < cutoff {
            let _ = fs::remove_dir_all(path);
        }
    }
    Ok(())
}

fn is_profile_candidate(target: &PopularBinaryProfile) -> bool {
    target.process_count > 0
        && !matches!(
            target.name.as_str(),
            "perf" | "fixer" | "fixerd" | "fixer-server"
        )
}

fn running_pids_for_binary(target_path: &Path) -> Vec<i32> {
    let mut pids = Vec::new();
    let canonical_target = maybe_canonicalize(target_path);
    let Ok(entries) = fs::read_dir("/proc") else {
        return pids;
    };
    for entry in entries.flatten() {
        let file_name = entry.file_name();
        let Some(name) = file_name.to_str() else {
            continue;
        };
        let Ok(pid) = name.parse::<i32>() else {
            continue;
        };
        let exe_link = entry.path().join("exe");
        let Ok(path) = fs::read_link(&exe_link) else {
            continue;
        };
        if maybe_canonicalize(&path) == canonical_target {
            pids.push(pid);
        }
    }
    pids.sort_unstable();
    pids
}

fn profile_popular_binary(
    config: &FixerConfig,
    perf_dir: &Path,
    target: &PopularBinaryProfile,
    sampled_pids: &[i32],
) -> Result<Option<PerfProfileCapture>> {
    let timestamp = now_rfc3339().replace(':', "-");
    let safe_name = safe_perf_name(&target.name);
    let data_path = perf_dir.join(format!("{timestamp}-{safe_name}.data"));
    let pid_list = sampled_pids
        .iter()
        .map(i32::to_string)
        .collect::<Vec<_>>()
        .join(",");
    let record = Command::new("perf")
        .env("LC_ALL", "C")
        .args([
            "record",
            "-g",
            "-o",
            data_path.to_string_lossy().as_ref(),
            "-p",
            pid_list.as_str(),
            "--",
            "sleep",
            &config.service.perf_duration_seconds.to_string(),
        ])
        .output()?;
    if !record.status.success() {
        return Ok(None);
    }

    let report = Command::new("perf")
        .env("LC_ALL", "C")
        .args([
            "report",
            "--stdio",
            "-i",
            data_path.to_string_lossy().as_ref(),
            "--sort",
            "comm,dso,symbol",
            "--percent-limit",
            "1",
            "--no-children",
        ])
        .output()?;
    if !report.status.success() {
        return Ok(None);
    }
    let dso_paths = observed_dso_paths(sampled_pids, &target.path);
    let hot_paths =
        parse_perf_hot_paths(&String::from_utf8_lossy(&report.stdout), target, &dso_paths);
    if hot_paths.is_empty() {
        return Ok(None);
    }
    Ok(Some(PerfProfileCapture {
        data_path,
        sampled_pids: sampled_pids.to_vec(),
        hot_paths,
    }))
}

fn observed_dso_paths(sampled_pids: &[i32], target_path: &Path) -> HashMap<String, PathBuf> {
    let mut paths = HashMap::new();
    remember_dso_path(&mut paths, target_path);
    for pid in sampled_pids {
        let maps_path = PathBuf::from(format!("/proc/{pid}/maps"));
        let Ok(raw) = fs::read_to_string(&maps_path) else {
            continue;
        };
        for line in raw.lines() {
            let Some(candidate) = line.split_whitespace().last() else {
                continue;
            };
            if !candidate.starts_with('/') {
                continue;
            }
            remember_dso_path(&mut paths, Path::new(candidate));
        }
    }
    paths
}

fn remember_dso_path(paths: &mut HashMap<String, PathBuf>, candidate: &Path) {
    let canonical = maybe_canonicalize(candidate);
    let full = canonical.to_string_lossy().to_string();
    paths.entry(full).or_insert_with(|| canonical.clone());
    if let Some(name) = canonical.file_name().and_then(|value| value.to_str()) {
        paths.entry(name.to_string()).or_insert(canonical);
    }
}

fn parse_perf_hot_paths(
    report: &str,
    target: &PopularBinaryProfile,
    dso_paths: &HashMap<String, PathBuf>,
) -> Vec<PerfHotPath> {
    let mut hot_paths = Vec::new();
    for line in report.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        let parts = trimmed.split_whitespace().collect::<Vec<_>>();
        if parts.len() < 4 || !parts[0].ends_with('%') {
            continue;
        }
        let Ok(percent) = parts[0].trim_end_matches('%').parse::<f64>() else {
            continue;
        };
        let comm = parts[1].to_string();
        let dso = parts[2].to_string();
        let symbol_index = if parts
            .get(3)
            .is_some_and(|value| value.starts_with('[') && value.ends_with(']'))
        {
            4
        } else {
            3
        };
        if symbol_index >= parts.len() {
            continue;
        }
        let symbol = normalize_perf_symbol(&parts[symbol_index..].join(" "));
        if symbol.is_empty() {
            continue;
        }
        let (dso_path, package_name) = resolve_perf_dso_owner(dso.as_str(), dso_paths, target);
        hot_paths.push(PerfHotPath {
            percent,
            comm,
            dso,
            dso_path,
            package_name,
            symbol,
        });
    }
    hot_paths.sort_by(|left, right| right.percent.total_cmp(&left.percent));
    hot_paths.dedup_by(|left, right| left.dso == right.dso && left.symbol == right.symbol);
    hot_paths.truncate(PERF_REPORT_LIMIT);
    hot_paths
}

fn normalize_perf_symbol(symbol: &str) -> String {
    let mut normalized = symbol.split_whitespace().collect::<Vec<_>>().join(" ");
    while let Some(stripped) = normalized.strip_suffix(" - -") {
        normalized = stripped.trim_end().to_string();
    }
    normalized
}

fn resolve_perf_dso_owner(
    dso: &str,
    dso_paths: &HashMap<String, PathBuf>,
    target: &PopularBinaryProfile,
) -> (Option<PathBuf>, Option<String>) {
    if dso == "[kernel.kallsyms]" {
        if let Some(release) = running_kernel_release() {
            return (
                kernel_reference_path(&release),
                Some(format!("linux-image-{release}")),
            );
        }
        return (None, None);
    }
    let dso_path = resolve_perf_dso_path(dso, dso_paths, &target.path);
    let package_name = dso_path
        .as_deref()
        .and_then(map_path_to_package)
        .or_else(|| target.package_name.clone());
    (dso_path, package_name)
}

fn resolve_perf_dso_path(
    dso: &str,
    dso_paths: &HashMap<String, PathBuf>,
    target_path: &Path,
) -> Option<PathBuf> {
    if dso.starts_with('/') {
        return Some(maybe_canonicalize(Path::new(dso)));
    }
    dso_paths.get(dso).cloned().or_else(|| {
        target_path
            .file_name()
            .and_then(|value| value.to_str())
            .filter(|value| *value == dso)
            .map(|_| target_path.to_path_buf())
    })
}

fn running_kernel_release() -> Option<String> {
    fs::read_to_string("/proc/sys/kernel/osrelease")
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
}

fn kernel_reference_path(release: &str) -> Option<PathBuf> {
    let boot_image = PathBuf::from(format!("/boot/vmlinuz-{release}"));
    if boot_image.exists() {
        return Some(boot_image);
    }
    let modules_dir = PathBuf::from(format!("/lib/modules/{release}"));
    modules_dir.exists().then_some(modules_dir)
}

fn safe_perf_name(name: &str) -> String {
    let sanitized = name
        .chars()
        .map(|ch| if ch.is_ascii_alphanumeric() { ch } else { '-' })
        .collect::<String>();
    sanitized.trim_matches('-').to_string()
}

fn summarize_hot_symbol(symbol: &str) -> String {
    let compact = symbol.trim();
    if compact.chars().count() <= 64 {
        return compact.to_string();
    }
    let shortened = compact.chars().take(61).collect::<String>();
    format!("{shortened}...")
}

fn collect_bpftrace(config: &FixerConfig, store: &Store) -> Result<usize> {
    if !store.capability_available("bpftrace")? {
        return Ok(0);
    }
    let Some(script) = &config.service.bpftrace_script else {
        return Ok(0);
    };
    let output = command_output(
        "timeout",
        &[
            &config.service.bpftrace_timeout_seconds.to_string(),
            "bpftrace",
            "-e",
            script,
        ],
    )
    .unwrap_or_default();
    if output.trim().is_empty() {
        return Ok(0);
    }
    let finding = FindingInput {
        kind: "hotspot".to_string(),
        title: "eBPF trace result".to_string(),
        severity: "medium".to_string(),
        fingerprint: hash_text(format!("bpftrace:{output}")),
        summary: "Optional eBPF trace produced a result.".to_string(),
        details: json!({ "output": output }),
        artifact: None,
        repo_root: None,
        ecosystem: None,
    };
    let _ = store.record_finding(&finding)?;
    Ok(1)
}

fn map_path_to_package(path: &Path) -> Option<String> {
    let output = command_output_os("dpkg-query", &[OsStr::new("-S"), path.as_os_str()]).ok()?;
    output
        .lines()
        .next()
        .and_then(|line| line.split_once(':'))
        .map(|(pkg, _)| pkg.to_string())
}

fn looks_like_warning(line: &str) -> bool {
    let lower = line.to_ascii_lowercase();
    lower.contains("warning") || lower.contains("error") || lower.contains("panic")
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ParsedCoredumpInfo {
    pid: Option<i64>,
    process_name: Option<String>,
    signal_number: Option<i64>,
    signal_name: Option<String>,
    timestamp: Option<String>,
    command_line: Option<String>,
    executable: Option<String>,
    storage: Option<String>,
    stack_threads: Vec<ParsedCoredumpThread>,
    stack_thread_count: usize,
    total_stack_frame_count: usize,
    useful_stack_frame_count: usize,
    primary_stack: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
struct ParsedCoredumpThread {
    thread_id: String,
    frames: Vec<String>,
    #[serde(skip_serializing)]
    frame_details: Vec<ParsedStackFrame>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ParsedStackFrame {
    raw: String,
    normalized: String,
    symbol: String,
    object: Option<String>,
    offset: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
struct SymbolizationReport {
    total_frames: usize,
    improved_frames: usize,
    unresolved_frames: usize,
    suggested_debug_packages: Vec<String>,
    available_debug_packages: Vec<String>,
    suggested_debuginfod_urls: Vec<String>,
    resolver_hits: Vec<ResolvedStackFrame>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
struct ResolvedStackFrame {
    thread_id: String,
    frame_index: usize,
    object: String,
    original_symbol: String,
    resolved_symbol: String,
    source: String,
}

fn parse_coredump_info(raw: &str) -> Option<ParsedCoredumpInfo> {
    let mut pid = None;
    let mut process_name = None;
    let mut signal_number = None;
    let mut signal_name = None;
    let mut timestamp = None;
    let mut command_line = None;
    let mut executable = None;
    let mut storage = None;
    let mut stack_threads = Vec::new();
    let mut current_thread: Option<ParsedCoredumpThread> = None;

    for line in raw.lines() {
        let trimmed = line.trim();
        if let Some(rest) = trimmed.strip_prefix("PID:") {
            let rest = rest.trim();
            if let Some((pid_text, name_text)) = rest.split_once('(') {
                pid = pid_text.trim().parse::<i64>().ok();
                process_name = Some(name_text.trim_end_matches(')').trim().to_string());
            } else {
                pid = rest.parse::<i64>().ok();
            }
            continue;
        }
        if let Some(rest) = trimmed.strip_prefix("Signal:") {
            let rest = rest.trim();
            if let Some((number, name_text)) = rest.split_once('(') {
                signal_number = number.trim().parse::<i64>().ok();
                signal_name = Some(name_text.trim_end_matches(')').trim().to_string());
            } else {
                signal_number = rest.parse::<i64>().ok();
            }
            continue;
        }
        if let Some(rest) = trimmed.strip_prefix("Timestamp:") {
            timestamp = Some(rest.trim().to_string());
            continue;
        }
        if let Some(rest) = trimmed.strip_prefix("Command Line:") {
            command_line = Some(rest.trim().to_string());
            continue;
        }
        if let Some(rest) = trimmed.strip_prefix("Executable:") {
            executable = Some(rest.trim().to_string());
            continue;
        }
        if let Some(rest) = trimmed.strip_prefix("Storage:") {
            storage = Some(rest.trim().to_string());
            continue;
        }
        if let Some(rest) = trimmed.strip_prefix("Stack trace of thread ") {
            if let Some(thread) = current_thread.take() {
                if !thread.frames.is_empty() {
                    stack_threads.push(thread);
                }
            }
            current_thread = Some(ParsedCoredumpThread {
                thread_id: rest.trim_end_matches(':').trim().to_string(),
                frames: Vec::new(),
                frame_details: Vec::new(),
            });
            continue;
        }
        if trimmed.starts_with('#') {
            if let Some(thread) = current_thread.as_mut() {
                let frame = parse_stack_frame(trimmed);
                thread.frames.push(frame.normalized.clone());
                thread.frame_details.push(frame);
            }
            continue;
        }
        if let Some(thread) = current_thread.take() {
            if !thread.frames.is_empty() {
                stack_threads.push(thread);
            }
        }
    }

    if let Some(thread) = current_thread.take() {
        if !thread.frames.is_empty() {
            stack_threads.push(thread);
        }
    }

    if stack_threads.is_empty() {
        return None;
    }

    let mut parsed = ParsedCoredumpInfo {
        pid,
        process_name,
        signal_number,
        signal_name,
        timestamp,
        command_line,
        executable,
        storage,
        stack_threads,
        stack_thread_count: 0,
        total_stack_frame_count: 0,
        useful_stack_frame_count: 0,
        primary_stack: Vec::new(),
    };
    refresh_stack_summary(&mut parsed);
    Some(parsed)
}

fn parse_stack_frame(frame: &str) -> ParsedStackFrame {
    let trimmed = frame.trim();
    let Some(after_index) = trimmed.split_once(' ') else {
        return ParsedStackFrame {
            raw: trimmed.to_string(),
            normalized: trimmed.to_string(),
            symbol: trimmed.to_string(),
            object: None,
            offset: None,
        };
    };
    let remainder = after_index.1.trim_start();
    let Some(after_addr) = remainder.split_once(' ') else {
        return ParsedStackFrame {
            raw: trimmed.to_string(),
            normalized: trimmed.to_string(),
            symbol: trimmed.to_string(),
            object: None,
            offset: None,
        };
    };
    let rest = after_addr.1.trim_start();
    let mut symbol = rest.to_string();
    let mut object = None;
    let mut offset = None;
    if let Some(paren_start) = rest.rfind(" (") {
        symbol = rest[..paren_start].trim().to_string();
        let raw_object = rest[paren_start + 2..].trim_end_matches(')').to_string();
        if let Some((candidate_object, candidate_offset)) = raw_object.split_once(" + ") {
            object = Some(candidate_object.trim().to_string());
            offset = candidate_offset
                .trim()
                .trim_start_matches("0x")
                .parse::<u64>()
                .ok()
                .or_else(|| {
                    u64::from_str_radix(candidate_offset.trim().trim_start_matches("0x"), 16).ok()
                });
        } else if !raw_object.trim().is_empty() {
            object = Some(raw_object.trim().to_string());
        }
    }
    ParsedStackFrame {
        raw: trimmed.to_string(),
        normalized: format_stack_frame(&symbol, object.as_deref())
            .unwrap_or_else(|| rest.to_string()),
        symbol,
        object,
        offset,
    }
}

fn format_stack_frame(symbol: &str, object: Option<&str>) -> Option<String> {
    let symbol = symbol.trim();
    let object = object.map(str::trim).filter(|value| !value.is_empty());
    if symbol.is_empty() {
        return object.map(ToString::to_string);
    }
    object.map(|object| format!("{symbol} [{object}]"))
}

fn refresh_stack_summary(parsed: &mut ParsedCoredumpInfo) {
    parsed.stack_thread_count = parsed.stack_threads.len();
    parsed.total_stack_frame_count = parsed
        .stack_threads
        .iter()
        .map(|thread| thread.frames.len())
        .sum();
    parsed.primary_stack = parsed
        .stack_threads
        .iter()
        .max_by_key(|thread| (count_useful_frames(&thread.frames), thread.frames.len()))
        .map(|thread| thread.frames.clone())
        .unwrap_or_default();
    parsed.useful_stack_frame_count = count_useful_frames(&parsed.primary_stack);
}

fn improve_stack_symbols(parsed: &mut ParsedCoredumpInfo) -> SymbolizationReport {
    let mut improved_frames = 0usize;
    let mut unresolved_frames = 0usize;
    let mut resolver_hits = Vec::new();
    let mut suggested_debug_packages = BTreeSet::new();
    let mut available_debug_packages = BTreeSet::new();
    let mut package_hint_cache = HashMap::<String, Vec<String>>::new();
    let mut available_package_cache = HashMap::<String, Vec<String>>::new();
    let mut nm_cache = HashMap::<String, Vec<(u64, String)>>::new();

    for thread in &mut parsed.stack_threads {
        for (frame_index, frame) in thread.frame_details.iter_mut().enumerate() {
            let Some(object) = frame
                .object
                .as_deref()
                .filter(|object| *object != "n/a" && Path::new(object).exists())
            else {
                if frame.symbol.trim() == "n/a" {
                    unresolved_frames += 1;
                }
                continue;
            };

            if frame.symbol.trim() == "n/a" {
                if let Some((resolved_symbol, source)) =
                    resolve_frame_symbol(Path::new(object), frame.offset, &mut nm_cache)
                {
                    let original_symbol = frame.symbol.clone();
                    frame.symbol = resolved_symbol.clone();
                    frame.normalized = format_stack_frame(&resolved_symbol, Some(object))
                        .unwrap_or_else(|| resolved_symbol.clone());
                    if let Some(serialized_frame) = thread.frames.get_mut(frame_index) {
                        *serialized_frame = frame.normalized.clone();
                    }
                    resolver_hits.push(ResolvedStackFrame {
                        thread_id: thread.thread_id.clone(),
                        frame_index,
                        object: object.to_string(),
                        original_symbol,
                        resolved_symbol,
                        source,
                    });
                    improved_frames += 1;
                }
            }

            if frame.symbol.trim() == "n/a" {
                unresolved_frames += 1;
                if let Some(package_name) = map_path_to_package(Path::new(object)) {
                    for candidate in package_hint_cache
                        .entry(package_name.clone())
                        .or_insert_with(|| candidate_debug_packages(&package_name))
                    {
                        suggested_debug_packages.insert(candidate.clone());
                    }
                    for package in available_package_cache
                        .entry(package_name)
                        .or_insert_with(|| available_debug_packages_for(object))
                    {
                        available_debug_packages.insert(package.clone());
                    }
                }
            }
        }
    }

    refresh_stack_summary(parsed);

    SymbolizationReport {
        total_frames: parsed.total_stack_frame_count,
        improved_frames,
        unresolved_frames,
        suggested_debug_packages: suggested_debug_packages.into_iter().collect(),
        available_debug_packages: available_debug_packages.into_iter().collect(),
        suggested_debuginfod_urls: suggested_debuginfod_urls(unresolved_frames),
        resolver_hits,
    }
}

fn resolve_frame_symbol(
    object: &Path,
    offset: Option<u64>,
    nm_cache: &mut HashMap<String, Vec<(u64, String)>>,
) -> Option<(String, String)> {
    let offset = offset?;
    if command_exists("addr2line") {
        if let Some(symbol) = symbol_from_addr2line(object, offset) {
            return Some((symbol, "addr2line".to_string()));
        }
    }
    if command_exists("nm") {
        if let Some(symbol) = nearest_dynamic_symbol(object, offset, nm_cache) {
            return Some((symbol, "nm-dynamic".to_string()));
        }
    }
    None
}

fn symbol_from_addr2line(object: &Path, offset: u64) -> Option<String> {
    let output = Command::new("addr2line")
        .args(["-Cfipe"])
        .arg(object)
        .arg(format!("0x{offset:x}"))
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let rendered = String::from_utf8_lossy(&output.stdout);
    let line = rendered.lines().next().map(str::trim).unwrap_or("");
    if line.is_empty() || line.starts_with("??") {
        return None;
    }
    Some(line.split(" at ").next().unwrap_or(line).trim().to_string())
}

fn nearest_dynamic_symbol(
    object: &Path,
    offset: u64,
    nm_cache: &mut HashMap<String, Vec<(u64, String)>>,
) -> Option<String> {
    let cache_key = object.to_string_lossy().to_string();
    let symbols = nm_cache
        .entry(cache_key.clone())
        .or_insert_with(|| load_dynamic_symbols(object));
    let (symbol_offset, symbol_name) = symbols
        .iter()
        .take_while(|(candidate_offset, _)| *candidate_offset <= offset)
        .last()
        .cloned()?;
    let delta = offset.saturating_sub(symbol_offset);
    if delta == 0 {
        Some(symbol_name)
    } else {
        Some(format!("{symbol_name}+0x{delta:x}"))
    }
}

fn load_dynamic_symbols(object: &Path) -> Vec<(u64, String)> {
    let output = Command::new("nm").args(["-D", "-n"]).arg(object).output();
    let Ok(output) = output else {
        return Vec::new();
    };
    if !output.status.success() {
        return Vec::new();
    }
    String::from_utf8_lossy(&output.stdout)
        .lines()
        .filter_map(|line| {
            let parts = line.split_whitespace().collect::<Vec<_>>();
            if parts.len() < 3 {
                return None;
            }
            let offset = u64::from_str_radix(parts[0], 16).ok()?;
            Some((offset, parts[2].to_string()))
        })
        .collect()
}

fn candidate_debug_packages(package_name: &str) -> Vec<String> {
    let mut candidates = vec![
        format!("{package_name}-dbgsym"),
        format!("{package_name}-dbg"),
    ];
    candidates.sort();
    candidates.dedup();
    candidates
}

fn available_debug_packages_for(object: &str) -> Vec<String> {
    let Some(package_name) = map_path_to_package(Path::new(object)) else {
        return Vec::new();
    };
    if !command_exists("apt-cache") {
        return Vec::new();
    }
    candidate_debug_packages(&package_name)
        .into_iter()
        .filter(|candidate| {
            command_output(
                "apt-cache",
                &["search", "--names-only", &format!("^{candidate}$")],
            )
            .map(|output| {
                output
                    .lines()
                    .any(|line| line.split_whitespace().next() == Some(candidate.as_str()))
            })
            .unwrap_or(false)
        })
        .collect()
}

fn suggested_debuginfod_urls(unresolved_frames: usize) -> Vec<String> {
    if unresolved_frames == 0 || std::env::var_os("DEBUGINFOD_URLS").is_some() {
        return Vec::new();
    }
    vec![
        "https://debuginfod.debian.net".to_string(),
        "https://debuginfod.elfutils.org".to_string(),
    ]
}

fn count_useful_frames(frames: &[String]) -> usize {
    frames.iter().filter(|frame| frame_is_useful(frame)).count()
}

fn frame_is_useful(frame: &str) -> bool {
    let trimmed = frame.trim();
    !trimmed.is_empty() && trimmed != "n/a [n/a]"
}

#[cfg(test)]
mod tests {
    use super::{
        RunawayHypothesis, StuckProcessGroup, StuckProcessInvestigationSummary,
        apparmor_finding_from_kernel_line, classify_runaway_loop, classify_stuck_process,
        dominant_syscall_sequence, extend_unique_log_lines, investigation_cooldown_active,
        is_low_signal_kernel_warning, is_profile_candidate, kernel_module_lookup_names,
        kernel_module_package_hint, kernel_warning_module_candidates, looks_like_warning,
        normalize_oom_task_memcg_target, normalize_perf_symbol,
        normalize_stuck_process_target_name, parse_apparmor_denial, parse_coredump_info,
        parse_dkms_status_line, parse_kernel_oom_kill_events, parse_latest_desktop_resume_failure,
        parse_perf_hot_paths, parse_postgres_collation_mismatch_rows, parse_strace_syscall_name,
        process_runtime_seconds, safe_perf_name, stuck_process_investigation_fingerprint,
        stuck_process_source_fingerprint, summarize_top_syscalls, system_uptime_seconds,
    };
    use crate::models::PopularBinaryProfile;
    use serde_json::Value;
    use std::collections::{BTreeMap, BTreeSet, HashMap};
    use std::path::{Path, PathBuf};

    #[test]
    fn warning_detection_handles_common_keywords() {
        assert!(looks_like_warning("warning: something happened"));
        assert!(looks_like_warning("ERROR: boom"));
        assert!(!looks_like_warning("all good"));
    }

    #[test]
    fn parses_apparmor_denial_lines() {
        let line = "Mar 28 18:59:23 smallcat kernel: audit: type=1400 audit(1774709963.724:166286): apparmor=\"DENIED\" operation=\"open\" class=\"file\" profile=\"/usr/sbin/cupsd\" name=\"/etc/paperspecs\" pid=934836 comm=\"cupsd\" requested_mask=\"r\" denied_mask=\"r\" fsuid=0 ouid=0";
        let parsed = parse_apparmor_denial(line).expect("AppArmor line should parse");
        assert_eq!(parsed.profile, "/usr/sbin/cupsd");
        assert_eq!(parsed.comm.as_deref(), Some("cupsd"));
        assert_eq!(parsed.operation.as_deref(), Some("open"));
        assert_eq!(parsed.class.as_deref(), Some("file"));
        assert_eq!(parsed.name.as_deref(), Some("/etc/paperspecs"));
    }

    #[test]
    fn apparmor_denials_become_structured_warning_findings() {
        let line = "Mar 28 18:58:46 smallcat kernel: audit: type=1400 audit(1774709926.444:166268): apparmor=\"DENIED\" operation=\"create\" class=\"net\" info=\"failed protocol match\" error=-13 profile=\"rsyslogd\" pid=928892 comm=\"rsyslogd\" family=\"unix\" sock_type=\"dgram\" protocol=0 requested=\"create\" denied=\"create\" addr=none";
        let finding =
            apparmor_finding_from_kernel_line(line).expect("AppArmor finding should be created");
        assert_eq!(finding.title, "AppArmor denial in rsyslogd");
        assert_eq!(
            finding.summary,
            "AppArmor denied rsyslogd: create net unix/dgram"
        );
        assert_eq!(
            finding.details.get("subsystem").and_then(Value::as_str),
            Some("apparmor")
        );
    }

    #[test]
    fn ignores_low_signal_kernel_suppression_lines() {
        let line = "Mar 28 18:59:23 smallcat kernel: kauditd_printk_skb: 4 callbacks suppressed";
        assert!(is_low_signal_kernel_warning(line));
        assert!(apparmor_finding_from_kernel_line(line).is_none());
    }

    #[test]
    fn apparmor_summary_surfaces_mediating_command_when_it_differs() {
        let line = "Mar 28 18:59:23 smallcat kernel: audit: type=1400 audit(1774709963.724:166286): apparmor=\"DENIED\" operation=\"create\" class=\"net\" info=\"failed protocol match\" error=-13 profile=\"/usr/sbin/cupsd\" pid=934836 comm=\"dbus\" family=\"unix\" sock_type=\"stream\" protocol=0 requested=\"create\" denied=\"create\" addr=none";
        let finding =
            apparmor_finding_from_kernel_line(line).expect("AppArmor finding should be created");
        assert_eq!(
            finding.summary,
            "AppArmor denied cupsd via dbus: create net unix/stream"
        );
    }

    #[test]
    fn normalize_stuck_process_target_name_collapses_kworker_slots() {
        assert_eq!(
            normalize_stuck_process_target_name("kworker/u33:2+i915_flip"),
            "kworker+i915_flip"
        );
        assert_eq!(
            normalize_stuck_process_target_name("kworker/0:1-events"),
            "kworker"
        );
        assert_eq!(normalize_stuck_process_target_name("postgres"), "postgres");
    }

    #[test]
    fn stuck_process_fingerprint_ignores_kworker_slot_noise() {
        let base_investigation = StuckProcessInvestigationSummary {
            sampled_pid: 42,
            sampled_pid_count: 1,
            sampled_pids: vec![42],
            command_line: None,
            executable: None,
            process_state: Some("D".to_string()),
            runtime_seconds: 900,
            wchan: Some("drm_atomic_helper_wait_for_flip_done".to_string()),
            cwd: None,
            root: None,
            fd_targets: Vec::new(),
            io_excerpt: None,
            status_excerpt: None,
            sched_excerpt: None,
            stack_excerpt: Some("drm_atomic_helper_wait_for_flip_done\n__schedule".to_string()),
            hypothesis: RunawayHypothesis {
                classification: "unknown-uninterruptible-wait".to_string(),
                confidence: 0.5,
                explanation: "kernel worker is blocked in flip wait".to_string(),
            },
            likely_external_root_cause: false,
            raw_artifacts: BTreeMap::new(),
            package_metadata: None,
        };
        let a = StuckProcessGroup {
            name: "kworker+i915_flip".to_string(),
            executable: None,
            package_name: None,
            pids: vec![1001],
            sample_pid: 1001,
            sample_runtime_seconds: 900,
            comm: "kworker/u33:0+i915_flip".to_string(),
        };
        let b = StuckProcessGroup {
            name: "kworker+i915_flip".to_string(),
            executable: None,
            package_name: None,
            pids: vec![1002],
            sample_pid: 1002,
            sample_runtime_seconds: 1800,
            comm: "kworker/u33:3+i915_flip".to_string(),
        };

        assert_eq!(
            stuck_process_source_fingerprint(&a),
            stuck_process_source_fingerprint(&b)
        );
        assert_eq!(
            stuck_process_investigation_fingerprint(&a, &base_investigation),
            stuck_process_investigation_fingerprint(&b, &base_investigation)
        );
    }

    #[test]
    fn merged_kernel_log_streams_dedupe_and_preserve_order() {
        let mut lines = Vec::new();
        let mut seen = BTreeSet::new();
        extend_unique_log_lines(&mut lines, &mut seen, "a\nb\n");
        extend_unique_log_lines(&mut lines, &mut seen, "b\nc\n");
        assert_eq!(lines, vec!["a", "b", "c"]);
    }

    #[test]
    fn low_signal_kernel_warning_filters_show_signal_callback_spam() {
        assert!(is_low_signal_kernel_warning(
            "Mar 29 14:50:11 nucat kernel: show_signal_msg: 666 callbacks suppressed"
        ));
        assert!(is_low_signal_kernel_warning(
            "Mar 29 12:41:59 nucat kernel: show_signal: 666 callbacks suppressed"
        ));
    }

    #[test]
    fn parses_kernel_oom_kill_events_into_structured_investigations() {
        let raw = "\
Mar 29 23:54:40 nucat kernel: Out of memory: Killed process 2415866 (element-desktop) total-vm:1464797676kB, anon-rss:204948kB, file-rss:164kB, shmem-rss:15408kB, UID:1000 pgtables:1996kB oom_score_adj:300\n\
Mar 29 23:54:40 nucat kernel: oom-kill:constraint=CONSTRAINT_NONE,nodemask=(null),cpuset=user.slice,mems_allowed=0,global_oom,task_memcg=/user.slice/user-1000.slice/user@1000.service/app.slice/app-element\\x2ddesktop@1cf7c2c7954847c9a04e1e68b4e8e95b.service,task=element-desktop,pid=2415866,uid=1000\n\
Mar 29 23:54:37 nucat kernel: MainThread invoked oom-killer: gfp_mask=0x140cca(GFP_HIGHUSER_MOVABLE|__GFP_COMP), order=0, oom_score_adj=200\n";
        let events = parse_kernel_oom_kill_events(raw);
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].process_name, "element-desktop");
        assert_eq!(events[0].pid, 2415866);
        assert_eq!(events[0].anon_rss_kb, 204948);
        assert_eq!(events[0].cgroup_target.as_deref(), Some("element-desktop"));
        assert_eq!(events[0].invoker.as_deref(), Some("MainThread"));
    }

    #[test]
    fn parses_desktop_resume_failures_into_structured_investigations() {
        let raw = "\
Mar 30 00:41:39 tinycat systemd-logind[953]: The system will suspend now!\n\
Mar 30 00:41:40 tinycat kernel: PM: suspend entry (deep)\n\
Mar 30 01:38:57 tinycat kernel: radeon 0000:01:05.0: ring 0 stalled for more than 10240msec\n\
Mar 30 01:38:57 tinycat kernel: [drm:r600_ib_test [radeon]] *ERROR* radeon: fence wait failed (-35).\n\
Mar 30 01:38:57 tinycat kernel: [drm:radeon_resume_kms [radeon]] *ERROR* ib ring test failed (-35).\n\
Mar 30 01:38:58 tinycat kernel: PM: suspend exit\n\
Mar 30 01:38:58 tinycat ksmserver[1174]: radeon: The kernel rejected CS, see dmesg for more information.\n\
Mar 30 01:38:58 tinycat plasmashell[1176]: radeon: The kernel rejected CS, see dmesg for more information.\n\
Mar 30 01:38:58 tinycat systemd-coredump[1695]: Process 853 (Xorg) of user 0 terminated abnormally with signal 7/BUS, processing...\n\
Mar 30 01:38:58 tinycat systemd-coredump[1696]: Process 1213 (kwin_x11) of user 1000 terminated abnormally with signal 7/BUS, processing...\n\
Mar 30 01:38:59 tinycat kwin_x11[1702]: qt.qpa.xcb: could not connect to display :0\n\
Mar 30 01:38:59 tinycat sddm[829]: Display server stopping...\n\
Mar 30 01:38:59 tinycat sddm[829]: Display server stopped.\n\
Mar 30 01:38:59 tinycat sddm[829]: Adding new display...\n\
Mar 30 01:39:00 tinycat sddm[829]: Failed to read display number from pipe\n\
Mar 30 01:39:00 tinycat sddm[829]: Attempt 1 starting the Display server on vt 1 failed\n";
        let event = parse_latest_desktop_resume_failure(raw).expect("desktop resume event");
        assert_eq!(event.driver, "radeon");
        assert_eq!(event.session_type, "x11");
        assert_eq!(event.display_manager, "sddm");
        assert_eq!(event.crashed_processes, vec!["Xorg", "kwin_x11"]);
        assert!(
            event
                .gpu_error_lines
                .iter()
                .any(|line| line.contains("ring 0 stalled"))
        );
        assert!(
            event
                .session_error_lines
                .iter()
                .any(|line| line.contains("Failed to read display number from pipe"))
        );
        assert_eq!(event.display_target(), "radeon X11 desktop");
        assert!(event.public_summary().contains("Xorg, kwin_x11 crashed"));
    }

    #[test]
    fn normalizes_oom_memcg_targets_from_systemd_app_units() {
        assert_eq!(
            normalize_oom_task_memcg_target(
                "/user.slice/user-1000.slice/user@1000.service/app.slice/app-google\\x2dchrome@22ccba5c949444b6969fe39ce4794260.service"
            ),
            Some("google-chrome".to_string())
        );
        assert_eq!(
            normalize_oom_task_memcg_target(
                "/user.slice/user-1000.slice/user@1000.service/app.slice/app-org.kde.yakuake-12836.scope/tab(595051).scope"
            ),
            Some("org.kde.yakuake".to_string())
        );
    }

    #[test]
    fn kernel_warning_candidates_extract_module_from_device_warning() {
        let line = "Mar 28 18:47:22 nucat kernel: iwlwifi 0000:04:00.0: missed_beacons:21, missed_beacons_since_rx:3";
        assert_eq!(kernel_warning_module_candidates(line), vec!["iwlwifi"]);
    }

    #[test]
    fn kernel_warning_candidates_map_nvrm_to_nvidia() {
        let line =
            "Mar 28 19:30:47 geocint kernel: NVRM: GPU 0000:3b:00.0 is already bound to nouveau.";
        assert_eq!(kernel_warning_module_candidates(line), vec!["nvidia"]);
    }

    #[test]
    fn kernel_warning_candidates_extract_bracketed_module_names() {
        let line = "Mar 28 19:17:57 geocint kernel: RIP: 0010:nvkm_gr_units+0x9/0x30 [nouveau]";
        assert_eq!(kernel_warning_module_candidates(line), vec!["nouveau"]);
    }

    #[test]
    fn kernel_module_lookup_names_include_debian_nvidia_aliases() {
        assert_eq!(
            kernel_module_lookup_names("nvidia_uvm"),
            vec!["nvidia_uvm", "nvidia-current-uvm"]
        );
        assert_eq!(
            kernel_module_lookup_names("nvidia"),
            vec!["nvidia", "nvidia-current"]
        );
    }

    #[test]
    fn kernel_module_package_hint_uses_running_kernel_image_for_in_tree_modules() {
        let path = Path::new(
            "/lib/modules/6.19.8+deb14-amd64/kernel/drivers/net/wireless/intel/iwlwifi/iwlwifi.ko.xz",
        );
        assert_eq!(
            kernel_module_package_hint(path, "iwlwifi"),
            Some("linux-image-6.19.8+deb14-amd64".to_string())
        );
    }

    #[test]
    fn kernel_module_package_hint_maps_nvidia_dkms_modules_to_nvidia_kernel_dkms() {
        let path = Path::new("/lib/modules/6.17.10+deb14-amd64/updates/dkms/nvidia-current.ko.xz");
        assert_eq!(
            kernel_module_package_hint(path, "nvidia"),
            Some("nvidia-kernel-dkms".to_string())
        );
    }

    #[test]
    fn parses_dkms_status_entries() {
        let entry = parse_dkms_status_line(
            "nvidia-current/550.163.01, 6.17.10+deb14-amd64, x86_64: installed",
        )
        .expect("dkms status line should parse");
        assert_eq!(entry.module_name, "nvidia-current");
        assert_eq!(entry.version, "550.163.01");
        assert_eq!(entry.kernel_release, "6.17.10+deb14-amd64");
        assert_eq!(entry.status, "installed");
    }

    #[test]
    fn parses_postgres_collation_mismatch_rows_from_tsv() {
        let rows = parse_postgres_collation_mismatch_rows(
            "batumarket\t2.42\t2.43\npostgres\t2.42\t2.43\nfixer\t2.43\t2.43\n",
        );
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0].database_name, "batumarket");
        assert_eq!(rows[0].stored_collation_version, "2.42");
        assert_eq!(rows[0].actual_collation_version, "2.43");
        assert_eq!(rows[1].database_name, "postgres");
    }

    #[test]
    fn parses_coredump_stack_traces() {
        let raw = "\
PID: 1173642 (nl)\n\
Signal: 6 (ABRT)\n\
Timestamp: Fri 2026-02-06 04:17:30 +04\n\
Command Line: nl -ba scripts/render_longfast_animation.py\n\
Executable: /usr/bin/coreutils\n\
Storage: /var/lib/systemd/coredump/core.nl.zst (missing)\n\
Message: Process 1173642 (nl) of user 1000 dumped core.\n\
\n\
Stack trace of thread 1173642:\n\
#0  0x00007fedbc47d16c __pthread_kill_implementation (libc.so.6 + 0x9716c)\n\
#1  0x00007fedbc426702 __GI_raise (libc.so.6 + 0x40702)\n\
#2  0x000055723de68a2a n/a (/usr/bin/coreutils + 0x2c6a2a)\n\
ELF object binary architecture: AMD x86-64\n";
        let parsed = parse_coredump_info(raw).expect("stack trace should parse");
        assert_eq!(parsed.process_name.as_deref(), Some("nl"));
        assert_eq!(parsed.executable.as_deref(), Some("/usr/bin/coreutils"));
        assert_eq!(parsed.primary_stack.len(), 3);
        assert_eq!(
            parsed.primary_stack[0],
            "__pthread_kill_implementation [libc.so.6]"
        );
        assert_eq!(parsed.useful_stack_frame_count, 3);
    }

    #[test]
    fn rejects_stackless_coredumps() {
        let raw = "\
PID: 3917413 (ZoomWebviewHost)\n\
Signal: 11 (SEGV)\n\
Executable: /opt/zoom/ZoomWebviewHost\n\
        Message: Process 3917413 (ZoomWebviewHost) of user 1000 dumped core.\n";
        assert!(parse_coredump_info(raw).is_none());
    }

    #[test]
    fn keeps_n_a_only_stack_traces_as_low_signal() {
        let raw = "\
PID: 3917412 (ZoomWebviewHost)\n\
Signal: 11 (SEGV)\n\
Executable: /opt/zoom/ZoomWebviewHost\n\
Message: Process 3917412 (ZoomWebviewHost) of user 1000 dumped core.\n\
\n\
Stack trace of thread 3917506:\n\
#0  0x00007efec319bdb4 n/a (n/a + 0x0)\n";
        let parsed = parse_coredump_info(raw).expect("frame-only trace should still parse");
        assert_eq!(parsed.useful_stack_frame_count, 0);
        assert_eq!(parsed.primary_stack, vec!["n/a [n/a]".to_string()]);
    }

    #[test]
    fn prefers_most_informative_thread() {
        let raw = "\
PID: 3917405 (ZoomWebviewHost)\n\
Signal: 11 (SEGV)\n\
Executable: /opt/zoom/ZoomWebviewHost\n\
Message: Process 3917405 (ZoomWebviewHost) of user 1000 dumped core.\n\
\n\
Stack trace of thread 111:\n\
#0  0x00007efec319bdb4 n/a (n/a + 0x0)\n\
\n\
Stack trace of thread 222:\n\
#0  0x00007efec319bdb4 n/a (/opt/zoom/cef/libcef.so + 0x8d9bdb4)\n\
#1  0x00007efeb824b830 __restore_rt (/usr/lib/x86_64-linux-gnu/libc.so.6 + 0x40830)\n";
        let parsed = parse_coredump_info(raw).expect("informative thread should be selected");
        assert_eq!(parsed.stack_thread_count, 2);
        assert_eq!(parsed.total_stack_frame_count, 3);
        assert_eq!(parsed.useful_stack_frame_count, 2);
        assert_eq!(parsed.primary_stack[0], "n/a [/opt/zoom/cef/libcef.so]");
    }

    #[test]
    fn perf_report_parser_extracts_hot_paths_for_profiled_binary() {
        let report = "\
  37.42%  chrome  libc.so.6  [.] memcpy\n\
  18.10%  chrome  chrome     [.] Blink::run\n\
";
        let target = PopularBinaryProfile {
            name: "chrome".to_string(),
            path: PathBuf::from("/opt/google/chrome/chrome"),
            package_name: Some("google-chrome-stable".to_string()),
            process_count: 9,
            total_cpu_percent: 23.4,
            max_cpu_percent: 19.8,
        };
        let mut dso_paths = HashMap::new();
        dso_paths.insert(
            "chrome".to_string(),
            PathBuf::from("/opt/google/chrome/chrome"),
        );
        dso_paths.insert(
            "libc.so.6".to_string(),
            PathBuf::from("/usr/lib/x86_64-linux-gnu/libc.so.6"),
        );

        let hot_paths = parse_perf_hot_paths(report, &target, &dso_paths);
        assert_eq!(hot_paths.len(), 2);
        assert_eq!(hot_paths[0].comm, "chrome");
        assert_eq!(hot_paths[0].symbol, "memcpy");
        assert_eq!(
            hot_paths[0].dso_path.as_deref(),
            Some(Path::new("/usr/lib/x86_64-linux-gnu/libc.so.6"))
        );
        assert_eq!(hot_paths[1].symbol, "Blink::run");
        assert_eq!(
            hot_paths[1].dso_path.as_deref(),
            Some(Path::new("/opt/google/chrome/chrome"))
        );
    }

    #[test]
    fn profile_candidates_skip_fixer_binaries_and_zero_counts() {
        assert!(!is_profile_candidate(&PopularBinaryProfile {
            name: "fixerd".to_string(),
            path: PathBuf::from("/usr/bin/fixerd"),
            package_name: Some("fixer".to_string()),
            process_count: 1,
            total_cpu_percent: 1.0,
            max_cpu_percent: 1.0,
        }));
        assert!(!is_profile_candidate(&PopularBinaryProfile {
            name: "firefox".to_string(),
            path: PathBuf::from("/usr/bin/firefox"),
            package_name: Some("firefox-esr".to_string()),
            process_count: 0,
            total_cpu_percent: 0.0,
            max_cpu_percent: 0.0,
        }));
        assert!(is_profile_candidate(&PopularBinaryProfile {
            name: "firefox".to_string(),
            path: PathBuf::from("/usr/bin/firefox"),
            package_name: Some("firefox-esr".to_string()),
            process_count: 3,
            total_cpu_percent: 15.0,
            max_cpu_percent: 15.0,
        }));
    }

    #[test]
    fn safe_perf_name_normalizes_binary_names() {
        assert_eq!(
            safe_perf_name("google-chrome-stable"),
            "google-chrome-stable"
        );
        assert_eq!(safe_perf_name("code - oss"), "code---oss");
    }

    #[test]
    fn normalize_perf_symbol_trims_trailing_perf_source_markers() {
        assert_eq!(normalize_perf_symbol("memcpy - -"), "memcpy");
        assert_eq!(
            normalize_perf_symbol("std::__foo<int> - - - -"),
            "std::__foo<int>"
        );
    }

    #[test]
    fn parses_strace_syscall_names_with_attached_pid_prefixes() {
        assert_eq!(
            parse_strace_syscall_name(
                "[pid 12454] 12:00:01.123456 recvmsg(8, 0x7ffc, 0) = 48 <0.000012>"
            ),
            Some("recvmsg".to_string())
        );
        assert_eq!(
            parse_strace_syscall_name(
                "2047604 18:19:19.100524 clock_nanosleep(CLOCK_MONOTONIC, TIMER_ABSTIME, {tv_sec=1, tv_nsec=2}, NULL) = 0 <0.432673>"
            ),
            Some("clock_nanosleep".to_string())
        );
        assert_eq!(
            parse_strace_syscall_name(
                "12:00:01.123456 ppoll([{fd=8, events=POLLIN}], 1, NULL, NULL, 8) = 1 <0.000010>"
            ),
            Some("ppoll".to_string())
        );
    }

    #[test]
    fn classifies_dbus_spin_from_trace_and_symbols() {
        let syscalls = vec![
            "recvmsg".to_string(),
            "sendmsg".to_string(),
            "ppoll".to_string(),
            "recvmsg".to_string(),
            "sendmsg".to_string(),
            "ppoll".to_string(),
        ];
        let top_syscalls = summarize_top_syscalls(&syscalls);
        let sequence = dominant_syscall_sequence(&syscalls);
        assert_eq!(sequence, vec!["recvmsg", "sendmsg", "ppoll"]);
        let hypothesis = classify_runaway_loop(
            &[
                "12:00:01 recvmsg(8, ..., 0) = 48 <0.000012> /run/user/1000/bus".to_string(),
                "12:00:01 sendmsg(8, ..., 0) = 32 <0.000010> org.freedesktop.DBus".to_string(),
            ],
            &top_syscalls,
            &["QDBusConnection::send".to_string()],
        );
        assert_eq!(hypothesis.classification, "dbus-spin");
        assert!(hypothesis.confidence > 0.8);
    }

    #[test]
    fn classifies_missing_file_retry_loops() {
        let syscalls = vec![
            "openat".to_string(),
            "statx".to_string(),
            "openat".to_string(),
            "statx".to_string(),
        ];
        let top_syscalls = summarize_top_syscalls(&syscalls);
        let hypothesis = classify_runaway_loop(
            &[
                "12:00:01 openat(AT_FDCWD, \"/tmp/missing\", O_RDONLY) = -1 ENOENT (No such file or directory) <0.000009>".to_string(),
                "12:00:01 statx(AT_FDCWD, \"/tmp/missing\", 0, STATX_ALL, 0x7fff) = -1 ENOENT (No such file or directory) <0.000008>".to_string(),
            ],
            &top_syscalls,
            &[],
        );
        assert_eq!(hypothesis.classification, "file-not-found-retry");
        assert!(hypothesis.confidence > 0.8);
    }

    #[test]
    fn cooldown_only_blocks_recent_investigations() {
        assert!(investigation_cooldown_active(
            &chrono::Utc::now().to_rfc3339(),
            3600
        ));
        assert!(!investigation_cooldown_active(
            &(chrono::Utc::now() - chrono::Duration::hours(3)).to_rfc3339(),
            3600
        ));
    }

    #[test]
    fn classifies_stuck_processes_waiting_on_fuse() {
        let hypothesis = classify_stuck_process(
            Some("fuse_wait_answer\nrequest_wait_answer\n"),
            Some("fuse_wait_answer"),
            &["/mnt/problematic-tree".to_string()],
        );
        assert_eq!(hypothesis.classification, "fuse-wait");
        assert!(hypothesis.confidence > 0.8);
    }

    #[test]
    fn process_runtime_uses_proc_stat_start_time() {
        let runtime =
            process_runtime_seconds(std::process::id() as i32, system_uptime_seconds(), 100.0);
        assert!(runtime.is_some());
    }
}
