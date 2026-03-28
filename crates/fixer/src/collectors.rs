use crate::adapters::{inspect_repo, resolve_repo_root};
use crate::capabilities::detect_capabilities;
use crate::config::FixerConfig;
use crate::models::{FindingInput, ObservedArtifact};
use crate::storage::Store;
use crate::util::{
    command_exists, command_output, command_output_os, hash_text, maybe_canonicalize, now_rfc3339,
};
use anyhow::Result;
use serde::Serialize;
use serde_json::{Value, json};
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::ffi::OsStr;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

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
    }
    report.artifacts_seen += collect_repos(&config.service.watched_repos, store)?;
    if config.service.collect_crashes {
        report.findings_seen += collect_crashes(config, store)?;
    }
    if config.service.collect_warnings {
        report.findings_seen += collect_warning_logs(config, store)?;
        report.findings_seen += collect_kernel_warnings(config, store)?;
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
    let mut seen = BTreeMap::<PathBuf, usize>::new();
    for entry in fs::read_dir("/proc")? {
        let entry = entry?;
        let file_name = entry.file_name();
        let Some(name) = file_name.to_str() else {
            continue;
        };
        if !name.chars().all(|ch| ch.is_ascii_digit()) {
            continue;
        }
        let exe_link = entry.path().join("exe");
        if let Ok(path) = fs::read_link(&exe_link) {
            *seen.entry(path).or_insert(0) += 1;
        }
    }

    let total = seen.len();
    for (path, count) in seen {
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
                "process_count": count,
                "collected_at": now_rfc3339(),
            }),
        };
        let _ = store.upsert_artifact(&artifact)?;
    }
    Ok(total)
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
                    summary: "The watched repository does not expose an obvious upstream URL.".to_string(),
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

        let exe = parsed.executable.as_ref().map(PathBuf::from).or_else(|| {
            event.get("exe")
                .and_then(Value::as_str)
                .map(PathBuf::from)
        });
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
    let output = command_output(
        "journalctl",
        &[
            "-k",
            "-p",
            "warning",
            "-n",
            &config.service.journal_lines.to_string(),
            "--no-pager",
        ],
    )
    .unwrap_or_default();
    let mut count = 0;
    for line in output.lines() {
        if line.trim().is_empty() {
            continue;
        }
        let finding = FindingInput {
            kind: "warning".to_string(),
            title: "Kernel warning".to_string(),
            severity: "medium".to_string(),
            fingerprint: hash_text(format!("kernel-warning:{line}")),
            summary: line.trim().to_string(),
            details: json!({ "line": line.trim() }),
            artifact: None,
            repo_root: None,
            ecosystem: None,
        };
        let _ = store.record_finding(&finding)?;
        count += 1;
    }
    Ok(count)
}

fn collect_perf_hotspots(config: &FixerConfig, store: &Store) -> Result<usize> {
    if !store.capability_available("perf")? {
        return Ok(0);
    }
    let perf_dir = config.service.state_dir.join("perf");
    fs::create_dir_all(&perf_dir)?;
    let timestamp = now_rfc3339().replace(':', "-");
    let data_path = perf_dir.join(format!("{timestamp}.data"));
    let status = Command::new("perf")
        .args([
            "record",
            "-a",
            "-g",
            "-o",
            data_path.to_string_lossy().as_ref(),
            "--",
            "sleep",
            &config.service.perf_duration_seconds.to_string(),
        ])
        .status()?;
    if !status.success() {
        return Ok(0);
    }
    let report = command_output(
        "perf",
        &[
            "report",
            "--stdio",
            "-i",
            data_path.to_string_lossy().as_ref(),
            "--sort",
            "comm,symbol,dso",
            "--percent-limit",
            "1",
        ],
    )?;
    let mut count = 0;
    for line in report.lines().take(200) {
        let trimmed = line.trim();
        if !trimmed.contains('%') || trimmed.starts_with('#') {
            continue;
        }
        let parts = trimmed.split_whitespace().collect::<Vec<_>>();
        if parts.len() < 4 {
            continue;
        }
        let finding = FindingInput {
            kind: "hotspot".to_string(),
            title: format!("Perf hotspot: {}", parts.get(1).copied().unwrap_or("unknown")),
            severity: "medium".to_string(),
            fingerprint: hash_text(format!("hotspot:{trimmed}")),
            summary: trimmed.to_string(),
            details: json!({
                "perf_line": trimmed,
                "perf_data": data_path,
            }),
            artifact: None,
            repo_root: None,
            ecosystem: None,
        };
        let _ = store.record_finding(&finding)?;
        count += 1;
        if count >= 10 {
            break;
        }
    }
    Ok(count)
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
        let raw_object = rest[paren_start + 2..]
            .trim_end_matches(')')
            .to_string();
        if let Some((candidate_object, candidate_offset)) = raw_object.split_once(" + ") {
            object = Some(candidate_object.trim().to_string());
            offset = candidate_offset
                .trim()
                .trim_start_matches("0x")
                .parse::<u64>()
                .ok()
                .or_else(|| u64::from_str_radix(candidate_offset.trim().trim_start_matches("0x"), 16).ok());
        } else if !raw_object.trim().is_empty() {
            object = Some(raw_object.trim().to_string());
        }
    }
    ParsedStackFrame {
        raw: trimmed.to_string(),
        normalized: format_stack_frame(&symbol, object.as_deref()).unwrap_or_else(|| rest.to_string()),
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
    let line = rendered
        .lines()
        .next()
        .map(str::trim)
        .unwrap_or("");
    if line.is_empty() || line.starts_with("??") {
        return None;
    }
    Some(
        line.split(" at ")
            .next()
            .unwrap_or(line)
            .trim()
            .to_string(),
    )
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
    let output = Command::new("nm")
        .args(["-D", "-n"])
        .arg(object)
        .output();
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
            command_output("apt-cache", &["search", "--names-only", &format!("^{candidate}$")])
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
    use super::{looks_like_warning, parse_coredump_info};

    #[test]
    fn warning_detection_handles_common_keywords() {
        assert!(looks_like_warning("warning: something happened"));
        assert!(looks_like_warning("ERROR: boom"));
        assert!(!looks_like_warning("all good"));
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
}
