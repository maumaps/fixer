use crate::adapters::{inspect_repo, resolve_repo_root};
use crate::capabilities::detect_capabilities;
use crate::config::FixerConfig;
use crate::models::{FindingInput, ObservedArtifact, PopularBinaryProfile};
use crate::storage::Store;
use crate::util::{
    command_exists, command_output, command_output_os, find_postgres_binary, hash_text,
    maybe_canonicalize, now_rfc3339,
};
use anyhow::Result;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::ffi::OsStr;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

const PERF_PROFILE_TARGET_LIMIT: usize = 3;
const PERF_TOP_HOTSPOTS_PER_TARGET: usize = 3;
const PERF_REPORT_LIMIT: usize = 12;

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
    line.contains("kauditd_printk_skb:") && line.contains("callbacks suppressed")
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
    fs::create_dir_all(&perf_dir)?;
    let mut count = 0;
    let mut assessed_targets = Vec::new();
    let mut current_fingerprints = Vec::new();

    for target in targets
        .into_iter()
        .filter(is_profile_candidate)
        .take(PERF_PROFILE_TARGET_LIMIT)
    {
        let sampled_pids = running_pids_for_binary(&target.path);
        if sampled_pids.is_empty() {
            continue;
        }
        let Some(profile) = profile_popular_binary(config, &perf_dir, &target, &sampled_pids)?
        else {
            continue;
        };
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
    }
    if !assessed_targets.is_empty() {
        store.prune_perf_hotspot_findings(&assessed_targets, &current_fingerprints)?;
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
        apparmor_finding_from_kernel_line, extend_unique_log_lines, is_low_signal_kernel_warning,
        is_profile_candidate, kernel_module_lookup_names, kernel_module_package_hint,
        kernel_warning_module_candidates, looks_like_warning, normalize_perf_symbol,
        parse_apparmor_denial, parse_coredump_info, parse_dkms_status_line, parse_perf_hot_paths,
        parse_postgres_collation_mismatch_rows, safe_perf_name,
    };
    use crate::models::PopularBinaryProfile;
    use serde_json::Value;
    use std::collections::{BTreeSet, HashMap};
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
    fn merged_kernel_log_streams_dedupe_and_preserve_order() {
        let mut lines = Vec::new();
        let mut seen = BTreeSet::new();
        extend_unique_log_lines(&mut lines, &mut seen, "a\nb\n");
        extend_unique_log_lines(&mut lines, &mut seen, "b\nc\n");
        assert_eq!(lines, vec!["a", "b", "c"]);
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
        }));
        assert!(!is_profile_candidate(&PopularBinaryProfile {
            name: "firefox".to_string(),
            path: PathBuf::from("/usr/bin/firefox"),
            package_name: Some("firefox-esr".to_string()),
            process_count: 0,
        }));
        assert!(is_profile_candidate(&PopularBinaryProfile {
            name: "firefox".to_string(),
            path: PathBuf::from("/usr/bin/firefox"),
            package_name: Some("firefox-esr".to_string()),
            process_count: 3,
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
}
