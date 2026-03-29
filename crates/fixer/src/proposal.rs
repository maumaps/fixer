use crate::config::FixerConfig;
use crate::models::{
    CodexJobSpec, CodexJobStatus, ComplaintCollectionReport, InstalledPackageMetadata,
    OpportunityRecord, PreparedWorkspace, ProposalRecord, SharedOpportunity,
};
use crate::storage::Store;
use crate::util::{command_exists, command_output, now_rfc3339, read_text};
use crate::workspace::resolve_installed_package_metadata;
use anyhow::{Context, Result, anyhow};
use serde_json::{Value, json};
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

pub fn create_proposal(
    store: &Store,
    config: &FixerConfig,
    opportunity: &OpportunityRecord,
    workspace: &PreparedWorkspace,
    engine: &str,
) -> Result<ProposalRecord> {
    let bundle_dir = config.service.state_dir.join("proposals").join(format!(
        "{}-{}",
        opportunity.id,
        now_rfc3339().replace(':', "-")
    ));
    fs::create_dir_all(&bundle_dir)?;

    let evidence_path = bundle_dir.join("evidence.json");
    let prompt_path = bundle_dir.join("prompt.md");
    let output_path = bundle_dir.join("codex-output.txt");

    let evidence = json!({
        "opportunity": opportunity,
        "workspace": workspace,
    });
    fs::write(&evidence_path, serde_json::to_vec_pretty(&evidence)?)?;

    let prompt = build_prompt(
        opportunity,
        &fs::canonicalize(&evidence_path).unwrap_or_else(|_| evidence_path.clone()),
        workspace,
        config,
    );
    fs::write(&prompt_path, prompt.as_bytes())?;

    match engine {
        "deterministic" => {
            let summary_path = bundle_dir.join("proposal.md");
            fs::write(
                &summary_path,
                format!(
                    "# Deterministic proposal\n\nInspect opportunity {} and apply a bounded fix based on {}\n",
                    opportunity.id,
                    evidence_path.display()
                ),
            )?;
            store.create_proposal(
                opportunity.id,
                engine,
                "ready",
                &bundle_dir,
                Some(&summary_path),
            )
        }
        "codex" => {
            let job = write_codex_job_spec(
                config,
                opportunity,
                workspace,
                &bundle_dir,
                &prompt_path,
                &output_path,
            )?;
            let status = execute_codex_job(config, &job)?;
            store.create_proposal(
                opportunity.id,
                "codex",
                &status.state,
                &bundle_dir,
                Some(&output_path),
            )
        }
        other => Err(anyhow!("unknown proposal engine `{other}`")),
    }
}

pub fn prepare_codex_job(
    config: &FixerConfig,
    opportunity: &OpportunityRecord,
    workspace: &PreparedWorkspace,
    run_as_user: &str,
    allow_kernel: bool,
) -> Result<CodexJobSpec> {
    let bundle_dir = config.service.state_dir.join("proposals").join(format!(
        "{}-{}",
        opportunity.id,
        now_rfc3339().replace(':', "-")
    ));
    fs::create_dir_all(&bundle_dir)?;
    let job_workspace = snapshot_workspace_for_job(workspace, &bundle_dir)?;
    let evidence_path = bundle_dir.join("evidence.json");
    let prompt_path = bundle_dir.join("prompt.md");
    let output_path = bundle_dir.join("codex-output.txt");

    let evidence = json!({
        "opportunity": opportunity,
        "workspace": job_workspace,
        "source_workspace": workspace,
    });
    fs::write(&evidence_path, serde_json::to_vec_pretty(&evidence)?)?;

    let prompt = build_prompt(
        opportunity,
        &fs::canonicalize(&evidence_path).unwrap_or_else(|_| evidence_path.clone()),
        &job_workspace,
        config,
    );
    fs::write(&prompt_path, prompt.as_bytes())?;

    let mut job = write_codex_job_spec(
        config,
        opportunity,
        &job_workspace,
        &bundle_dir,
        &prompt_path,
        &output_path,
    )?;
    job.run_as_user = run_as_user.to_string();
    job.allow_kernel = allow_kernel;
    fs::write(
        bundle_dir.join("job.json"),
        serde_json::to_vec_pretty(&job)?,
    )?;
    Ok(job)
}

pub fn load_codex_job(job_dir: &std::path::Path) -> Result<CodexJobSpec> {
    let job_path = job_dir.join("job.json");
    let raw =
        fs::read(&job_path).with_context(|| format!("failed to read {}", job_path.display()))?;
    serde_json::from_slice(&raw).with_context(|| format!("failed to parse {}", job_path.display()))
}

pub fn load_published_codex_session(bundle_dir: &Path) -> Result<Value> {
    let evidence_path = bundle_dir.join("evidence.json");
    let prompt_path = bundle_dir.join("prompt.md");
    let output_path = bundle_dir.join("codex-output.txt");
    let evidence_raw = fs::read(&evidence_path)
        .with_context(|| format!("failed to read {}", evidence_path.display()))?;
    let evidence: Value = serde_json::from_slice(&evidence_raw)
        .with_context(|| format!("failed to parse {}", evidence_path.display()))?;
    let workspace_root = evidence
        .get("workspace")
        .and_then(|value| value.get("repo_root"))
        .and_then(Value::as_str)
        .map(PathBuf::from);
    let source_workspace_root = evidence
        .get("source_workspace")
        .and_then(|value| value.get("repo_root"))
        .and_then(Value::as_str)
        .map(PathBuf::from);
    let prompt = truncate_public_session_text(
        &sanitize_public_session_text(
            &read_text(&prompt_path)
                .with_context(|| format!("failed to read {}", prompt_path.display()))?,
            bundle_dir,
            workspace_root.as_deref(),
            source_workspace_root.as_deref(),
        ),
        16 * 1024,
    );
    let response = output_path
        .exists()
        .then(|| {
            let raw = read_text(&output_path)
                .with_context(|| format!("failed to read {}", output_path.display()))?;
            Ok::<String, anyhow::Error>(truncate_public_session_text(
                &sanitize_public_session_text(
                    &raw,
                    bundle_dir,
                    workspace_root.as_deref(),
                    source_workspace_root.as_deref(),
                ),
                64 * 1024,
            ))
        })
        .transpose()?;
    let diff =
        render_public_session_diff(source_workspace_root.as_deref(), workspace_root.as_deref())?;
    Ok(json!({
        "prompt": prompt,
        "response": response,
        "diff": diff,
    }))
}

pub fn execute_codex_job(config: &FixerConfig, job: &CodexJobSpec) -> Result<CodexJobStatus> {
    let started_at = now_rfc3339();
    let prompt = read_text(&job.prompt_path)
        .with_context(|| format!("failed to read {}", job.prompt_path.display()))?;
    let outcome = run_codex_process(config, &job.workspace.repo_root, &job.output_path, &prompt)?;
    let finished_at = now_rfc3339();
    let log_path = job.bundle_dir.join("codex-run.log");
    if !outcome.log.is_empty() {
        fs::write(&log_path, outcome.log.as_bytes())?;
    }
    let error = if outcome.success {
        None
    } else {
        Some(summarize_failure_log(&outcome.log))
    };
    let status = CodexJobStatus {
        job_id: job.job_id.clone(),
        state: if outcome.success {
            "ready".to_string()
        } else {
            "failed".to_string()
        },
        started_at,
        finished_at,
        output_path: job.output_path.exists().then(|| job.output_path.clone()),
        failure_kind: (!outcome.success).then(|| classify_codex_failure(&outcome.log)),
        error,
    };
    fs::write(
        job.bundle_dir.join("status.json"),
        serde_json::to_vec_pretty(&status)?,
    )?;
    Ok(status)
}

pub fn create_external_report_proposal(
    store: &Store,
    config: &FixerConfig,
    opportunity: &OpportunityRecord,
    acquisition_error: &str,
) -> Result<ProposalRecord> {
    let bundle_dir = config.service.state_dir.join("proposals").join(format!(
        "{}-{}",
        opportunity.id,
        now_rfc3339().replace(':', "-")
    ));
    fs::create_dir_all(&bundle_dir)?;

    let evidence_path = bundle_dir.join("evidence.json");
    let summary_path = bundle_dir.join("proposal.md");
    let package_name = opportunity
        .evidence
        .get("package_name")
        .and_then(Value::as_str)
        .ok_or_else(|| {
            anyhow!(
                "opportunity {} has no package name for external report",
                opportunity.id
            )
        })?;
    let package = resolve_installed_package_metadata(package_name)?;
    let system = collect_system_context();
    let evidence = json!({
        "report_kind": "external-bug-report",
        "opportunity": opportunity,
        "package": package,
        "system": system,
        "workspace_error": acquisition_error,
    });
    fs::write(&evidence_path, serde_json::to_vec_pretty(&evidence)?)?;
    fs::write(
        &summary_path,
        render_external_bug_report(opportunity, &package, &system, &evidence_path),
    )?;
    store.create_proposal(
        opportunity.id,
        "deterministic",
        "ready",
        &bundle_dir,
        Some(&summary_path),
    )
}

pub fn supports_local_remediation(opportunity: &OpportunityRecord) -> bool {
    opportunity
        .evidence
        .get("details")
        .and_then(|details| details.get("subsystem"))
        .and_then(Value::as_str)
        == Some("postgres-collation")
}

pub fn supports_process_investigation_report(opportunity: &OpportunityRecord) -> bool {
    opportunity.kind == "investigation"
        && opportunity
            .evidence
            .get("details")
            .and_then(|details| details.get("subsystem"))
            .and_then(Value::as_str)
            .is_some_and(|subsystem| matches!(subsystem, "runaway-process" | "stuck-process"))
}

pub fn create_process_investigation_report_proposal(
    store: &Store,
    config: &FixerConfig,
    opportunity: &OpportunityRecord,
    acquisition_error: Option<&str>,
) -> Result<ProposalRecord> {
    let bundle_dir = config.service.state_dir.join("proposals").join(format!(
        "{}-{}",
        opportunity.id,
        now_rfc3339().replace(':', "-")
    ));
    fs::create_dir_all(&bundle_dir)?;

    let evidence_path = bundle_dir.join("evidence.json");
    let summary_path = bundle_dir.join("proposal.md");
    let package = opportunity
        .evidence
        .get("package_name")
        .and_then(Value::as_str)
        .and_then(|package_name| resolve_installed_package_metadata(package_name).ok());
    let system = collect_system_context();
    let report_kind = opportunity
        .evidence
        .get("details")
        .and_then(|details| details.get("subsystem"))
        .and_then(Value::as_str)
        .unwrap_or("investigation");
    let evidence = json!({
        "report_kind": format!("{report_kind}-investigation"),
        "opportunity": opportunity,
        "package": package,
        "system": system,
        "workspace_error": acquisition_error,
    });
    fs::write(&evidence_path, serde_json::to_vec_pretty(&evidence)?)?;
    fs::write(
        &summary_path,
        render_process_investigation_report(
            opportunity,
            package.as_ref(),
            &system,
            &evidence_path,
            acquisition_error,
        ),
    )?;
    store.create_proposal(
        opportunity.id,
        "deterministic",
        "ready",
        &bundle_dir,
        Some(&summary_path),
    )
}

pub fn create_local_remediation_proposal(
    store: &Store,
    config: &FixerConfig,
    opportunity: &OpportunityRecord,
) -> Result<ProposalRecord> {
    let bundle_dir = config.service.state_dir.join("proposals").join(format!(
        "{}-{}",
        opportunity.id,
        now_rfc3339().replace(':', "-")
    ));
    fs::create_dir_all(&bundle_dir)?;

    let evidence_path = bundle_dir.join("evidence.json");
    let summary_path = bundle_dir.join("proposal.md");
    let remediation_sql_path = bundle_dir.join("remediation.sql");
    let package = opportunity
        .evidence
        .get("package_name")
        .and_then(Value::as_str)
        .and_then(|package_name| resolve_installed_package_metadata(package_name).ok());
    let system = collect_system_context();
    let remediation_sql = render_local_remediation_sql(opportunity)?;
    let evidence = json!({
        "report_kind": "local-remediation",
        "opportunity": opportunity,
        "package": package,
        "system": system,
        "remediation_sql": remediation_sql,
    });
    fs::write(&evidence_path, serde_json::to_vec_pretty(&evidence)?)?;
    fs::write(&remediation_sql_path, remediation_sql.as_bytes())?;
    fs::write(
        &summary_path,
        render_local_remediation_report(
            opportunity,
            package.as_ref(),
            &system,
            &evidence_path,
            &remediation_sql_path,
        )?,
    )?;
    store.create_proposal(
        opportunity.id,
        "deterministic",
        "ready",
        &bundle_dir,
        Some(&summary_path),
    )
}

pub fn create_complaint_plan_proposal(
    store: &Store,
    config: &FixerConfig,
    opportunity: &OpportunityRecord,
    complaint_text: &str,
    collection_report: Option<&ComplaintCollectionReport>,
    related: &[SharedOpportunity],
) -> Result<ProposalRecord> {
    let bundle_dir = config.service.state_dir.join("proposals").join(format!(
        "{}-{}",
        opportunity.id,
        now_rfc3339().replace(':', "-")
    ));
    fs::create_dir_all(&bundle_dir)?;

    let evidence_path = bundle_dir.join("evidence.json");
    let summary_path = bundle_dir.join("plan.md");
    let evidence = json!({
        "report_kind": "complaint-plan",
        "opportunity": opportunity,
        "complaint_text": complaint_text,
        "collection_report": collection_report,
        "related_opportunities": related,
    });
    fs::write(&evidence_path, serde_json::to_vec_pretty(&evidence)?)?;
    fs::write(
        &summary_path,
        render_complaint_plan(
            opportunity,
            complaint_text,
            collection_report,
            related,
            &evidence_path,
        ),
    )?;
    store.create_proposal(
        opportunity.id,
        "planner",
        "ready",
        &bundle_dir,
        Some(&summary_path),
    )
}

pub fn prepare_submission(store: &Store, proposal_id: i64) -> Result<PathBuf> {
    let proposal = store.get_proposal(proposal_id)?;
    let opportunity = store.get_opportunity(proposal.opportunity_id)?;
    let path = proposal.bundle_path.join("submission.md");
    let mut file = fs::File::create(&path)?;
    writeln!(file, "# Submission bundle")?;
    writeln!(file)?;
    writeln!(file, "- Proposal ID: {}", proposal.id)?;
    writeln!(file, "- Opportunity ID: {}", opportunity.id)?;
    writeln!(file, "- Title: {}", opportunity.title)?;
    writeln!(file, "- Summary: {}", opportunity.summary)?;
    writeln!(
        file,
        "- Ecosystem: {}",
        opportunity
            .ecosystem
            .unwrap_or_else(|| "unknown".to_string())
    )?;
    writeln!(
        file,
        "- Repo root: {}",
        opportunity
            .repo_root
            .map(|x| x.display().to_string())
            .unwrap_or_else(|| "(none)".to_string())
    )?;
    if let Some(output) = proposal.output_path {
        writeln!(file, "- Output artifact: {}", output.display())?;
    }
    Ok(path)
}

fn write_codex_job_spec(
    config: &FixerConfig,
    opportunity: &OpportunityRecord,
    workspace: &PreparedWorkspace,
    bundle_dir: &std::path::Path,
    prompt_path: &std::path::Path,
    output_path: &std::path::Path,
) -> Result<CodexJobSpec> {
    let job = CodexJobSpec {
        job_id: format!("{}-{}", opportunity.id, now_rfc3339().replace(':', "-")),
        opportunity_id: opportunity.id,
        run_as_user: String::new(),
        workspace: workspace.clone(),
        bundle_dir: bundle_dir.to_path_buf(),
        prompt_path: prompt_path.to_path_buf(),
        output_path: output_path.to_path_buf(),
        failure_pause_threshold: config.patch.lease_failure_pause_threshold,
        failure_pause_window_seconds: config.patch.lease_failure_pause_window_seconds,
        allow_kernel: false,
    };
    fs::write(
        bundle_dir.join("job.json"),
        serde_json::to_vec_pretty(&job)?,
    )?;
    Ok(job)
}

fn snapshot_workspace_for_job(
    workspace: &PreparedWorkspace,
    bundle_dir: &std::path::Path,
) -> Result<PreparedWorkspace> {
    let target = bundle_dir.join("workspace");
    copy_directory_recursively(&workspace.repo_root, &target)?;
    let mut job_workspace = workspace.clone();
    job_workspace.repo_root = target;
    job_workspace.acquisition_note = format!(
        "{} Fixer created an isolated job snapshot for autonomous Codex execution.",
        workspace.acquisition_note
    );
    Ok(job_workspace)
}

fn copy_directory_recursively(
    source: &std::path::Path,
    destination: &std::path::Path,
) -> Result<()> {
    if destination.exists() {
        fs::remove_dir_all(destination).with_context(|| {
            format!(
                "failed to clear existing workspace snapshot {}",
                destination.display()
            )
        })?;
    }
    let status = Command::new("cp")
        .args(["-a"])
        .arg(source)
        .arg(destination)
        .status()
        .with_context(|| {
            format!(
                "failed to create workspace snapshot from {}",
                source.display()
            )
        })?;
    if !status.success() {
        return Err(anyhow!(
            "failed to snapshot workspace {} into {}",
            source.display(),
            destination.display()
        ));
    }
    Ok(())
}

fn render_public_session_diff(
    source_workspace_root: Option<&Path>,
    workspace_root: Option<&Path>,
) -> Result<Option<String>> {
    let (Some(source_workspace_root), Some(workspace_root)) =
        (source_workspace_root, workspace_root)
    else {
        return Ok(None);
    };
    if !source_workspace_root.exists() || !workspace_root.exists() {
        return Ok(None);
    }

    let output = Command::new("diff")
        .args([
            "-urN",
            "--exclude=.git",
            "--exclude=.pc",
            "--exclude=build",
            "--exclude=autom4te.cache",
            "--exclude=config.log",
        ])
        .arg(source_workspace_root)
        .arg(workspace_root)
        .output()
        .context("failed to generate a public diff for the Codex session")?;
    match output.status.code() {
        Some(0) => Ok(None),
        Some(1) => {
            let diff = normalize_public_patch_diff(
                &String::from_utf8_lossy(&output.stdout),
                source_workspace_root,
                workspace_root,
            );
            if diff.trim().is_empty() {
                Ok(None)
            } else {
                Ok(Some(truncate_public_session_text(&diff, 128 * 1024)))
            }
        }
        _ => Err(anyhow!(
            "failed to generate a public diff for the Codex session: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        )),
    }
}

fn normalize_public_patch_diff(
    text: &str,
    source_workspace_root: &Path,
    workspace_root: &Path,
) -> String {
    let mut replacements = vec![
        (workspace_root.to_path_buf(), "b".to_string()),
        (source_workspace_root.to_path_buf(), "a".to_string()),
    ];
    replacements.sort_by(|(left, _), (right, _)| {
        right
            .to_string_lossy()
            .len()
            .cmp(&left.to_string_lossy().len())
    });

    let mut normalized = text.to_string();
    for (from, to) in replacements {
        let from = from.to_string_lossy();
        if !from.is_empty() {
            normalized = normalized.replace(from.as_ref(), &to);
        }
    }

    let trailing_newline = normalized.ends_with('\n');
    let mut lines = normalized
        .lines()
        .filter(|line| {
            !(line.starts_with("diff -ur")
                || line.starts_with("diff -r ")
                || line.starts_with("Only in ")
                || line.starts_with("Binary files "))
        })
        .collect::<Vec<_>>()
        .join("\n");
    if trailing_newline && !lines.is_empty() {
        lines.push('\n');
    }
    lines
}

fn sanitize_public_session_text(
    text: &str,
    bundle_dir: &Path,
    workspace_root: Option<&Path>,
    source_workspace_root: Option<&Path>,
) -> String {
    let mut replacements = vec![
        (
            bundle_dir.join("evidence.json"),
            "./evidence.json".to_string(),
        ),
        (bundle_dir.join("workspace"), "./workspace".to_string()),
        (bundle_dir.to_path_buf(), ".".to_string()),
    ];
    if let Some(workspace_root) = workspace_root {
        replacements.push((workspace_root.to_path_buf(), "./workspace".to_string()));
    }
    if let Some(source_workspace_root) = source_workspace_root {
        replacements.push((source_workspace_root.to_path_buf(), "./source".to_string()));
    }
    replacements.sort_by(|(left, _), (right, _)| {
        right
            .to_string_lossy()
            .len()
            .cmp(&left.to_string_lossy().len())
    });

    let mut sanitized = text.to_string();
    for (from, to) in replacements {
        let from = from.to_string_lossy();
        if !from.is_empty() {
            sanitized = sanitized.replace(from.as_ref(), &to);
        }
    }
    sanitized
}

fn truncate_public_session_text(text: &str, max_len: usize) -> String {
    if text.len() <= max_len {
        return text.to_string();
    }
    let mut boundary = max_len;
    while boundary > 0 && !text.is_char_boundary(boundary) {
        boundary -= 1;
    }
    format!(
        "{}\n\n[truncated {} bytes]",
        &text[..boundary],
        text.len() - boundary
    )
}

struct CodexProcessOutcome {
    success: bool,
    log: String,
}

fn run_codex_process(
    config: &FixerConfig,
    repo_root: &std::path::Path,
    output_path: &std::path::Path,
    prompt: &str,
) -> Result<CodexProcessOutcome> {
    if !command_exists(&config.patch.codex_command) {
        return Err(anyhow!(
            "Codex CLI `{}` was not found in PATH",
            config.patch.codex_command
        ));
    }
    let mut cmd = Command::new(&config.patch.codex_command);
    if let Some(approval_policy) = &config.patch.approval_policy {
        cmd.arg("-a").arg(approval_policy);
    }
    cmd.arg("exec");
    cmd.arg("--skip-git-repo-check");
    if let Some(model) = &config.patch.model {
        cmd.arg("-m").arg(model);
    }
    if let Some(sandbox) = &config.patch.sandbox {
        cmd.arg("-s").arg(sandbox);
    }
    cmd.arg("-C").arg(&repo_root).arg("-o").arg(output_path);
    for arg in &config.patch.codex_args {
        cmd.arg(arg);
    }
    cmd.arg("-")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());

    let mut child = cmd
        .spawn()
        .with_context(|| format!("failed to launch {}", config.patch.codex_command))?;
    if let Some(stdin) = child.stdin.as_mut() {
        stdin.write_all(prompt.as_bytes())?;
    }
    let output = child.wait_with_output()?;
    let log = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    Ok(CodexProcessOutcome {
        success: output.status.success(),
        log,
    })
}

fn classify_codex_failure(log: &str) -> String {
    let lower = log.to_ascii_lowercase();
    if lower.contains("401 unauthorized") || lower.contains("missing bearer") {
        "auth".to_string()
    } else if lower.contains("500 internal server error")
        || lower.contains("failed to connect to websocket")
    {
        "api".to_string()
    } else {
        "execution".to_string()
    }
}

fn summarize_failure_log(log: &str) -> String {
    let summary = log
        .lines()
        .rev()
        .take(8)
        .collect::<Vec<_>>()
        .into_iter()
        .rev()
        .collect::<Vec<_>>()
        .join("\n");
    if summary.trim().is_empty() {
        "codex execution failed without additional output".to_string()
    } else {
        summary
    }
}

fn build_prompt(
    opportunity: &OpportunityRecord,
    evidence_path: &std::path::Path,
    workspace: &PreparedWorkspace,
    config: &FixerConfig,
) -> String {
    let extra = config.patch.extra_instructions.as_deref().unwrap_or(
        "Keep the patch narrowly scoped, validate locally, and explain any uncertainty.",
    );
    let investigation_hint = if supports_process_investigation_report(opportunity) {
        "\n\nStart by explaining the likely root cause from the collected perf, strace, and /proc evidence. If you cannot land a safe patch, leave a diagnosis that is strong enough for an upstream bug report."
    } else {
        ""
    };
    format!(
        "You are working on a bounded fixer proposal.\n\nRead the evidence bundle at `{}`. The prepared workspace is `{}` and it was acquired via `{}`. Produce the smallest reasonable patch for the target repository, run relevant tests if available, and summarize what changed.{} \n\n{}",
        evidence_path.display(),
        workspace.repo_root.display(),
        workspace.source_kind,
        investigation_hint,
        extra
    )
}

fn render_external_bug_report(
    opportunity: &OpportunityRecord,
    package: &InstalledPackageMetadata,
    system: &Value,
    evidence_path: &std::path::Path,
) -> String {
    if opportunity.kind != "crash" {
        return render_external_issue_report(opportunity, package, system, evidence_path);
    }
    let details = opportunity
        .evidence
        .get("details")
        .cloned()
        .unwrap_or_else(|| json!({}));
    let signal_name = details
        .get("signal_name")
        .and_then(Value::as_str)
        .unwrap_or("unknown");
    let signal_number = details
        .get("signal_number")
        .and_then(Value::as_i64)
        .map(|value| value.to_string())
        .unwrap_or_else(|| "?".to_string());
    let top_frames = details
        .get("primary_stack")
        .and_then(Value::as_array)
        .map(|frames| {
            frames
                .iter()
                .take(6)
                .filter_map(Value::as_str)
                .map(ToString::to_string)
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    let improved_frames = details
        .get("symbolization")
        .and_then(|value| value.get("improved_frames"))
        .and_then(Value::as_u64)
        .unwrap_or_default();
    let unresolved_frames = details
        .get("symbolization")
        .and_then(|value| value.get("unresolved_frames"))
        .and_then(Value::as_u64)
        .unwrap_or_default();
    let sanitized_command_line = details
        .get("command_line")
        .and_then(Value::as_str)
        .map(sanitize_command_line_for_report)
        .unwrap_or_else(|| "unknown".to_string());
    let suggested_title = format!(
        "{} {} crashes with signal {} ({}) on {}",
        package.package_name,
        package
            .installed_version
            .as_deref()
            .unwrap_or("unknown-version"),
        signal_number,
        signal_name,
        system
            .get("os_pretty_name")
            .and_then(Value::as_str)
            .unwrap_or("unknown OS")
    );
    let mut body = String::new();
    body.push_str("# External Bug Report Draft\n\n");
    if package.upgrade_available {
        body.push_str("## Recommended Action\n\n");
        body.push_str("A newer package version is available from configured APT sources. Update first, retest, and only file the bug if the crash still reproduces.\n\n");
        if let Some(command) = &package.update_command {
            body.push_str("Update command:\n\n```bash\n");
            body.push_str(command);
            body.push_str("\n```\n\n");
        }
    } else {
        body.push_str("## Recommended Action\n\n");
        body.push_str("No newer package version is available from configured APT sources. File a vendor bug report with the details below.\n\n");
    }

    body.push_str("## Package And Environment\n\n");
    body.push_str(&format!(
        "- Package: `{}`\n- Source package: `{}`\n- Installed version: `{}`\n- Candidate version: `{}`\n- Architecture: `{}`\n- Vendor: `{}`\n- Maintainer: `{}`\n- Homepage: `{}`\n- OS: `{}`\n- Kernel: `{}`\n",
        package.package_name,
        package.source_package,
        package.installed_version.as_deref().unwrap_or("unknown"),
        package.candidate_version.as_deref().unwrap_or("unknown"),
        package.architecture.as_deref().unwrap_or("unknown"),
        package.vendor.as_deref().unwrap_or("unknown"),
        package.maintainer.as_deref().unwrap_or("unknown"),
        package.homepage.as_deref().unwrap_or("unknown"),
        system.get("os_pretty_name").and_then(Value::as_str).unwrap_or("unknown"),
        system.get("kernel").and_then(Value::as_str).unwrap_or("unknown"),
    ));
    if let Some((report_url, source)) = suggested_report_destination(package, system) {
        body.push_str(&format!(
            "- Suggested report URL: `{report_url}`\n- Report URL source: `{source}`\n"
        ));
    }
    if !package.apt_origins.is_empty() {
        body.push_str("- APT origins:\n");
        for origin in &package.apt_origins {
            body.push_str(&format!("  - `{origin}`\n"));
        }
    }
    if let Some(update_command) = &package.update_command {
        body.push_str(&format!("- Update command: `{update_command}`\n"));
    }
    if package.apt_origins.is_empty() {
        if let Some(policy_raw) = &package.apt_policy_raw {
            body.push_str("\nAPT policy snapshot:\n\n```text\n");
            body.push_str(policy_raw);
            body.push_str("\n```\n");
        }
    }
    let debug_packages = details
        .get("symbolization")
        .and_then(|value| value.get("suggested_debug_packages"))
        .and_then(Value::as_array)
        .map(|packages| {
            packages
                .iter()
                .filter_map(Value::as_str)
                .collect::<Vec<_>>()
                .join(", ")
        })
        .unwrap_or_default();
    if !debug_packages.is_empty() {
        body.push_str(&format!("- Suggested debug packages: `{debug_packages}`\n"));
    }
    let debuginfod_urls = details
        .get("symbolization")
        .and_then(|value| value.get("suggested_debuginfod_urls"))
        .and_then(Value::as_array)
        .map(|urls| {
            urls.iter()
                .filter_map(Value::as_str)
                .collect::<Vec<_>>()
                .join(", ")
        })
        .unwrap_or_default();
    if !debuginfod_urls.is_empty() {
        body.push_str(&format!(
            "- Suggested debuginfod URLs: `{debuginfod_urls}`\n"
        ));
    }

    body.push_str("\n## Crash Details\n\n");
    body.push_str(&format!(
        "- Timestamp: `{}`\n- Executable: `{}`\n- Signal: `{}` (`{}`)\n- Command line: `{}`\n- Improved frames: `{}`\n- Unresolved frames: `{}`\n",
        details.get("timestamp").and_then(Value::as_str).unwrap_or("unknown"),
        details.get("executable").and_then(Value::as_str).unwrap_or("unknown"),
        signal_number,
        signal_name,
        sanitized_command_line,
        improved_frames,
        unresolved_frames,
    ));

    if !top_frames.is_empty() {
        body.push_str("\n## Top Stack Frames\n\n");
        for frame in top_frames {
            body.push_str(&format!("- `{frame}`\n"));
        }
    }

    body.push_str("\n## Suggested Report Title\n\n");
    body.push_str(&format!("{suggested_title}\n\n"));
    body.push_str("## Suggested Report Body\n\n");
    body.push_str("The application crashed on the system described above. The crash was observed by Fixer from a local coredump and symbolized locally where possible.\n\n");
    body.push_str(&format!(
        "Observed signal: {} ({}). Top stack summary: {}.\n\n",
        signal_number, signal_name, opportunity.summary
    ));
    body.push_str("Please advise whether this matches a known issue, whether a newer build is expected to fix it, and whether additional diagnostic data should be collected.\n\n");
    body.push_str("## Evidence Bundle\n\n");
    body.push_str(&format!(
        "Full local evidence: `{}`\n",
        evidence_path.display()
    ));
    body
}

fn render_external_issue_report(
    opportunity: &OpportunityRecord,
    package: &InstalledPackageMetadata,
    system: &Value,
    evidence_path: &std::path::Path,
) -> String {
    let details = opportunity
        .evidence
        .get("details")
        .cloned()
        .unwrap_or_else(|| json!({}));
    let subsystem = details
        .get("subsystem")
        .and_then(Value::as_str)
        .unwrap_or("warning");
    let log_line = details
        .get("line")
        .and_then(Value::as_str)
        .unwrap_or(&opportunity.summary);
    let kernel_module = details.get("kernel_module").and_then(Value::as_str);
    let issue_subject = if subsystem == "apparmor" {
        package.package_name.clone()
    } else if let Some(kernel_module) = kernel_module {
        format!("{kernel_module} kernel warning")
    } else {
        opportunity.title.to_ascii_lowercase()
    };
    let suggested_title = if subsystem == "apparmor" {
        format!(
            "{} AppArmor denial on {}",
            package.package_name,
            system
                .get("os_pretty_name")
                .and_then(Value::as_str)
                .unwrap_or("unknown OS")
        )
    } else {
        format!(
            "{} on {}",
            issue_subject,
            system
                .get("os_pretty_name")
                .and_then(Value::as_str)
                .unwrap_or("unknown OS")
        )
    };

    let mut body = String::new();
    body.push_str("# External Issue Report Draft\n\n");
    if package.upgrade_available {
        body.push_str("## Recommended Action\n\n");
        body.push_str("A newer package version is available from configured APT sources. Update first, retest, and only file the bug if the issue still reproduces.\n\n");
        if let Some(command) = &package.update_command {
            body.push_str("Update command:\n\n```bash\n");
            body.push_str(command);
            body.push_str("\n```\n\n");
        }
    } else {
        body.push_str("## Recommended Action\n\n");
        body.push_str("No newer package version is available from configured APT sources. File a vendor or distro bug report with the details below.\n\n");
    }

    body.push_str("## Package And Environment\n\n");
    body.push_str(&format!(
        "- Package: `{}`\n- Source package: `{}`\n- Installed version: `{}`\n- Candidate version: `{}`\n- Architecture: `{}`\n- Vendor: `{}`\n- Maintainer: `{}`\n- Homepage: `{}`\n- OS: `{}`\n- Kernel: `{}`\n",
        package.package_name,
        package.source_package,
        package.installed_version.as_deref().unwrap_or("unknown"),
        package.candidate_version.as_deref().unwrap_or("unknown"),
        package.architecture.as_deref().unwrap_or("unknown"),
        package.vendor.as_deref().unwrap_or("unknown"),
        package.maintainer.as_deref().unwrap_or("unknown"),
        package.homepage.as_deref().unwrap_or("unknown"),
        system.get("os_pretty_name").and_then(Value::as_str).unwrap_or("unknown"),
        system.get("kernel").and_then(Value::as_str).unwrap_or("unknown"),
    ));
    if let Some((report_url, source)) = suggested_report_destination(package, system) {
        body.push_str(&format!(
            "- Suggested report URL: `{report_url}`\n- Report URL source: `{source}`\n"
        ));
    }
    if !package.apt_origins.is_empty() {
        body.push_str("- APT origins:\n");
        for origin in &package.apt_origins {
            body.push_str(&format!("  - `{origin}`\n"));
        }
    }
    if let Some(update_command) = &package.update_command {
        body.push_str(&format!("- Update command: `{update_command}`\n"));
    }
    if package.apt_origins.is_empty() {
        if let Some(policy_raw) = &package.apt_policy_raw {
            body.push_str("\nAPT policy snapshot:\n\n```text\n");
            body.push_str(policy_raw);
            body.push_str("\n```\n");
        }
    }

    body.push_str("\n## Issue Details\n\n");
    body.push_str(&format!(
        "- Kind: `{}`\n- Subsystem: `{}`\n- Summary: `{}`\n",
        opportunity.kind, subsystem, opportunity.summary
    ));
    if let Some(profile) = details.get("profile").and_then(Value::as_str) {
        body.push_str(&format!("- Profile: `{profile}`\n"));
    }
    if let Some(kernel_module) = kernel_module {
        body.push_str(&format!("- Kernel module: `{kernel_module}`\n"));
    }
    if let Some(kernel_module_path) = details.get("kernel_module_path").and_then(Value::as_str) {
        body.push_str(&format!("- Kernel module path: `{kernel_module_path}`\n"));
    }
    if let Some(comm) = details.get("comm").and_then(Value::as_str) {
        body.push_str(&format!("- Command: `{comm}`\n"));
    }
    if let Some(operation) = details.get("operation").and_then(Value::as_str) {
        body.push_str(&format!("- Operation: `{operation}`\n"));
    }
    if let Some(class) = details.get("class").and_then(Value::as_str) {
        body.push_str(&format!("- Class: `{class}`\n"));
    }
    if let Some(name) = details.get("name").and_then(Value::as_str) {
        body.push_str(&format!("- Target: `{name}`\n"));
    }
    if let Some(family) = details.get("family").and_then(Value::as_str) {
        body.push_str(&format!("- Family: `{family}`\n"));
    }
    if let Some(sock_type) = details.get("sock_type").and_then(Value::as_str) {
        body.push_str(&format!("- Socket type: `{sock_type}`\n"));
    }
    if let Some(requested) = details.get("requested").and_then(Value::as_str) {
        body.push_str(&format!("- Requested: `{requested}`\n"));
    }
    if let Some(denied) = details.get("denied").and_then(Value::as_str) {
        body.push_str(&format!("- Denied: `{denied}`\n"));
    }
    body.push_str(&format!("- Raw log line: `{log_line}`\n"));

    body.push_str("\n## Suggested Report Title\n\n");
    body.push_str(&format!("{suggested_title}\n\n"));
    body.push_str("## Suggested Report Body\n\n");
    body.push_str(
        "The issue described above was observed locally by Fixer from the system journal.\n\n",
    );
    body.push_str(&format!(
        "Observed summary: {}. Raw log: {}.\n\n",
        opportunity.summary, log_line
    ));
    body.push_str("Please advise whether this matches a known issue, whether a newer package build is expected to fix it, and whether additional diagnostic data should be collected.\n\n");
    body.push_str("## Evidence Bundle\n\n");
    body.push_str(&format!(
        "Full local evidence: `{}`\n",
        evidence_path.display()
    ));
    body
}

fn render_process_investigation_report(
    opportunity: &OpportunityRecord,
    package: Option<&InstalledPackageMetadata>,
    system: &Value,
    evidence_path: &std::path::Path,
    acquisition_error: Option<&str>,
) -> String {
    let details = opportunity
        .evidence
        .get("details")
        .cloned()
        .unwrap_or_else(|| json!({}));
    let subsystem = details
        .get("subsystem")
        .and_then(Value::as_str)
        .unwrap_or("runaway-process");
    let classification = details
        .get("loop_classification")
        .and_then(Value::as_str)
        .unwrap_or(if subsystem == "stuck-process" {
            "unknown-uninterruptible-wait"
        } else {
            "unknown-userspace-loop"
        });
    let confidence = details
        .get("loop_confidence")
        .and_then(Value::as_f64)
        .unwrap_or(0.0);
    let explanation = details
        .get("loop_explanation")
        .and_then(Value::as_str)
        .unwrap_or(if subsystem == "stuck-process" {
            "Fixer collected `/proc` evidence for a process wedged in `D` state but could not derive a stronger kernel-side hypothesis yet."
        } else {
            "Fixer collected a CPU-hot process sample but could not derive a stronger hypothesis yet."
        });
    let target_name = details
        .get("profile_target")
        .and_then(|value| value.get("name"))
        .and_then(Value::as_str)
        .unwrap_or("process");
    let hot_symbols = details
        .get("top_hot_symbols")
        .and_then(Value::as_array)
        .map(|items| {
            items
                .iter()
                .filter_map(Value::as_str)
                .take(5)
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    let top_syscalls = details
        .get("top_syscalls")
        .and_then(Value::as_array)
        .map(|items| {
            items
                .iter()
                .filter_map(|item| {
                    Some(format!(
                        "{} x{}",
                        item.get("name")?.as_str()?,
                        item.get("count")?.as_u64()?
                    ))
                })
                .take(5)
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    let dominant_sequence = details
        .get("dominant_sequence")
        .and_then(Value::as_array)
        .map(|items| {
            items
                .iter()
                .filter_map(Value::as_str)
                .collect::<Vec<_>>()
                .join(" -> ")
        })
        .unwrap_or_default();
    let command_line = details
        .get("command_line")
        .and_then(Value::as_str)
        .map(sanitize_command_line_for_report);
    let process_state = details.get("process_state").and_then(Value::as_str);
    let wchan = details.get("wchan").and_then(Value::as_str);
    let strace_duration = details
        .get("strace_duration_seconds")
        .and_then(Value::as_u64)
        .unwrap_or(0);
    let sampled_pid = details
        .get("sampled_pid")
        .and_then(Value::as_i64)
        .map(|value| value.to_string())
        .unwrap_or_else(|| "unknown".to_string());
    let package_name = package
        .map(|pkg| pkg.package_name.clone())
        .or_else(|| {
            opportunity
                .evidence
                .get("package_name")
                .and_then(Value::as_str)
                .map(ToString::to_string)
        })
        .unwrap_or_else(|| "unknown".to_string());
    let source_package = package
        .map(|pkg| pkg.source_package.clone())
        .or_else(|| {
            details
                .get("package_metadata")
                .and_then(|value| value.get("source_package"))
                .and_then(Value::as_str)
                .map(ToString::to_string)
        })
        .unwrap_or_else(|| "unknown".to_string());

    let mut body = String::new();
    if subsystem == "stuck-process" {
        body.push_str("# Stuck Process Investigation Report\n\n");
    } else {
        body.push_str("# Runaway CPU Investigation Report\n\n");
    }
    body.push_str("## Recommended Action\n\n");
    match acquisition_error {
        Some(error) => {
            if subsystem == "stuck-process" {
                body.push_str("Fixer diagnosed a likely stuck-process wait, but it could not automatically acquire a patchable source workspace on this host.\n\n");
            } else {
                body.push_str("Fixer diagnosed a likely runaway CPU loop, but it could not automatically acquire a patchable source workspace on this host.\n\n");
            }
            body.push_str(&format!("Workspace acquisition error: `{error}`\n\n"));
            body.push_str("Use the diagnosis below to file an upstream or distro bug, or to fetch a source tree manually before retrying `fixer propose-fix <id> --engine codex`.\n\n");
        }
        None => {
            if subsystem == "stuck-process" {
                body.push_str("Fixer gathered enough evidence to describe the wait. Review the diagnosis below, then decide whether this looks like a package bug or a lower-level filesystem or kernel stall.\n\n");
            } else {
                body.push_str("Fixer gathered enough evidence to describe the loop. Review the diagnosis below, then run `fixer propose-fix <id> --engine codex` against a prepared source tree if you want an automated patch attempt.\n\n");
            }
        }
    }

    body.push_str("## Package And Environment\n\n");
    body.push_str(&format!(
        "- Package: `{}`\n- Source package: `{}`\n- OS: `{}`\n- Kernel: `{}`\n",
        package_name,
        source_package,
        system
            .get("os_pretty_name")
            .and_then(Value::as_str)
            .unwrap_or("unknown"),
        system
            .get("kernel")
            .and_then(Value::as_str)
            .unwrap_or("unknown"),
    ));
    if let Some(package) = package {
        body.push_str(&format!(
            "- Installed version: `{}`\n- Candidate version: `{}`\n- Homepage: `{}`\n",
            package.installed_version.as_deref().unwrap_or("unknown"),
            package.candidate_version.as_deref().unwrap_or("unknown"),
            package.homepage.as_deref().unwrap_or("unknown"),
        ));
        if let Some((report_url, source)) = suggested_report_destination(package, system) {
            body.push_str(&format!(
                "- Suggested report URL: `{report_url}`\n- Report URL source: `{source}`\n"
            ));
        }
    }

    body.push_str("\n## Why Fixer Believes It Is Stuck\n\n");
    body.push_str(&format!(
        "- Target process: `{}`\n- Sampled PID: `{}`\n- Loop classification: `{}`\n- Confidence: `{:.2}`\n- Explanation: {}\n",
        target_name, sampled_pid, classification, confidence, explanation
    ));
    if let Some(process_state) = process_state {
        body.push_str(&format!("- Process state: `{process_state}`\n"));
    }
    if let Some(wchan) = wchan {
        body.push_str(&format!("- Wait channel: `{wchan}`\n"));
    }
    if let Some(command_line) = command_line {
        body.push_str(&format!("- Command line: `{command_line}`\n"));
    }
    if strace_duration > 0 {
        body.push_str(&format!(
            "- Strace capture duration: `{strace_duration}` seconds\n"
        ));
    }
    if subsystem == "stuck-process" {
        if let Some(runtime_seconds) = details.get("runtime_seconds").and_then(Value::as_u64) {
            body.push_str(&format!(
                "- Runtime before capture: `{runtime_seconds}` seconds\n"
            ));
        }
        if let Some(fd_targets) = details.get("fd_targets").and_then(Value::as_array) {
            let targets = fd_targets
                .iter()
                .filter_map(Value::as_str)
                .take(8)
                .collect::<Vec<_>>();
            if !targets.is_empty() {
                body.push_str("- Open targets:\n");
                for target in targets {
                    body.push_str(&format!("  - `{target}`\n"));
                }
            }
        }
    }

    if !hot_symbols.is_empty() {
        body.push_str("\n## Dominant Call Path\n\n");
        for symbol in hot_symbols {
            body.push_str(&format!("- `{symbol}`\n"));
        }
    }

    if !top_syscalls.is_empty() {
        body.push_str("\n## Dominant Syscalls\n\n");
        for syscall in top_syscalls {
            body.push_str(&format!("- `{syscall}`\n"));
        }
    }
    if !dominant_sequence.is_empty() {
        body.push_str("\n## Repeated Loop Shape\n\n");
        body.push_str(&format!("`{dominant_sequence}`\n"));
    }
    if subsystem == "stuck-process" {
        if let Some(io_excerpt) = details.get("io_excerpt").and_then(Value::as_str) {
            body.push_str("\n## I/O Snapshot\n\n```text\n");
            body.push_str(io_excerpt);
            body.push_str("\n```\n");
        }
        if let Some(stack_excerpt) = details.get("stack_excerpt").and_then(Value::as_str) {
            body.push_str("\n## Kernel Stack Excerpt\n\n```text\n");
            body.push_str(stack_excerpt);
            body.push_str("\n```\n");
        }
    }

    body.push_str("\n## Validation Steps\n\n");
    if subsystem == "stuck-process" {
        body.push_str("1. Confirm the process is still in `D` state with `ps -p <pid> -o pid,stat,wchan:40,comm`.\n");
        body.push_str("2. Re-read `/proc/<pid>/stack`, `/proc/<pid>/wchan`, and `/proc/<pid>/fd` to confirm the blocking path still points at the same wait site.\n");
        body.push_str("3. If you intervene on the suspected filesystem or mount backend, verify the process leaves `D` state instead of simply moving to a different wait site.\n");
    } else {
        body.push_str("1. Confirm the process still shows sustained CPU time with `systemd-cgtop`, `top`, or `ps -p <pid> -o %cpu,stat,comm`.\n");
        body.push_str("2. Re-run a short syscall sample and confirm the dominant syscalls still match the sequence above.\n");
        body.push_str("3. If you change the package, compare a fresh perf sample and strace excerpt to make sure the loop disappears rather than simply moving elsewhere.\n");
    }

    body.push_str("\n## Next Step\n\n");
    if acquisition_error.is_some() {
        body.push_str("Treat this as an upstream-report-ready diagnosis. Include the summary above, plus the evidence bundle path below, when filing the bug.\n");
    } else {
        if subsystem == "stuck-process"
            && details
                .get("likely_external_root_cause")
                .and_then(Value::as_bool)
                .unwrap_or(false)
        {
            body.push_str("Treat this as the diagnosis half of the pipeline. The evidence currently points below user space, so the next action is usually a kernel, mount, or storage investigation rather than a package patch.\n");
        } else {
            body.push_str("Treat this as the diagnosis half of the pipeline. A patch attempt should focus on the subsystem implicated by the dominant evidence above.\n");
        }
    }

    body.push_str("\n## Evidence Bundle\n\n");
    body.push_str(&format!(
        "Full local evidence: `{}`\n",
        evidence_path.display()
    ));
    body
}

fn render_local_remediation_sql(opportunity: &OpportunityRecord) -> Result<String> {
    let details = opportunity
        .evidence
        .get("details")
        .cloned()
        .unwrap_or_else(|| json!({}));
    let subsystem = details
        .get("subsystem")
        .and_then(Value::as_str)
        .unwrap_or_default();
    if subsystem != "postgres-collation" {
        return Err(anyhow!(
            "deterministic local remediation is not implemented for subsystem `{subsystem}`"
        ));
    }
    let database_name = details
        .get("database_name")
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow!("postgres collation remediation is missing `database_name`"))?;
    let affected_indexes = affected_index_candidates(&details);
    let mut sql = String::new();
    if affected_indexes.is_empty() {
        sql.push_str(
            "-- No collation-dependent btree indexes were identified by the dependency query.\n",
        );
        sql.push_str(
            "-- Review range-partitioned text keys manually before refreshing the recorded version.\n",
        );
    } else {
        for index in &affected_indexes {
            sql.push_str(&format!(
                "REINDEX INDEX {};\n",
                sql_qualified_ident(&index.index_name)
            ));
        }
    }
    sql.push_str(&format!(
        "ALTER DATABASE {} REFRESH COLLATION VERSION;\n",
        sql_ident(database_name)
    ));
    Ok(sql)
}

fn render_local_remediation_report(
    opportunity: &OpportunityRecord,
    package: Option<&InstalledPackageMetadata>,
    system: &Value,
    evidence_path: &std::path::Path,
    remediation_sql_path: &std::path::Path,
) -> Result<String> {
    let details = opportunity
        .evidence
        .get("details")
        .cloned()
        .unwrap_or_else(|| json!({}));
    let database_name = details
        .get("database_name")
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow!("postgres collation remediation is missing `database_name`"))?;
    let cluster_name = details
        .get("cluster_name")
        .and_then(Value::as_str)
        .unwrap_or("unknown");
    let cluster_version = details
        .get("cluster_version")
        .and_then(Value::as_i64)
        .map(|value| value.to_string())
        .unwrap_or_else(|| "unknown".to_string());
    let port = details
        .get("port")
        .and_then(Value::as_str)
        .unwrap_or("5432");
    let stored_version = details
        .get("stored_collation_version")
        .and_then(Value::as_str)
        .unwrap_or("unknown");
    let actual_version = details
        .get("actual_collation_version")
        .and_then(Value::as_str)
        .unwrap_or("unknown");
    let verification_query = format!(
        "SELECT datname, datcollversion, pg_database_collation_actual_version(oid) FROM pg_database WHERE datname = {}",
        sql_literal(database_name)
    );
    let connect_command = format!("psql -p {port} -U postgres -d {database_name}");
    let affected_indexes = affected_index_candidates(&details);
    let pg_amcheck_command = pg_amcheck_command(&details, database_name, port, &affected_indexes);

    let mut body = String::new();
    body.push_str("# Deterministic Remediation Plan\n\n");
    body.push_str("## Summary\n\n");
    body.push_str(&format!(
        "- Issue: PostgreSQL collation version mismatch\n- Database: `{}`\n- Cluster: `{}/{}`\n- Stored collation version: `{}`\n- Actual system collation version: `{}`\n- OS: `{}`\n",
        database_name,
        cluster_version,
        cluster_name,
        stored_version,
        actual_version,
        system
            .get("os_pretty_name")
            .and_then(Value::as_str)
            .unwrap_or("unknown"),
    ));
    if let Some(package) = package {
        body.push_str(&format!(
            "- Package: `{}` {}\n",
            package.package_name,
            package
                .installed_version
                .as_deref()
                .map(|version| format!("({version})"))
                .unwrap_or_default()
        ));
    }

    body.push_str("\n## Why This Needs Action\n\n");
    body.push_str("PostgreSQL records the collation version that a database was built against. When the operating system's locale data changes, the stored version can drift from the current system version. That can leave locale-sensitive indexes and sort order assumptions stale until they are rebuilt.\n\n");
    body.push_str("A quick `pg_amcheck` pass is useful triage when it is available, but it should not be treated as proof that rebuilding can be skipped after a libc collation change.\n\n");

    body.push_str("## Candidate Indexes\n\n");
    if affected_indexes.is_empty() {
        body.push_str("Fixer did not find any collation-dependent btree indexes with the dependency query for this database.\n\n");
    } else {
        body.push_str(&format!(
            "Fixer found `{}` candidate btree indexes that use non-`C`/`POSIX` libc collations:\n\n",
            affected_indexes.len()
        ));
        for index in affected_indexes.iter().take(20) {
            body.push_str(&format!(
                "- `{}` on `{}` using collation `{}`\n",
                index.index_name, index.table_name, index.collation_name
            ));
        }
        if affected_indexes.len() > 20 {
            body.push_str(&format!(
                "- ... and {} more listed in the evidence bundle\n",
                affected_indexes.len() - 20
            ));
        }
        body.push('\n');
    }

    body.push_str("## Proposed Fix\n\n");
    body.push_str("Run the verification and SQL below in a maintenance window, because targeted `REINDEX INDEX` still takes strong locks and should not race with normal writes.\n\n");
    if let Some(pg_amcheck_command) = &pg_amcheck_command {
        body.push_str("Suggested `pg_amcheck` smoke test:\n\n```bash\n");
        body.push_str(pg_amcheck_command);
        body.push_str("\n```\n\n");
    } else {
        body.push_str("`pg_amcheck` was not found on this host. If it is installed in a versioned PostgreSQL bin directory, call it explicitly before reindexing.\n\n");
    }
    body.push_str("Remediation SQL:\n\n```sql\n");
    body.push_str(&fs::read_to_string(remediation_sql_path).unwrap_or_default());
    body.push_str("```\n\n");

    body.push_str("## Suggested Execution\n\n");
    body.push_str(&format!(
        "1. Stop or quiesce application writes to `{database_name}`.\n2. Run `pg_amcheck` first if available and review any failures.\n3. Run `{connect_command}` and execute the SQL from `{}`.\n4. Re-run the verification query below.\n5. Retest application code paths that depend on locale-sensitive ordering or indexing.\n\n",
        remediation_sql_path.display()
    ));

    body.push_str("Verification query:\n\n```sql\n");
    body.push_str(&verification_query);
    body.push_str(";\n```\n\n");

    if let Some(warning_excerpt) = details
        .get("detection_warning_excerpt")
        .and_then(Value::as_str)
        .filter(|value| !value.trim().is_empty())
    {
        body.push_str("## Detection Warning\n\n```text\n");
        body.push_str(warning_excerpt);
        body.push_str("\n```\n\n");
    }

    body.push_str("## Evidence Bundle\n\n");
    body.push_str(&format!(
        "- Full local evidence: `{}`\n- Remediation SQL: `{}`\n",
        evidence_path.display(),
        remediation_sql_path.display(),
    ));
    Ok(body)
}

fn render_complaint_plan(
    opportunity: &OpportunityRecord,
    complaint_text: &str,
    collection_report: Option<&ComplaintCollectionReport>,
    related: &[SharedOpportunity],
    evidence_path: &std::path::Path,
) -> String {
    let mut body = String::new();
    body.push_str("# Complaint Triage Plan\n\n");
    body.push_str("## Complaint\n\n");
    body.push_str(complaint_text.trim());
    body.push_str("\n\n");

    body.push_str("## Local Intake\n\n");
    body.push_str(&format!(
        "- Complaint opportunity: `#{}`\n- State: `{}`\n- Score: `{}`\n",
        opportunity.id, opportunity.state, opportunity.score
    ));
    if let Some(report) = collection_report {
        body.push_str(&format!(
            "- Immediate collection: `{}` capabilities, `{}` artifacts, `{}` findings\n",
            report.capabilities_seen, report.artifacts_seen, report.findings_seen
        ));
    } else {
        body.push_str("- Immediate collection: skipped\n");
    }

    if related.is_empty() {
        body.push_str("\n## Related Local Evidence\n\n");
        body.push_str("Fixer did not find any strong local matches for this complaint yet.\n\n");
        body.push_str("## Suggested Next Steps\n\n");
        body.push_str("1. Reproduce the issue while `fixerd` is running.\n");
        body.push_str("2. Run `fixer collect` again right after reproduction.\n");
        body.push_str(
            "3. Check `fixer crashes`, `fixer warnings`, and `fixer hotspots` for new evidence.\n",
        );
        body.push_str("4. Re-run `fixer complain ...` with more concrete wording such as package names, commands, or symptoms.\n");
    } else {
        body.push_str("\n## Related Local Evidence\n\n");
        for item in related.iter().take(8) {
            body.push_str(&format!(
                "- Opportunity `#{}` [{}] score `{}`: {}",
                item.opportunity.id,
                item.opportunity.kind,
                item.opportunity.score,
                item.opportunity.title
            ));
            if let Some(package_name) = item.finding.package_name.as_deref() {
                body.push_str(&format!(" (package `{package_name}`)"));
            }
            body.push_str(&format!("\n  Summary: {}\n", item.opportunity.summary));
        }

        let crash_count = related
            .iter()
            .filter(|item| item.opportunity.kind == "crash")
            .count();
        let warning_count = related
            .iter()
            .filter(|item| item.opportunity.kind == "warning")
            .count();
        let hotspot_count = related
            .iter()
            .filter(|item| item.opportunity.kind == "hotspot")
            .count();

        body.push_str("\n## Suggested Next Steps\n\n");
        let mut step = 1;
        if crash_count > 0 {
            body.push_str(&format!(
                "{step}. Inspect the matched crash opportunities first with `fixer inspect <id>` because they are the strongest evidence for this complaint.\n"
            ));
            step += 1;
        }
        if warning_count > 0 {
            body.push_str(&format!(
                "{step}. Review the matched warnings to see whether they explain the symptom or point at the owning package/service.\n"
            ));
            step += 1;
        }
        if hotspot_count > 0 {
            body.push_str(&format!(
                "{step}. Review the matched hotspots for hot functions and owning packages, then decide whether this is a performance regression or expected workload.\n"
            ));
            step += 1;
        }
        body.push_str(&format!(
            "{step}. If one of the matched opportunities is the real issue, run `fixer propose-fix <id> --engine deterministic` first, then escalate to `--engine codex` only when there is a patchable repo.\n"
        ));
    }

    body.push_str("\n## Evidence Bundle\n\n");
    body.push_str(&format!(
        "Full local evidence: `{}`\n",
        evidence_path.display()
    ));
    body
}

fn collect_system_context() -> Value {
    let os_release = read_text(std::path::Path::new("/etc/os-release")).unwrap_or_default();
    let os_pretty_name = parse_os_release_field(&os_release, "PRETTY_NAME");
    let os_bug_report_url = parse_os_release_field(&os_release, "BUG_REPORT_URL");
    let kernel = command_output("uname", &["-srmo"]).ok();
    json!({
        "os_pretty_name": os_pretty_name,
        "os_bug_report_url": os_bug_report_url,
        "kernel": kernel,
    })
}

fn parse_os_release_field(raw: &str, field_name: &str) -> Option<String> {
    raw.lines().find_map(|line| {
        let (name, value) = line.split_once('=')?;
        if name.trim() == field_name {
            Some(value.trim().trim_matches('"').to_string())
        } else {
            None
        }
    })
}

fn sanitize_command_line_for_report(raw: &str) -> String {
    raw.split_whitespace()
        .map(sanitize_urlish_token)
        .collect::<Vec<_>>()
        .join(" ")
}

fn sanitize_urlish_token(token: &str) -> String {
    let Some((scheme_start, scheme)) = ["zoommtg://", "https://", "http://"]
        .iter()
        .find_map(|scheme| token.find(scheme).map(|index| (index, *scheme)))
    else {
        return token.to_string();
    };

    let prefix = &token[..scheme_start];
    let url_with_suffix = &token[scheme_start..];
    let suffix_len = url_with_suffix
        .chars()
        .rev()
        .take_while(|ch| matches!(ch, '\'' | '"' | ')' | ']' | '}'))
        .count();
    let split_index = url_with_suffix.len().saturating_sub(suffix_len);
    let (url, suffix) = url_with_suffix.split_at(split_index);
    let sanitized_url = sanitize_url_query(url, scheme);
    format!("{prefix}{sanitized_url}{suffix}")
}

fn sanitize_url_query(url: &str, scheme: &str) -> String {
    if !url.starts_with(scheme) {
        return url.to_string();
    }
    let Some((base, query)) = url.split_once('?') else {
        return url.to_string();
    };
    let sanitized_query = query
        .split('&')
        .map(|part| match part.split_once('=') {
            Some((key, value)) if is_safe_report_query_key(key) => format!("{key}={value}"),
            Some((key, _value)) => format!("{key}=<redacted>"),
            None => part.to_string(),
        })
        .collect::<Vec<_>>()
        .join("&");
    format!("{base}?{sanitized_query}")
}

fn is_safe_report_query_key(key: &str) -> bool {
    matches!(key.to_ascii_lowercase().as_str(), "action" | "browser")
}

fn suggested_report_destination(
    package: &InstalledPackageMetadata,
    system: &Value,
) -> Option<(String, String)> {
    if let Some(report_url) = &package.report_url {
        return Some((
            report_url.clone(),
            package
                .report_url_source
                .clone()
                .unwrap_or_else(|| "package metadata".to_string()),
        ));
    }
    system
        .get("os_bug_report_url")
        .and_then(Value::as_str)
        .filter(|url| !url.trim().is_empty())
        .map(|url| (url.to_string(), "os-release BUG_REPORT_URL".to_string()))
}

fn sql_ident(name: &str) -> String {
    format!("\"{}\"", name.replace('"', "\"\""))
}

fn sql_qualified_ident(name: &str) -> String {
    name.split('.').map(sql_ident).collect::<Vec<_>>().join(".")
}

fn sql_literal(name: &str) -> String {
    format!("'{}'", name.replace('\'', "''"))
}

#[derive(Debug, Clone)]
struct AffectedIndexCandidate {
    table_name: String,
    index_name: String,
    collation_name: String,
}

fn affected_index_candidates(details: &Value) -> Vec<AffectedIndexCandidate> {
    details
        .get("affected_index_candidates")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(|item| {
            Some(AffectedIndexCandidate {
                table_name: item.get("table_name")?.as_str()?.to_string(),
                index_name: item.get("index_name")?.as_str()?.to_string(),
                collation_name: item.get("collation_name")?.as_str()?.to_string(),
            })
        })
        .collect()
}

fn pg_amcheck_command(
    details: &Value,
    database_name: &str,
    port: &str,
    affected_indexes: &[AffectedIndexCandidate],
) -> Option<String> {
    if affected_indexes.is_empty() {
        return None;
    }
    let binary = details.get("pg_amcheck_path").and_then(Value::as_str)?;
    let mut parts = vec![
        binary.to_string(),
        "-p".to_string(),
        port.to_string(),
        "-U".to_string(),
        "postgres".to_string(),
        "-d".to_string(),
        database_name.to_string(),
        "--install-missing".to_string(),
        "--parent-check".to_string(),
        "--rootdescend".to_string(),
        "--checkunique".to_string(),
        "--verbose".to_string(),
    ];
    for index in affected_indexes {
        parts.push(format!("--index={}", index.index_name));
    }
    Some(parts.join(" "))
}

#[cfg(test)]
mod tests {
    use super::{
        load_published_codex_session, pg_amcheck_command, render_external_bug_report,
        render_local_remediation_report, render_local_remediation_sql,
        render_process_investigation_report, sanitize_command_line_for_report,
        suggested_report_destination,
    };
    use crate::models::{InstalledPackageMetadata, OpportunityRecord};
    use serde_json::{Value, json};
    use std::path::Path;

    #[test]
    fn redacts_url_query_values_in_report_command_lines() {
        let raw =
            "/opt/zoom/zoom $'zoommtg:///join?action=join&confno=123456&pwd=secret&browser=chrome'";
        let sanitized = sanitize_command_line_for_report(raw);
        assert!(sanitized.contains(
            "zoommtg:///join?action=join&confno=<redacted>&pwd=<redacted>&browser=chrome'"
        ));
        assert!(!sanitized.contains("123456"));
        assert!(!sanitized.contains("secret"));
    }

    #[test]
    fn renders_warning_reports_for_non_crash_opportunities() {
        let opportunity = OpportunityRecord {
            id: 1,
            finding_id: 1,
            kind: "warning".to_string(),
            title: "AppArmor denial in rsyslogd".to_string(),
            score: 64,
            state: "open".to_string(),
            summary: "AppArmor denied rsyslogd: create net unix/dgram".to_string(),
            evidence: json!({
                "details": {
                    "subsystem": "apparmor",
                    "line": "audit: apparmor DENIED",
                    "profile": "rsyslogd",
                    "comm": "rsyslogd",
                    "operation": "create",
                    "class": "net",
                    "family": "unix",
                    "sock_type": "dgram"
                },
                "package_name": "rsyslog"
            }),
            repo_root: None,
            ecosystem: None,
            created_at: "2026-03-28T00:00:00Z".to_string(),
            updated_at: "2026-03-28T00:00:00Z".to_string(),
        };
        let package = InstalledPackageMetadata {
            package_name: "rsyslog".to_string(),
            source_package: "rsyslog".to_string(),
            installed_version: Some("1.0".to_string()),
            candidate_version: Some("1.0".to_string()),
            architecture: Some("amd64".to_string()),
            maintainer: Some("Darafei Praliaskouski <me@komzpa.net>".to_string()),
            vendor: Some("Debian".to_string()),
            homepage: Some("https://www.rsyslog.com".to_string()),
            report_url: Some("https://bugs.debian.org/rsyslog".to_string()),
            report_url_source: Some("test".to_string()),
            status: Some("installed".to_string()),
            apt_policy_raw: None,
            apt_origins: vec!["https://deb.debian.org/debian sid/main amd64 Packages".to_string()],
            upgrade_available: false,
            update_command: None,
            cloneable_homepage: false,
        };
        let system = json!({
            "os_pretty_name": "Debian GNU/Linux forky/sid",
            "kernel": "Linux test",
        });
        let rendered = render_external_bug_report(
            &opportunity,
            &package,
            &system,
            Path::new("/tmp/evidence.json"),
        );
        assert!(rendered.contains("# External Issue Report Draft"));
        assert!(rendered.contains("Suggested report URL: `https://bugs.debian.org/rsyslog`"));
        assert!(rendered.contains("Profile: `rsyslogd`"));
        assert!(rendered.contains("Socket type: `dgram`"));
    }

    #[test]
    fn falls_back_to_os_bug_report_url_when_package_metadata_has_none() {
        let package = InstalledPackageMetadata {
            package_name: "rsyslog".to_string(),
            source_package: "rsyslog".to_string(),
            installed_version: Some("1.0".to_string()),
            candidate_version: Some("1.0".to_string()),
            architecture: Some("amd64".to_string()),
            maintainer: Some("Darafei Praliaskouski <me@komzpa.net>".to_string()),
            vendor: Some("Debian".to_string()),
            homepage: Some("https://www.rsyslog.com".to_string()),
            report_url: None,
            report_url_source: None,
            status: Some("installed".to_string()),
            apt_policy_raw: None,
            apt_origins: Vec::new(),
            upgrade_available: false,
            update_command: None,
            cloneable_homepage: false,
        };
        let system = json!({
            "os_bug_report_url": "https://bugs.debian.org/",
        });
        assert_eq!(
            suggested_report_destination(&package, &system),
            Some((
                "https://bugs.debian.org/".to_string(),
                "os-release BUG_REPORT_URL".to_string()
            ))
        );
    }

    #[test]
    fn kernel_warning_reports_surface_kernel_module_context() {
        let opportunity = OpportunityRecord {
            id: 1,
            finding_id: 1,
            kind: "warning".to_string(),
            title: "Kernel warning".to_string(),
            score: 64,
            state: "open".to_string(),
            summary: "iwlwifi missed_beacons warning".to_string(),
            evidence: json!({
                "details": {
                    "line": "kernel: iwlwifi 0000:04:00.0: missed_beacons:21",
                    "kernel_module": "iwlwifi",
                    "kernel_module_path": "/lib/modules/6.19.8+deb14-amd64/kernel/drivers/net/wireless/intel/iwlwifi/iwlwifi.ko.xz"
                },
                "package_name": "linux-image-6.19.8+deb14-amd64"
            }),
            repo_root: None,
            ecosystem: None,
            created_at: "2026-03-28T00:00:00Z".to_string(),
            updated_at: "2026-03-28T00:00:00Z".to_string(),
        };
        let package = InstalledPackageMetadata {
            package_name: "linux-image-6.19.8+deb14-amd64".to_string(),
            source_package: "linux-signed-amd64".to_string(),
            installed_version: Some("6.19.8-1".to_string()),
            candidate_version: Some("6.19.8-1".to_string()),
            architecture: Some("amd64".to_string()),
            maintainer: Some("Debian Kernel Team <debian-kernel@lists.debian.org>".to_string()),
            vendor: Some("Debian".to_string()),
            homepage: Some("https://www.kernel.org/".to_string()),
            report_url: Some("https://bugs.debian.org/".to_string()),
            report_url_source: Some("test".to_string()),
            status: Some("installed".to_string()),
            apt_policy_raw: None,
            apt_origins: vec!["https://deb.debian.org/debian sid/main amd64 Packages".to_string()],
            upgrade_available: false,
            update_command: None,
            cloneable_homepage: false,
        };
        let system = json!({
            "os_pretty_name": "Debian GNU/Linux forky/sid",
            "kernel": "Linux 6.19.8+deb14-amd64",
        });
        let rendered = render_external_bug_report(
            &opportunity,
            &package,
            &system,
            Path::new("/tmp/evidence.json"),
        );
        assert!(rendered.contains("iwlwifi kernel warning on Debian GNU/Linux forky/sid"));
        assert!(rendered.contains("Kernel module: `iwlwifi`"));
        assert!(rendered.contains("Kernel module path: `/lib/modules/6.19.8+deb14-amd64/kernel/drivers/net/wireless/intel/iwlwifi/iwlwifi.ko.xz`"));
    }

    #[test]
    fn renders_postgres_collation_remediation() {
        let opportunity = OpportunityRecord {
            id: 1,
            finding_id: 1,
            kind: "warning".to_string(),
            title: "PostgreSQL collation mismatch in postgres on 18/main".to_string(),
            score: 92,
            state: "open".to_string(),
            summary:
                "Database `postgres` stores collation version `2.42` but the system reports `2.43`."
                    .to_string(),
            evidence: json!({
                "details": {
                    "subsystem": "postgres-collation",
                    "cluster_name": "main",
                    "cluster_version": 18,
                    "port": "5432",
                    "database_name": "postgres",
                    "stored_collation_version": "2.42",
                    "actual_collation_version": "2.43",
                    "pg_amcheck_path": "/usr/lib/postgresql/18/bin/pg_amcheck",
                    "affected_index_candidates": [
                        {
                            "table_name": "public.users",
                            "index_name": "public.users_name_idx",
                            "collation_name": "default",
                            "index_definition": "CREATE INDEX users_name_idx ON public.users USING btree (name)"
                        },
                        {
                            "table_name": "public.users",
                            "index_name": "public.users_email_idx",
                            "collation_name": "default",
                            "index_definition": "CREATE INDEX users_email_idx ON public.users USING btree (email)"
                        }
                    ],
                    "detection_warning_excerpt": "WARNING: database \"postgres\" has a collation version mismatch"
                },
                "package_name": "postgresql-18"
            }),
            repo_root: None,
            ecosystem: Some("postgres".to_string()),
            created_at: "2026-03-28T00:00:00Z".to_string(),
            updated_at: "2026-03-28T00:00:00Z".to_string(),
        };
        let sql = render_local_remediation_sql(&opportunity).unwrap();
        assert!(sql.contains("REINDEX INDEX \"public\".\"users_name_idx\";"));
        assert!(sql.contains("REINDEX INDEX \"public\".\"users_email_idx\";"));
        assert!(sql.contains("ALTER DATABASE \"postgres\" REFRESH COLLATION VERSION;"));

        let dir = tempfile::tempdir().unwrap();
        let sql_path = dir.path().join("remediation.sql");
        std::fs::write(&sql_path, sql.as_bytes()).unwrap();
        let system = json!({
            "os_pretty_name": "Debian GNU/Linux forky/sid",
        });
        let rendered = render_local_remediation_report(
            &opportunity,
            None,
            &system,
            Path::new("/tmp/evidence.json"),
            &sql_path,
        )
        .unwrap();
        assert!(rendered.contains("PostgreSQL collation version mismatch"));
        assert!(rendered.contains("public.users_name_idx"));
        assert!(rendered.contains("public.users_email_idx"));
        assert!(rendered.contains("Suggested `pg_amcheck` smoke test"));
        assert!(rendered.contains("--index=public.users_name_idx"));
        assert!(rendered.contains("ALTER DATABASE \"postgres\" REFRESH COLLATION VERSION;"));
        assert!(
            rendered.contains("WARNING: database \"postgres\" has a collation version mismatch")
        );
    }

    #[test]
    fn pg_amcheck_command_is_omitted_when_binary_is_missing() {
        let details = json!({});
        assert!(pg_amcheck_command(&details, "postgres", "5432", &[]).is_none());
    }

    #[test]
    fn runaway_investigation_reports_include_root_cause_and_validation_steps() {
        let opportunity = OpportunityRecord {
            id: 7,
            finding_id: 7,
            kind: "investigation".to_string(),
            title: "Runaway CPU investigation for kdeconnectd".to_string(),
            score: 90,
            state: "open".to_string(),
            summary: "kdeconnectd is stuck in a likely dbus spin loop.".to_string(),
            evidence: json!({
                "package_name": "kdeconnect",
                "details": {
                    "subsystem": "runaway-process",
                    "profile_target": { "name": "kdeconnectd" },
                    "sampled_pid": 4242,
                    "loop_classification": "dbus-spin",
                    "loop_confidence": 0.91,
                    "loop_explanation": "Repeated recvmsg/sendmsg activity against the DBus socket suggests a message-loop spin.",
                    "top_hot_symbols": [
                        "QDBusConnection::send (82.10% in libQt6DBus.so.6)",
                        "KdeConnect::LanLinkProvider::onMessage (11.40% in kdeconnectd)"
                    ],
                    "top_syscalls": [
                        { "name": "recvmsg", "count": 122 },
                        { "name": "sendmsg", "count": 121 },
                        { "name": "ppoll", "count": 120 }
                    ],
                    "dominant_sequence": ["recvmsg", "sendmsg", "ppoll"],
                    "process_state": "R (running)",
                    "wchan": "do_epoll_wait",
                    "command_line": "/usr/libexec/kdeconnectd --replace"
                }
            }),
            repo_root: None,
            ecosystem: None,
            created_at: "2026-03-29T00:00:00Z".to_string(),
            updated_at: "2026-03-29T00:00:00Z".to_string(),
        };
        let system = json!({
            "os_pretty_name": "Debian GNU/Linux forky/sid",
            "kernel": "Linux 6.19.8+deb14-amd64"
        });
        let rendered = render_process_investigation_report(
            &opportunity,
            None,
            &system,
            Path::new("/tmp/evidence.json"),
            Some("could not acquire source package automatically"),
        );
        assert!(rendered.contains("Runaway CPU Investigation Report"));
        assert!(rendered.contains("dbus-spin"));
        assert!(rendered.contains("QDBusConnection::send"));
        assert!(rendered.contains("recvmsg x122"));
        assert!(rendered.contains("Validation Steps"));
        assert!(rendered.contains("workspace"));
    }

    #[test]
    fn stuck_process_investigation_reports_explain_d_state_waits() {
        let opportunity = OpportunityRecord {
            id: 8,
            finding_id: 8,
            kind: "investigation".to_string(),
            title: "Stuck D-state investigation for rg".to_string(),
            score: 88,
            state: "open".to_string(),
            summary: "rg has 3 processes stuck in `D` state.".to_string(),
            evidence: json!({
                "package_name": "ripgrep",
                "details": {
                    "subsystem": "stuck-process",
                    "profile_target": { "name": "rg" },
                    "sampled_pid": 7331,
                    "runtime_seconds": 981,
                    "loop_classification": "fuse-wait",
                    "loop_confidence": 0.91,
                    "loop_explanation": "The kernel stack and wait channel point to FUSE request handling.",
                    "process_state": "D (disk sleep)",
                    "wchan": "fuse_wait_answer",
                    "fd_targets": [
                        "/mnt/problematic-tree",
                        "/mnt/problematic-tree/src"
                    ],
                    "io_excerpt": "read_bytes: 0\nwrite_bytes: 0",
                    "stack_excerpt": "fuse_wait_answer\nrequest_wait_answer\n",
                    "likely_external_root_cause": true
                }
            }),
            repo_root: None,
            ecosystem: None,
            created_at: "2026-03-29T00:00:00Z".to_string(),
            updated_at: "2026-03-29T00:00:00Z".to_string(),
        };
        let system = json!({
            "os_pretty_name": "Debian GNU/Linux forky/sid",
            "kernel": "Linux 6.19.8+deb14-amd64"
        });
        let rendered = render_process_investigation_report(
            &opportunity,
            None,
            &system,
            Path::new("/tmp/evidence.json"),
            None,
        );
        assert!(rendered.contains("Stuck Process Investigation Report"));
        assert!(rendered.contains("fuse-wait"));
        assert!(rendered.contains("fuse_wait_answer"));
        assert!(rendered.contains("/mnt/problematic-tree"));
        assert!(rendered.contains("kernel, mount, or storage investigation"));
    }

    #[test]
    fn published_codex_session_sanitizes_local_bundle_paths() {
        let dir = tempfile::tempdir().unwrap();
        let bundle_dir = dir.path().join("proposal");
        let source_dir = dir.path().join("source");
        let workspace_dir = bundle_dir.join("workspace");
        std::fs::create_dir_all(source_dir.join("src")).unwrap();
        std::fs::create_dir_all(&workspace_dir).unwrap();
        std::fs::write(
            bundle_dir.join("prompt.md"),
            format!(
                "Read the evidence bundle at `{}` and patch `{}`.",
                bundle_dir.join("evidence.json").display(),
                workspace_dir.display()
            ),
        )
        .unwrap();
        std::fs::write(
            bundle_dir.join("codex-output.txt"),
            format!(
                "Patched [src/file.c]({}) after reading `{}`.",
                workspace_dir.join("src/file.c").display(),
                source_dir.join("src/file.c").display()
            ),
        )
        .unwrap();
        std::fs::write(source_dir.join("src/file.c"), "old\n").unwrap();
        std::fs::create_dir_all(workspace_dir.join("src")).unwrap();
        std::fs::write(workspace_dir.join("src/file.c"), "new\n").unwrap();
        std::fs::write(
            bundle_dir.join("evidence.json"),
            serde_json::to_vec_pretty(&json!({
                "workspace": { "repo_root": workspace_dir },
                "source_workspace": { "repo_root": source_dir },
            }))
            .unwrap(),
        )
        .unwrap();

        let published = load_published_codex_session(&bundle_dir).unwrap();
        let prompt = published.get("prompt").and_then(Value::as_str).unwrap();
        let response = published.get("response").and_then(Value::as_str).unwrap();
        let diff = published.get("diff").and_then(Value::as_str).unwrap();

        assert!(prompt.contains("./evidence.json"));
        assert!(prompt.contains("./workspace"));
        assert!(!prompt.contains(bundle_dir.to_string_lossy().as_ref()));
        assert!(response.contains("./workspace/src/file.c"));
        assert!(response.contains("./source/src/file.c"));
        assert!(!response.contains(source_dir.to_string_lossy().as_ref()));
        assert!(diff.contains("--- a/src/file.c"));
        assert!(diff.contains("+++ b/src/file.c"));
        assert!(!diff.contains("diff -urN"));
        assert!(!diff.contains("./source/src/file.c"));
        assert!(!diff.contains("./workspace/src/file.c"));
    }
}
