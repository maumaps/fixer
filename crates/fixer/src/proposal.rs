use crate::config::FixerConfig;
use crate::models::{
    ComplaintCollectionReport, InstalledPackageMetadata, OpportunityRecord, PreparedWorkspace,
    ProposalRecord, SharedOpportunity,
};
use crate::storage::Store;
use crate::util::{command_exists, command_output, now_rfc3339, read_text};
use crate::workspace::resolve_installed_package_metadata;
use anyhow::{Context, Result, anyhow};
use serde_json::{Value, json};
use std::fs;
use std::io::Write;
use std::path::PathBuf;
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
        "codex" => run_codex(
            store,
            config,
            opportunity,
            workspace,
            &bundle_dir,
            &output_path,
            &prompt,
        ),
        other => Err(anyhow!("unknown proposal engine `{other}`")),
    }
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

fn run_codex(
    store: &Store,
    config: &FixerConfig,
    opportunity: &OpportunityRecord,
    workspace: &PreparedWorkspace,
    bundle_dir: &std::path::Path,
    output_path: &std::path::Path,
    prompt: &str,
) -> Result<ProposalRecord> {
    if !command_exists(&config.patch.codex_command) {
        return Err(anyhow!(
            "Codex CLI `{}` was not found in PATH",
            config.patch.codex_command
        ));
    }
    let repo_root = workspace.repo_root.clone();

    let mut cmd = Command::new(&config.patch.codex_command);
    if let Some(approval_policy) = &config.patch.approval_policy {
        cmd.arg("-a").arg(approval_policy);
    }
    cmd.arg("exec");
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
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit());

    let mut child = cmd
        .spawn()
        .with_context(|| format!("failed to launch {}", config.patch.codex_command))?;
    if let Some(stdin) = child.stdin.as_mut() {
        stdin.write_all(prompt.as_bytes())?;
    }
    let status = child.wait()?;
    let proposal_state = if status.success() { "ready" } else { "failed" };
    store.create_proposal(
        opportunity.id,
        "codex",
        proposal_state,
        bundle_dir,
        Some(output_path),
    )
}

fn build_prompt(
    evidence_path: &std::path::Path,
    workspace: &PreparedWorkspace,
    config: &FixerConfig,
) -> String {
    let extra = config.patch.extra_instructions.as_deref().unwrap_or(
        "Keep the patch narrowly scoped, validate locally, and explain any uncertainty.",
    );
    format!(
        "You are working on a bounded fixer proposal.\n\nRead the evidence bundle at `{}`. The prepared workspace is `{}` and it was acquired via `{}`. Produce the smallest reasonable patch for the target repository, run relevant tests if available, and summarize what changed.\n\n{}",
        evidence_path.display(),
        workspace.repo_root.display(),
        workspace.source_kind,
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
        pg_amcheck_command, render_external_bug_report, render_local_remediation_report,
        render_local_remediation_sql, sanitize_command_line_for_report,
        suggested_report_destination,
    };
    use crate::models::{InstalledPackageMetadata, OpportunityRecord};
    use serde_json::json;
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
}
