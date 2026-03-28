use crate::config::FixerConfig;
use crate::models::{InstalledPackageMetadata, OpportunityRecord, PreparedWorkspace, ProposalRecord};
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
    let bundle_dir = config
        .service
        .state_dir
        .join("proposals")
        .join(format!("{}-{}", opportunity.id, now_rfc3339().replace(':', "-")));
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
            store.create_proposal(opportunity.id, engine, "ready", &bundle_dir, Some(&summary_path))
        }
        "codex" => run_codex(store, config, opportunity, workspace, &bundle_dir, &output_path, &prompt),
        other => Err(anyhow!("unknown proposal engine `{other}`")),
    }
}

pub fn create_external_report_proposal(
    store: &Store,
    config: &FixerConfig,
    opportunity: &OpportunityRecord,
    acquisition_error: &str,
) -> Result<ProposalRecord> {
    let bundle_dir = config
        .service
        .state_dir
        .join("proposals")
        .join(format!("{}-{}", opportunity.id, now_rfc3339().replace(':', "-")));
    fs::create_dir_all(&bundle_dir)?;

    let evidence_path = bundle_dir.join("evidence.json");
    let summary_path = bundle_dir.join("proposal.md");
    let package_name = opportunity
        .evidence
        .get("package_name")
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow!("opportunity {} has no package name for external report", opportunity.id))?;
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
    writeln!(file, "- Ecosystem: {}", opportunity.ecosystem.unwrap_or_else(|| "unknown".to_string()))?;
    writeln!(file, "- Repo root: {}", opportunity.repo_root.map(|x| x.display().to_string()).unwrap_or_else(|| "(none)".to_string()))?;
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
    cmd.arg("-C")
        .arg(&repo_root)
        .arg("-o")
        .arg(output_path);
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
    store.create_proposal(opportunity.id, "codex", proposal_state, bundle_dir, Some(output_path))
}

fn build_prompt(
    evidence_path: &std::path::Path,
    workspace: &PreparedWorkspace,
    config: &FixerConfig,
) -> String {
    let extra = config
        .patch
        .extra_instructions
        .as_deref()
        .unwrap_or("Keep the patch narrowly scoped, validate locally, and explain any uncertainty.");
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
        "- Package: `{}`\n- Installed version: `{}`\n- Candidate version: `{}`\n- Architecture: `{}`\n- Vendor: `{}`\n- Maintainer: `{}`\n- Homepage: `{}`\n- OS: `{}`\n- Kernel: `{}`\n",
        package.package_name,
        package.installed_version.as_deref().unwrap_or("unknown"),
        package.candidate_version.as_deref().unwrap_or("unknown"),
        package.architecture.as_deref().unwrap_or("unknown"),
        package.vendor.as_deref().unwrap_or("unknown"),
        package.maintainer.as_deref().unwrap_or("unknown"),
        package.homepage.as_deref().unwrap_or("unknown"),
        system.get("os_pretty_name").and_then(Value::as_str).unwrap_or("unknown"),
        system.get("kernel").and_then(Value::as_str).unwrap_or("unknown"),
    ));
    if let Some(report_url) = &package.report_url {
        let source = package
            .report_url_source
            .as_deref()
            .unwrap_or("package metadata");
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
        body.push_str(&format!("- Suggested debuginfod URLs: `{debuginfod_urls}`\n"));
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
        signal_number,
        signal_name,
        opportunity.summary
    ));
    body.push_str("Please advise whether this matches a known issue, whether a newer build is expected to fix it, and whether additional diagnostic data should be collected.\n\n");
    body.push_str("## Evidence Bundle\n\n");
    body.push_str(&format!("Full local evidence: `{}`\n", evidence_path.display()));
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

#[cfg(test)]
mod tests {
    use super::sanitize_command_line_for_report;

    #[test]
    fn redacts_url_query_values_in_report_command_lines() {
        let raw = "/opt/zoom/zoom $'zoommtg:///join?action=join&confno=123456&pwd=secret&browser=chrome'";
        let sanitized = sanitize_command_line_for_report(raw);
        assert!(sanitized.contains("zoommtg:///join?action=join&confno=<redacted>&pwd=<redacted>&browser=chrome'"));
        assert!(!sanitized.contains("123456"));
        assert!(!sanitized.contains("secret"));
    }
}
