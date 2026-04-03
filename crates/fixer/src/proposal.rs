use crate::config::FixerConfig;
use crate::models::{
    CodexJobSpec, CodexJobStatus, ComplaintCollectionReport, InstalledPackageMetadata,
    OpportunityRecord, PatchAttempt, PatchDriver, PreparedWorkspace, ProposalRecord,
    SharedOpportunity,
};
use crate::storage::Store;
use crate::util::{command_exists, command_output, now_rfc3339, read_text};
use crate::workspace::resolve_installed_package_metadata;
use anyhow::{Context, Result, anyhow};
use chrono::{DateTime, Duration as ChronoDuration, Utc};
use regex::Regex;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::io::ErrorKind;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::OnceLock;

fn create_bundle_dir(config: &FixerConfig, opportunity_id: i64) -> Result<PathBuf> {
    let proposals_root = match fs::create_dir_all(config.service.state_dir.join("proposals")) {
        Ok(()) => config.service.state_dir.join("proposals"),
        Err(error) if error.kind() == ErrorKind::PermissionDenied => {
            let fallback = std::env::temp_dir().join("fixer-proposals");
            fs::create_dir_all(&fallback).with_context(|| {
                format!(
                    "failed to create fallback proposal directory {}",
                    fallback.display()
                )
            })?;
            fallback
        }
        Err(error) => {
            return Err(error).with_context(|| {
                format!(
                    "failed to create proposal directory {}",
                    config.service.state_dir.join("proposals").display()
                )
            });
        }
    };
    prune_proposal_bundles(
        &proposals_root,
        config.service.proposal_bundle_retention_days,
        config.service.proposal_bundle_keep_per_opportunity,
    )?;
    let bundle_dir = proposals_root.join(format!(
        "{}-{}",
        opportunity_id,
        now_rfc3339().replace(':', "-")
    ));
    fs::create_dir_all(&bundle_dir)?;
    Ok(bundle_dir)
}

pub fn create_proposal(
    store: &Store,
    config: &FixerConfig,
    opportunity: &OpportunityRecord,
    workspace: &PreparedWorkspace,
    engine: &str,
) -> Result<ProposalRecord> {
    create_proposal_with_prior_patch(store, config, opportunity, workspace, None, engine)
}

pub fn create_proposal_with_prior_patch(
    store: &Store,
    config: &FixerConfig,
    opportunity: &OpportunityRecord,
    workspace: &PreparedWorkspace,
    prior_best_patch: Option<&PatchAttempt>,
    engine: &str,
) -> Result<ProposalRecord> {
    let bundle_dir = create_bundle_dir(config, opportunity.id)?;

    let evidence_path = bundle_dir.join("evidence.json");
    let prompt_path = bundle_dir.join("prompt.md");
    let output_path = bundle_dir.join("codex-output.txt");
    let prior_patch_context = materialize_prior_patch_context(&bundle_dir, prior_best_patch)?;

    let mut evidence = json!({
        "opportunity": opportunity,
        "workspace": workspace,
    });
    if let Some(context) = prior_patch_context_json(&prior_patch_context) {
        evidence["prior_best_patch"] = context;
    }
    fs::write(&evidence_path, serde_json::to_vec_pretty(&evidence)?)?;

    let prompt = build_prompt(
        opportunity,
        &fs::canonicalize(&evidence_path).unwrap_or_else(|_| evidence_path.clone()),
        workspace,
        prior_patch_context.as_ref(),
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
    prepare_codex_job_with_prior_patch(
        config,
        opportunity,
        workspace,
        None,
        run_as_user,
        allow_kernel,
    )
}

pub fn prepare_codex_job_with_prior_patch(
    config: &FixerConfig,
    opportunity: &OpportunityRecord,
    workspace: &PreparedWorkspace,
    prior_best_patch: Option<&PatchAttempt>,
    run_as_user: &str,
    allow_kernel: bool,
) -> Result<CodexJobSpec> {
    let bundle_dir = create_bundle_dir(config, opportunity.id)?;
    let job_workspace = snapshot_workspace_for_job(workspace, &bundle_dir)?;
    let evidence_path = bundle_dir.join("evidence.json");
    let prompt_path = bundle_dir.join("prompt.md");
    let output_path = bundle_dir.join("codex-output.txt");
    let prior_patch_context = materialize_prior_patch_context(&bundle_dir, prior_best_patch)?;

    let mut evidence = json!({
        "opportunity": opportunity,
        "workspace": job_workspace,
        "source_workspace": workspace,
    });
    if let Some(context) = prior_patch_context_json(&prior_patch_context) {
        evidence["prior_best_patch"] = context;
    }
    fs::write(&evidence_path, serde_json::to_vec_pretty(&evidence)?)?;

    let prompt = build_prompt(
        opportunity,
        &fs::canonicalize(&evidence_path).unwrap_or_else(|_| evidence_path.clone()),
        &job_workspace,
        prior_patch_context.as_ref(),
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

fn prune_proposal_bundles(
    root: &Path,
    retention_days: u64,
    keep_per_opportunity: usize,
) -> Result<()> {
    if !root.exists() {
        return Ok(());
    }

    let keep_per_opportunity = keep_per_opportunity.max(1);
    let cutoff = (retention_days > 0).then(|| {
        Utc::now() - ChronoDuration::seconds((retention_days.saturating_mul(24 * 60 * 60)) as i64)
    });
    let mut grouped: BTreeMap<String, Vec<(DateTime<Utc>, PathBuf)>> = BTreeMap::new();

    for entry in fs::read_dir(root)? {
        let entry = entry?;
        let path = entry.path();
        if !path.is_dir() {
            continue;
        }
        let file_name = entry.file_name();
        let Some(file_name) = file_name.to_str() else {
            continue;
        };
        let Some((opportunity_id, _)) = file_name.split_once('-') else {
            continue;
        };
        if opportunity_id.parse::<i64>().is_err() {
            continue;
        }
        let modified = entry
            .metadata()
            .and_then(|metadata| metadata.modified())
            .ok()
            .map(DateTime::<Utc>::from)
            .unwrap_or_else(Utc::now);
        grouped
            .entry(opportunity_id.to_string())
            .or_default()
            .push((modified, path));
    }

    for bundles in grouped.values_mut() {
        bundles.sort_by(|left, right| right.0.cmp(&left.0));
        for (index, (modified, path)) in bundles.iter().enumerate() {
            let stale = cutoff.is_some_and(|cutoff| *modified < cutoff);
            if index >= keep_per_opportunity || stale {
                fs::remove_dir_all(path).with_context(|| {
                    format!("failed to prune proposal bundle {}", path.display())
                })?;
            }
        }
    }

    Ok(())
}

pub fn load_codex_job_status(bundle_dir: &Path) -> Result<CodexJobStatus> {
    let path = bundle_dir.join("status.json");
    let raw = fs::read(&path).with_context(|| format!("failed to read {}", path.display()))?;
    serde_json::from_slice(&raw).with_context(|| format!("failed to parse {}", path.display()))
}

pub fn load_published_codex_session(bundle_dir: &Path) -> Result<Value> {
    let evidence_path = bundle_dir.join("evidence.json");
    let prompt_path = {
        let published = bundle_dir.join("published-prompt.md");
        if published.exists() {
            published
        } else {
            bundle_dir.join("prompt.md")
        }
    };
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
    let raw_response = output_path
        .exists()
        .then(|| {
            read_text(&output_path)
                .with_context(|| format!("failed to read {}", output_path.display()))
        })
        .transpose()?;
    let git_add_paths = raw_response
        .as_deref()
        .map(extract_git_add_paths_from_response)
        .unwrap_or_default();
    let response = raw_response.as_ref().map(|raw| {
        truncate_public_session_text(
            &sanitize_public_session_text(
                raw,
                bundle_dir,
                workspace_root.as_deref(),
                source_workspace_root.as_deref(),
            ),
            64 * 1024,
        )
    });
    let diff = render_public_session_diff(
        source_workspace_root.as_deref(),
        workspace_root.as_deref(),
        &git_add_paths,
    )?;
    let status = load_codex_job_status(bundle_dir).ok();
    Ok(json!({
        "prompt": prompt,
        "response": response,
        "diff": diff,
        "model": status.as_ref().and_then(|value| value.selected_model.clone()),
        "models_used": status
            .as_ref()
            .map(|value| value.models_used.clone())
            .unwrap_or_default(),
        "rate_limit_fallback_used": status
            .as_ref()
            .map(|value| value.rate_limit_fallback_used)
            .unwrap_or(false),
    }))
}

struct PriorPatchContext {
    summary: String,
    created_at: String,
    fixer_version: Option<String>,
    patch_path: Option<PathBuf>,
    session_path: Option<PathBuf>,
}

fn materialize_prior_patch_context(
    bundle_dir: &Path,
    prior_best_patch: Option<&PatchAttempt>,
) -> Result<Option<PriorPatchContext>> {
    let Some(prior_best_patch) = prior_best_patch else {
        return Ok(None);
    };
    let mut context = PriorPatchContext {
        summary: prior_best_patch.summary.clone(),
        created_at: prior_best_patch.created_at.clone(),
        fixer_version: prior_patch_fixer_version(prior_best_patch).map(ToString::to_string),
        patch_path: None,
        session_path: None,
    };
    if let Some(diff) = prior_best_patch_diff(prior_best_patch) {
        let patch_path = bundle_dir.join("prior-best.patch");
        fs::write(&patch_path, diff.as_bytes())?;
        context.patch_path = Some(patch_path);
    }
    if let Some(session) = prior_best_patch_session(prior_best_patch) {
        let session_path = bundle_dir.join("prior-best-session.md");
        let mut rendered = String::from("# Prior Fixer patch attempt\n\n");
        if let Some(version) = context.fixer_version.as_deref() {
            rendered.push_str(&format!("- Fixer version: `{version}`\n"));
        } else {
            rendered.push_str("- Fixer version: legacy or unknown\n");
        }
        rendered.push_str(&format!("- Created at: `{}`\n", context.created_at));
        rendered.push_str(&format!("- Summary: {}\n", context.summary));
        if let Some(prompt) = session.get("prompt").and_then(Value::as_str) {
            rendered.push_str("\n## Prompt\n\n");
            rendered.push_str(prompt);
            rendered.push('\n');
        }
        if let Some(response) = session.get("response").and_then(Value::as_str) {
            rendered.push_str("\n## Response\n\n");
            rendered.push_str(response);
            rendered.push('\n');
        }
        if let Some(diff) = session.get("diff").and_then(Value::as_str) {
            rendered.push_str("\n## Diff\n\n```diff\n");
            rendered.push_str(diff);
            if !diff.ends_with('\n') {
                rendered.push('\n');
            }
            rendered.push_str("```\n");
        }
        fs::write(&session_path, rendered.as_bytes())?;
        context.session_path = Some(session_path);
    }
    Ok(Some(context))
}

fn prior_patch_context_json(context: &Option<PriorPatchContext>) -> Option<Value> {
    let context = context.as_ref()?;
    Some(json!({
        "summary": context.summary,
        "created_at": context.created_at,
        "fixer_version": context.fixer_version,
        "patch_path": context.patch_path.as_ref().map(|path| path.display().to_string()),
        "session_path": context.session_path.as_ref().map(|path| path.display().to_string()),
    }))
}

fn prior_patch_fixer_version(attempt: &PatchAttempt) -> Option<&str> {
    attempt
        .details
        .get("worker_fixer_version")
        .and_then(Value::as_str)
        .or_else(|| attempt.details.get("fixer_version").and_then(Value::as_str))
}

fn prior_best_patch_session(attempt: &PatchAttempt) -> Option<&Value> {
    attempt.details.get("published_session")
}

fn prior_best_patch_diff(attempt: &PatchAttempt) -> Option<&str> {
    prior_best_patch_session(attempt)
        .and_then(|session| session.get("diff"))
        .and_then(Value::as_str)
        .filter(|diff| !diff.trim().is_empty())
}

pub fn execute_codex_job(config: &FixerConfig, job: &CodexJobSpec) -> Result<CodexJobStatus> {
    let started_at = now_rfc3339();
    let base_patch_prompt = read_text(&job.prompt_path)
        .with_context(|| format!("failed to read {}", job.prompt_path.display()))?;
    let source_workspace_root = source_workspace_root_from_bundle(&job.bundle_dir);
    let evidence_path = job.bundle_dir.join("evidence.json");
    let mut transcripts = Vec::new();
    let mut logs = Vec::new();
    let mut patch_prompt = base_patch_prompt.clone();
    let mut plan_output_path: Option<PathBuf> = None;
    let mut models_used = Vec::<String>::new();
    let mut rate_limit_fallback_used = false;
    let mut selected_model: Option<String> = None;

    if config.patch.plan_before_patch {
        let plan_prompt = build_plan_prompt(
            &evidence_path,
            &job.workspace,
            source_workspace_root.as_deref(),
        );
        let plan_prompt_path = job.bundle_dir.join("plan-prompt.md");
        let current_plan_output_path = job.bundle_dir.join("plan-output.txt");
        let plan_stage = run_codex_stage(
            config,
            &job.workspace.repo_root,
            &plan_prompt_path,
            &current_plan_output_path,
            "Plan Pass",
            &plan_prompt,
        )?;
        logs.push(render_stage_log(&plan_stage));
        models_used.extend(plan_stage.models_used.clone());
        rate_limit_fallback_used |= plan_stage.rate_limit_fallback_used;
        selected_model = plan_stage.selected_model.clone().or(selected_model);
        transcripts.push(CodexStageTranscript {
            label: plan_stage.label.to_string(),
            prompt: plan_prompt,
            response: plan_stage.output.clone(),
        });
        if !plan_stage.success {
            let published_prompt = render_combined_prompt(&transcripts);
            let published_output = render_combined_output(&transcripts, Some(&plan_stage.error));
            fs::write(
                job.bundle_dir.join("published-prompt.md"),
                published_prompt.as_bytes(),
            )?;
            fs::write(&job.output_path, published_output.as_bytes())?;
            let finished_at = now_rfc3339();
            fs::write(
                job.bundle_dir.join("codex-run.log"),
                logs.join("\n\n").as_bytes(),
            )?;
            let status = CodexJobStatus {
                job_id: job.job_id.clone(),
                state: "failed".to_string(),
                started_at,
                finished_at,
                output_path: job.output_path.exists().then(|| job.output_path.clone()),
                selected_model,
                models_used: ordered_unique_strings(&models_used),
                rate_limit_fallback_used,
                failure_stage: Some("plan".to_string()),
                failure_kind: Some(classify_codex_failure(&plan_stage.log)),
                error: Some(plan_stage.error),
                exit_status: plan_stage.exit_status,
                last_stderr_excerpt: plan_stage.stderr_excerpt,
                review_failure_category: None,
            };
            fs::write(
                job.bundle_dir.join("status.json"),
                serde_json::to_vec_pretty(&status)?,
            )?;
            return Ok(status);
        }
        patch_prompt = build_patch_prompt_with_plan(&base_patch_prompt, &current_plan_output_path);
        plan_output_path = Some(current_plan_output_path);
    }

    let mut patch_stage_output_path = job.bundle_dir.join("patch-output.txt");
    let initial_patch_stage = run_codex_stage(
        config,
        &job.workspace.repo_root,
        &job.prompt_path,
        &patch_stage_output_path,
        "Patch Pass",
        &patch_prompt,
    )?;
    logs.push(render_stage_log(&initial_patch_stage));
    models_used.extend(initial_patch_stage.models_used.clone());
    rate_limit_fallback_used |= initial_patch_stage.rate_limit_fallback_used;
    selected_model = initial_patch_stage
        .selected_model
        .clone()
        .or(selected_model);
    let mut patch_stage = initial_patch_stage;
    let mut patch_stage_prompt = patch_prompt.clone();
    if !patch_stage.success && should_retry_after_compaction_failure(&patch_stage.log) {
        let retry_prompt = build_compact_patch_retry_prompt(&base_patch_prompt);
        let retry_output_path = job.bundle_dir.join("patch-retry-output.txt");
        let retry_stage = run_codex_stage(
            config,
            &job.workspace.repo_root,
            &job.bundle_dir.join("patch-retry-prompt.md"),
            &retry_output_path,
            "Patch Pass Retry 1",
            &retry_prompt,
        )?;
        logs.push(render_stage_log(&retry_stage));
        models_used.extend(retry_stage.models_used.clone());
        rate_limit_fallback_used |= retry_stage.rate_limit_fallback_used;
        selected_model = retry_stage.selected_model.clone().or(selected_model);
        patch_stage = retry_stage;
        patch_stage_prompt = retry_prompt;
        patch_stage_output_path = retry_output_path;
    }
    transcripts.push(CodexStageTranscript {
        label: patch_stage.label.to_string(),
        prompt: patch_stage_prompt.clone(),
        response: patch_stage.output.clone(),
    });
    if !patch_stage.success {
        let published_prompt = render_combined_prompt(&transcripts);
        let published_output = render_combined_output(&transcripts, Some(&patch_stage.error));
        fs::write(
            job.bundle_dir.join("published-prompt.md"),
            published_prompt.as_bytes(),
        )?;
        fs::write(&job.output_path, published_output.as_bytes())?;
        let finished_at = now_rfc3339();
        fs::write(
            job.bundle_dir.join("codex-run.log"),
            logs.join("\n\n").as_bytes(),
        )?;
        let status = CodexJobStatus {
            job_id: job.job_id.clone(),
            state: "failed".to_string(),
            started_at,
            finished_at,
            output_path: job.output_path.exists().then(|| job.output_path.clone()),
            selected_model,
            models_used: ordered_unique_strings(&models_used),
            rate_limit_fallback_used,
            failure_stage: Some("patch".to_string()),
            failure_kind: Some(classify_codex_failure(&patch_stage.log)),
            error: Some(patch_stage.error),
            exit_status: patch_stage.exit_status,
            last_stderr_excerpt: patch_stage.stderr_excerpt,
            review_failure_category: None,
        };
        fs::write(
            job.bundle_dir.join("status.json"),
            serde_json::to_vec_pretty(&status)?,
        )?;
        return Ok(status);
    }

    let mut workflow_failure: Option<(String, String)> = None;
    let mut workflow_failure_stage: Option<String> = None;
    let mut workflow_exit_status: Option<i32> = None;
    let mut workflow_stderr_excerpt: Option<String> = None;
    let mut workflow_review_failure_category: Option<String> = None;
    let patch_output_indicates_triage = stage_output_marks_successful_triage(&patch_stage.output);
    let mut current_author_output_path = patch_stage_output_path;
    if config.patch.review_after_patch && !patch_output_indicates_triage {
        let mut refinement_round = 0;
        loop {
            let review_label = format!("Review Pass {}", refinement_round + 1);
            let current_changed_paths = workspace_changed_paths(&job.workspace.repo_root);
            let review_output_path = job
                .bundle_dir
                .join(format!("review-{}-output.txt", refinement_round + 1));
            let current_author_output = read_text(&current_author_output_path).unwrap_or_default();
            if let Some(local_review_output) =
                build_local_metadata_review(&current_author_output, &current_changed_paths)
            {
                fs::write(&review_output_path, local_review_output.as_bytes())?;
                transcripts.push(CodexStageTranscript {
                    label: format!("{review_label} (local metadata check)"),
                    prompt: "Local metadata consistency check".to_string(),
                    response: local_review_output.clone(),
                });
                if refinement_round >= config.patch.review_fix_passes {
                    workflow_failure = Some((
                        "review".to_string(),
                        format!(
                            "{} still found unresolved metadata issues after {} refinement pass(es).",
                            review_label, refinement_round
                        ),
                    ));
                    workflow_failure_stage = Some("review".to_string());
                    workflow_review_failure_category = Some("git-add-paths-mismatch".to_string());
                    break;
                }
                refinement_round += 1;
                let refine_label = format!("Refinement Pass {}", refinement_round);
                let current_changed_paths = workspace_changed_paths(&job.workspace.repo_root);
                let refine_prompt = build_refinement_prompt(
                    &evidence_path,
                    &job.workspace,
                    source_workspace_root.as_deref(),
                    plan_output_path.as_deref(),
                    &current_author_output_path,
                    &review_output_path,
                    refinement_round,
                    &current_changed_paths,
                );
                let refine_prompt_path = job
                    .bundle_dir
                    .join(format!("refine-{}-prompt.md", refinement_round));
                let refine_output_path = job
                    .bundle_dir
                    .join(format!("refine-{}-output.txt", refinement_round));
                let refine_stage = run_codex_stage(
                    config,
                    &job.workspace.repo_root,
                    &refine_prompt_path,
                    &refine_output_path,
                    &refine_label,
                    &refine_prompt,
                )?;
                logs.push(render_stage_log(&refine_stage));
                models_used.extend(refine_stage.models_used.clone());
                rate_limit_fallback_used |= refine_stage.rate_limit_fallback_used;
                selected_model = refine_stage.selected_model.clone().or(selected_model);
                transcripts.push(CodexStageTranscript {
                    label: refine_stage.label.to_string(),
                    prompt: refine_prompt,
                    response: refine_stage.output.clone(),
                });
                if !refine_stage.success {
                    workflow_failure = Some((
                        classify_codex_failure(&refine_stage.log),
                        refine_stage.error,
                    ));
                    workflow_failure_stage = Some("refinement".to_string());
                    workflow_exit_status = refine_stage.exit_status;
                    workflow_stderr_excerpt = refine_stage.stderr_excerpt.clone();
                    break;
                }
                current_author_output_path = refine_output_path;
                continue;
            }
            let review_prompt = build_review_prompt(
                &evidence_path,
                &job.workspace,
                source_workspace_root.as_deref(),
                &current_author_output_path,
                refinement_round,
                &current_changed_paths,
            );
            let review_prompt_path = job
                .bundle_dir
                .join(format!("review-{}-prompt.md", refinement_round + 1));
            let review_stage = run_codex_stage(
                config,
                &job.workspace.repo_root,
                &review_prompt_path,
                &review_output_path,
                &review_label,
                &review_prompt,
            )?;
            logs.push(render_stage_log(&review_stage));
            models_used.extend(review_stage.models_used.clone());
            rate_limit_fallback_used |= review_stage.rate_limit_fallback_used;
            selected_model = review_stage.selected_model.clone().or(selected_model);
            transcripts.push(CodexStageTranscript {
                label: review_stage.label.to_string(),
                prompt: review_prompt,
                response: review_stage.output.clone(),
            });
            if !review_stage.success {
                workflow_failure = Some((
                    classify_codex_failure(&review_stage.log),
                    review_stage.error,
                ));
                workflow_failure_stage = Some("review".to_string());
                workflow_exit_status = review_stage.exit_status;
                workflow_stderr_excerpt = review_stage.stderr_excerpt.clone();
                break;
            }
            let verdict = parse_review_verdict(&review_stage.output);
            match verdict {
                Some(CodexReviewVerdict::Ok) => break,
                Some(CodexReviewVerdict::FixNeeded) => {
                    if refinement_round >= config.patch.review_fix_passes {
                        workflow_failure = Some((
                            "review".to_string(),
                            format!(
                                "{} still found unresolved issues after {} refinement pass(es).",
                                review_label, refinement_round
                            ),
                        ));
                        workflow_failure_stage = Some("review".to_string());
                        workflow_exit_status = review_stage.exit_status;
                        workflow_stderr_excerpt = review_stage.stderr_excerpt.clone();
                        workflow_review_failure_category = review_failure_category(
                            Some(&CodexReviewVerdict::FixNeeded),
                            &review_stage.output,
                        );
                        break;
                    }
                    refinement_round += 1;
                    let refine_label = format!("Refinement Pass {}", refinement_round);
                    let current_changed_paths = workspace_changed_paths(&job.workspace.repo_root);
                    let refine_prompt = build_refinement_prompt(
                        &evidence_path,
                        &job.workspace,
                        source_workspace_root.as_deref(),
                        plan_output_path.as_deref(),
                        &current_author_output_path,
                        &review_output_path,
                        refinement_round,
                        &current_changed_paths,
                    );
                    let refine_prompt_path = job
                        .bundle_dir
                        .join(format!("refine-{}-prompt.md", refinement_round));
                    let refine_output_path = job
                        .bundle_dir
                        .join(format!("refine-{}-output.txt", refinement_round));
                    let refine_stage = run_codex_stage(
                        config,
                        &job.workspace.repo_root,
                        &refine_prompt_path,
                        &refine_output_path,
                        &refine_label,
                        &refine_prompt,
                    )?;
                    logs.push(render_stage_log(&refine_stage));
                    models_used.extend(refine_stage.models_used.clone());
                    rate_limit_fallback_used |= refine_stage.rate_limit_fallback_used;
                    selected_model = refine_stage.selected_model.clone().or(selected_model);
                    transcripts.push(CodexStageTranscript {
                        label: refine_stage.label.to_string(),
                        prompt: refine_prompt,
                        response: refine_stage.output.clone(),
                    });
                    if !refine_stage.success {
                        workflow_failure = Some((
                            classify_codex_failure(&refine_stage.log),
                            refine_stage.error,
                        ));
                        workflow_failure_stage = Some("refinement".to_string());
                        workflow_exit_status = refine_stage.exit_status;
                        workflow_stderr_excerpt = refine_stage.stderr_excerpt.clone();
                        break;
                    }
                    current_author_output_path = refine_output_path;
                }
                None => {
                    workflow_failure = Some((
                        "review".to_string(),
                        format!(
                            "{} did not return a `RESULT: ok` or `RESULT: fix-needed` line.",
                            review_label
                        ),
                    ));
                    workflow_failure_stage = Some("review".to_string());
                    workflow_exit_status = review_stage.exit_status;
                    workflow_stderr_excerpt = review_stage.stderr_excerpt.clone();
                    workflow_review_failure_category =
                        review_failure_category(None, &review_stage.output);
                    break;
                }
            }
        }
    }

    let finished_at = now_rfc3339();
    fs::write(
        job.bundle_dir.join("published-prompt.md"),
        render_combined_prompt(&transcripts).as_bytes(),
    )?;
    fs::write(
        &job.output_path,
        render_combined_output(
            &transcripts,
            workflow_failure.as_ref().map(|(_, error)| error),
        )
        .as_bytes(),
    )?;
    fs::write(
        job.bundle_dir.join("codex-run.log"),
        logs.join("\n\n").as_bytes(),
    )?;
    let status = CodexJobStatus {
        job_id: job.job_id.clone(),
        state: if workflow_failure.is_none() {
            "ready".to_string()
        } else {
            "failed".to_string()
        },
        started_at,
        finished_at,
        output_path: job.output_path.exists().then(|| job.output_path.clone()),
        selected_model,
        models_used: ordered_unique_strings(&models_used),
        rate_limit_fallback_used,
        failure_stage: workflow_failure_stage,
        failure_kind: workflow_failure.as_ref().map(|(kind, _)| kind.clone()),
        error: workflow_failure.map(|(_, error)| error),
        exit_status: workflow_exit_status,
        last_stderr_excerpt: workflow_stderr_excerpt,
        review_failure_category: workflow_review_failure_category,
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
    let bundle_dir = create_bundle_dir(config, opportunity.id)?;

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
            .is_some_and(|subsystem| {
                matches!(
                    subsystem,
                    "runaway-process"
                        | "stuck-process"
                        | "oom-kill"
                        | "desktop-resume"
                        | "desktop-graphics-session"
                        | "network-driver-hang"
                )
            })
}

pub fn process_investigation_blocker_kind(message: &str) -> &'static str {
    let lower = message.to_ascii_lowercase();
    if lower.contains("codex auth lease")
        || lower.contains("codex auth was not found")
        || lower.contains("log in as")
        || lower.contains("lease has expired")
        || lower.contains("lease is paused")
        || lower.contains("lease budget")
    {
        "codex-auth"
    } else if lower.contains("no repo root or package name")
        || lower.contains("patchable workspace")
        || lower.contains("workspace")
        || lower.contains("source package")
        || lower.contains("source tree")
    {
        "workspace"
    } else {
        "automatic-patch"
    }
}

pub fn create_process_investigation_report_proposal(
    store: &Store,
    config: &FixerConfig,
    opportunity: &OpportunityRecord,
    acquisition_error: Option<&str>,
) -> Result<ProposalRecord> {
    let bundle_dir = create_bundle_dir(config, opportunity.id)?;

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
    let blocker_kind = acquisition_error.map(process_investigation_blocker_kind);
    let evidence = json!({
        "report_kind": format!("{report_kind}-investigation"),
        "opportunity": opportunity,
        "package": package,
        "system": system,
        "automatic_patch_blocker": acquisition_error,
        "automatic_patch_blocker_kind": blocker_kind,
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
    let bundle_dir = create_bundle_dir(config, opportunity.id)?;

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
    let bundle_dir = create_bundle_dir(config, opportunity.id)?;

    let evidence_path = bundle_dir.join("evidence.json");
    let summary_path = bundle_dir.join("plan.md");
    let system = collect_system_context();
    let desktop_diagnosis = diagnose_desktop_app_failure(complaint_text, &system);
    let related_desktop_summary = summarize_related_desktop_signals(related);
    let evidence = json!({
        "report_kind": "complaint-plan",
        "opportunity": opportunity,
        "complaint_text": complaint_text,
        "collection_report": collection_report,
        "related_opportunities": related,
        "system": system,
        "desktop_diagnosis": desktop_diagnosis,
        "related_desktop_summary": related_desktop_summary,
    });
    fs::write(&evidence_path, serde_json::to_vec_pretty(&evidence)?)?;
    fs::write(
        &summary_path,
        render_complaint_plan(
            opportunity,
            complaint_text,
            collection_report,
            related,
            evidence.get("system").unwrap_or(&Value::Null),
            evidence.get("desktop_diagnosis").unwrap_or(&Value::Null),
            evidence
                .get("related_desktop_summary")
                .unwrap_or(&Value::Null),
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
        worker_lease_id: None,
        worker_issue_id: None,
        worker_install_id: None,
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
    let _ = initialize_workspace_git_baseline(&target);
    let mut job_workspace = workspace.clone();
    job_workspace.repo_root = target;
    job_workspace.acquisition_note = format!(
        "{} Fixer created an isolated job snapshot for autonomous Codex execution.",
        workspace.acquisition_note
    );
    Ok(job_workspace)
}

fn initialize_workspace_git_baseline(workspace_root: &Path) -> Result<()> {
    if workspace_root.join(".git").exists() || !command_exists("git") {
        return Ok(());
    }

    let run = |args: &[&str]| -> Result<()> {
        let status = Command::new("git")
            .args(args)
            .current_dir(workspace_root)
            .status()
            .with_context(|| {
                format!(
                    "failed to run git {:?} in {}",
                    args,
                    workspace_root.display()
                )
            })?;
        if status.success() {
            Ok(())
        } else {
            Err(anyhow!(
                "git {:?} failed in {}",
                args,
                workspace_root.display()
            ))
        }
    };

    run(&["init", "-q"])?;
    run(&["config", "user.name", "Fixer"])?;
    run(&["config", "user.email", "fixer@localhost"])?;
    run(&["add", "-A", "."])?;
    run(&["commit", "-q", "-m", "Fixer baseline"])?;
    Ok(())
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
        .args(["-a", "--reflink=auto"])
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
    git_add_paths: &[String],
) -> Result<Option<String>> {
    let (Some(source_workspace_root), Some(workspace_root)) =
        (source_workspace_root, workspace_root)
    else {
        return Ok(None);
    };
    if !source_workspace_root.exists() || !workspace_root.exists() {
        return Ok(None);
    }

    if let Some(diff) = render_public_session_git_diff(workspace_root, git_add_paths)? {
        return Ok(Some(truncate_public_session_text(&diff, 128 * 1024)));
    }

    let output = Command::new("diff")
        .args([
            "-urN",
            "--exclude=.git",
            "--exclude=.pc",
            "--exclude=.deps",
            "--exclude=.libs",
            "--exclude=build",
            "--exclude=autom4te.cache",
            "--exclude=Makefile",
            "--exclude=config.status",
            "--exclude=config.cache",
            "--exclude=config.log",
            "--exclude=config.h",
            "--exclude=stamp-h1",
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

fn render_public_session_git_diff(
    workspace_root: &Path,
    git_add_paths: &[String],
) -> Result<Option<String>> {
    if !workspace_root.join(".git").exists() || !command_exists("git") {
        return Ok(None);
    }
    let intended_paths = sanitize_git_add_paths(git_add_paths);
    if !intended_paths.is_empty() {
        let mut add_cmd = Command::new("git");
        add_cmd
            .args(["add", "-N", "--"])
            .args(intended_paths.iter())
            .current_dir(workspace_root);
        let _ = add_cmd.status();
    }

    let output = Command::new("git")
        .args([
            "diff",
            "--no-ext-diff",
            "--binary",
            "--relative",
            "--src-prefix=a/",
            "--dst-prefix=b/",
            "HEAD",
            "--",
            ".",
        ])
        .current_dir(workspace_root)
        .output()
        .context("failed to generate a git-backed public diff for the Codex session")?;
    if !output.status.success() {
        return Ok(None);
    }

    let diff = filter_generated_public_diff_blocks(&String::from_utf8_lossy(&output.stdout));
    if diff.trim().is_empty() {
        Ok(None)
    } else {
        Ok(Some(diff))
    }
}

fn workspace_changed_paths(workspace_root: &Path) -> Vec<String> {
    if !workspace_root.join(".git").exists() || !command_exists("git") {
        return Vec::new();
    }

    let tracked_output = Command::new("git")
        .args(["diff", "--name-only", "--relative"])
        .current_dir(workspace_root)
        .output();
    let untracked_output = Command::new("git")
        .args(["ls-files", "--others", "--exclude-standard"])
        .current_dir(workspace_root)
        .output();

    let mut paths = Vec::new();
    if let Ok(output) = tracked_output {
        if output.status.success() {
            paths.extend(
                String::from_utf8_lossy(&output.stdout)
                    .lines()
                    .map(str::trim)
                    .filter(|line| !line.is_empty())
                    .filter(|line| !is_generated_workspace_metadata_path(line))
                    .map(ToString::to_string),
            );
        }
    }
    if let Ok(output) = untracked_output {
        if output.status.success() {
            paths.extend(
                String::from_utf8_lossy(&output.stdout)
                    .lines()
                    .map(str::trim)
                    .filter(|line| !line.is_empty())
                    .filter(|line| !is_generated_workspace_metadata_path(line))
                    .map(ToString::to_string),
            );
        }
    }
    paths.sort();
    paths.dedup();
    paths
}

fn build_local_metadata_review(
    authoring_response: &str,
    current_changed_paths: &[String],
) -> Option<String> {
    let actual_paths = sanitize_git_add_paths(
        &current_changed_paths
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>(),
    );
    if actual_paths.is_empty() {
        return None;
    }
    let declared_paths =
        sanitize_git_add_paths(&extract_git_add_paths_from_response(authoring_response));
    if declared_paths == actual_paths {
        return None;
    }

    let missing_paths = actual_paths
        .iter()
        .filter(|path| !declared_paths.contains(path))
        .cloned()
        .collect::<Vec<_>>();
    let extra_paths = declared_paths
        .iter()
        .filter(|path| !actual_paths.contains(path))
        .cloned()
        .collect::<Vec<_>>();

    let mut findings = vec![format!(
        "Patch metadata drift: the workspace currently changes `{}`, but `## Git Add Paths` lists `{}`. Update `## Git Add Paths` to match the real shipped file set exactly, and make sure `## Issue Connection` explains every functional file that remains in the patch.",
        actual_paths.join("`, `"),
        if declared_paths.is_empty() {
            "(nothing)".to_string()
        } else {
            declared_paths.join("`, `")
        }
    )];
    if !missing_paths.is_empty() {
        findings.push(format!(
            "Missing from `## Git Add Paths`: `{}`.",
            missing_paths.join("`, `")
        ));
    }
    if !extra_paths.is_empty() {
        findings.push(format!(
            "Listed in `## Git Add Paths` but not actually changed: `{}`.",
            extra_paths.join("`, `")
        ));
    }

    Some(format!(
        "RESULT: fix-needed\n\n## Findings\n1. {}",
        findings.join("\n2. ")
    ))
}

fn sanitize_git_add_paths(paths: &[String]) -> Vec<String> {
    paths
        .iter()
        .filter_map(|path| {
            let trimmed = path.trim().trim_matches('`').trim();
            if trimmed.is_empty() || trimmed.starts_with('/') {
                return None;
            }
            let trimmed = trimmed.strip_prefix("- ").unwrap_or(trimmed).trim();
            let path = Path::new(trimmed);
            if path.components().any(|component| {
                matches!(
                    component,
                    std::path::Component::ParentDir
                        | std::path::Component::RootDir
                        | std::path::Component::Prefix(_)
                )
            }) {
                return None;
            }
            (!is_generated_workspace_metadata_path(trimmed)).then(|| trimmed.to_string())
        })
        .collect()
}

fn is_generated_workspace_metadata_path(path: &str) -> bool {
    let normalized = path.trim().trim_start_matches("./").trim_start_matches('/');
    normalized == ".codex" || normalized.starts_with(".codex/")
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
    let filtered = normalized
        .lines()
        .filter(|line| {
            !(line.starts_with("diff -ur")
                || line.starts_with("diff -r ")
                || line.starts_with("Only in ")
                || line.starts_with("Binary files "))
        })
        .collect::<Vec<_>>()
        .join("\n");
    let mut filtered = filter_generated_public_diff_blocks(&filtered);
    if trailing_newline && !filtered.is_empty() {
        filtered.push('\n');
    }
    filtered
}

fn filter_generated_public_diff_blocks(diff: &str) -> String {
    let mut kept_blocks = Vec::new();
    let mut current_block = Vec::new();
    let mut current_path: Option<String> = None;

    let flush_block = |kept_blocks: &mut Vec<String>,
                       current_block: &mut Vec<String>,
                       current_path: &mut Option<String>| {
        if current_block.is_empty() {
            *current_path = None;
            return;
        }
        if current_path
            .as_deref()
            .is_none_or(|path| !is_generated_public_diff_path(path))
        {
            kept_blocks.push(current_block.join("\n"));
        }
        current_block.clear();
        *current_path = None;
    };

    for line in diff.lines() {
        if line.starts_with("--- ") {
            flush_block(&mut kept_blocks, &mut current_block, &mut current_path);
            current_path = Some(extract_public_diff_path(line));
        } else if current_path.is_none() && line.starts_with("+++ ") {
            current_path = Some(extract_public_diff_path(line));
        }
        current_block.push(line.to_string());
    }
    flush_block(&mut kept_blocks, &mut current_block, &mut current_path);
    kept_blocks.join("\n")
}

fn extract_public_diff_path(header_line: &str) -> String {
    header_line
        .split_whitespace()
        .nth(1)
        .unwrap_or_default()
        .trim()
        .trim_start_matches("a/")
        .trim_start_matches("b/")
        .to_string()
}

fn is_generated_public_diff_path(path: &str) -> bool {
    let trimmed = path.trim();
    if trimmed.is_empty() || trimmed == "/dev/null" {
        return false;
    }
    let normalized = trimmed.trim_start_matches("./");
    if is_generated_workspace_metadata_path(normalized) {
        return true;
    }
    let basename = normalized.rsplit('/').next().unwrap_or(normalized);
    normalized.contains("/.deps/")
        || normalized.starts_with(".deps/")
        || normalized.contains("/.libs/")
        || normalized.starts_with(".libs/")
        || matches!(
            basename,
            "Makefile" | "config.status" | "config.cache" | "config.log" | "config.h" | "stamp-h1"
        )
}

fn extract_git_add_paths_from_response(response: &str) -> Vec<String> {
    let authoring_response =
        latest_patch_authoring_response(response).unwrap_or_else(|| response.trim().to_string());
    extract_markdown_section(&authoring_response, "Git Add Paths")
        .map(|section| {
            section
                .lines()
                .map(str::trim)
                .filter(|line| !line.is_empty())
                .filter(|line| !line.starts_with('#'))
                .map(ToString::to_string)
                .collect::<Vec<_>>()
        })
        .unwrap_or_default()
}

fn latest_patch_authoring_response(response: &str) -> Option<String> {
    let mut saw_heading = false;
    let mut current_label: Option<String> = None;
    let mut current_lines = Vec::new();
    let mut selected: Option<String> = None;
    let finalize_section =
        |label: Option<&str>, lines: &mut Vec<String>, selected: &mut Option<String>| {
            let content = lines.join("\n").trim().to_string();
            if label.is_some_and(is_patch_authoring_stage) && !content.is_empty() {
                *selected = Some(content);
            }
            lines.clear();
        };
    for line in response.lines() {
        if let Some(label) = line.strip_prefix("## ") {
            let label = label.trim();
            if is_codex_stage_heading(label) {
                saw_heading = true;
                finalize_section(current_label.as_deref(), &mut current_lines, &mut selected);
                current_label = Some(label.to_string());
                continue;
            }
        }
        current_lines.push(line.to_string());
    }
    finalize_section(current_label.as_deref(), &mut current_lines, &mut selected);
    if selected.is_some() {
        selected
    } else if saw_heading {
        None
    } else {
        let trimmed = response.trim();
        (!trimmed.is_empty()).then(|| trimmed.to_string())
    }
}

fn is_patch_authoring_stage(label: &str) -> bool {
    label == "Patch Pass" || label.starts_with("Refinement Pass ")
}

fn is_codex_stage_heading(label: &str) -> bool {
    label == "Plan Pass"
        || label == "Patch Pass"
        || label.starts_with("Review Pass ")
        || label.starts_with("Refinement Pass ")
        || label == "Workflow Note"
}

fn extract_markdown_section(text: &str, heading: &str) -> Option<String> {
    let mut in_section = false;
    let mut lines = Vec::new();
    for line in text.lines() {
        if let Some(current_heading) = line.strip_prefix("## ") {
            let current_heading = current_heading.trim();
            if in_section {
                break;
            }
            if current_heading == heading {
                in_section = true;
            }
            continue;
        }
        if in_section {
            lines.push(line);
        }
    }
    let content = lines.join("\n").trim().to_string();
    if content.is_empty() {
        None
    } else {
        Some(content)
    }
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
    stderr: String,
    model_used: Option<String>,
    exit_status: Option<i32>,
}

struct CodexStageOutcome {
    label: String,
    success: bool,
    output: String,
    log: String,
    error: String,
    selected_model: Option<String>,
    models_used: Vec<String>,
    rate_limit_fallback_used: bool,
    exit_status: Option<i32>,
    stderr_excerpt: Option<String>,
}

struct CodexStageTranscript {
    label: String,
    prompt: String,
    response: String,
}

enum CodexReviewVerdict {
    Ok,
    FixNeeded,
}

fn review_failure_category(verdict: Option<&CodexReviewVerdict>, output: &str) -> Option<String> {
    match verdict {
        Some(CodexReviewVerdict::FixNeeded) => Some("findings-persisted".to_string()),
        Some(CodexReviewVerdict::Ok) => None,
        None if output.trim().is_empty() => Some("missing-review-output".to_string()),
        None => Some("invalid-review-verdict".to_string()),
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
struct CodexModelLimitState {
    primary_model: Option<String>,
    primary_rate_limited_until: Option<String>,
    updated_at: Option<String>,
}

fn configured_primary_model_label(config: &FixerConfig) -> String {
    if let Some(m) = config
        .patch
        .model
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
    {
        return m.to_string();
    }
    match config.patch.driver {
        PatchDriver::Codex => "codex-default",
        PatchDriver::Claude => "claude-default",
        PatchDriver::Gemini => "gemini-default",
        PatchDriver::Aider => "aider-default",
    }
    .to_string()
}

fn configured_spark_model(config: &FixerConfig) -> Option<String> {
    config
        .patch
        .spark_model
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToString::to_string)
}

fn codex_model_limit_state_path(config: &FixerConfig) -> PathBuf {
    config.service.state_dir.join("codex-model-state.json")
}

fn load_codex_model_limit_state(config: &FixerConfig) -> CodexModelLimitState {
    let path = codex_model_limit_state_path(config);
    let Ok(raw) = fs::read(&path) else {
        return CodexModelLimitState::default();
    };
    serde_json::from_slice(&raw).unwrap_or_default()
}

fn save_codex_model_limit_state(config: &FixerConfig, state: &CodexModelLimitState) -> Result<()> {
    let path = codex_model_limit_state_path(config);
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(path, serde_json::to_vec_pretty(state)?)?;
    Ok(())
}

fn primary_model_rate_limit_active(config: &FixerConfig) -> bool {
    let state = load_codex_model_limit_state(config);
    let Some(until_raw) = state.primary_rate_limited_until.as_deref() else {
        return false;
    };
    let Some(primary_model) = state.primary_model.as_deref() else {
        return false;
    };
    if primary_model != configured_primary_model_label(config) {
        return false;
    }
    DateTime::parse_from_rfc3339(until_raw)
        .map(|until| until.with_timezone(&Utc) > Utc::now())
        .unwrap_or(false)
}

fn remember_primary_model_rate_limit(config: &FixerConfig) -> Result<()> {
    let mut state = load_codex_model_limit_state(config);
    state.primary_model = Some(configured_primary_model_label(config));
    state.primary_rate_limited_until = Some(
        (Utc::now() + ChronoDuration::seconds(config.patch.rate_limit_cooldown_seconds as i64))
            .to_rfc3339(),
    );
    state.updated_at = Some(Utc::now().to_rfc3339());
    save_codex_model_limit_state(config, &state)
}

fn clear_primary_model_rate_limit(config: &FixerConfig) -> Result<()> {
    let path = codex_model_limit_state_path(config);
    if path.exists() {
        fs::remove_file(path)?;
    }
    Ok(())
}

fn initial_stage_model(config: &FixerConfig) -> Option<String> {
    if config.patch.driver != PatchDriver::Codex {
        return config.patch.model.clone();
    }
    let spark_model = configured_spark_model(config);
    if config.patch.spark_fallback_on_rate_limit
        && spark_model.is_some()
        && primary_model_rate_limit_active(config)
    {
        return spark_model;
    }
    config.patch.model.clone()
}

fn should_retry_with_spark(
    config: &FixerConfig,
    should_fallback: bool,
    attempted_model: Option<&str>,
) -> Option<String> {
    if config.patch.driver != PatchDriver::Codex {
        return None;
    }
    if !should_fallback || !config.patch.spark_fallback_on_rate_limit {
        return None;
    }
    let spark_model = configured_spark_model(config)?;
    if attempted_model.is_some_and(|model| model == spark_model) {
        return None;
    }
    Some(spark_model)
}

fn ordered_unique_strings(values: &[String]) -> Vec<String> {
    let mut unique = Vec::new();
    for value in values {
        if unique.iter().any(|item| item == value) {
            continue;
        }
        unique.push(value.clone());
    }
    unique
}

fn run_codex_stage(
    config: &FixerConfig,
    repo_root: &Path,
    prompt_path: &Path,
    output_path: &Path,
    label: impl Into<String>,
    prompt: &str,
) -> Result<CodexStageOutcome> {
    let label = label.into();
    fs::write(prompt_path, prompt.as_bytes())?;
    let mut models_used = Vec::new();
    let mut logs = Vec::new();
    let initial_model = initial_stage_model(config);
    let mut outcome = run_driver_process(
        config,
        repo_root,
        prompt_path,
        output_path,
        prompt,
        initial_model.as_deref(),
    )?;
    if let Some(model) = outcome.model_used.clone() {
        models_used.push(model);
    }
    logs.push(render_process_attempt_log(&outcome));
    let mut rate_limit_fallback_used = false;
    // Check proactively whether the primary model's weekly budget is running low,
    // even if the current run succeeded, so we can fall back to spark before the
    // hard rate-limit hits next time.
    let proactive_spark_fallback = should_use_spark_for_weak_weekly_budget(
        config,
        &outcome.log,
        config.patch.spark_weekly_headroom_threshold,
    );

    if proactive_spark_fallback {
        let _ = remember_primary_model_rate_limit(config);
    }

    let primary_label = configured_primary_model_label(config);
    if !outcome.success {
        let failure_kind = classify_codex_failure(&outcome.log);
        let should_retry_with_spark_now = failure_kind == "rate-limit" || proactive_spark_fallback;

        if failure_kind == "rate-limit" {
            let attempted_model = outcome.model_used.as_deref();
            if attempted_model.unwrap_or("codex-default") == primary_label {
                let _ = remember_primary_model_rate_limit(config);
            }
        }
        if let Some(spark_model) = should_retry_with_spark(
            config,
            should_retry_with_spark_now,
            outcome.model_used.as_deref(),
        ) {
            let retry_outcome = run_driver_process(
                config,
                repo_root,
                prompt_path,
                output_path,
                prompt,
                Some(&spark_model),
            )?;
            if let Some(model) = retry_outcome.model_used.clone() {
                models_used.push(model);
            }
            logs.push(render_process_attempt_log(&retry_outcome));
            outcome = retry_outcome;
            rate_limit_fallback_used = true;
        }
    } else if outcome.model_used.as_deref() == Some(primary_label.as_str())
        && !proactive_spark_fallback
    {
        let _ = clear_primary_model_rate_limit(config);
    }
    let output = if output_path.exists() {
        read_text(output_path)
            .with_context(|| format!("failed to read {}", output_path.display()))?
    } else {
        String::new()
    };
    let error = if outcome.success {
        String::new()
    } else {
        summarize_failure_log(&logs.join("\n\n"))
    };
    let stderr_excerpt =
        (!outcome.stderr.trim().is_empty()).then(|| summarize_failure_log(&outcome.stderr));
    Ok(CodexStageOutcome {
        label,
        success: outcome.success,
        output,
        log: logs.join("\n\n"),
        error,
        selected_model: outcome.model_used,
        models_used,
        rate_limit_fallback_used,
        exit_status: outcome.exit_status,
        stderr_excerpt,
    })
}

fn render_process_attempt_log(outcome: &CodexProcessOutcome) -> String {
    format!(
        "model: {}\n\n{}",
        outcome.model_used.as_deref().unwrap_or("unknown"),
        outcome.log
    )
}

fn render_stage_log(stage: &CodexStageOutcome) -> String {
    format!(
        "== {} ==\nstatus: {}\nmodel: {}\nmodels-tried: {}\nrate-limit-fallback: {}\n\n{}",
        stage.label,
        if stage.success { "ok" } else { "failed" },
        stage.selected_model.as_deref().unwrap_or("codex-default"),
        if stage.models_used.is_empty() {
            "codex-default".to_string()
        } else {
            stage.models_used.join(", ")
        },
        stage.rate_limit_fallback_used,
        stage.log
    )
}

fn render_combined_prompt(stages: &[CodexStageTranscript]) -> String {
    stages
        .iter()
        .map(|stage| format!("## {}\n\n{}", stage.label, stage.prompt))
        .collect::<Vec<_>>()
        .join("\n\n")
}

fn render_combined_output(stages: &[CodexStageTranscript], note: Option<&String>) -> String {
    let mut sections = stages
        .iter()
        .map(|stage| format!("## {}\n\n{}", stage.label, stage.response))
        .collect::<Vec<_>>();
    if let Some(note) = note.filter(|value| !value.trim().is_empty()) {
        sections.push(format!("## Workflow Note\n\n{}", note));
    }
    sections.join("\n\n")
}

fn parse_review_verdict(output: &str) -> Option<CodexReviewVerdict> {
    for line in output.lines() {
        let normalized = line.trim().to_ascii_lowercase();
        if normalized == "result: ok" {
            return Some(CodexReviewVerdict::Ok);
        }
        if normalized == "result: fix-needed" {
            return Some(CodexReviewVerdict::FixNeeded);
        }
    }
    None
}

fn stage_output_marks_successful_triage(output: &str) -> bool {
    [
        "No source change landed.",
        "outside this repository",
        "outside this source tree",
        "speculative and unsafe",
        "no safe code change was made",
    ]
    .iter()
    .any(|marker| output.contains(marker))
}

fn source_workspace_root_from_bundle(bundle_dir: &Path) -> Option<PathBuf> {
    let evidence_path = bundle_dir.join("evidence.json");
    let raw = fs::read(&evidence_path).ok()?;
    let evidence = serde_json::from_slice::<Value>(&raw).ok()?;
    evidence
        .get("source_workspace")
        .and_then(|value| value.get("repo_root"))
        .and_then(Value::as_str)
        .map(PathBuf::from)
}

fn run_codex_process(
    config: &FixerConfig,
    repo_root: &std::path::Path,
    output_path: &std::path::Path,
    prompt: &str,
    model: Option<&str>,
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
    if let Some(model) = model {
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
    let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
    let stderr = String::from_utf8_lossy(&output.stderr).into_owned();
    let log = format!("{stdout}{stderr}");
    Ok(CodexProcessOutcome {
        success: output.status.success(),
        log,
        stderr,
        model_used: Some(
            model
                .map(ToString::to_string)
                .unwrap_or_else(|| "codex-default".to_string()),
        ),
        exit_status: output.status.code(),
    })
}

fn run_driver_process(
    config: &FixerConfig,
    repo_root: &Path,
    prompt_path: &Path,
    output_path: &Path,
    prompt: &str,
    model: Option<&str>,
) -> Result<CodexProcessOutcome> {
    match config.patch.driver {
        PatchDriver::Codex => run_codex_process(config, repo_root, output_path, prompt, model),
        PatchDriver::Claude => run_claude_process(config, repo_root, output_path, prompt, model),
        PatchDriver::Gemini => run_gemini_process(config, repo_root, output_path, prompt, model),
        PatchDriver::Aider => run_aider_process(config, repo_root, prompt_path, output_path, model),
    }
}

fn run_claude_process(
    config: &FixerConfig,
    repo_root: &Path,
    output_path: &Path,
    prompt: &str,
    model: Option<&str>,
) -> Result<CodexProcessOutcome> {
    if !command_exists(&config.patch.claude_command) {
        return Err(anyhow!(
            "Claude CLI `{}` was not found in PATH",
            config.patch.claude_command
        ));
    }
    let model_used = model
        .map(ToString::to_string)
        .unwrap_or_else(|| "claude-default".to_string());
    let mut cmd = Command::new(&config.patch.claude_command);
    for arg in &config.patch.claude_args {
        cmd.arg(arg);
    }
    if let Some(m) = model {
        cmd.arg("--model").arg(m);
    }
    // --dangerously-skip-permissions is safe here: repo_root is an isolated
    // temporary workspace prepared by create_proposal_with_prior_patch, not the
    // user's live tree.
    cmd.arg("--dangerously-skip-permissions")
        .arg("--output-format")
        .arg("text")
        .arg("-p")
        .arg("-")
        .current_dir(repo_root)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = cmd
        .spawn()
        .with_context(|| format!("failed to launch {}", config.patch.claude_command))?;
    if let Some(stdin) = child.stdin.as_mut() {
        stdin.write_all(prompt.as_bytes())?;
    }
    let output = child.wait_with_output()?;
    let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
    let stderr = String::from_utf8_lossy(&output.stderr).into_owned();
    let log = format!("{stdout}{stderr}");
    if output.status.success() {
        fs::write(output_path, stdout.as_bytes())?;
    }
    Ok(CodexProcessOutcome {
        success: output.status.success(),
        log,
        stderr,
        model_used: Some(model_used),
        exit_status: output.status.code(),
    })
}

fn run_gemini_process(
    config: &FixerConfig,
    repo_root: &Path,
    output_path: &Path,
    prompt: &str,
    model: Option<&str>,
) -> Result<CodexProcessOutcome> {
    if !command_exists(&config.patch.gemini_command) {
        return Err(anyhow!(
            "Gemini CLI `{}` was not found in PATH",
            config.patch.gemini_command
        ));
    }
    let model_used = model
        .map(ToString::to_string)
        .unwrap_or_else(|| "gemini-default".to_string());
    let mut cmd = Command::new(&config.patch.gemini_command);
    for arg in &config.patch.gemini_args {
        cmd.arg(arg);
    }
    if let Some(m) = model {
        cmd.arg("-m").arg(m);
    }
    cmd.arg("-p")
        .arg("-")
        .current_dir(repo_root)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = cmd
        .spawn()
        .with_context(|| format!("failed to launch {}", config.patch.gemini_command))?;
    if let Some(stdin) = child.stdin.as_mut() {
        stdin.write_all(prompt.as_bytes())?;
    }
    let output = child.wait_with_output()?;
    let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
    let stderr = String::from_utf8_lossy(&output.stderr).into_owned();
    let log = format!("{stdout}{stderr}");
    if output.status.success() {
        fs::write(output_path, stdout.as_bytes())?;
    }
    Ok(CodexProcessOutcome {
        success: output.status.success(),
        log,
        stderr,
        model_used: Some(model_used),
        exit_status: output.status.code(),
    })
}

fn run_aider_process(
    config: &FixerConfig,
    repo_root: &Path,
    prompt_path: &Path,
    output_path: &Path,
    model: Option<&str>,
) -> Result<CodexProcessOutcome> {
    if !command_exists(&config.patch.aider_command) {
        return Err(anyhow!(
            "aider `{}` was not found in PATH",
            config.patch.aider_command
        ));
    }
    let model_name = model.unwrap_or("llama3");
    let model_used = format!("ollama/{}", model_name);
    let mut cmd = Command::new(&config.patch.aider_command);
    cmd.env("OLLAMA_API_BASE", &config.patch.ollama_base_url);
    cmd.arg("--model").arg(&model_used);
    cmd.arg("--yes")
        .arg("--no-pretty")
        .arg("--no-check-update")
        .arg("--no-show-model-warnings")
        .arg("--message-file")
        .arg(prompt_path);
    for arg in &config.patch.aider_args {
        cmd.arg(arg);
    }
    cmd.current_dir(repo_root)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let child = cmd
        .spawn()
        .with_context(|| format!("failed to launch {}", config.patch.aider_command))?;
    let output = child.wait_with_output()?;
    let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
    let stderr = String::from_utf8_lossy(&output.stderr).into_owned();
    let log = format!("{stdout}{stderr}");
    if output.status.success() {
        fs::write(output_path, stdout.as_bytes())?;
    }
    Ok(CodexProcessOutcome {
        success: output.status.success(),
        log,
        stderr,
        model_used: Some(model_used),
        exit_status: output.status.code(),
    })
}

fn classify_codex_failure(log: &str) -> String {
    let lower = log.to_ascii_lowercase();
    if lower.contains("401 unauthorized") || lower.contains("missing bearer") {
        "auth".to_string()
    } else if lower.contains("rate-limit")
        || lower.contains("rate limit")
        || lower.contains("ratelimit")
        || lower.contains("rate_limit")
        || lower.contains("rate limit exceeded")
        || lower.contains("too many requests")
        || lower.contains("429")
        || lower.contains("quota")
        || lower.contains("usage limit")
        || lower.contains("x-ratelimit")
        || lower.contains("insufficient quota")
    {
        "rate-limit".to_string()
    } else if lower.contains("500 internal server error")
        || lower.contains("failed to connect to websocket")
    {
        "api".to_string()
    } else {
        "execution".to_string()
    }
}

fn should_retry_after_compaction_failure(log: &str) -> bool {
    let lower = log.to_ascii_lowercase();
    lower.contains("compact_remote")
        || (lower.contains("remote compaction failed")
            && (lower.contains("high demand")
                || lower.contains("context window")
                || lower.contains("context_length_exceeded")))
}

fn should_use_spark_for_weak_weekly_budget(
    config: &FixerConfig,
    log: &str,
    fallback_threshold_percent: f64,
) -> bool {
    if !config.patch.spark_fallback_on_rate_limit {
        return false;
    }
    if log.trim().is_empty() {
        return false;
    }
    if fallback_threshold_percent <= 0.0 {
        return false;
    }
    if fallback_threshold_percent >= 100.0 {
        return true;
    }

    if parse_codex_status_weekly_limit_threshold(log, fallback_threshold_percent) {
        return true;
    }

    static WEEKLY_KEYWORD_RE: OnceLock<Regex> = OnceLock::new();
    static PERCENT_RE: OnceLock<Regex> = OnceLock::new();
    static REMAINING_TO_LIMIT_RE: OnceLock<Regex> = OnceLock::new();

    let weekly_keyword_re = WEEKLY_KEYWORD_RE
        .get_or_init(|| Regex::new(r"(?i)(week|weekly|per\s+week|7\s*day|7-day|7d)").unwrap());
    let percent_re = PERCENT_RE.get_or_init(|| Regex::new(r"(?i)(\d+(?:\.\d+)?)\s*%").unwrap());
    let remaining_to_limit_re = REMAINING_TO_LIMIT_RE.get_or_init(|| {
        Regex::new(
            r"(?i)(?:remaining|left)\s*[:=]?\s*(\d+(?:\.\d+)?)(?:\s*(?:/|of)\s*)(\d+(?:\.\d+)?)",
        )
        .unwrap()
    });

    let lower = log.to_ascii_lowercase();
    for line in lower.lines() {
        if !weekly_keyword_re.is_match(line) {
            continue;
        }

        if let Some(capture) = percent_re.captures(line) {
            if let Some(value_raw) = capture.get(1).and_then(|v| v.as_str().parse::<f64>().ok()) {
                if value_raw <= fallback_threshold_percent {
                    return true;
                }
            }
        }

        if let Some(capture) = remaining_to_limit_re.captures(line) {
            let remaining = capture.get(1).and_then(|v| v.as_str().parse::<f64>().ok());
            let limit = capture.get(2).and_then(|v| v.as_str().parse::<f64>().ok());
            if let (Some(remaining), Some(limit)) = (remaining, limit) {
                if limit > 0.0 && (remaining / limit) * 100.0 <= fallback_threshold_percent {
                    return true;
                }
            }
        }
    }

    false
}

fn parse_codex_status_weekly_limit_threshold(log: &str, fallback_threshold_percent: f64) -> bool {
    if fallback_threshold_percent <= 0.0 {
        return false;
    }
    for value in extract_json_objects(log) {
        if codex_json_has_weekly_headroom_below_threshold(&value, fallback_threshold_percent, false)
        {
            return true;
        }
    }
    false
}

fn extract_json_objects(log: &str) -> Vec<Value> {
    let mut objects = Vec::new();
    let mut depth = 0usize;
    let mut start = None;
    for (index, ch) in log.char_indices() {
        if ch == '{' {
            if depth == 0 {
                start = Some(index);
            }
            depth += 1;
        } else if ch == '}' {
            if depth > 0 {
                depth -= 1;
                if depth == 0 {
                    if let Some(start_index) = start {
                        let raw = &log[start_index..=index];
                        if let Ok(value) = serde_json::from_str::<Value>(raw) {
                            objects.push(value);
                        }
                    }
                    start = None;
                }
            }
        }
    }
    objects
}

fn codex_json_has_weekly_headroom_below_threshold(
    value: &Value,
    threshold_percent: f64,
    in_weekly_context: bool,
) -> bool {
    match value {
        Value::Object(map) => {
            let mut remaining = None;
            let mut limit = None;
            let mut weekly_context = in_weekly_context;
            let mut remaining_percent = None;
            for (key, nested) in map {
                let key_lower = key.to_ascii_lowercase();
                let is_weekly_key = is_weekly_context_key(&key_lower);
                if is_weekly_key {
                    weekly_context = true;
                }
                if let Value::String(raw) = nested {
                    if is_weekly_context_hint_key(&key_lower) && is_weekly_duration_hint(raw) {
                        weekly_context = true;
                    }
                    if is_weekly_period_hint_field(key_lower.as_str(), raw) {
                        weekly_context = true;
                    }
                }
                if is_remaining_key(&key_lower) {
                    remaining = parse_f64_from_value(nested);
                    continue;
                }
                if is_limit_key(&key_lower) {
                    limit = parse_f64_from_value(nested);
                    continue;
                }
                if is_remaining_percent_key(&key_lower) {
                    remaining_percent = parse_f64_from_value(nested);
                    continue;
                }
                if key_lower.contains("percent") {
                    if key_lower.contains("remaining") && remaining_percent.is_none() {
                        remaining_percent = parse_f64_from_value(nested);
                    }
                }
            }
            if weekly_context {
                if let Some(raw_percent) = remaining_percent {
                    if raw_percent >= 0.0 && raw_percent <= threshold_percent {
                        return true;
                    }
                }
                if let (Some(remaining), Some(limit)) = (remaining, limit) {
                    if limit > 0.0 {
                        let remaining_percent = (remaining / limit) * 100.0;
                        if remaining_percent <= threshold_percent {
                            return true;
                        }
                    }
                }
            }
            // Second pass: recurse into child objects with the weekly_context flag
            // that may have been set during the first pass above.
            for (key, nested) in map {
                let key_lower = key.to_ascii_lowercase();
                let child_weekly_context = weekly_context || is_weekly_context_key(&key_lower);
                if codex_json_has_weekly_headroom_below_threshold(
                    nested,
                    threshold_percent,
                    child_weekly_context,
                ) {
                    return true;
                }
            }
            false
        }
        Value::Array(values) => values.iter().any(|value| {
            codex_json_has_weekly_headroom_below_threshold(
                value,
                threshold_percent,
                in_weekly_context,
            )
        }),
        _ => false,
    }
}

fn is_weekly_context_key(key: &str) -> bool {
    let key = key.to_ascii_lowercase();
    key.contains("week") || key == "7d" || key == "weekly" || key == "per_week"
}

fn is_weekly_context_hint_key(key: &str) -> bool {
    let key = key.to_ascii_lowercase();
    key.contains("period")
        || key.contains("window")
        || key.contains("interval")
        || key == "duration"
}

fn is_weekly_period_hint_field(key: &str, raw: &str) -> bool {
    if !key.contains("period") && !key.contains("duration") && !key.contains("window") {
        return false;
    }
    is_weekly_duration_hint(raw)
}

fn parse_f64_from_value(value: &Value) -> Option<f64> {
    match value {
        Value::Number(number) => number.as_f64(),
        Value::String(raw) => parse_f64_string(raw),
        _ => None,
    }
}

fn parse_f64_string(raw: &str) -> Option<f64> {
    raw.trim()
        .trim_end_matches('%')
        .replace(',', "")
        .trim()
        .parse::<f64>()
        .ok()
}

fn is_remaining_key(key: &str) -> bool {
    let key = key.to_ascii_lowercase();
    key == "remaining" || key == "remaining_requests" || key == "remaining_tokens"
}

fn is_remaining_percent_key(key: &str) -> bool {
    let key = key.to_ascii_lowercase();
    key == "remaining_percent"
        || key == "remaining_ratio"
        || key == "remaining_pct"
        || key == "remaining_percentage"
        || key == "remaining_ratio_percentage"
}

fn is_limit_key(key: &str) -> bool {
    let key = key.to_ascii_lowercase();
    key == "limit" || key == "limit_requests" || key == "limit_tokens"
}

fn is_weekly_duration_hint(value: &str) -> bool {
    let value = value.to_ascii_lowercase();
    value.contains("week")
        || value.contains("weekly")
        || value.contains("7d")
        || value.contains("7 day")
        || value.contains("7 days")
        || value.contains("7-day")
        || value.contains("7_days")
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
    prior_patch_context: Option<&PriorPatchContext>,
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
    let prior_patch_hint = prior_patch_context
        .map(|context| {
            let version = context
                .fixer_version
                .as_deref()
                .map(|value| format!("It was generated by Fixer `{value}`."))
                .unwrap_or_else(|| {
                    "It was generated by an older or legacy Fixer version.".to_string()
                });
            let patch_path = context
                .patch_path
                .as_ref()
                .map(|path| format!("\n- Prior patch: `{}`", path.display()))
                .unwrap_or_default();
            let session_path = context
                .session_path
                .as_ref()
                .map(|path| format!("\n- Prior published session: `{}`", path.display()))
                .unwrap_or_default();
            format!(
                "\n\nA previous Fixer patch attempt already exists for this issue. {version} Review that patch before changing code, improve it instead of starting blind, and clean up anything awkward or underexplained. In particular, remove avoidable `goto`, tighten the explanation of what the patch is doing, and make the resulting diff feel ready for upstream git review.{patch_path}{session_path}"
            )
        })
        .unwrap_or_default();
    format!(
        "You are working on a bounded fixer proposal.\n\nRead the evidence bundle at `{}`. The prepared workspace is `{}` and it was acquired via `{}`. Produce the smallest reasonable patch for the target repository, keep the change upstreamable, prefer the clearest control flow available, and do not keep avoidable `goto` when a simpler structure would read better. The final explanation must connect the observed issue evidence to the actual code change, not just paraphrase the diff.{}{} \n\n{}\n\n{}",
        evidence_path.display(),
        workspace.repo_root.display(),
        workspace.source_kind,
        investigation_hint,
        prior_patch_hint,
        extra,
        patch_response_contract(),
    )
}

fn build_plan_prompt(
    evidence_path: &Path,
    workspace: &PreparedWorkspace,
    source_workspace_root: Option<&Path>,
) -> String {
    let source_hint = source_workspace_root
        .map(|path| {
            format!(
                " The original pre-edit snapshot is available at `{}` if you need to inspect it.",
                path.display()
            )
        })
        .unwrap_or_default();
    format!(
        "You are planning a fixer patch before any edits happen.\n\nRead the evidence bundle at `{}`. The prepared workspace is `{}` and it was acquired via `{}`.{} Inspect the relevant code, but do not edit files in this pass.\n\nReturn a short markdown plan with these exact sections:\n\n## Problem\n## Proposed Subject\n## Patch Plan\n## Risks\n## Validation\n\nThe plan must explain how the proposed code change addresses the observed issue evidence, call out any prior Fixer patch that should be improved or replaced, and reject awkward control flow such as avoidable `goto` if there is a cleaner bounded alternative.",
        evidence_path.display(),
        workspace.repo_root.display(),
        workspace.source_kind,
        source_hint,
    )
}

fn build_patch_prompt_with_plan(patch_prompt: &str, plan_output_path: &Path) -> String {
    format!(
        "{}\n\nBefore editing, read the plan at `{}` and follow it unless the code proves part of it wrong. If you change course, say so explicitly in the final write-up instead of silently drifting from the plan.",
        patch_prompt,
        plan_output_path.display()
    )
}

fn build_compact_patch_retry_prompt(base_patch_prompt: &str) -> String {
    format!(
        "{base_patch_prompt}\n\nWorkflow note: A previous patch pass failed during Codex remote compaction under high demand. Re-run this patch pass from a fresh context, keep the explanation concise, and avoid rehashing long evidence verbatim."
    )
}

fn build_review_prompt(
    evidence_path: &Path,
    workspace: &PreparedWorkspace,
    source_workspace_root: Option<&Path>,
    latest_patch_output_path: &Path,
    refinement_round: u32,
    current_changed_paths: &[String],
) -> String {
    let source_hint = source_workspace_root
        .map(|path| {
            format!(
                " The original pre-edit snapshot is available at `{}` for diffing.",
                path.display()
            )
        })
        .unwrap_or_default();
    let round_hint = if refinement_round == 0 {
        "Review the first patch pass."
    } else {
        "Review the patch again after the latest refinement."
    };
    let changed_paths_hint = if current_changed_paths.is_empty() {
        String::new()
    } else {
        format!(
            " The workspace currently changes these repo-relative paths: {}. Verify that `## Git Add Paths` matches this exact set and that `## Issue Connection` explains every shipped functional file.",
            current_changed_paths.join(", ")
        )
    };
    format!(
        "You are reviewing a freshly generated fixer patch.\n\nRead the evidence bundle at `{}`. The prepared workspace is `{}` and it was acquired via `{}`. {}{}{} The latest author response is at `{}`. Inspect the current code and changed paths like a strict code reviewer. Focus on correctness, regressions, maintainability, awkward control flow such as avoidable `goto`, missing validation, weak or non-gittable commit message text, and explanations that fail to connect the observed issue evidence to the code change.\n\nDo not apply code changes in this pass.\n\nReturn a short markdown review report. The first non-empty line must be exactly one of:\n\nRESULT: ok\nRESULT: fix-needed\n\nIf you choose `RESULT: fix-needed`, add a `## Findings` section with concrete, actionable items.",
        evidence_path.display(),
        workspace.repo_root.display(),
        workspace.source_kind,
        round_hint,
        source_hint,
        changed_paths_hint,
        latest_patch_output_path.display(),
    )
}

fn build_refinement_prompt(
    evidence_path: &Path,
    workspace: &PreparedWorkspace,
    source_workspace_root: Option<&Path>,
    plan_output_path: Option<&Path>,
    latest_patch_output_path: &Path,
    review_output_path: &Path,
    refinement_round: u32,
    current_changed_paths: &[String],
) -> String {
    let source_hint = source_workspace_root
        .map(|path| {
            format!(
                " The original pre-edit snapshot is available at `{}` if you need to compare the current patch against it.",
                path.display()
            )
        })
        .unwrap_or_default();
    let plan_hint = plan_output_path
        .map(|path| {
            format!(
                " Re-read the planning pass at `{}` before editing.",
                path.display()
            )
        })
        .unwrap_or_default();
    let changed_paths_hint = if current_changed_paths.is_empty() {
        String::new()
    } else {
        format!(
            " The workspace currently changes these repo-relative paths: {}. Either keep that exact set synchronized with `## Git Add Paths` and `## Issue Connection`, or revert any unintended file before you answer.",
            current_changed_paths.join(", ")
        )
    };
    format!(
        "You are refining a fixer patch after an explicit code review.\n\nRead the evidence bundle at `{}`. The prepared workspace is `{}` and it was acquired via `{}`. Read the latest author response at `{}`. Read the review report at `{}`. This is refinement round {}.{}{}{} Address the review findings with the smallest reasonable follow-up changes. Keep the patch upstream-friendly, avoid awkward control flow when a simpler structure will do, keep the final response gittable, run relevant tests if available, and summarize which review findings you addressed.\n\n{}",
        evidence_path.display(),
        workspace.repo_root.display(),
        workspace.source_kind,
        latest_patch_output_path.display(),
        review_output_path.display(),
        refinement_round,
        source_hint,
        plan_hint,
        changed_paths_hint,
        patch_response_contract(),
    )
}

fn patch_response_contract() -> &'static str {
    "In every authoring pass, your final response must start with `Subject: <single-line git commit subject>` and then include these markdown sections exactly:\n\n## Commit Message\nA short upstream-friendly explanation of what changed and why.\n\n## Issue Connection\nExplain how the code change addresses the observed issue evidence instead of merely paraphrasing the diff.\n\n## Git Add Paths\nList the repo-relative paths that belong in the final patch, one per line. Include intentionally new files, and do not list generated build artifacts.\n\n## Validation\nList the checks you ran, or say clearly that you could not run them."
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
    let is_stuck_process = subsystem == "stuck-process";
    let is_oom_kill = subsystem == "oom-kill";
    let is_desktop_resume = subsystem == "desktop-resume";
    let is_desktop_graphics_session = subsystem == "desktop-graphics-session";
    let is_network_driver_hang = subsystem == "network-driver-hang";
    let desktop_issue_variant = details
        .get("issue_variant")
        .and_then(Value::as_str)
        .unwrap_or("resume-display-failure");
    let suspected_root_cause = details.get("suspected_root_cause").and_then(Value::as_str);
    let classification = details
        .get("loop_classification")
        .and_then(Value::as_str)
        .unwrap_or(if is_stuck_process {
            "unknown-uninterruptible-wait"
        } else if is_desktop_resume {
            "resume-display-failure"
        } else if is_desktop_graphics_session {
            "desktop-graphics-session-failure"
        } else if is_oom_kill {
            "kernel-oom-kill"
        } else if is_network_driver_hang {
            "network-driver-hang"
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
        .unwrap_or(if is_stuck_process {
            "Fixer collected `/proc` evidence for a process wedged in `D` state but could not derive a stronger kernel-side hypothesis yet."
        } else if is_desktop_resume {
            if desktop_issue_variant == "sddm-greeter-nss-compat-crash" {
                "Fixer correlated the SDDM greeter crash with NVIDIA-linked fault markers and NSS account-resolution frames, which points at a login-stack configuration mismatch rather than a pure GPU rendering bug."
            } else {
                "Fixer correlated suspend/resume timing with graphics stack errors, desktop-process crashes, and display-manager restart attempts."
            }
        } else if is_desktop_graphics_session {
            "Fixer correlated repeated EGL/Mesa/Qt warnings across multiple desktop apps with compositor or session instability, which points at a shared graphics/session failure rather than one broken app."
        } else if is_oom_kill {
            "Fixer collected kernel log evidence showing that the OOM killer selected and terminated this process."
        } else if is_network_driver_hang {
            "Fixer detected kernel-reported network adapter hardware failures and collected driver, firmware, and module parameter context."
        } else {
            "Fixer collected a CPU-hot process sample but could not derive a stronger hypothesis yet."
        });
    let thread_backtrace_summary = details
        .get("thread_backtrace_summary")
        .and_then(Value::as_str);
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
        .or_else(|| {
            details
                .get("package_metadata")
                .and_then(|value| value.get("package_name"))
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
    if is_stuck_process {
        body.push_str("# Stuck Process Investigation Report\n\n");
    } else if is_desktop_resume {
        body.push_str("# Desktop Resume Failure Investigation Report\n\n");
    } else if is_desktop_graphics_session {
        body.push_str("# Desktop Graphics/Session Failure Investigation Report\n\n");
    } else if is_oom_kill {
        body.push_str("# OOM Kill Investigation Report\n\n");
    } else if is_network_driver_hang {
        body.push_str("# Network Driver Hang Investigation Report\n\n");
    } else {
        body.push_str("# Runaway CPU Investigation Report\n\n");
    }
    body.push_str("## Recommended Action\n\n");
    match acquisition_error {
        Some(error) => {
            let blocker_kind = process_investigation_blocker_kind(error);
            if blocker_kind == "codex-auth" {
                body.push_str("Fixer gathered enough evidence to describe the issue, and a patch might still be possible, but this host could not start the automated Codex pass.\n\n");
                body.push_str(&format!("Automatic patch attempt blocker: `{error}`\n\n"));
                body.push_str("Fix the local Codex auth lease or login state, then retry the patch pass if this issue still looks worth pursuing.\n\n");
            } else if blocker_kind == "workspace" && is_stuck_process {
                body.push_str("Fixer diagnosed a likely stuck-process wait, but it could not automatically acquire a patchable source workspace on this host.\n\n");
                body.push_str(&format!("Workspace acquisition blocker: `{error}`\n\n"));
                body.push_str("Use the diagnosis below to file an upstream or distro bug, or to fetch a source tree manually before retrying `fixer propose-fix <id> --engine codex`.\n\n");
            } else if blocker_kind == "workspace" && is_desktop_resume {
                if desktop_issue_variant == "sddm-greeter-nss-compat-crash" {
                    body.push_str("Fixer diagnosed an SDDM greeter startup failure, but it could not automatically acquire a patchable display-manager or system-configuration workspace on this host.\n\n");
                } else {
                    body.push_str("Fixer diagnosed a suspend/resume display-stack failure, but it could not automatically acquire a patchable graphics or desktop source workspace on this host.\n\n");
                }
                body.push_str(&format!("Workspace acquisition blocker: `{error}`\n\n"));
                body.push_str("Use the diagnosis below to file an upstream or distro bug, or to fetch a source tree manually before retrying `fixer propose-fix <id> --engine codex`.\n\n");
            } else if blocker_kind == "workspace" && is_desktop_graphics_session {
                body.push_str("Fixer diagnosed a shared desktop graphics/session failure, but it could not automatically acquire a patchable compositor, Mesa, Qt, or desktop source workspace on this host.\n\n");
                body.push_str(&format!("Workspace acquisition blocker: `{error}`\n\n"));
                body.push_str("Use the diagnosis below to file an upstream or distro bug, or to fetch a source tree manually before retrying `fixer propose-fix <id> --engine codex`.\n\n");
            } else if blocker_kind == "workspace" && is_network_driver_hang {
                body.push_str("Fixer diagnosed a network driver hardware hang, but it could not automatically acquire a patchable kernel source workspace on this host.\n\n");
                body.push_str(&format!("Workspace acquisition blocker: `{error}`\n\n"));
                body.push_str("Use the diagnosis below to file an upstream or distro kernel bug, or apply a known module-parameter workaround if one is listed.\n\n");
            } else if blocker_kind == "workspace" && is_oom_kill {
                body.push_str("Fixer diagnosed a kernel OOM kill, but it could not automatically acquire a patchable source workspace on this host.\n\n");
                body.push_str(&format!("Workspace acquisition blocker: `{error}`\n\n"));
                body.push_str("Use the diagnosis below to file an upstream or distro bug, or to fetch a source tree manually before retrying `fixer propose-fix <id> --engine codex`.\n\n");
            } else if blocker_kind == "workspace" {
                body.push_str("Fixer diagnosed a likely runaway CPU loop, but it could not automatically acquire a patchable source workspace on this host.\n\n");
                body.push_str(&format!("Workspace acquisition blocker: `{error}`\n\n"));
                body.push_str("Use the diagnosis below to file an upstream or distro bug, or to fetch a source tree manually before retrying `fixer propose-fix <id> --engine codex`.\n\n");
            } else {
                body.push_str("Fixer gathered enough evidence to describe the issue, but the automatic patch attempt did not get far enough to produce a real patch on this host.\n\n");
                body.push_str(&format!("Automatic patch attempt blocker: `{error}`\n\n"));
                body.push_str("Use the diagnosis below to understand the issue first, then retry the patch pass once the blocker above is resolved.\n\n");
            }
        }
        None => {
            if is_stuck_process {
                body.push_str("Fixer gathered enough evidence to describe the wait. Review the diagnosis below, then decide whether this looks like a package bug or a lower-level filesystem or kernel stall.\n\n");
            } else if is_desktop_resume {
                if desktop_issue_variant == "sddm-greeter-nss-compat-crash" {
                    body.push_str("Fixer gathered enough evidence to describe the greeter startup failure. Review the diagnosis below, then decide whether this looks like an SDDM/NSS configuration mismatch, an NVIDIA userspace mismatch, or a broader display-manager regression.\n\n");
                } else {
                    body.push_str("Fixer gathered enough evidence to describe the suspend/resume failure. Review the diagnosis below, then decide whether this looks like a graphics-driver, X11, compositor, or display-manager regression.\n\n");
                }
            } else if is_desktop_graphics_session {
                body.push_str("Fixer gathered enough evidence to describe the shared desktop failure. Review the diagnosis below, then decide whether this looks like a Wayland/compositor regression, a Mesa or driver issue, or a Qt desktop-stack mismatch.\n\n");
            } else if is_oom_kill {
                body.push_str("Fixer gathered enough evidence to describe the OOM kill. Review the diagnosis below, then decide whether this points at application memory growth, an unusually heavy workload, or broader system memory pressure.\n\n");
            } else if is_network_driver_hang {
                body.push_str("Fixer gathered enough evidence to describe the network driver hang. Review the driver and hardware details below, then decide whether to apply a module-parameter workaround, file an upstream or Debian kernel bug, or attempt a kernel source patch.\n\n");
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

    if is_oom_kill {
        body.push_str("\n## Why Fixer Believes This Was an OOM Kill\n\n");
        body.push_str(&format!(
            "- Victim process: `{}`\n- Killed PID: `{}`\n- Classification: `{}`\n- Confidence: `{:.2}`\n- Explanation: {}\n",
            target_name,
            details
                .get("pid")
                .and_then(Value::as_i64)
                .map(|value| value.to_string())
                .unwrap_or_else(|| "unknown".to_string()),
            classification,
            confidence,
            explanation
        ));
        if let Some(invoker) = details.get("invoker").and_then(Value::as_str) {
            body.push_str(&format!("- OOM killer invoker: `{invoker}`\n"));
        }
        if let Some(task_memcg) = details.get("task_memcg").and_then(Value::as_str) {
            body.push_str(&format!("- Memory cgroup: `{task_memcg}`\n"));
        }
        if let Some(total_vm_kb) = details.get("total_vm_kb").and_then(Value::as_u64) {
            body.push_str(&format!(
                "- Virtual memory at kill time: `{:.1}` GiB\n",
                total_vm_kb as f64 / (1024.0 * 1024.0)
            ));
        }
        if let Some(anon_rss_kb) = details.get("anon_rss_kb").and_then(Value::as_u64) {
            body.push_str(&format!(
                "- Anonymous RSS at kill time: `{:.0}` MiB\n",
                anon_rss_kb as f64 / 1024.0
            ));
        }
        if let Some(file_rss_kb) = details.get("file_rss_kb").and_then(Value::as_u64) {
            body.push_str(&format!(
                "- File-backed RSS at kill time: `{:.0}` MiB\n",
                file_rss_kb as f64 / 1024.0
            ));
        }
        if let Some(shmem_rss_kb) = details.get("shmem_rss_kb").and_then(Value::as_u64) {
            body.push_str(&format!(
                "- Shared-memory RSS at kill time: `{:.0}` MiB\n",
                shmem_rss_kb as f64 / 1024.0
            ));
        }
        if let Some(oom_score_adj) = details.get("oom_score_adj").and_then(Value::as_i64) {
            body.push_str(&format!("- oom_score_adj: `{oom_score_adj}`\n"));
        }
    } else {
        if is_desktop_resume {
            body.push_str("\n## Why Fixer Believes Resume Broke The Desktop\n\n");
        } else if is_desktop_graphics_session {
            body.push_str("\n## Why Fixer Believes The Desktop Graphics Session Is Breaking\n\n");
        } else if is_network_driver_hang {
            body.push_str("\n## Why Fixer Believes This Is A Hardware Hang\n\n");
        } else {
            body.push_str("\n## Why Fixer Believes It Is Stuck\n\n");
        }
        if is_network_driver_hang {
            if let Some(driver) = details.get("driver").and_then(Value::as_str) {
                body.push_str(&format!("- Network driver: `{driver}`\n"));
            }
            if let Some(iface) = details.get("interface").and_then(Value::as_str) {
                body.push_str(&format!("- Interface: `{iface}`\n"));
            }
            if let Some(pci) = details.get("pci_address").and_then(Value::as_str) {
                body.push_str(&format!("- PCI address: `{pci}`\n"));
            }
            body.push_str(&format!(
                "- Hang type: `{}`\n- Classification: `{}`\n- Confidence: `{:.2}`\n- Explanation: {}\n",
                details.get("hang_type").and_then(Value::as_str).unwrap_or("unknown"),
                classification,
                confidence,
                explanation
            ));
        } else if is_desktop_resume || is_desktop_graphics_session {
            body.push_str(&format!(
                "- Affected desktop target: `{}`\n- Failure classification: `{}`\n- Confidence: `{:.2}`\n- Explanation: {}\n",
                target_name, classification, confidence, explanation
            ));
            if let Some(root_cause) = suspected_root_cause {
                body.push_str(&format!("- Suspected root cause: `{root_cause}`\n"));
            }
        } else {
            body.push_str(&format!(
                "- Target process: `{}`\n- Sampled PID: `{}`\n- Loop classification: `{}`\n- Confidence: `{:.2}`\n- Explanation: {}\n",
                target_name, sampled_pid, classification, confidence, explanation
            ));
            if let Some(summary) = thread_backtrace_summary {
                body.push_str(&format!("- Thread backtrace summary: `{summary}`\n"));
            }
        }
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
        if is_desktop_resume || is_desktop_graphics_session {
            if let Some(driver) = details.get("driver").and_then(Value::as_str) {
                body.push_str(&format!("- Graphics driver: `{driver}`\n"));
            }
            if let Some(session_type) = details.get("session_type").and_then(Value::as_str) {
                body.push_str(&format!(
                    "- Session type: `{}`\n",
                    session_type.to_uppercase()
                ));
            }
            if let Some(current_desktop) = details.get("current_desktop").and_then(Value::as_str) {
                body.push_str(&format!("- Desktop shell: `{current_desktop}`\n"));
            }
            if let Some(compositor) = details.get("compositor").and_then(Value::as_str) {
                body.push_str(&format!("- Compositor: `{compositor}`\n"));
            }
            if let Some(display_manager) = details.get("display_manager").and_then(Value::as_str) {
                body.push_str(&format!("- Display manager: `{display_manager}`\n"));
            }
            if let Some(apps) = details.get("affected_apps").and_then(Value::as_array) {
                let apps = apps.iter().filter_map(Value::as_str).collect::<Vec<_>>();
                if !apps.is_empty() {
                    body.push_str(&format!("- Affected apps: `{}`\n", apps.join(", ")));
                }
            }
            if let Some(crashes) = details.get("crashed_processes").and_then(Value::as_array) {
                let crashes = crashes.iter().filter_map(Value::as_str).collect::<Vec<_>>();
                if !crashes.is_empty() {
                    body.push_str(&format!(
                        "- Crashed desktop processes: `{}`\n",
                        crashes.join(", ")
                    ));
                }
            }
            if let Some(suspend_line) = details.get("suspend_line").and_then(Value::as_str) {
                body.push_str(&format!("- Suspend marker: `{suspend_line}`\n"));
            }
            if let Some(resume_line) = details.get("resume_line").and_then(Value::as_str) {
                body.push_str(&format!("- Resume marker: `{resume_line}`\n"));
            }
        }
    }
    if is_stuck_process {
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
    if is_desktop_resume || is_desktop_graphics_session {
        if let Some(marker_kinds) = details.get("marker_kinds").and_then(Value::as_array) {
            let markers = marker_kinds
                .iter()
                .filter_map(Value::as_str)
                .take(8)
                .collect::<Vec<_>>();
            if !markers.is_empty() {
                body.push_str("\n## Diagnostic Markers\n\n");
                for marker in markers {
                    body.push_str(&format!("- `{marker}`\n"));
                }
            }
        }
        if let Some(gpu_error_lines) = details.get("gpu_error_lines").and_then(Value::as_array) {
            let lines = gpu_error_lines
                .iter()
                .filter_map(Value::as_str)
                .take(6)
                .collect::<Vec<_>>();
            if !lines.is_empty() {
                body.push_str("\n## Graphics Stack Errors\n\n");
                for line in lines {
                    body.push_str(&format!("- `{line}`\n"));
                }
            }
        }
        if let Some(session_error_lines) =
            details.get("session_error_lines").and_then(Value::as_array)
        {
            let lines = session_error_lines
                .iter()
                .filter_map(Value::as_str)
                .take(6)
                .collect::<Vec<_>>();
            if !lines.is_empty() {
                body.push_str("\n## Session And Display-Manager Errors\n\n");
                for line in lines {
                    body.push_str(&format!("- `{line}`\n"));
                }
            }
        }
        if let Some(root_cause_lines) = details.get("root_cause_lines").and_then(Value::as_array) {
            let lines = root_cause_lines
                .iter()
                .filter_map(Value::as_str)
                .take(6)
                .collect::<Vec<_>>();
            if !lines.is_empty() {
                body.push_str("\n## Suspected Root-Cause Markers\n\n");
                for line in lines {
                    body.push_str(&format!("- `{line}`\n"));
                }
            }
        }
        if let Some(crash_lines) = details.get("crash_lines").and_then(Value::as_array) {
            let lines = crash_lines
                .iter()
                .filter_map(Value::as_str)
                .take(6)
                .collect::<Vec<_>>();
            if !lines.is_empty() {
                body.push_str("\n## Crash Correlation\n\n");
                for line in lines {
                    body.push_str(&format!("- `{line}`\n"));
                }
            }
        }
        if let Some(warning_lines) = details.get("warning_lines").and_then(Value::as_array) {
            let lines = warning_lines
                .iter()
                .filter_map(Value::as_str)
                .take(8)
                .collect::<Vec<_>>();
            if !lines.is_empty() && is_desktop_graphics_session {
                body.push_str("\n## Desktop Graphics Warnings\n\n");
                for line in lines {
                    body.push_str(&format!("- `{line}`\n"));
                }
            }
        }
    }
    if is_network_driver_hang {
        if let Some(hang_lines) = details.get("hang_lines").and_then(Value::as_array) {
            let lines = hang_lines
                .iter()
                .filter_map(Value::as_str)
                .take(8)
                .collect::<Vec<_>>();
            if !lines.is_empty() {
                body.push_str("\n## Kernel Hardware Hang Log Lines\n\n");
                body.push_str("```text\n");
                for line in lines {
                    body.push_str(line);
                    body.push('\n');
                }
                body.push_str("```\n");
            }
        }
        if let Some(reg_dump) = details.get("register_dump").and_then(Value::as_array) {
            let lines = reg_dump
                .iter()
                .filter_map(Value::as_str)
                .collect::<Vec<_>>();
            if !lines.is_empty() {
                body.push_str("\n## Hardware Register State At Hang\n\n");
                body.push_str("```text\n");
                for line in lines {
                    body.push_str(line);
                    body.push('\n');
                }
                body.push_str("```\n");
            }
        }
        if let Some(link_events) = details.get("link_events").and_then(Value::as_array) {
            let lines = link_events
                .iter()
                .filter_map(Value::as_str)
                .collect::<Vec<_>>();
            if !lines.is_empty() {
                body.push_str("\n## Link State Events\n\n");
                body.push_str("```text\n");
                for line in lines {
                    body.push_str(line);
                    body.push('\n');
                }
                body.push_str("```\n");
            }
        }
        if let Some(pci_info) = details.get("pci_device_info").and_then(Value::as_str) {
            body.push_str("\n## PCI Device Identity\n\n");
            body.push_str("```text\n");
            body.push_str(pci_info);
            body.push_str("\n```\n");
        }
        if let Some(ethtool_info) = details.get("ethtool_driver_info").and_then(Value::as_str) {
            body.push_str("\n## Driver And Firmware Version\n\n");
            body.push_str("```text\n");
            body.push_str(ethtool_info);
            body.push_str("\n```\n");
        }
        if let Some(stats) = details.get("ethtool_stats").and_then(Value::as_str) {
            body.push_str("\n## Interface Statistics\n\n");
            body.push_str("```text\n");
            body.push_str(stats);
            body.push_str("\n```\n");
        }
        let module_params = details.get("module_params");
        if let Some(params) = module_params.and_then(Value::as_object) {
            if !params.is_empty() {
                body.push_str("\n## Active Module Parameters\n\n");
                for (k, v) in params {
                    body.push_str(&format!("- `{k}` = `{}`\n", v.as_str().unwrap_or_default()));
                }
            }
        }
        if let Some(eee_enabled) = details.get("eee_enabled").and_then(Value::as_bool) {
            body.push_str("\n## Known Workarounds\n\n");
            if eee_enabled {
                let iface = details
                    .get("interface")
                    .and_then(Value::as_str)
                    .unwrap_or("<iface>");
                let driver = details
                    .get("driver")
                    .and_then(Value::as_str)
                    .unwrap_or("<driver>");
                body.push_str("Energy-Efficient Ethernet (EEE) is **enabled** on this interface. Disabling EEE is a known workaround for hardware unit hangs in some Intel adapters:\n\n");
                body.push_str(&format!("```bash\n# Disable EEE temporarily\nethtool --set-eee {iface} eee off\n\n# To persist across reboots, add to /etc/modprobe.d/{driver}.conf:\n# options {driver} EEE=0\n```\n"));
            } else {
                body.push_str("EEE is already disabled on this interface — this common workaround is already applied.\n");
            }
        }
    }

    if !hot_symbols.is_empty() {
        body.push_str("\n## Dominant Call Path\n\n");
        for symbol in hot_symbols {
            body.push_str(&format!("- `{symbol}`\n"));
        }
    }

    if let Some(signals) = details
        .get("lock_contention_signals")
        .and_then(Value::as_array)
    {
        let signals = signals
            .iter()
            .filter_map(Value::as_str)
            .take(8)
            .collect::<Vec<_>>();
        if !signals.is_empty() {
            body.push_str("\n## Contention Signals\n\n");
            for signal in signals {
                body.push_str(&format!("- `{signal}`\n"));
            }
        }
    }

    if let Some(clusters) = details
        .get("common_frame_clusters")
        .and_then(Value::as_array)
    {
        let clusters = clusters
            .iter()
            .filter_map(Value::as_object)
            .take(4)
            .collect::<Vec<_>>();
        if !clusters.is_empty() {
            body.push_str("\n## Common Thread Clusters\n\n");
            for cluster in clusters {
                let count = cluster
                    .get("thread_count")
                    .and_then(Value::as_u64)
                    .unwrap_or_default();
                let frames = cluster
                    .get("frames")
                    .and_then(Value::as_array)
                    .map(|items| {
                        items
                            .iter()
                            .filter_map(Value::as_str)
                            .take(4)
                            .collect::<Vec<_>>()
                            .join(" -> ")
                    })
                    .unwrap_or_default();
                if !frames.is_empty() {
                    body.push_str(&format!("- `{count}` thread(s): `{frames}`\n"));
                }
            }
        }
    }

    if let Some(backtraces) = details
        .get("representative_backtraces")
        .and_then(Value::as_array)
    {
        let backtraces = backtraces
            .iter()
            .filter_map(Value::as_object)
            .take(3)
            .collect::<Vec<_>>();
        if !backtraces.is_empty() {
            body.push_str("\n## Representative Thread Backtraces\n\n");
            for trace in backtraces {
                let label = trace
                    .get("label")
                    .and_then(Value::as_str)
                    .unwrap_or("thread");
                let count = trace
                    .get("thread_count")
                    .and_then(Value::as_u64)
                    .unwrap_or(1);
                let frames = trace
                    .get("frames")
                    .and_then(Value::as_array)
                    .map(|items| {
                        items
                            .iter()
                            .filter_map(Value::as_str)
                            .take(8)
                            .collect::<Vec<_>>()
                            .join("\n")
                    })
                    .unwrap_or_default();
                if !frames.is_empty() {
                    body.push_str(&format!(
                        "### `{label}` ({count} thread(s))\n\n```text\n{frames}\n```\n\n"
                    ));
                }
            }
        }
    }

    if let Some(backtrace_excerpt) = details
        .get("raw_backtrace_excerpt")
        .and_then(Value::as_str)
        .filter(|value| !value.trim().is_empty())
    {
        body.push_str("\n## Raw Thread Backtrace Snapshot\n\n```text\n");
        body.push_str(backtrace_excerpt);
        body.push_str("\n```\n");
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
    if is_stuck_process {
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
    if is_stuck_process {
        body.push_str("1. Confirm the process is still in `D` state with `ps -p <pid> -o pid,stat,wchan:40,comm`.\n");
        body.push_str("2. Re-read `/proc/<pid>/stack`, `/proc/<pid>/wchan`, and `/proc/<pid>/fd` to confirm the blocking path still points at the same wait site.\n");
        body.push_str("3. If you intervene on the suspected filesystem or mount backend, verify the process leaves `D` state instead of simply moving to a different wait site.\n");
    } else if is_desktop_resume {
        if desktop_issue_variant == "sddm-greeter-nss-compat-crash" {
            body.push_str("1. Re-read the latest greeter coredump with `coredumpctl debug <pid> --debugger-arguments='-batch -ex \"thread apply all bt\"'` and confirm the stack still includes `libnvidia-tls`, `getpwnam`, or `nss_compat` frames.\n");
            body.push_str("2. Inspect `/etc/nsswitch.conf` and verify whether `passwd`, `group`, or `shadow` still use `compat`; if they do, check whether `/etc/passwd`, `/etc/group`, and `/etc/shadow` actually contain any `+` or `-` compat entries.\n");
            body.push_str("3. After switching to `files systemd` or otherwise correcting the NSS configuration, restart `sddm` and verify the greeter stays up, connects to the daemon, and no longer logs `HelperExitStatus(11)`.\n");
        } else {
            body.push_str("1. Reproduce one suspend/resume cycle and confirm the journal still shows the same graphics-driver errors right before or right after resume.\n");
            body.push_str("2. Check whether `Xorg`, `kwin_x11`, or the display manager are crashing with the same signals and backtraces.\n");
            body.push_str("3. If you change the kernel, Mesa, Xorg driver, or session type, verify the desktop comes back cleanly after resume and the journal no longer shows the same display-stack failure markers.\n");
        }
    } else if is_desktop_graphics_session {
        body.push_str("1. Reproduce the launch failure and confirm the journal still shows the same `libEGL`, `MESA-LOADER`, `qt.qpa.wayland`, or compositor-hang markers.\n");
        body.push_str("2. Check whether the same set of apps fail under Wayland but recover under `QT_QPA_PLATFORM=xcb` or a software-rendered fallback, which helps separate session/compositor breakage from one broken app.\n");
        body.push_str("3. Compare `kwin_wayland`, Mesa, Qt, portal, and GPU-driver package versions, then verify whether a coherent desktop-stack upgrade or downgrade removes the shared warnings and crashes.\n");
    } else if is_oom_kill {
        body.push_str("1. Confirm the kernel is still logging OOM activity with `journalctl -k -g 'Out of memory|Killed process|oom-kill'`.\n");
        body.push_str("2. Check whether the same package or cgroup repeatedly gets selected as the OOM victim under the same workload.\n");
        body.push_str("3. Compare the victim's memory footprint and cgroup context before and after any package, workload, or memory-limit change.\n");
    } else {
        body.push_str("1. Confirm the process still shows sustained CPU time with `systemd-cgtop`, `top`, or `ps -p <pid> -o %cpu,stat,comm`.\n");
        body.push_str("2. Re-run a short syscall sample and confirm the dominant syscalls still match the sequence above.\n");
        body.push_str("3. Collect a fresh multi-thread userspace backtrace with `gdb --batch -p <pid> -ex 'thread apply all bt full' -ex detach -ex quit` and confirm the same thread clusters still dominate.\n");
        body.push_str("4. If you change the package, compare a fresh perf sample, backtrace, and strace excerpt to make sure the loop disappears rather than simply moving elsewhere.\n");
    }

    body.push_str("\n## Next Step\n\n");
    if acquisition_error.is_some() {
        body.push_str("Treat this as an upstream-report-ready diagnosis. Include the summary above, plus the evidence bundle path below, when filing the bug.\n");
    } else {
        if is_stuck_process
            && details
                .get("likely_external_root_cause")
                .and_then(Value::as_bool)
                .unwrap_or(false)
        {
            body.push_str("Treat this as the diagnosis half of the pipeline. The evidence currently points below user space, so the next action is usually a kernel, mount, or storage investigation rather than a package patch.\n");
        } else if is_desktop_resume {
            if desktop_issue_variant == "sddm-greeter-nss-compat-crash" {
                body.push_str("Treat this as the diagnosis half of the pipeline. The evidence currently points at display-manager startup and NSS configuration, so the next action is usually a system-configuration fix or distro integration bug report rather than a narrow application patch.\n");
            } else {
                body.push_str("Treat this as the diagnosis half of the pipeline. The evidence currently points at the graphics stack around suspend/resume, so the next action is usually a kernel, Mesa, Xorg-driver, or compositor investigation rather than a narrow package patch.\n");
            }
        } else if is_desktop_graphics_session {
            body.push_str("Treat this as the diagnosis half of the pipeline. The evidence currently points at the shared Wayland/compositor/graphics stack, so the next action is usually a KWin, Mesa, Qt, portal, or GPU-driver investigation rather than a narrow application patch.\n");
        } else if is_oom_kill {
            body.push_str("Treat this as the diagnosis half of the pipeline. The next action is to decide whether the application is growing unreasonably, the workload needs limits, or the host is simply under-provisioned for the current memory demand.\n");
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

pub fn annotate_process_investigation_report_blocker(
    bundle_dir: &Path,
    blocker: &str,
) -> Result<()> {
    let evidence_path = bundle_dir.join("evidence.json");
    let summary_path = bundle_dir.join("proposal.md");
    let raw = fs::read(&evidence_path)
        .with_context(|| format!("failed to read {}", evidence_path.display()))?;
    let mut evidence: Value = serde_json::from_slice(&raw)
        .with_context(|| format!("failed to parse {}", evidence_path.display()))?;
    evidence["automatic_patch_blocker"] = json!(blocker);
    evidence["automatic_patch_blocker_kind"] = json!(process_investigation_blocker_kind(blocker));
    if process_investigation_blocker_kind(blocker) == "workspace" {
        evidence["workspace_error"] = json!(blocker);
    }
    fs::write(&evidence_path, serde_json::to_vec_pretty(&evidence)?)?;

    let opportunity: OpportunityRecord = serde_json::from_value(
        evidence
            .get("opportunity")
            .cloned()
            .ok_or_else(|| anyhow!("missing opportunity in {}", evidence_path.display()))?,
    )?;
    let package = evidence
        .get("package")
        .cloned()
        .filter(|value| !value.is_null())
        .map(serde_json::from_value::<InstalledPackageMetadata>)
        .transpose()?;
    let system = evidence.get("system").cloned().unwrap_or_else(|| json!({}));
    fs::write(
        &summary_path,
        render_process_investigation_report(
            &opportunity,
            package.as_ref(),
            &system,
            &evidence_path,
            Some(blocker),
        ),
    )?;
    Ok(())
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
    system: &Value,
    desktop_diagnosis: &Value,
    related_desktop_summary: &Value,
    evidence_path: &std::path::Path,
) -> String {
    let mut body = String::new();
    let (visibility, sharing) = complaint_visibility_summary(&opportunity.state);
    body.push_str("# Complaint Triage Plan\n\n");
    body.push_str("## Complaint\n\n");
    body.push_str(complaint_text.trim());
    body.push_str("\n\n");

    body.push_str("## What Fixer Did\n\n");
    body.push_str(&format!(
        "- Complaint opportunity: `#{}`\n- Score: `{}`\n- Visibility: {}\n- Sharing: {}\n",
        opportunity.id, opportunity.score, visibility, sharing
    ));
    if let Some(report) = collection_report {
        body.push_str(&format!(
            "- Immediate collection: `{}` capabilities, `{}` artifacts, `{}` findings\n",
            report.capabilities_seen, report.artifacts_seen, report.findings_seen
        ));
    } else {
        body.push_str("- Immediate collection: skipped\n");
    }
    if let Some(session_type) = system.get("session_type").and_then(Value::as_str) {
        body.push_str(&format!(
            "- Session type: `{}`\n",
            session_type.to_uppercase()
        ));
    }
    if let Some(desktop) = system.get("current_desktop").and_then(Value::as_str) {
        body.push_str(&format!("- Desktop session: `{desktop}`\n"));
    }

    if let Some(summary) = desktop_diagnosis.get("summary").and_then(Value::as_str) {
        body.push_str("\n## Initial Diagnosis\n\n");
        body.push_str(summary);
        body.push_str("\n\n");
        if let Some(app_name) = desktop_diagnosis.get("app_name").and_then(Value::as_str) {
            body.push_str(&format!("- Likely affected app: `{app_name}`\n"));
        }
        if let Some(package_name) = desktop_diagnosis
            .get("package_name")
            .and_then(Value::as_str)
        {
            body.push_str(&format!("- Likely package: `{package_name}`\n"));
        }
        if let Some(session_hint) = desktop_diagnosis
            .get("session_hint")
            .and_then(Value::as_str)
        {
            body.push_str(&format!("- Session hint: `{session_hint}`\n"));
        }
        if let Some(subsystems) = desktop_diagnosis
            .get("suspected_subsystems")
            .and_then(Value::as_array)
        {
            let subsystems = subsystems
                .iter()
                .filter_map(Value::as_str)
                .collect::<Vec<_>>();
            if !subsystems.is_empty() {
                body.push_str(&format!(
                    "- Suspected subsystem: `{}`\n",
                    subsystems.join(", ")
                ));
            }
        }
        if let Some(markers) = desktop_diagnosis.get("markers").and_then(Value::as_array) {
            let markers = markers.iter().filter_map(Value::as_str).collect::<Vec<_>>();
            if !markers.is_empty() {
                body.push_str(&format!(
                    "- Markers seen in complaint: `{}`\n",
                    markers.join(", ")
                ));
            }
        }
        if let Some(package_metadata) = desktop_diagnosis.get("package_metadata") {
            if let Some(installed_version) = package_metadata
                .get("installed_version")
                .and_then(Value::as_str)
            {
                body.push_str(&format!("- Installed version: `{installed_version}`\n"));
            }
            if let Some(candidate_version) = package_metadata
                .get("candidate_version")
                .and_then(Value::as_str)
            {
                body.push_str(&format!("- Candidate version: `{candidate_version}`\n"));
            }
            if let Some(report_url) = package_metadata.get("report_url").and_then(Value::as_str) {
                body.push_str(&format!("- Suggested report URL: `{report_url}`\n"));
            }
        }
    }
    if let Some(summary) = related_desktop_summary
        .get("summary")
        .and_then(Value::as_str)
    {
        body.push_str("\n## Correlated Desktop Signals\n\n");
        body.push_str(summary);
        body.push_str("\n\n");
        if let Some(apps) = related_desktop_summary
            .get("affected_apps")
            .and_then(Value::as_array)
        {
            let apps = apps.iter().filter_map(Value::as_str).collect::<Vec<_>>();
            if !apps.is_empty() {
                body.push_str(&format!("- Affected apps: `{}`\n", apps.join(", ")));
            }
        }
        if let Some(marker_count) = related_desktop_summary
            .get("marker_match_count")
            .and_then(Value::as_u64)
        {
            body.push_str(&format!(
                "- Matching desktop warning records: `{marker_count}`\n"
            ));
        }
        if let Some(crash_count) = related_desktop_summary
            .get("crash_count")
            .and_then(Value::as_u64)
            .filter(|count| *count > 0)
        {
            body.push_str(&format!("- Matched crash records: `{crash_count}`\n"));
        }
    }

    if related.is_empty() {
        body.push_str("\n## Related Local Evidence\n\n");
        body.push_str("Fixer did not find any strong local matches for this complaint yet.\n\n");
        body.push_str("## Suggested Next Steps\n\n");
        if desktop_diagnosis.get("summary").is_some() {
            body.push_str("1. Reproduce the launch failure while `fixerd` is running so Fixer can catch a matching crash or warning.\n");
            body.push_str("2. Run `fixer collect` immediately after the failure, then check `fixer crashes` and `fixer warnings` for fresh Qt, Mesa, Wayland, or compositor evidence.\n");
            body.push_str("3. If this looks Wayland-specific, retest once under X11 if available, or note explicitly that it only fails on Wayland.\n");
            body.push_str("4. Re-run `fixer complain` and paste the exact command, package version, and any new stderr or journal excerpts.\n");
        } else {
            body.push_str("1. Reproduce the issue while `fixerd` is running.\n");
            body.push_str("2. Run `fixer collect` again right after reproduction.\n");
            body.push_str(
                "3. Check `fixer crashes`, `fixer warnings`, and `fixer hotspots` for new evidence.\n",
            );
            body.push_str("4. Re-run `fixer complain` with more concrete wording such as package names, commands, or symptoms.\n");
        }
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
        if related_desktop_summary.get("summary").is_some() {
            body.push_str(&format!(
                "{step}. Treat repeated EGL or Qt startup warnings across multiple apps as a shared graphics-session problem first, and compare KWin, portal, and GPU-driver state before blaming a single application.\n"
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

fn complaint_visibility_summary(state: &str) -> (&'static str, &'static str) {
    if state == "local-only" {
        (
            "private to this machine",
            "not eligible for sync until you opt in",
        )
    } else {
        ("local triage first", "eligible for sync on next upload")
    }
}

fn diagnose_desktop_app_failure(complaint_text: &str, system: &Value) -> Value {
    let lower = complaint_text.to_ascii_lowercase();
    let marker_specs = [
        ("libegl", "libEGL"),
        ("mesa-loader", "MESA-LOADER"),
        ("qthreadstorage", "QThreadStorage"),
        ("qt.qpa", "qt.qpa"),
        ("wayland", "Wayland"),
        ("wayland_display", "WAYLAND_DISPLAY"),
        ("drm", "DRM"),
        ("gbm", "GBM"),
        ("egl", "EGL"),
    ];
    let markers = marker_specs
        .into_iter()
        .filter_map(|(needle, label)| lower.contains(needle).then_some(label.to_string()))
        .collect::<BTreeSet<_>>();
    let app_specs = [
        ("spectacle", "spectacle", "spectacle"),
        ("plasmashell", "plasmashell", "plasma-workspace"),
        ("kwin_wayland", "kwin_wayland", "kwin-wayland"),
        ("kwin-wayland", "kwin_wayland", "kwin-wayland"),
        ("kwin_x11", "kwin_x11", "kwin-x11"),
        ("kwin-x11", "kwin_x11", "kwin-x11"),
        ("pipewire", "pipewire", "pipewire"),
        (
            "xdg-desktop-portal",
            "xdg-desktop-portal",
            "xdg-desktop-portal",
        ),
        ("qt6", "qt6", "qt6-base"),
        ("mesa", "mesa", "mesa-utils"),
    ];
    let app_match = app_specs
        .into_iter()
        .find(|(needle, _, _)| lower.contains(needle));
    let app_name = app_match.map(|(_, app_name, _)| app_name.to_string());
    let package_name = app_match.map(|(_, _, package_name)| package_name.to_string());

    let mut suspected_subsystems = BTreeSet::new();
    if lower.contains("libegl")
        || lower.contains("mesa-loader")
        || lower.contains("egl")
        || lower.contains("drm")
        || lower.contains("gbm")
    {
        suspected_subsystems.insert("graphics stack".to_string());
    }
    if lower.contains("wayland")
        || system
            .get("session_type")
            .and_then(Value::as_str)
            .is_some_and(|value| value.eq_ignore_ascii_case("wayland"))
        || system
            .get("wayland_display")
            .and_then(Value::as_str)
            .is_some()
    {
        suspected_subsystems.insert("wayland session".to_string());
    }
    if lower.contains("qthreadstorage")
        || lower.contains("qt.qpa")
        || lower.contains("qt")
        || app_name.as_deref() == Some("spectacle")
    {
        suspected_subsystems.insert("qt desktop app".to_string());
    }
    if lower.contains("portal") || lower.contains("screen") || lower.contains("screenshot") {
        suspected_subsystems.insert("desktop portal or capture path".to_string());
    }

    if app_name.is_none() && markers.is_empty() && suspected_subsystems.is_empty() {
        return Value::Null;
    }

    let session_hint = if lower.contains("wayland")
        || system
            .get("session_type")
            .and_then(Value::as_str)
            .is_some_and(|value| value.eq_ignore_ascii_case("wayland"))
    {
        Some("Wayland".to_string())
    } else if lower.contains("x11")
        || system
            .get("session_type")
            .and_then(Value::as_str)
            .is_some_and(|value| value.eq_ignore_ascii_case("x11"))
    {
        Some("X11".to_string())
    } else {
        None
    };
    let package_metadata = package_name
        .as_deref()
        .and_then(|name| resolve_installed_package_metadata(name).ok())
        .map(|metadata| json!(metadata))
        .unwrap_or(Value::Null);
    let target = app_name
        .clone()
        .unwrap_or_else(|| "the affected app".to_string());
    let summary = if suspected_subsystems.contains("graphics stack")
        && suspected_subsystems.contains("wayland session")
    {
        format!(
            "The complaint text looks like a desktop-app launch failure in `{target}` with Wayland and graphics-stack markers. This could be a Wayland, Mesa, compositor, or Qt integration issue rather than a Fixer-local problem."
        )
    } else if suspected_subsystems.contains("graphics stack") {
        format!(
            "The complaint text looks like `{target}` is failing in the local graphics stack. The pasted stderr mentions EGL or Mesa loader problems, which often point at Mesa, the compositor, or a driver mismatch."
        )
    } else {
        format!(
            "The complaint text looks like `{target}` is failing during desktop-app startup. The pasted markers suggest a Qt or session-integration issue worth checking in local crashes, warnings, and package metadata."
        )
    };

    json!({
        "app_name": app_name,
        "package_name": package_name,
        "summary": summary,
        "session_hint": session_hint,
        "markers": markers.into_iter().collect::<Vec<_>>(),
        "suspected_subsystems": suspected_subsystems.into_iter().collect::<Vec<_>>(),
        "package_metadata": package_metadata,
    })
}

fn summarize_related_desktop_signals(related: &[SharedOpportunity]) -> Value {
    let marker_needles = [
        "libegl",
        "mesa-loader",
        "qthreadstorage",
        "qt.qpa",
        "wayland",
    ];
    let mut affected_apps = BTreeSet::new();
    let mut marker_match_count = 0u64;
    let mut crash_count = 0u64;

    for item in related {
        let haystack = format!(
            "{}\n{}\n{}",
            item.finding.title, item.finding.summary, item.finding.details
        )
        .to_ascii_lowercase();
        if marker_needles
            .iter()
            .any(|needle| haystack.contains(needle))
        {
            marker_match_count += 1;
            if item.finding.kind == "crash" {
                crash_count += 1;
            }
            if let Some(name) = item
                .finding
                .artifact_name
                .as_deref()
                .or(item.finding.package_name.as_deref())
                .or_else(|| {
                    item.opportunity
                        .evidence
                        .get("package_name")
                        .and_then(Value::as_str)
                })
            {
                affected_apps.insert(name.to_string());
            }
        }
    }

    if marker_match_count == 0 {
        return Value::Null;
    }

    let summary = if affected_apps.len() >= 2 {
        format!(
            "Fixer found the same EGL, Mesa, Qt, or Wayland startup markers in {} related opportunities across multiple apps. That pattern usually points at the current desktop session, compositor, portal, or graphics stack rather than a single app-specific bug.",
            marker_match_count
        )
    } else if crash_count > 0 {
        format!(
            "Fixer found matching desktop startup markers alongside {} related crash record(s). That combination suggests a shared Qt or graphics-session startup failure, not just a one-off warning.",
            crash_count
        )
    } else {
        format!(
            "Fixer found {} related warning record(s) with the same desktop startup markers, which is enough to suspect a shared session or graphics-stack issue.",
            marker_match_count
        )
    };

    json!({
        "summary": summary,
        "affected_apps": affected_apps.into_iter().collect::<Vec<_>>(),
        "marker_match_count": marker_match_count,
        "crash_count": crash_count,
    })
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
        "session_type": std::env::var("XDG_SESSION_TYPE").ok(),
        "wayland_display": std::env::var("WAYLAND_DISPLAY").ok(),
        "display": std::env::var("DISPLAY").ok(),
        "current_desktop": std::env::var("XDG_CURRENT_DESKTOP")
            .ok()
            .or_else(|| std::env::var("DESKTOP_SESSION").ok()),
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
        build_compact_patch_retry_prompt, classify_codex_failure, diagnose_desktop_app_failure,
        extract_git_add_paths_from_response, filter_generated_public_diff_blocks,
        initialize_workspace_git_baseline, is_generated_public_diff_path,
        load_published_codex_session, parse_review_verdict, pg_amcheck_command,
        prepare_codex_job_with_prior_patch, primary_model_rate_limit_active,
        remember_primary_model_rate_limit, render_complaint_plan, render_external_bug_report,
        render_local_remediation_report, render_local_remediation_sql,
        render_process_investigation_report, render_public_session_git_diff,
        sanitize_command_line_for_report, should_retry_after_compaction_failure,
        should_use_spark_for_weak_weekly_budget, suggested_report_destination,
        summarize_related_desktop_signals,
    };
    use crate::config::FixerConfig;
    use crate::models::{
        CodexJobStatus, FindingRecord, InstalledPackageMetadata, OpportunityRecord, PatchAttempt,
        PreparedWorkspace, SharedOpportunity,
    };
    use serde_json::{Value, json};
    use std::path::{Path, PathBuf};

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
    fn oom_kill_investigation_reports_explain_kernel_victim_selection() {
        let opportunity = OpportunityRecord {
            id: 9,
            finding_id: 9,
            kind: "investigation".to_string(),
            title: "OOM kill investigation for element-desktop".to_string(),
            score: 108,
            state: "open".to_string(),
            summary: "element-desktop was killed by the kernel OOM killer.".to_string(),
            evidence: json!({
                "package_name": "element-desktop",
                "details": {
                    "subsystem": "oom-kill",
                    "profile_target": { "name": "element-desktop" },
                    "pid": 2415866,
                    "loop_classification": "kernel-oom-kill",
                    "loop_confidence": 1.0,
                    "loop_explanation": "The kernel OOM killer explicitly selected and terminated the process.",
                    "invoker": "MainThread",
                    "task_memcg": "/user.slice/user-1000.slice/user@1000.service/app.slice/app-element\\x2ddesktop@1cf7c2c7954847c9a04e1e68b4e8e95b.service",
                    "total_vm_kb": 1464797676u64,
                    "anon_rss_kb": 204948u64,
                    "file_rss_kb": 164u64,
                    "shmem_rss_kb": 15408u64,
                    "oom_score_adj": 300
                }
            }),
            repo_root: None,
            ecosystem: None,
            created_at: "2026-03-29T00:00:00Z".to_string(),
            updated_at: "2026-03-29T00:00:00Z".to_string(),
        };
        let system = json!({
            "os_pretty_name": "Debian GNU/Linux trixie/sid",
            "kernel": "Linux 6.19.8+deb14-amd64"
        });
        let rendered = render_process_investigation_report(
            &opportunity,
            None,
            &system,
            Path::new("/tmp/evidence.json"),
            Some("could not acquire source package automatically"),
        );
        assert!(rendered.contains("OOM Kill Investigation Report"));
        assert!(rendered.contains("Why Fixer Believes This Was an OOM Kill"));
        assert!(rendered.contains("Anonymous RSS at kill time"));
        assert!(rendered.contains("MainThread"));
        assert!(rendered.contains("journalctl -k -g 'Out of memory|Killed process|oom-kill'"));
    }

    #[test]
    fn desktop_resume_investigation_reports_explain_disappearing_desktop() {
        let opportunity = OpportunityRecord {
            id: 10,
            finding_id: 10,
            kind: "investigation".to_string(),
            title: "Desktop resume failure investigation for radeon X11 desktop".to_string(),
            score: 109,
            state: "open".to_string(),
            summary: "After suspend/resume, radeon X11 desktop failed: Xorg, kwin_x11 crashed after GPU/display errors, and sddm restarted the display stack.".to_string(),
            evidence: json!({
                "package_name": "linux-image-6.19.8+deb14-amd64",
                "details": {
                    "subsystem": "desktop-resume",
                    "profile_target": { "name": "radeon X11 desktop" },
                    "loop_classification": "resume-display-failure",
                    "loop_confidence": 0.99,
                    "loop_explanation": "Fixer correlated suspend/resume timing with graphics stack errors, desktop-process crashes, and display-manager restart attempts.",
                    "driver": "radeon",
                    "session_type": "x11",
                    "display_manager": "sddm",
                    "crashed_processes": ["Xorg", "kwin_x11"],
                    "gpu_error_lines": [
                        "Mar 30 01:38:57 tinycat kernel: radeon 0000:01:05.0: ring 0 stalled for more than 10240msec"
                    ],
                    "session_error_lines": [
                        "Mar 30 01:39:00 tinycat sddm[829]: Failed to read display number from pipe"
                    ],
                    "suspend_line": "Mar 30 00:41:40 tinycat kernel: PM: suspend entry (deep)",
                    "resume_line": "Mar 30 01:38:58 tinycat kernel: PM: suspend exit",
                    "likely_external_root_cause": true
                }
            }),
            repo_root: None,
            ecosystem: None,
            created_at: "2026-03-30T01:38:58Z".to_string(),
            updated_at: "2026-03-30T01:38:58Z".to_string(),
        };
        let system = json!({
            "os_pretty_name": "Debian GNU/Linux trixie/sid",
            "kernel": "Linux 6.19.8+deb14-amd64"
        });
        let rendered = render_process_investigation_report(
            &opportunity,
            None,
            &system,
            Path::new("/tmp/evidence.json"),
            None,
        );
        assert!(rendered.contains("Desktop Resume Failure Investigation Report"));
        assert!(rendered.contains("Why Fixer Believes Resume Broke The Desktop"));
        assert!(rendered.contains("Xorg, kwin_x11"));
        assert!(rendered.contains("Graphics Stack Errors"));
        assert!(rendered.contains("display-manager"));
        assert!(rendered.contains("kernel, Mesa, Xorg-driver, or compositor investigation"));
    }

    #[test]
    fn sddm_greeter_reports_explain_nss_compat_mismatch() {
        let opportunity = OpportunityRecord {
            id: 12,
            finding_id: 12,
            kind: "investigation".to_string(),
            title: "Desktop resume failure investigation for nvidia sddm greeter".to_string(),
            score: 120,
            state: "open".to_string(),
            summary: "sddm-greeter-qt6 crashed while resolving account data through NSS, and sddm kept restarting before the login prompt appeared.".to_string(),
            evidence: json!({
                "package_name": "nvidia-driver",
                "details": {
                    "subsystem": "desktop-resume",
                    "profile_target": { "name": "nvidia sddm greeter" },
                    "loop_classification": "sddm-greeter-nss-compat-crash",
                    "loop_confidence": 0.99,
                    "loop_explanation": "sddm-greeter-qt6 crashed while resolving account data through NSS, and sddm kept restarting before the login prompt appeared.",
                    "driver": "nvidia",
                    "session_type": "x11",
                    "display_manager": "sddm",
                    "issue_variant": "sddm-greeter-nss-compat-crash",
                    "suspected_root_cause": "NSS compat lookup mismatch",
                    "crashed_processes": ["sddm-greeter-qt6"],
                    "gpu_error_lines": [
                        "Apr 02 22:16:03 blackcat kernel: sddm-greeter-qt6[16832]: segfault at 0 ip 00007f5d3d113abc sp 00007ffd4e4b1cb0 error 4 in libnvidia-tls.so.555.58.02[7f5d3d112000+4000]"
                    ],
                    "session_error_lines": [
                        "Apr 02 22:16:03 blackcat sddm[15118]: Greeter stopped. SDDM::Auth::HelperExitStatus(11)"
                    ],
                    "root_cause_lines": [
                        "Apr 02 22:16:04 blackcat coredumpctl[17000]: #4  0x00007f5d3cb1c111 in _nss_compat_getpwnam_r () from /lib/x86_64-linux-gnu/libnss_compat.so.2",
                        "Apr 02 22:16:04 blackcat coredumpctl[17000]: passwd: compat systemd"
                    ],
                    "resume_line": "No suspend marker captured; greeter failed during display-manager startup.",
                    "likely_external_root_cause": true
                }
            }),
            repo_root: None,
            ecosystem: None,
            created_at: "2026-04-02T00:00:00Z".to_string(),
            updated_at: "2026-04-02T00:00:00Z".to_string(),
        };
        let system = json!({
            "os_pretty_name": "Debian GNU/Linux trixie/sid",
            "kernel": "Linux 6.19.8+deb14-amd64"
        });
        let rendered = render_process_investigation_report(
            &opportunity,
            None,
            &system,
            Path::new("/tmp/evidence.json"),
            None,
        );
        assert!(rendered.contains("greeter startup failure"));
        assert!(rendered.contains("NSS compat lookup mismatch"));
        assert!(rendered.contains("coredumpctl debug"));
        assert!(rendered.contains("/etc/nsswitch.conf"));
        assert!(rendered.contains("HelperExitStatus(11)"));
    }

    #[test]
    fn desktop_graphics_session_reports_explain_shared_wayland_failure() {
        let opportunity = OpportunityRecord {
            id: 13,
            finding_id: 13,
            kind: "investigation".to_string(),
            title: "Desktop graphics/session failure investigation for KDE Wayland desktop".to_string(),
            score: 118,
            state: "open".to_string(),
            summary: "Repeated EGL/Mesa/Qt desktop warnings affected spectacle, dolphin, kate on KDE WAYLAND, with crashes in spectacle.".to_string(),
            evidence: json!({
                "package_name": "kwin-wayland",
                "details": {
                    "subsystem": "desktop-graphics-session",
                    "profile_target": { "name": "KDE Wayland desktop" },
                    "loop_classification": "desktop-graphics-session-failure",
                    "loop_confidence": 0.96,
                    "loop_explanation": "Fixer correlated repeated EGL/Mesa/Qt warnings across multiple desktop apps with compositor or session instability, which points at a shared graphics/session failure rather than one broken app.",
                    "driver": "nvidia",
                    "session_type": "wayland",
                    "current_desktop": "KDE",
                    "compositor": "kwin_wayland",
                    "affected_apps": ["spectacle", "dolphin", "kate"],
                    "crashed_processes": ["spectacle"],
                    "warning_lines": [
                        "Apr 03 14:00:01 nucat spectacle[1144]: libEGL warning: failed to get driver name for fd -1",
                        "Apr 03 14:00:01 nucat spectacle[1144]: libEGL warning: MESA-LOADER: failed to retrieve device information"
                    ],
                    "session_error_lines": [
                        "Apr 03 14:00:03 nucat kwin_wayland_wrapper[1500]: kwin_wayland_drm: The main thread was hanging temporarily!"
                    ],
                    "crash_lines": [
                        "Apr 03 14:00:04 nucat systemd-coredump[1600]: Process 1144 (spectacle) of user 1000 terminated abnormally with signal 6/ABRT, processing..."
                    ],
                    "marker_kinds": ["egl-mesa", "wayland-session", "kwin-compositor", "coredump"],
                    "likely_external_root_cause": true
                }
            }),
            repo_root: None,
            ecosystem: None,
            created_at: "2026-04-03T10:00:00Z".to_string(),
            updated_at: "2026-04-03T10:00:00Z".to_string(),
        };
        let system = json!({
            "os_pretty_name": "Debian GNU/Linux trixie/sid",
            "kernel": "Linux 6.19.8+deb14-amd64"
        });
        let rendered = render_process_investigation_report(
            &opportunity,
            None,
            &system,
            Path::new("/tmp/evidence.json"),
            None,
        );
        assert!(rendered.contains("Desktop Graphics/Session Failure Investigation Report"));
        assert!(rendered.contains("Why Fixer Believes The Desktop Graphics Session Is Breaking"));
        assert!(rendered.contains("Affected apps: `spectacle, dolphin, kate`"));
        assert!(rendered.contains("Diagnostic Markers"));
        assert!(rendered.contains("Desktop Graphics Warnings"));
        assert!(rendered.contains("KWin, Mesa, Qt, portal, or GPU-driver investigation"));
    }

    #[test]
    fn process_investigation_report_mentions_codex_auth_blockers_explicitly() {
        let opportunity = OpportunityRecord {
            id: 11,
            finding_id: 11,
            kind: "investigation".to_string(),
            title: "Runaway CPU investigation for postgres".to_string(),
            score: 106,
            state: "open".to_string(),
            summary: "postgres is stuck in a likely file not found retry loop.".to_string(),
            evidence: json!({
                "package_name": "postgresql-18",
                "details": {
                    "subsystem": "runaway-process",
                    "profile_target": { "name": "postgres" },
                    "loop_classification": "file-not-found-retry",
                    "loop_confidence": 0.84,
                    "loop_explanation": "The trace keeps retrying file lookups that fail with ENOENT.",
                    "top_hot_symbols": ["verify_compact_attribute (3.15% in postgres)"],
                    "top_syscalls": [{ "name": "openat", "count": 1428 }],
                    "process_state": "S (sleeping)",
                    "wchan": "ep_poll"
                }
            }),
            repo_root: None,
            ecosystem: None,
            created_at: "2026-03-30T00:00:00Z".to_string(),
            updated_at: "2026-03-30T00:00:00Z".to_string(),
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
            Some(
                "the current Codex auth lease is paused: auto-paused after 3 recent Codex failures",
            ),
        );
        assert!(rendered.contains("could not start the automated Codex pass"));
        assert!(rendered.contains("Automatic patch attempt blocker"));
        assert!(rendered.contains("Codex auth lease is paused"));
    }

    #[test]
    fn desktop_app_complaint_diagnosis_detects_spectacle_wayland_markers() {
        let system = json!({
            "session_type": "wayland",
            "current_desktop": "KDE",
        });
        let diagnosis = diagnose_desktop_app_failure(
            "spectacle dies on wayland with libEGL warning and MESA-LOADER noise\nQThreadStorage: entry 2 destroyed before end of thread",
            &system,
        );
        assert_eq!(
            diagnosis.get("app_name").and_then(Value::as_str),
            Some("spectacle")
        );
        assert_eq!(
            diagnosis.get("session_hint").and_then(Value::as_str),
            Some("Wayland")
        );
        let items = diagnosis
            .get("suspected_subsystems")
            .and_then(Value::as_array)
            .unwrap();
        assert!(
            items
                .iter()
                .any(|item| item.as_str() == Some("graphics stack"))
        );
    }

    #[test]
    fn complaint_plan_reports_visibility_and_desktop_diagnosis() {
        let opportunity = OpportunityRecord {
            id: 12553,
            finding_id: 12553,
            kind: "complaint".to_string(),
            title: "User complaint: spectacle dies on Wayland".to_string(),
            score: 54,
            state: "open".to_string(),
            summary: "spectacle prints libEGL warnings and quits".to_string(),
            evidence: json!({}),
            repo_root: None,
            ecosystem: None,
            created_at: "2026-04-03T00:00:00Z".to_string(),
            updated_at: "2026-04-03T00:00:00Z".to_string(),
        };
        let system = json!({
            "session_type": "wayland",
            "current_desktop": "KDE",
        });
        let diagnosis = diagnose_desktop_app_failure(
            "spectacle dies on wayland with libEGL warning and MESA-LOADER noise\nQThreadStorage: entry 2 destroyed before end of thread",
            &system,
        );
        let related_summary = summarize_related_desktop_signals(&[]);
        let rendered = render_complaint_plan(
            &opportunity,
            "spectacle dies on wayland with libEGL warning and MESA-LOADER noise",
            None,
            &[],
            &system,
            &diagnosis,
            &related_summary,
            Path::new("/tmp/evidence.json"),
        );
        assert!(rendered.contains("Visibility: local triage first"));
        assert!(rendered.contains("Sharing: eligible for sync on next upload"));
        assert!(rendered.contains("Likely affected app: `spectacle`"));
        assert!(rendered.contains("Wayland"));
    }

    #[test]
    fn related_desktop_signal_summary_detects_cross_app_egl_pattern() {
        let related = vec![
            SharedOpportunity {
                local_opportunity_id: 1,
                opportunity: OpportunityRecord {
                    id: 1,
                    finding_id: 1,
                    kind: "warning".to_string(),
                    title: "System warning".to_string(),
                    score: 64,
                    state: "open".to_string(),
                    summary: "dolphin prints libEGL warnings on startup".to_string(),
                    evidence: json!({"package_name": "dolphin"}),
                    repo_root: None,
                    ecosystem: None,
                    created_at: "now".to_string(),
                    updated_at: "now".to_string(),
                },
                finding: FindingRecord {
                    id: 1,
                    kind: "warning".to_string(),
                    title: "System warning".to_string(),
                    severity: "medium".to_string(),
                    fingerprint: "w1".to_string(),
                    summary: "libEGL warning: MESA-LOADER: failed to retrieve device information"
                        .to_string(),
                    details: json!({"line": "libEGL warning: failed to get driver name for fd -1"}),
                    artifact_name: Some("dolphin".to_string()),
                    artifact_path: None,
                    package_name: Some("dolphin".to_string()),
                    repo_root: None,
                    ecosystem: None,
                    first_seen: "now".to_string(),
                    last_seen: "now".to_string(),
                },
            },
            SharedOpportunity {
                local_opportunity_id: 2,
                opportunity: OpportunityRecord {
                    id: 2,
                    finding_id: 2,
                    kind: "crash".to_string(),
                    title: "Crash with stack trace in spectacle".to_string(),
                    score: 90,
                    state: "open".to_string(),
                    summary: "spectacle aborts during Qt startup".to_string(),
                    evidence: json!({"package_name": "spectacle"}),
                    repo_root: None,
                    ecosystem: None,
                    created_at: "now".to_string(),
                    updated_at: "now".to_string(),
                },
                finding: FindingRecord {
                    id: 2,
                    kind: "crash".to_string(),
                    title: "Crash with stack trace in spectacle".to_string(),
                    severity: "high".to_string(),
                    fingerprint: "c1".to_string(),
                    summary: "QThreadStorage fatal after libEGL warnings".to_string(),
                    details: json!({"line": "QThreadStorage: entry 2 destroyed before end of thread"}),
                    artifact_name: Some("spectacle".to_string()),
                    artifact_path: None,
                    package_name: Some("spectacle".to_string()),
                    repo_root: None,
                    ecosystem: None,
                    first_seen: "now".to_string(),
                    last_seen: "now".to_string(),
                },
            },
        ];
        let summary = summarize_related_desktop_signals(&related);
        assert!(summary.get("summary").is_some());
        assert_eq!(
            summary.get("marker_match_count").and_then(Value::as_u64),
            Some(2)
        );
        let apps = summary
            .get("affected_apps")
            .and_then(Value::as_array)
            .unwrap();
        assert!(apps.iter().any(|item| item.as_str() == Some("dolphin")));
        assert!(apps.iter().any(|item| item.as_str() == Some("spectacle")));
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

    #[test]
    fn review_verdict_parser_accepts_explicit_results() {
        assert!(matches!(
            parse_review_verdict("RESULT: ok\n\nLooks good."),
            Some(super::CodexReviewVerdict::Ok)
        ));
        assert!(matches!(
            parse_review_verdict("Some heading\nRESULT: fix-needed\n\n## Findings"),
            Some(super::CodexReviewVerdict::FixNeeded)
        ));
        assert!(parse_review_verdict("No explicit verdict here").is_none());
    }

    #[test]
    fn published_codex_session_prefers_combined_prompt_when_present() {
        let dir = tempfile::tempdir().unwrap();
        let bundle_dir = dir.path().join("proposal");
        let source_dir = dir.path().join("source");
        let workspace_dir = bundle_dir.join("workspace");
        std::fs::create_dir_all(source_dir.join("src")).unwrap();
        std::fs::create_dir_all(workspace_dir.join("src")).unwrap();
        std::fs::write(bundle_dir.join("prompt.md"), "initial prompt").unwrap();
        std::fs::write(
            bundle_dir.join("published-prompt.md"),
            "## Patch Pass\n\ninitial prompt\n\n## Review Pass 1\n\nreview prompt",
        )
        .unwrap();
        std::fs::write(bundle_dir.join("codex-output.txt"), "combined response").unwrap();
        std::fs::write(source_dir.join("src/file.c"), "old\n").unwrap();
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

        assert!(prompt.contains("## Review Pass 1"));
        assert!(!prompt.contains("initial prompt\ninitial prompt"));
    }

    #[test]
    fn published_codex_session_includes_model_metadata_from_status() {
        let dir = tempfile::tempdir().unwrap();
        let bundle_dir = dir.path().join("proposal");
        let source_dir = dir.path().join("source");
        let workspace_dir = bundle_dir.join("workspace");
        std::fs::create_dir_all(source_dir.join("src")).unwrap();
        std::fs::create_dir_all(workspace_dir.join("src")).unwrap();
        std::fs::write(bundle_dir.join("prompt.md"), "initial prompt").unwrap();
        std::fs::write(bundle_dir.join("codex-output.txt"), "combined response").unwrap();
        std::fs::write(source_dir.join("src/file.c"), "old\n").unwrap();
        std::fs::write(workspace_dir.join("src/file.c"), "new\n").unwrap();
        std::fs::write(
            bundle_dir.join("status.json"),
            serde_json::to_vec_pretty(&CodexJobStatus {
                job_id: "job-1".to_string(),
                state: "ready".to_string(),
                started_at: "2026-03-30T00:00:00Z".to_string(),
                finished_at: "2026-03-30T00:01:00Z".to_string(),
                output_path: Some(bundle_dir.join("codex-output.txt")),
                selected_model: Some("gpt-5.3-codex-spark".to_string()),
                models_used: vec!["gpt-5.4".to_string(), "gpt-5.3-codex-spark".to_string()],
                rate_limit_fallback_used: true,
                failure_stage: None,
                error: None,
                failure_kind: None,
                exit_status: None,
                last_stderr_excerpt: None,
                review_failure_category: None,
            })
            .unwrap(),
        )
        .unwrap();
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
        assert_eq!(
            published.get("model").and_then(Value::as_str),
            Some("gpt-5.3-codex-spark")
        );
        assert_eq!(
            published
                .get("models_used")
                .and_then(Value::as_array)
                .map(|items| items.len()),
            Some(2)
        );
        assert_eq!(
            published
                .get("rate_limit_fallback_used")
                .and_then(Value::as_bool),
            Some(true)
        );
    }

    #[test]
    fn generated_public_diff_paths_are_filtered() {
        assert!(is_generated_public_diff_path(".deps/Action.Po"));
        assert!(is_generated_public_diff_path("linux/.deps/ProcessTable.Po"));
        assert!(is_generated_public_diff_path("Makefile"));
        assert!(!is_generated_public_diff_path("linux/LinuxProcessTable.c"));
    }

    #[test]
    fn public_diff_filter_keeps_source_changes_and_drops_build_artifacts() {
        let diff = "\
--- a/.deps/Action.Po\n\
+++ b/.deps/Action.Po\n\
@@ -0,0 +1 @@\n\
+generated\n\
--- a/linux/LinuxProcess.h\n\
+++ b/linux/LinuxProcess.h\n\
@@ -1,2 +1,3 @@\n\
 struct LinuxProcess {\n\
+   uint64_t last_deleted_lib_calctime;\n\
 };\n";

        let filtered = filter_generated_public_diff_blocks(diff);

        assert!(!filtered.contains(".deps/Action.Po"));
        assert!(filtered.contains("linux/LinuxProcess.h"));
        assert!(filtered.contains("last_deleted_lib_calctime"));
    }

    #[test]
    fn extracts_git_add_paths_from_latest_patch_pass() {
        let response = "\
## Patch Pass

Subject: htop: improve maps scan scheduling

## Commit Message
Example.

## Issue Connection
Example.

## Git Add Paths
- linux/LinuxProcess.h
- linux/LinuxProcessTable.c

## Validation
- not run

## Review Pass 1

RESULT: ok
";

        let paths = extract_git_add_paths_from_response(response);

        assert_eq!(
            paths,
            vec![
                "- linux/LinuxProcess.h".to_string(),
                "- linux/LinuxProcessTable.c".to_string()
            ]
        );
    }

    #[test]
    fn git_backed_public_diff_ignores_untracked_build_artifacts() {
        let dir = tempfile::tempdir().unwrap();
        let workspace = dir.path().join("workspace");
        std::fs::create_dir_all(workspace.join("linux")).unwrap();
        std::fs::create_dir_all(workspace.join(".deps")).unwrap();
        std::fs::write(
            workspace.join("linux/LinuxProcessTable.c"),
            "static int maps = 1;\n",
        )
        .unwrap();
        initialize_workspace_git_baseline(&workspace).unwrap();
        std::fs::write(
            workspace.join("linux/LinuxProcessTable.c"),
            "static int maps = 2;\n",
        )
        .unwrap();
        std::fs::write(workspace.join(".deps/Action.Po"), "generated\n").unwrap();

        let diff = render_public_session_git_diff(&workspace, &[])
            .unwrap()
            .unwrap();

        assert!(diff.contains("linux/LinuxProcessTable.c"));
        assert!(!diff.contains(".deps/Action.Po"));
    }

    #[test]
    fn git_backed_public_diff_includes_intended_new_files() {
        let dir = tempfile::tempdir().unwrap();
        let workspace = dir.path().join("workspace");
        std::fs::create_dir_all(workspace.join("src")).unwrap();
        std::fs::write(workspace.join("src/existing.c"), "old\n").unwrap();
        initialize_workspace_git_baseline(&workspace).unwrap();
        std::fs::write(workspace.join("src/new.c"), "new file\n").unwrap();
        std::fs::write(workspace.join(".deps-temp"), "generated\n").unwrap();

        let diff = render_public_session_git_diff(&workspace, &["src/new.c".to_string()])
            .unwrap()
            .unwrap();

        assert!(diff.contains("src/new.c"));
        assert!(!diff.contains(".deps-temp"));
    }

    #[test]
    fn classify_codex_failure_detects_rate_limit_signals() {
        assert_eq!(
            classify_codex_failure("HTTP 429 Too Many Requests: rate limit exceeded"),
            "rate-limit"
        );
        assert_eq!(
            classify_codex_failure("usage limit reached for this model"),
            "rate-limit"
        );
        assert_eq!(
            classify_codex_failure("Request failed with error code rate_limit_exceeded"),
            "rate-limit"
        );
        assert_eq!(
            classify_codex_failure("OpenAI usage blocked by x-ratelimit-limit"),
            "rate-limit"
        );
    }

    #[test]
    fn detects_compaction_failures_that_should_retry_from_fresh_context() {
        assert!(should_retry_after_compaction_failure(
            "ERROR codex_core::compact_remote: remote compaction failed ... high demand"
        ));
        assert!(should_retry_after_compaction_failure(
            "remote compaction failed because context window was exceeded"
        ));
        assert!(!should_retry_after_compaction_failure(
            "HTTP 429 Too Many Requests: rate limit exceeded"
        ));
    }

    #[test]
    fn compact_patch_retry_prompt_keeps_fresh_context_note() {
        let prompt = build_compact_patch_retry_prompt("base patch prompt");
        assert!(prompt.contains("base patch prompt"));
        assert!(prompt.contains("fresh context"));
        assert!(prompt.contains("remote compaction"));
    }

    #[test]
    fn detects_weekly_rate_limit_headroom_threshold() {
        let config = FixerConfig::default();
        assert!(should_use_spark_for_weak_weekly_budget(
            &config,
            "weekly remaining 15%",
            20.0
        ));
        assert!(!should_use_spark_for_weak_weekly_budget(
            &config,
            "weekly remaining: 35%",
            20.0
        ));
        assert!(should_use_spark_for_weak_weekly_budget(
            &config,
            "per week usage: remaining 18/100",
            20.0
        ));
        assert!(!should_use_spark_for_weak_weekly_budget(
            &config,
            "per week usage: remaining 80/100",
            20.0
        ));
    }

    #[test]
    fn detects_weekly_rate_limit_headroom_from_status_json_payload() {
        let config = FixerConfig::default();
        let low_weekly_status = r#"{
            "status": {
                "requests": {
                    "remaining": 15,
                    "limit": 100,
                    "duration": "7d"
                }
            }
        }"#;
        assert!(should_use_spark_for_weak_weekly_budget(
            &config,
            low_weekly_status,
            20.0
        ));

        let low_weekly_percent_status = r#"{
            "models": [
                { "name": "gpt-5.4", "remaining_percent": 12, "window": "weekly" }
            ]
        }"#;
        assert!(should_use_spark_for_weak_weekly_budget(
            &config,
            low_weekly_percent_status,
            20.0
        ));

        let safe_weekly_status = r#"{
            "status": {
                "requests": {
                    "remaining": 80,
                    "limit": 100,
                    "period": "daily"
                }
            }
        }"#;
        assert!(!should_use_spark_for_weak_weekly_budget(
            &config,
            safe_weekly_status,
            20.0
        ));
    }

    #[test]
    fn remembers_primary_model_rate_limit_for_spark_preference() {
        let dir = tempfile::tempdir().unwrap();
        let mut config = FixerConfig::default();
        config.service.state_dir = dir.path().join("state");
        config.patch.model = Some("gpt-5.4".to_string());
        config.patch.spark_model = Some("gpt-5.3-codex-spark".to_string());
        config.patch.rate_limit_cooldown_seconds = 3600;

        assert!(!primary_model_rate_limit_active(&config));
        remember_primary_model_rate_limit(&config).unwrap();
        assert!(primary_model_rate_limit_active(&config));
    }

    #[test]
    fn proposal_bundle_pruning_keeps_only_recent_bundles_per_opportunity() {
        let dir = tempfile::tempdir().unwrap();
        let proposals_root = dir.path().join("proposals");
        std::fs::create_dir_all(&proposals_root).unwrap();

        for suffix in ["00", "01", "02", "03"] {
            let bundle = proposals_root.join(format!("42-2026-03-30T00-00-{suffix}Z"));
            std::fs::create_dir_all(&bundle).unwrap();
            std::fs::write(bundle.join("marker.txt"), suffix).unwrap();
            std::thread::sleep(std::time::Duration::from_millis(20));
        }

        super::prune_proposal_bundles(&proposals_root, 7, 2).unwrap();

        let mut remaining = std::fs::read_dir(&proposals_root)
            .unwrap()
            .map(|entry| entry.unwrap().file_name().into_string().unwrap())
            .collect::<Vec<_>>();
        remaining.sort();
        assert_eq!(
            remaining,
            vec![
                "42-2026-03-30T00-00-02Z".to_string(),
                "42-2026-03-30T00-00-03Z".to_string()
            ]
        );
    }

    #[test]
    fn create_bundle_dir_falls_back_when_state_dir_is_not_writable() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().unwrap();
        let mut config = FixerConfig::default();
        let locked_state_dir = dir.path().join("locked-state");
        std::fs::create_dir_all(&locked_state_dir).unwrap();
        std::fs::set_permissions(&locked_state_dir, std::fs::Permissions::from_mode(0o555))
            .unwrap();
        config.service.state_dir = locked_state_dir;

        let bundle_dir = super::create_bundle_dir(&config, 42).unwrap();

        assert!(bundle_dir.starts_with(std::env::temp_dir().join("fixer-proposals")));
    }

    #[test]
    fn prior_best_patch_context_is_written_into_worker_prompt() {
        let dir = tempfile::tempdir().unwrap();
        let workspace_root = dir.path().join("source");
        std::fs::create_dir_all(workspace_root.join("src")).unwrap();
        std::fs::write(workspace_root.join("src/file.c"), "old\n").unwrap();

        let mut config = FixerConfig::default();
        config.service.state_dir = dir.path().join("state");

        let opportunity = OpportunityRecord {
            id: 42,
            finding_id: 42,
            kind: "investigation".to_string(),
            title: "Runaway CPU investigation for postgres".to_string(),
            score: 110,
            state: "open".to_string(),
            summary: "postgres is stuck in a likely file not found retry loop.".to_string(),
            evidence: json!({}),
            repo_root: None,
            ecosystem: Some("debian".to_string()),
            created_at: "2026-03-29T00:00:00Z".to_string(),
            updated_at: "2026-03-29T00:00:00Z".to_string(),
        };
        let workspace = PreparedWorkspace {
            repo_root: workspace_root.clone(),
            ecosystem: Some("debian".to_string()),
            source_kind: "debian-source".to_string(),
            package_name: Some("postgresql-18".to_string()),
            source_package: Some("postgresql-18".to_string()),
            homepage: None,
            acquisition_note: "prepared from apt source".to_string(),
        };
        let prior_patch = PatchAttempt {
            cluster_id: "issue-1".to_string(),
            install_id: "install-1".to_string(),
            outcome: "patch".to_string(),
            state: "ready".to_string(),
            summary: "Legacy patch proposal created locally.".to_string(),
            bundle_path: None,
            output_path: None,
            validation_status: Some("ready".to_string()),
            details: json!({
                "worker_fixer_version": "0.18.0",
                "published_session": {
                    "prompt": "old prompt",
                    "response": "old response",
                    "diff": "--- a/src/file.c\n+++ b/src/file.c\n@@\n-goto fail;\n+return false;\n",
                }
            }),
            created_at: "2026-03-29T00:00:00Z".to_string(),
        };

        let job = prepare_codex_job_with_prior_patch(
            &config,
            &opportunity,
            &workspace,
            Some(&prior_patch),
            "kom",
            false,
        )
        .unwrap();

        let prompt = std::fs::read_to_string(&job.prompt_path).unwrap();
        assert!(prompt.contains("A previous Fixer patch attempt already exists"));
        assert!(
            prompt.contains("older or legacy Fixer version") || prompt.contains("Fixer `0.18.0`")
        );
        assert!(prompt.contains("prior-best.patch"));
        assert!(prompt.contains("prior-best-session.md"));
        assert!(job.bundle_dir.join("prior-best.patch").exists());
        assert!(job.bundle_dir.join("prior-best-session.md").exists());

        let evidence: Value =
            serde_json::from_slice(&std::fs::read(job.bundle_dir.join("evidence.json")).unwrap())
                .unwrap();
        assert_eq!(
            evidence["prior_best_patch"]["fixer_version"].as_str(),
            Some("0.18.0")
        );
        assert_eq!(
            evidence["prior_best_patch"]["patch_path"]
                .as_str()
                .map(PathBuf::from)
                .map(|path| path.file_name().unwrap().to_string_lossy().to_string()),
            Some("prior-best.patch".to_string())
        );
    }

    #[test]
    fn local_metadata_review_accepts_matching_git_add_paths() {
        let response = r#"Subject: Fix htop retry loop

## Commit Message
Keep the retry guard narrow.

## Issue Connection
This keeps htop from spinning when the watched file is missing.

## Git Add Paths
htop.c

## Validation
not run
"#;

        assert!(super::build_local_metadata_review(response, &["htop.c".to_string()]).is_none());
    }

    #[test]
    fn local_metadata_review_flags_git_add_path_drift() {
        let response = r#"Subject: Fix ssh loop

## Commit Message
Handle EINTR.

## Issue Connection
This tightens the main loop.

## Git Add Paths
serverloop.c

## Validation
not run
"#;

        let review = super::build_local_metadata_review(
            response,
            &["packet.c".to_string(), "serverloop.c".to_string()],
        )
        .unwrap();

        assert!(review.starts_with("RESULT: fix-needed"));
        assert!(review.contains("workspace currently changes `packet.c`, `serverloop.c`"));
        assert!(review.contains("Missing from `## Git Add Paths`: `packet.c`."));
    }

    #[test]
    fn generated_workspace_metadata_paths_are_ignored() {
        assert!(super::is_generated_workspace_metadata_path(".codex"));
        assert!(super::is_generated_workspace_metadata_path("./.codex"));
        assert!(super::is_generated_workspace_metadata_path(
            ".codex/session.json"
        ));
        assert_eq!(
            super::sanitize_git_add_paths(&[
                ".codex".to_string(),
                "./.codex/session.json".to_string(),
                "src/pk-spawn.c".to_string()
            ]),
            vec!["src/pk-spawn.c".to_string()]
        );
    }
}
