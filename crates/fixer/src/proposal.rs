use crate::config::FixerConfig;
use crate::models::{
    CodexJobSpec, CodexJobStatus, ComplaintCollectionReport, InstalledPackageMetadata,
    OpportunityRecord, PatchAttempt, PreparedWorkspace, ProposalRecord, SharedOpportunity,
};
use crate::storage::Store;
use crate::util::{command_exists, command_output, now_rfc3339, read_text};
use crate::workspace::resolve_installed_package_metadata;
use anyhow::{Context, Result, anyhow};
use chrono::{DateTime, Duration as ChronoDuration, Utc};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::collections::BTreeMap;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

fn create_bundle_dir(config: &FixerConfig, opportunity_id: i64) -> Result<PathBuf> {
    let proposals_root = config.service.state_dir.join("proposals");
    fs::create_dir_all(&proposals_root)?;
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
                failure_kind: Some(classify_codex_failure(&plan_stage.log)),
                error: Some(plan_stage.error),
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

    let patch_stage = run_codex_stage(
        config,
        &job.workspace.repo_root,
        &job.prompt_path,
        &job.bundle_dir.join("patch-output.txt"),
        "Patch Pass",
        &patch_prompt,
    )?;
    logs.push(render_stage_log(&patch_stage));
    models_used.extend(patch_stage.models_used.clone());
    rate_limit_fallback_used |= patch_stage.rate_limit_fallback_used;
    selected_model = patch_stage.selected_model.clone().or(selected_model);
    transcripts.push(CodexStageTranscript {
        label: patch_stage.label.to_string(),
        prompt: patch_prompt.clone(),
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
            failure_kind: Some(classify_codex_failure(&patch_stage.log)),
            error: Some(patch_stage.error),
        };
        fs::write(
            job.bundle_dir.join("status.json"),
            serde_json::to_vec_pretty(&status)?,
        )?;
        return Ok(status);
    }

    let mut workflow_failure: Option<(String, String)> = None;
    let patch_output_indicates_triage = stage_output_marks_successful_triage(&patch_stage.output);
    let mut current_author_output_path = job.bundle_dir.join("patch-output.txt");
    if config.patch.review_after_patch && !patch_output_indicates_triage {
        let mut refinement_round = 0;
        loop {
            let review_label = format!("Review Pass {}", refinement_round + 1);
            let review_prompt = build_review_prompt(
                &evidence_path,
                &job.workspace,
                source_workspace_root.as_deref(),
                &current_author_output_path,
                refinement_round,
            );
            let review_prompt_path = job
                .bundle_dir
                .join(format!("review-{}-prompt.md", refinement_round + 1));
            let review_output_path = job
                .bundle_dir
                .join(format!("review-{}-output.txt", refinement_round + 1));
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
                break;
            }
            match parse_review_verdict(&review_stage.output) {
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
                        break;
                    }
                    refinement_round += 1;
                    let refine_label = format!("Refinement Pass {}", refinement_round);
                    let refine_prompt = build_refinement_prompt(
                        &evidence_path,
                        &job.workspace,
                        source_workspace_root.as_deref(),
                        plan_output_path.as_deref(),
                        &current_author_output_path,
                        &review_output_path,
                        refinement_round,
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
        failure_kind: workflow_failure.as_ref().map(|(kind, _)| kind.clone()),
        error: workflow_failure.map(|(_, error)| error),
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
                    "runaway-process" | "stuck-process" | "oom-kill" | "desktop-resume"
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
            .with_context(|| format!("failed to run git {:?} in {}", args, workspace_root.display()))?;
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
) -> Result<Option<String>> {
    let (Some(source_workspace_root), Some(workspace_root)) =
        (source_workspace_root, workspace_root)
    else {
        return Ok(None);
    };
    if !source_workspace_root.exists() || !workspace_root.exists() {
        return Ok(None);
    }

    if let Some(diff) = render_public_session_git_diff(workspace_root)? {
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

fn render_public_session_git_diff(workspace_root: &Path) -> Result<Option<String>> {
    if !workspace_root.join(".git").exists() || !command_exists("git") {
        return Ok(None);
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
    model_used: Option<String>,
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

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
struct CodexModelLimitState {
    primary_model: Option<String>,
    primary_rate_limited_until: Option<String>,
    updated_at: Option<String>,
}

fn configured_primary_model_label(config: &FixerConfig) -> String {
    config
        .patch
        .model
        .clone()
        .unwrap_or_else(|| "codex-default".to_string())
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
    failure_kind: &str,
    attempted_model: Option<&str>,
) -> Option<String> {
    if failure_kind != "rate-limit" || !config.patch.spark_fallback_on_rate_limit {
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
    let mut outcome = run_codex_process(
        config,
        repo_root,
        output_path,
        prompt,
        initial_model.as_deref(),
    )?;
    if let Some(model) = outcome.model_used.clone() {
        models_used.push(model);
    }
    logs.push(render_process_attempt_log(&outcome));
    let mut rate_limit_fallback_used = false;

    let primary_label = configured_primary_model_label(config);
    if !outcome.success {
        let failure_kind = classify_codex_failure(&outcome.log);
        if failure_kind == "rate-limit" {
            let attempted_model = outcome.model_used.as_deref();
            if attempted_model.unwrap_or("codex-default") == primary_label {
                let _ = remember_primary_model_rate_limit(config);
            }
        }
        if let Some(spark_model) =
            should_retry_with_spark(config, &failure_kind, outcome.model_used.as_deref())
        {
            let retry_outcome =
                run_codex_process(config, repo_root, output_path, prompt, Some(&spark_model))?;
            if let Some(model) = retry_outcome.model_used.clone() {
                models_used.push(model);
            }
            logs.push(render_process_attempt_log(&retry_outcome));
            outcome = retry_outcome;
            rate_limit_fallback_used = true;
        }
    } else if outcome.model_used.as_deref() == Some(primary_label.as_str()) {
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
    Ok(CodexStageOutcome {
        label,
        success: outcome.success,
        output,
        log: logs.join("\n\n"),
        error,
        selected_model: outcome.model_used,
        models_used,
        rate_limit_fallback_used,
    })
}

fn render_process_attempt_log(outcome: &CodexProcessOutcome) -> String {
    format!(
        "model: {}\n\n{}",
        outcome.model_used.as_deref().unwrap_or("codex-default"),
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
    let log = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    Ok(CodexProcessOutcome {
        success: output.status.success(),
        log,
        model_used: Some(
            model
                .map(ToString::to_string)
                .unwrap_or_else(|| "codex-default".to_string()),
        ),
    })
}

fn classify_codex_failure(log: &str) -> String {
    let lower = log.to_ascii_lowercase();
    if lower.contains("401 unauthorized") || lower.contains("missing bearer") {
        "auth".to_string()
    } else if lower.contains("rate limit")
        || lower.contains("rate-limit")
        || lower.contains("too many requests")
        || lower.contains("429")
        || lower.contains("quota")
        || lower.contains("usage limit")
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

fn build_review_prompt(
    evidence_path: &Path,
    workspace: &PreparedWorkspace,
    source_workspace_root: Option<&Path>,
    latest_patch_output_path: &Path,
    refinement_round: u32,
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
    format!(
        "You are reviewing a freshly generated fixer patch.\n\nRead the evidence bundle at `{}`. The prepared workspace is `{}` and it was acquired via `{}`. {}{} The latest author response is at `{}`. Inspect the current code and changed paths like a strict code reviewer. Focus on correctness, regressions, maintainability, awkward control flow such as avoidable `goto`, missing validation, weak or non-gittable commit message text, and explanations that fail to connect the observed issue evidence to the code change.\n\nDo not apply code changes in this pass.\n\nReturn a short markdown review report. The first non-empty line must be exactly one of:\n\nRESULT: ok\nRESULT: fix-needed\n\nIf you choose `RESULT: fix-needed`, add a `## Findings` section with concrete, actionable items.",
        evidence_path.display(),
        workspace.repo_root.display(),
        workspace.source_kind,
        round_hint,
        source_hint,
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
    format!(
        "You are refining a fixer patch after an explicit code review.\n\nRead the evidence bundle at `{}`. The prepared workspace is `{}` and it was acquired via `{}`. Read the latest author response at `{}`. Read the review report at `{}`. This is refinement round {}.{}{} Address the review findings with the smallest reasonable follow-up changes. Keep the patch upstream-friendly, avoid awkward control flow when a simpler structure will do, keep the final response gittable, run relevant tests if available, and summarize which review findings you addressed.\n\n{}",
        evidence_path.display(),
        workspace.repo_root.display(),
        workspace.source_kind,
        latest_patch_output_path.display(),
        review_output_path.display(),
        refinement_round,
        source_hint,
        plan_hint,
        patch_response_contract(),
    )
}

fn patch_response_contract() -> &'static str {
    "In every authoring pass, your final response must start with `Subject: <single-line git commit subject>` and then include these markdown sections exactly:\n\n## Commit Message\nA short upstream-friendly explanation of what changed and why.\n\n## Issue Connection\nExplain how the code change addresses the observed issue evidence instead of merely paraphrasing the diff.\n\n## Validation\nList the checks you ran, or say clearly that you could not run them."
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
    let classification = details
        .get("loop_classification")
        .and_then(Value::as_str)
        .unwrap_or(if is_stuck_process {
            "unknown-uninterruptible-wait"
        } else if is_desktop_resume {
            "resume-display-failure"
        } else if is_oom_kill {
            "kernel-oom-kill"
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
            "Fixer correlated suspend/resume timing with graphics stack errors, desktop-process crashes, and display-manager restart attempts."
        } else if is_oom_kill {
            "Fixer collected kernel log evidence showing that the OOM killer selected and terminated this process."
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
    if is_stuck_process {
        body.push_str("# Stuck Process Investigation Report\n\n");
    } else if is_desktop_resume {
        body.push_str("# Desktop Resume Failure Investigation Report\n\n");
    } else if is_oom_kill {
        body.push_str("# OOM Kill Investigation Report\n\n");
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
                body.push_str("Fixer diagnosed a suspend/resume display-stack failure, but it could not automatically acquire a patchable graphics or desktop source workspace on this host.\n\n");
                body.push_str(&format!("Workspace acquisition blocker: `{error}`\n\n"));
                body.push_str("Use the diagnosis below to file an upstream or distro bug, or to fetch a source tree manually before retrying `fixer propose-fix <id> --engine codex`.\n\n");
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
                body.push_str("Fixer gathered enough evidence to describe the suspend/resume failure. Review the diagnosis below, then decide whether this looks like a graphics-driver, X11, compositor, or display-manager regression.\n\n");
            } else if is_oom_kill {
                body.push_str("Fixer gathered enough evidence to describe the OOM kill. Review the diagnosis below, then decide whether this points at application memory growth, an unusually heavy workload, or broader system memory pressure.\n\n");
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
        } else {
            body.push_str("\n## Why Fixer Believes It Is Stuck\n\n");
        }
        if is_desktop_resume {
            body.push_str(&format!(
                "- Affected desktop target: `{}`\n- Failure classification: `{}`\n- Confidence: `{:.2}`\n- Explanation: {}\n",
                target_name, classification, confidence, explanation
            ));
        } else {
            body.push_str(&format!(
                "- Target process: `{}`\n- Sampled PID: `{}`\n- Loop classification: `{}`\n- Confidence: `{:.2}`\n- Explanation: {}\n",
                target_name, sampled_pid, classification, confidence, explanation
            ));
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
        if is_desktop_resume {
            if let Some(driver) = details.get("driver").and_then(Value::as_str) {
                body.push_str(&format!("- Graphics driver: `{driver}`\n"));
            }
            if let Some(session_type) = details.get("session_type").and_then(Value::as_str) {
                body.push_str(&format!(
                    "- Session type: `{}`\n",
                    session_type.to_uppercase()
                ));
            }
            if let Some(display_manager) = details.get("display_manager").and_then(Value::as_str) {
                body.push_str(&format!("- Display manager: `{display_manager}`\n"));
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
    if is_desktop_resume {
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
        body.push_str("1. Reproduce one suspend/resume cycle and confirm the journal still shows the same graphics-driver errors right before or right after resume.\n");
        body.push_str("2. Check whether `Xorg`, `kwin_x11`, or the display manager are crashing with the same signals and backtraces.\n");
        body.push_str("3. If you change the kernel, Mesa, Xorg driver, or session type, verify the desktop comes back cleanly after resume and the journal no longer shows the same display-stack failure markers.\n");
    } else if is_oom_kill {
        body.push_str("1. Confirm the kernel is still logging OOM activity with `journalctl -k -g 'Out of memory|Killed process|oom-kill'`.\n");
        body.push_str("2. Check whether the same package or cgroup repeatedly gets selected as the OOM victim under the same workload.\n");
        body.push_str("3. Compare the victim's memory footprint and cgroup context before and after any package, workload, or memory-limit change.\n");
    } else {
        body.push_str("1. Confirm the process still shows sustained CPU time with `systemd-cgtop`, `top`, or `ps -p <pid> -o %cpu,stat,comm`.\n");
        body.push_str("2. Re-run a short syscall sample and confirm the dominant syscalls still match the sequence above.\n");
        body.push_str("3. If you change the package, compare a fresh perf sample and strace excerpt to make sure the loop disappears rather than simply moving elsewhere.\n");
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
            body.push_str("Treat this as the diagnosis half of the pipeline. The evidence currently points at the graphics stack around suspend/resume, so the next action is usually a kernel, Mesa, Xorg-driver, or compositor investigation rather than a narrow package patch.\n");
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
        classify_codex_failure, filter_generated_public_diff_blocks, is_generated_public_diff_path,
        load_published_codex_session, parse_review_verdict, render_public_session_git_diff,
        pg_amcheck_command, prepare_codex_job_with_prior_patch, primary_model_rate_limit_active,
        remember_primary_model_rate_limit, render_external_bug_report,
        initialize_workspace_git_baseline,
        render_local_remediation_report, render_local_remediation_sql,
        render_process_investigation_report, sanitize_command_line_for_report,
        suggested_report_destination,
    };
    use crate::config::FixerConfig;
    use crate::models::{
        CodexJobStatus, InstalledPackageMetadata, OpportunityRecord, PatchAttempt,
        PreparedWorkspace,
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
                error: None,
                failure_kind: None,
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

        let diff = render_public_session_git_diff(&workspace).unwrap().unwrap();

        assert!(diff.contains("linux/LinuxProcessTable.c"));
        assert!(!diff.contains(".deps/Action.Po"));
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
}
