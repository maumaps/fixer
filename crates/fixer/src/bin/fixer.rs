use anyhow::Result;
use clap::{Parser, Subcommand, ValueEnum};
use fixer::app::{App, is_permission_or_readonly_error};
use fixer::config::FixerConfig;
use fixer::models::{FindingRecord, LeaseBudgetPreset, ParticipationMode};
use fixer::proposal;
use std::path::PathBuf;

#[derive(Parser)]
#[command(
    name = "fixer",
    about = "Local evidence engine for Linux maintenance opportunities"
)]
struct Cli {
    #[arg(long, global = true)]
    config: Option<PathBuf>,
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    Collect,
    Status,
    Capabilities,
    Crashes,
    Warnings,
    Hotspots,
    Complain {
        #[arg(long)]
        no_collect: bool,
        #[arg(required = true, num_args = 1.., trailing_var_arg = true)]
        description: Vec<String>,
    },
    Owners,
    Opportunities {
        #[arg(long)]
        state: Option<String>,
    },
    Top {
        #[arg(long, default_value = "binary")]
        kind: TopKind,
    },
    Inspect {
        id: i64,
    },
    Validate {
        id: i64,
    },
    ProposeFix {
        id: i64,
        #[arg(long, default_value = "codex")]
        engine: EngineKind,
    },
    PrepareSubmit {
        id: i64,
    },
    OptIn {
        #[arg(long, default_value = "submitter")]
        mode: OptInMode,
        #[arg(long)]
        richer_evidence: bool,
    },
    OptOut,
    Sync,
    Worker {
        #[command(subcommand)]
        command: WorkerCommands,
    },
    Auth {
        #[command(subcommand)]
        command: AuthCommands,
    },
    Participation,
}

#[derive(Copy, Clone, Debug, ValueEnum)]
enum TopKind {
    Package,
    Repo,
    Binary,
}

#[derive(Copy, Clone, Debug, ValueEnum)]
enum EngineKind {
    Codex,
    Deterministic,
}

#[derive(Copy, Clone, Debug, ValueEnum)]
enum OptInMode {
    LocalOnly,
    Submitter,
    SubmitterWorker,
}

#[derive(Subcommand)]
enum WorkerCommands {
    Run,
}

#[derive(Subcommand)]
enum AuthCommands {
    Lease {
        #[command(subcommand)]
        command: LeaseCommands,
    },
    #[command(hide = true)]
    ExecJob {
        #[arg(long)]
        job: PathBuf,
    },
}

#[derive(Subcommand)]
enum LeaseCommands {
    Bootstrap {
        user: String,
        #[arg(long)]
        enable_linger: bool,
    },
    Grant {
        user: String,
        #[arg(long)]
        ttl: Option<String>,
        #[arg(long)]
        budget: Option<LeaseBudgetKind>,
        #[arg(long)]
        allow_kernel: bool,
    },
    Status,
    Revoke,
}

#[derive(Copy, Clone, Debug, ValueEnum)]
enum LeaseBudgetKind {
    Off,
    Conservative,
    Balanced,
    Aggressive,
}

impl From<LeaseBudgetKind> for LeaseBudgetPreset {
    fn from(value: LeaseBudgetKind) -> Self {
        match value {
            LeaseBudgetKind::Off => LeaseBudgetPreset::Off,
            LeaseBudgetKind::Conservative => LeaseBudgetPreset::Conservative,
            LeaseBudgetKind::Balanced => LeaseBudgetPreset::Balanced,
            LeaseBudgetKind::Aggressive => LeaseBudgetPreset::Aggressive,
        }
    }
}

fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .without_time()
        .init();

    let cli = Cli::parse();
    if let Commands::Auth {
        command: AuthCommands::ExecJob { job },
    } = &cli.command
    {
        let config = FixerConfig::load(cli.config.as_deref())?;
        let job_spec = proposal::load_codex_job(job)?;
        let status = proposal::execute_codex_job(&config, &job_spec)?;
        println!("job_id: {}", status.job_id);
        println!("state: {}", status.state);
        if let Some(path) = status.output_path {
            println!("output_path: {}", path.display());
        }
        if let Some(kind) = status.failure_kind {
            println!("failure_kind: {kind}");
        }
        if let Some(error) = status.error {
            println!("error: {error}");
        }
        return Ok(());
    }
    let app = App::load(cli.config.as_deref())?;

    match cli.command {
        Commands::Collect => {
            let report = app.collect_once()?;
            println!(
                "collected {} capabilities, {} artifacts, {} findings",
                report.capabilities_seen, report.artifacts_seen, report.findings_seen
            );
        }
        Commands::Status => {
            let status = app.store.status()?;
            println!("capabilities: {}", status.capabilities);
            println!("artifacts: {}", status.artifacts);
            println!("findings: {}", status.findings);
            println!("opportunities: {}", status.opportunities);
            println!("proposals: {}", status.proposals);
        }
        Commands::Capabilities => {
            for capability in app.store.list_capabilities()? {
                let state = if capability.available {
                    "available"
                } else {
                    "missing"
                };
                let path = capability
                    .path
                    .map(|x| x.display().to_string())
                    .unwrap_or_else(|| "-".to_string());
                println!(
                    "{:<12} {:<9} {:<30} {}",
                    capability.name,
                    state,
                    path,
                    capability.notes.unwrap_or_default()
                );
            }
        }
        Commands::Crashes => print_findings(app.store.list_findings("crash")?),
        Commands::Warnings => print_findings(app.store.list_findings("warning")?),
        Commands::Hotspots => print_findings(app.store.list_findings("hotspot")?),
        Commands::Complain {
            no_collect,
            description,
        } => {
            let outcome = app.complain(&description.join(" "), !no_collect)?;
            println!("complaint opportunity #{}", outcome.opportunity.id);
            println!("state: {}", outcome.opportunity.state);
            if let Some(report) = outcome.collection_report {
                println!(
                    "collected: {} capabilities, {} artifacts, {} findings",
                    report.capabilities_seen, report.artifacts_seen, report.findings_seen
                );
            } else {
                println!("collected: skipped");
            }
            println!("plan proposal #{}", outcome.proposal.id);
            println!("plan: {}", outcome.proposal.bundle_path.display());
            println!("workspace: {}", outcome.workspace_root.display());
            if outcome.used_overlay {
                println!("workspace mode: local overlay");
            }
            if let Some(path) = outcome.proposal.output_path {
                println!("output: {}", path.display());
            }
            if !outcome.related_opportunity_ids.is_empty() {
                println!(
                    "related opportunities: {}",
                    outcome
                        .related_opportunity_ids
                        .iter()
                        .map(i64::to_string)
                        .collect::<Vec<_>>()
                        .join(", ")
                );
            }
        }
        Commands::Owners => {
            for (name, repo_root, owners) in app.store.list_repo_owners()? {
                println!("{name}");
                println!(
                    "  repo: {}",
                    if repo_root.is_empty() {
                        "(none)"
                    } else {
                        &repo_root
                    }
                );
                println!(
                    "  owners: {}",
                    if owners.is_empty() { "(none)" } else { &owners }
                );
            }
        }
        Commands::Opportunities { state } => {
            for item in app.store.list_opportunities(state.as_deref())? {
                println!(
                    "#{} [{}] score={} state={}",
                    item.id, item.kind, item.score, item.state
                );
                println!("  {}", item.title);
                println!("  {}", item.summary);
                if let Some(repo_root) = item.repo_root {
                    println!("  repo: {}", repo_root.display());
                }
                if let Some(ecosystem) = item.ecosystem {
                    println!("  ecosystem: {ecosystem}");
                }
            }
        }
        Commands::Top { kind } => {
            let kind = match kind {
                TopKind::Package => "package",
                TopKind::Repo => "repo",
                TopKind::Binary => "binary",
            };
            for entry in app.store.list_top(kind)? {
                println!("{:<5} {}", entry.count, entry.group);
            }
        }
        Commands::Inspect { id } => {
            let item = app.store.get_opportunity(id)?;
            println!("opportunity #{}", item.id);
            println!("title: {}", item.title);
            println!("kind: {}", item.kind);
            println!("score: {}", item.score);
            println!("state: {}", item.state);
            println!("summary: {}", item.summary);
            if let Some(repo_root) = item.repo_root {
                println!("repo_root: {}", repo_root.display());
            }
            if let Some(ecosystem) = item.ecosystem {
                println!("ecosystem: {ecosystem}");
            }
            println!(
                "evidence:\n{}",
                serde_json::to_string_pretty(&item.evidence)?
            );
            let validations = app.store.list_validations(id)?;
            if !validations.is_empty() {
                println!("validations:");
                for validation in validations {
                    println!("  [{}] {}", validation.status, validation.command);
                }
            }
        }
        Commands::Validate { id } => {
            for (command, status) in app.validate(id)? {
                println!("[{status}] {command}");
            }
        }
        Commands::ProposeFix { id, engine } => {
            let engine = match engine {
                EngineKind::Codex => "codex",
                EngineKind::Deterministic => "deterministic",
            };
            let proposal = app.propose_fix(id, engine)?;
            println!("proposal #{}", proposal.id);
            println!("state: {}", proposal.state);
            println!("bundle: {}", proposal.bundle_path.display());
            if let Some(path) = proposal.output_path {
                println!("output: {}", path.display());
            }
        }
        Commands::PrepareSubmit { id } => {
            let path = app.prepare_submit(id)?;
            println!("{}", path.display());
        }
        Commands::OptIn {
            mode,
            richer_evidence,
        } => {
            let mode = match mode {
                OptInMode::LocalOnly => ParticipationMode::LocalOnly,
                OptInMode::Submitter => ParticipationMode::Submitter,
                OptInMode::SubmitterWorker => ParticipationMode::SubmitterWorker,
            };
            let snapshot = app.opt_in(mode, richer_evidence).map_err(|e| {
                if is_permission_or_readonly_error(&e) {
                    e.context("(are you superuser? try: sudo fixer opt-in)")
                } else {
                    e
                }
            })?;
            println!("{}", snapshot.policy_text);
            println!();
            println!("install_id: {}", snapshot.identity.install_id);
            println!("server_url: {}", snapshot.server_url);
            println!("mode: {:?}", snapshot.state.mode);
            println!(
                "richer_evidence_allowed: {}",
                snapshot.state.richer_evidence_allowed
            );
        }
        Commands::OptOut => {
            let snapshot = app.opt_out()?;
            println!("install_id: {}", snapshot.identity.install_id);
            println!("mode: {:?}", snapshot.state.mode);
            println!(
                "opt_out_at: {}",
                snapshot.state.opt_out_at.unwrap_or_default()
            );
        }
        Commands::Sync => {
            let outcome = app.sync()?;
            println!("server_time: {}", outcome.hello.server_time);
            println!(
                "server_protocol_version: {}",
                outcome.hello.server_protocol_version
            );
            println!("items_uploaded: {}", outcome.items_uploaded);
            println!("submission_id: {}", outcome.receipt.submission_id);
            println!("duplicate: {}", outcome.receipt.duplicate);
            println!("quarantined: {}", outcome.receipt.quarantined);
            println!("promoted_clusters: {}", outcome.receipt.promoted_clusters);
            println!("message: {}", outcome.receipt.message);
            if let Some(message) = fixer::network::server_upgrade_message(&outcome.hello) {
                println!("upgrade: {message}");
            }
            if !outcome.redactions.is_empty() {
                println!("redactions: {}", outcome.redactions.join(", "));
            }
        }
        Commands::Worker { command } => match command {
            WorkerCommands::Run => {
                let outcome = app.worker_once()?;
                println!("server_time: {}", outcome.hello.server_time);
                println!(
                    "server_protocol_version: {}",
                    outcome.hello.server_protocol_version
                );
                println!("message: {}", outcome.offer.message);
                if let Some(message) = fixer::network::server_upgrade_message(&outcome.hello) {
                    println!("upgrade: {message}");
                }
                if let Some(lease) = outcome.offer.lease {
                    println!("lease_id: {}", lease.lease_id);
                    println!("issue_id: {}", lease.issue.id);
                    println!("issue_title: {}", lease.issue.title);
                }
                if let Some(result) = outcome.result {
                    println!("result: {}", result.attempt.summary);
                    if let Some(path) = result.attempt.output_path {
                        println!("output_path: {path}");
                    }
                    if let Some(path) = result.attempt.bundle_path {
                        println!("bundle_path: {path}");
                    }
                }
            }
        },
        Commands::Auth { command } => match command {
            AuthCommands::Lease { command } => match command {
                LeaseCommands::Bootstrap {
                    user,
                    enable_linger,
                } => {
                    let status = app.auth_lease_bootstrap(
                        &user,
                        enable_linger || app.config.patch.lease_bootstrap_enable_linger,
                    )?;
                    print_lease_status(&status);
                }
                LeaseCommands::Grant {
                    user,
                    ttl,
                    budget,
                    allow_kernel,
                } => {
                    let ttl_seconds = ttl
                        .as_deref()
                        .map(parse_duration_seconds)
                        .transpose()?
                        .unwrap_or(app.config.patch.lease_default_ttl_seconds);
                    let budget = budget
                        .map(LeaseBudgetPreset::from)
                        .unwrap_or_else(|| app.config.patch.lease_budget_preset.clone());
                    let lease = app.auth_lease_grant(&user, ttl_seconds, budget, allow_kernel)?;
                    println!("user: {}", lease.user);
                    println!("uid: {}", lease.uid);
                    println!("granted_at: {}", lease.granted_at);
                    println!("expires_at: {}", lease.expires_at);
                    println!("budget: {}", lease.budget_preset.as_str());
                    println!("allow_kernel: {}", lease.allow_kernel);
                    println!(
                        "limits: active={} daily={} timeout={}s",
                        lease.budget.max_active_jobs,
                        lease.budget.max_jobs_per_day,
                        lease.budget.job_timeout_seconds
                    );
                }
                LeaseCommands::Status => {
                    let status = app.auth_lease_status()?;
                    print_lease_status(&status);
                }
                LeaseCommands::Revoke => match app.auth_lease_revoke()? {
                    Some(lease) => {
                        println!("user: {}", lease.user);
                        println!("revoked_at: {}", lease.revoked_at.unwrap_or_default());
                        if let Some(reason) = lease.paused_reason {
                            println!("reason: {reason}");
                        }
                    }
                    None => println!("no active Codex auth lease"),
                },
            },
            AuthCommands::ExecJob { .. } => unreachable!("handled before app startup"),
        },
        Commands::Participation => {
            let snapshot = app.participation()?;
            println!("install_id: {}", snapshot.identity.install_id);
            println!("server_url: {}", snapshot.server_url);
            println!("mode: {:?}", snapshot.state.mode);
            println!(
                "consented_at: {}",
                snapshot.state.consented_at.as_deref().unwrap_or("never")
            );
            println!(
                "policy_version: {}",
                snapshot
                    .state
                    .consent_policy_version
                    .as_deref()
                    .unwrap_or("none")
            );
            println!(
                "richer_evidence_allowed: {}",
                snapshot.state.richer_evidence_allowed
            );
        }
    }

    Ok(())
}

fn print_lease_status(status: &fixer::models::CodexAuthLeaseStatus) {
    println!("ready: {}", status.ready);
    if let Some(lease) = &status.lease {
        println!("user: {}", lease.user);
        println!("uid: {}", lease.uid);
        println!("granted_at: {}", lease.granted_at);
        println!("expires_at: {}", lease.expires_at);
        println!("budget: {}", lease.budget_preset.as_str());
        println!("allow_kernel: {}", lease.allow_kernel);
        println!("active_jobs: {}", lease.active_jobs);
        println!(
            "jobs_today: {}/{}",
            lease.jobs_started_today, lease.budget.max_jobs_per_day
        );
        println!("jobs_day: {}", lease.jobs_started_day);
        println!("timeout_seconds: {}", lease.budget.job_timeout_seconds);
        if let Some(reason) = lease.paused_reason.as_deref() {
            println!("paused_reason: {reason}");
        }
        if let Some(revoked_at) = lease.revoked_at.as_deref() {
            println!("revoked_at: {revoked_at}");
        }
        if !lease.recent_failures.is_empty() {
            println!("recent_failures: {}", lease.recent_failures.len());
            for failure in &lease.recent_failures {
                println!(
                    "  [{}] {}: {}",
                    failure.occurred_at, failure.kind, failure.message
                );
            }
        }
    }
    for note in &status.notes {
        println!("note: {note}");
    }
}

fn parse_duration_seconds(raw: &str) -> Result<u64> {
    let value = raw.trim();
    if value.is_empty() {
        anyhow::bail!("duration must not be empty");
    }
    let split = value
        .find(|ch: char| !ch.is_ascii_digit())
        .unwrap_or(value.len());
    let (amount, suffix) = value.split_at(split);
    let amount: u64 = amount
        .parse()
        .map_err(|_| anyhow::anyhow!("invalid duration `{raw}`"))?;
    let multiplier = match suffix {
        "" | "s" => 1,
        "m" => 60,
        "h" => 60 * 60,
        "d" => 24 * 60 * 60,
        other => anyhow::bail!("unsupported duration suffix `{other}`"),
    };
    Ok(amount.saturating_mul(multiplier))
}

fn print_findings(items: Vec<FindingRecord>) {
    for item in items {
        println!("#{} [{}] {}", item.id, item.severity, item.title);
        println!("  {}", item.summary);
        if let Some(path) = item.artifact_path {
            println!("  path: {}", path.display());
        }
        if let Some(package_name) = item.package_name {
            println!("  package: {package_name}");
        }
        if let Some(repo_root) = item.repo_root {
            println!("  repo: {}", repo_root.display());
        }
        println!("  seen: {} -> {}", item.first_seen, item.last_seen);
    }
}
