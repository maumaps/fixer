use anyhow::Result;
use clap::{Parser, Subcommand, ValueEnum};
use fixer::app::App;
use fixer::models::{FindingRecord, ParticipationMode};
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

fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .without_time()
        .init();

    let cli = Cli::parse();
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
            let snapshot = app.opt_in(mode, richer_evidence)?;
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
            println!("items_uploaded: {}", outcome.items_uploaded);
            println!("submission_id: {}", outcome.receipt.submission_id);
            println!("duplicate: {}", outcome.receipt.duplicate);
            println!("quarantined: {}", outcome.receipt.quarantined);
            println!("promoted_clusters: {}", outcome.receipt.promoted_clusters);
            println!("message: {}", outcome.receipt.message);
            if !outcome.redactions.is_empty() {
                println!("redactions: {}", outcome.redactions.join(", "));
            }
        }
        Commands::Worker { command } => match command {
            WorkerCommands::Run => {
                let outcome = app.worker_once()?;
                println!("server_time: {}", outcome.hello.server_time);
                println!("message: {}", outcome.offer.message);
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
