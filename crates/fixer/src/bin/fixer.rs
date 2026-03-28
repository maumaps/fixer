use anyhow::Result;
use clap::{Parser, Subcommand, ValueEnum};
use fixer::app::App;
use fixer::models::FindingRecord;
use std::path::PathBuf;

#[derive(Parser)]
#[command(name = "fixer", about = "Local evidence engine for Linux maintenance opportunities")]
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
                let state = if capability.available { "available" } else { "missing" };
                let path = capability
                    .path
                    .map(|x| x.display().to_string())
                    .unwrap_or_else(|| "-".to_string());
                println!("{:<12} {:<9} {:<30} {}", capability.name, state, path, capability.notes.unwrap_or_default());
            }
        }
        Commands::Crashes => print_findings(app.store.list_findings("crash")?),
        Commands::Warnings => print_findings(app.store.list_findings("warning")?),
        Commands::Hotspots => print_findings(app.store.list_findings("hotspot")?),
        Commands::Owners => {
            for (name, repo_root, owners) in app.store.list_repo_owners()? {
                println!("{name}");
                println!("  repo: {}", if repo_root.is_empty() { "(none)" } else { &repo_root });
                println!("  owners: {}", if owners.is_empty() { "(none)" } else { &owners });
            }
        }
        Commands::Opportunities { state } => {
            for item in app.store.list_opportunities(state.as_deref())? {
                println!("#{} [{}] score={} state={}", item.id, item.kind, item.score, item.state);
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
