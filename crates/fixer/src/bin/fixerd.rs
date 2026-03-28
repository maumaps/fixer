use anyhow::Result;
use clap::{Parser, Subcommand};
use fixer::app::App;
use std::path::PathBuf;

#[derive(Parser)]
#[command(name = "fixerd", about = "Fixer collection daemon")]
struct Cli {
    #[arg(long, global = true)]
    config: Option<PathBuf>,
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    Run,
    CollectOnce,
}

fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();

    let cli = Cli::parse();
    let app = App::load(cli.config.as_deref())?;
    match cli.command {
        Command::Run => app.run_loop(),
        Command::CollectOnce => {
            let report = app.collect_once()?;
            tracing::info!(
                capabilities = report.capabilities_seen,
                artifacts = report.artifacts_seen,
                findings = report.findings_seen,
                "completed one-shot collection"
            );
            Ok(())
        }
    }
}
