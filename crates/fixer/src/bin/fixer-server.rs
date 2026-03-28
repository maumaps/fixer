use anyhow::Result;
use clap::{Parser, Subcommand};
use fixer::config::FixerConfig;
use fixer::server;
use std::path::PathBuf;

#[derive(Parser)]
#[command(
    name = "fixer-server",
    about = "Fixer aggregation and worker-coordination server"
)]
struct Cli {
    #[arg(long, global = true)]
    config: Option<PathBuf>,
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    Serve,
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();

    let cli = Cli::parse();
    let config = FixerConfig::load(cli.config.as_deref())?;
    match cli.command {
        Command::Serve => server::serve(config).await,
    }
}
