use anyhow::Result;
use clap::{Parser, Subcommand};
use fixer::config::FixerConfig;
use fixer::server;
use std::path::Path;
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
    let config_path = cli
        .config
        .as_deref()
        .or(Some(Path::new("/etc/fixer/fixer-server.toml")));
    let config = FixerConfig::load(config_path)?;
    match cli.command {
        Command::Serve => server::serve(config).await,
    }
}
