use anyhow::Result;
use clap::{Parser, Subcommand};
use fixer::config::FixerConfig;
use fixer::server::{self, UpstreamReviewRecord};
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
    RecordUpstreamReview {
        #[arg(long)]
        id: String,
        #[arg(long)]
        project: String,
        #[arg(long)]
        title: String,
        #[arg(long)]
        summary: String,
        #[arg(long)]
        pr_url: String,
        #[arg(long, default_value = "review")]
        state: String,
        #[arg(long)]
        merged_at: Option<String>,
        #[arg(long, default_value_t = true, action = clap::ArgAction::Set)]
        fixer_credit: bool,
        #[arg(long = "tag")]
        tags: Vec<String>,
        #[arg(long)]
        patch_issue_id: Option<String>,
        #[arg(long)]
        clear_patch_issue: bool,
        #[arg(long = "related-issue-id")]
        related_issue_ids: Vec<String>,
        #[arg(long)]
        replace_related_issues: bool,
        #[arg(long, default_value = "source_path_family")]
        relation: String,
        #[arg(long)]
        apply: bool,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    // Default to info so the service records what it does — reconnects,
    // recoveries, startup — instead of staying silent until something reaches
    // ERROR. RUST_LOG still overrides this.
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    let cli = Cli::parse();
    let config_path = cli
        .config
        .as_deref()
        .or(Some(Path::new("/etc/fixer/fixer-server.toml")));
    let config = FixerConfig::load(config_path)?;
    match cli.command {
        Command::Serve => server::serve(config).await,
        Command::RecordUpstreamReview {
            id,
            project,
            title,
            summary,
            pr_url,
            state,
            merged_at,
            fixer_credit,
            tags,
            patch_issue_id,
            clear_patch_issue,
            related_issue_ids,
            replace_related_issues,
            relation,
            apply,
        } => {
            let record = UpstreamReviewRecord {
                id,
                project,
                title,
                summary,
                pr_url,
                state,
                merged_at,
                fixer_credit,
                tags,
                patch_issue_id,
                clear_patch_issue,
                related_issue_ids,
                replace_related_issues,
                relation,
            };
            server::validate_upstream_review_record(&record)?;
            if !apply {
                println!(
                    "dry-run: review={} state={} direct_issue={} related_issues={} (rerun with --apply)",
                    record.id,
                    record.state,
                    record.patch_issue_id.as_deref().unwrap_or("none"),
                    record.related_issue_ids.len(),
                );
                return Ok(());
            }
            let result = server::record_upstream_review(&config, &record).await?;
            println!(
                "recorded upstream review {} direct_issue={} related_issues={}",
                result.review_id,
                result.patch_issue_id.as_deref().unwrap_or("none"),
                result.related_issue_count,
            );
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn record_upstream_review_is_dry_run_without_apply() {
        let cli = Cli::try_parse_from([
            "fixer-server",
            "record-upstream-review",
            "--id",
            "yakuake-mr-157",
            "--project",
            "Yakuake",
            "--title",
            "Focus raised sessions via active terminal",
            "--summary",
            "Targeted focus crash mitigation.",
            "--pr-url",
            "https://invent.kde.org/utilities/yakuake/-/merge_requests/157",
            "--patch-issue-id",
            "019f478f-3ab9-7aa2-af9f-76ffb768fd8b",
        ])
        .unwrap();

        let Command::RecordUpstreamReview {
            apply, relation, ..
        } = cli.command
        else {
            panic!("expected record-upstream-review command");
        };
        assert!(!apply);
        assert_eq!(relation, "source_path_family");
    }

    #[test]
    fn record_upstream_review_accepts_explicit_apply_and_related_issues() {
        let cli = Cli::try_parse_from([
            "fixer-server",
            "record-upstream-review",
            "--id",
            "supervisor-pr-1717",
            "--project",
            "Supervisor",
            "--title",
            "Skip idle reaping",
            "--summary",
            "Closed after maintainer review.",
            "--pr-url",
            "https://github.com/Supervisor/supervisor/pull/1717",
            "--state",
            "closed_unmerged",
            "--related-issue-id",
            "issue-a",
            "--related-issue-id",
            "issue-b",
            "--apply",
        ])
        .unwrap();

        let Command::RecordUpstreamReview {
            apply,
            related_issue_ids,
            ..
        } = cli.command
        else {
            panic!("expected record-upstream-review command");
        };
        assert!(apply);
        assert_eq!(related_issue_ids, ["issue-a", "issue-b"]);
    }
}
