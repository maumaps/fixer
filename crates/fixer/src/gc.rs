use crate::config::FixerConfig;
use anyhow::{Context, Result};
use chrono::{DateTime, Duration as ChronoDuration, Utc};
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::SystemTime;

#[derive(Debug, Clone, Default)]
pub struct GcOptions {
    pub dry_run: bool,
    pub skip_sync: bool,
    pub include_sources: bool,
    pub retention_days: Option<u64>,
    pub protected_paths: Vec<PathBuf>,
}

#[derive(Debug, Clone)]
pub struct GcOutcome {
    pub sync_attempted: bool,
    pub sync_skipped_reason: Option<String>,
    pub sync_warning: Option<String>,
    pub entries: Vec<GcEntry>,
    pub bytes_reclaimed: u64,
}

#[derive(Debug, Clone)]
pub struct GcEntry {
    pub path: PathBuf,
    pub kind: GcEntryKind,
    pub reason: String,
    pub bytes: u64,
    pub removed: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GcEntryKind {
    ProposalBundle,
    Investigation,
    PerfSample,
    SourceCheckout,
}

pub fn collect_gc_candidates(config: &FixerConfig, options: &GcOptions) -> Result<Vec<GcEntry>> {
    let retention_days = options
        .retention_days
        .unwrap_or(config.service.hotspot_investigation_retention_days);
    let mut entries = Vec::new();

    entries.extend(collect_proposal_candidates(
        &config.service.state_dir.join("proposals"),
        options
            .retention_days
            .unwrap_or(config.service.proposal_bundle_retention_days),
        config.service.proposal_bundle_keep_per_opportunity,
        &options
            .protected_paths
            .iter()
            .cloned()
            .collect::<BTreeSet<_>>(),
    )?);
    entries.extend(collect_aged_directory_candidates(
        &config.service.state_dir.join("investigations"),
        retention_days,
        GcEntryKind::Investigation,
        "investigation artifact older than retention window",
    )?);
    entries.extend(collect_aged_file_candidates(
        &config.service.state_dir.join("perf"),
        retention_days,
        GcEntryKind::PerfSample,
        "perf sample older than retention window",
    )?);

    if options.include_sources {
        entries.extend(collect_source_candidates(
            &config.service.state_dir.join("sources"),
            retention_days,
        )?);
    }

    entries.sort_by(|left, right| left.path.cmp(&right.path));
    Ok(entries)
}

pub fn apply_gc_candidates(candidates: &mut [GcEntry], dry_run: bool) -> Result<u64> {
    let mut reclaimed: u64 = 0;
    for candidate in candidates {
        if dry_run {
            continue;
        }
        remove_gc_path(&candidate.path).with_context(|| {
            format!("failed to remove gc candidate {}", candidate.path.display())
        })?;
        candidate.removed = true;
        reclaimed = reclaimed.saturating_add(candidate.bytes);
    }
    Ok(reclaimed)
}

fn collect_proposal_candidates(
    root: &Path,
    retention_days: u64,
    keep_per_opportunity: usize,
    protected_paths: &BTreeSet<PathBuf>,
) -> Result<Vec<GcEntry>> {
    if !root.exists() {
        return Ok(Vec::new());
    }

    let keep_per_opportunity = keep_per_opportunity.max(1);
    let cutoff = cutoff_for_retention(retention_days);
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

    let mut candidates = Vec::new();
    for bundles in grouped.values_mut() {
        bundles.sort_by(|left, right| right.0.cmp(&left.0));
        for (index, (modified, path)) in bundles.iter().enumerate() {
            let stale = *modified < cutoff;
            if index >= keep_per_opportunity || stale {
                if protected_paths.contains(path) {
                    continue;
                }
                let reason = if index >= keep_per_opportunity {
                    format!(
                        "proposal bundle exceeds keep-per-opportunity limit ({keep_per_opportunity})"
                    )
                } else {
                    "proposal bundle older than retention window".to_string()
                };
                candidates.push(GcEntry {
                    path: path.clone(),
                    kind: GcEntryKind::ProposalBundle,
                    reason,
                    bytes: path_size(path)?,
                    removed: false,
                });
            }
        }
    }
    Ok(candidates)
}

fn collect_aged_directory_candidates(
    root: &Path,
    retention_days: u64,
    kind: GcEntryKind,
    reason: &str,
) -> Result<Vec<GcEntry>> {
    if !root.exists() {
        return Ok(Vec::new());
    }
    let cutoff = cutoff_for_retention(retention_days);
    let mut candidates = Vec::new();
    for entry in fs::read_dir(root)? {
        let entry = entry?;
        let path = entry.path();
        if !path.is_dir() || modified_at(&path)? >= cutoff {
            continue;
        }
        candidates.push(GcEntry {
            bytes: path_size(&path)?,
            path,
            kind,
            reason: reason.to_string(),
            removed: false,
        });
    }
    Ok(candidates)
}

fn collect_aged_file_candidates(
    root: &Path,
    retention_days: u64,
    kind: GcEntryKind,
    reason: &str,
) -> Result<Vec<GcEntry>> {
    if !root.exists() {
        return Ok(Vec::new());
    }
    let cutoff = cutoff_for_retention(retention_days);
    let mut candidates = Vec::new();
    for entry in fs::read_dir(root)? {
        let entry = entry?;
        let path = entry.path();
        if !path.is_file() || modified_at(&path)? >= cutoff {
            continue;
        }
        candidates.push(GcEntry {
            bytes: path_size(&path)?,
            path,
            kind,
            reason: reason.to_string(),
            removed: false,
        });
    }
    Ok(candidates)
}

fn collect_source_candidates(root: &Path, retention_days: u64) -> Result<Vec<GcEntry>> {
    if !root.exists() {
        return Ok(Vec::new());
    }
    let mut candidates = Vec::new();
    for family in fs::read_dir(root)? {
        let family = family?;
        let family_path = family.path();
        if !family_path.is_dir() {
            continue;
        }
        candidates.extend(collect_aged_directory_candidates(
            &family_path,
            retention_days,
            GcEntryKind::SourceCheckout,
            "source checkout older than retention window",
        )?);
    }
    candidates.retain(|entry| !is_dirty_git_checkout(&entry.path));
    Ok(candidates)
}

fn is_dirty_git_checkout(path: &Path) -> bool {
    if !path.join(".git").exists() {
        return false;
    }
    let Ok(output) = Command::new("git")
        .arg("-C")
        .arg(path)
        .arg("status")
        .arg("--porcelain")
        .output()
    else {
        return true;
    };
    !output.status.success() || !output.stdout.is_empty()
}

fn cutoff_for_retention(retention_days: u64) -> DateTime<Utc> {
    Utc::now() - ChronoDuration::seconds((retention_days.saturating_mul(24 * 60 * 60)) as i64)
}

fn modified_at(path: &Path) -> Result<DateTime<Utc>> {
    Ok(DateTime::<Utc>::from(
        fs::metadata(path)
            .with_context(|| format!("failed to stat {}", path.display()))?
            .modified()
            .unwrap_or(SystemTime::UNIX_EPOCH),
    ))
}

fn path_size(path: &Path) -> Result<u64> {
    let metadata =
        fs::symlink_metadata(path).with_context(|| format!("failed to stat {}", path.display()))?;
    if metadata.is_file() {
        return Ok(metadata.len());
    }
    if !metadata.is_dir() {
        return Ok(0);
    }

    let mut total: u64 = 0;
    for entry in fs::read_dir(path)? {
        let entry = entry?;
        total = total.saturating_add(path_size(&entry.path())?);
    }
    Ok(total)
}

fn remove_gc_path(path: &Path) -> Result<()> {
    let metadata =
        fs::symlink_metadata(path).with_context(|| format!("failed to stat {}", path.display()))?;
    if metadata.is_dir() {
        fs::remove_dir_all(path)?;
    } else {
        fs::remove_file(path)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{
        GcEntryKind, GcOptions, apply_gc_candidates, collect_gc_candidates,
        collect_proposal_candidates,
    };
    use crate::config::FixerConfig;
    use std::collections::BTreeSet;
    use std::fs;
    use std::thread;
    use std::time::Duration;
    use tempfile::tempdir;

    #[test]
    fn proposal_gc_keeps_the_newest_bundle_per_opportunity() {
        let dir = tempdir().unwrap();
        let old_bundle = dir.path().join("42-old");
        let new_bundle = dir.path().join("42-new");
        fs::create_dir_all(&old_bundle).unwrap();
        fs::write(old_bundle.join("payload"), "old").unwrap();
        thread::sleep(Duration::from_millis(20));
        fs::create_dir_all(&new_bundle).unwrap();
        fs::write(new_bundle.join("payload"), "new").unwrap();

        let candidates = collect_proposal_candidates(dir.path(), 365, 1, &BTreeSet::new()).unwrap();

        assert_eq!(candidates.len(), 1);
        assert_eq!(candidates[0].kind, GcEntryKind::ProposalBundle);
        assert_eq!(candidates[0].path, old_bundle);
    }

    #[test]
    fn dry_run_reports_candidates_without_removing_them() {
        let dir = tempdir().unwrap();
        let mut config = FixerConfig::default();
        config.service.state_dir = dir.path().to_path_buf();
        config.service.proposal_bundle_keep_per_opportunity = 1;
        fs::create_dir_all(dir.path().join("proposals/7-a")).unwrap();
        thread::sleep(Duration::from_millis(20));
        fs::create_dir_all(dir.path().join("proposals/7-b")).unwrap();
        fs::create_dir_all(dir.path().join("perf")).unwrap();
        fs::write(dir.path().join("perf/sample.data"), vec![0_u8; 16]).unwrap();

        let mut candidates = collect_gc_candidates(
            &config,
            &GcOptions {
                dry_run: true,
                retention_days: Some(0),
                ..GcOptions::default()
            },
        )
        .unwrap();
        let reclaimed = apply_gc_candidates(&mut candidates, true).unwrap();

        assert_eq!(reclaimed, 0);
        assert!(dir.path().join("proposals/7-a").exists());
        assert!(dir.path().join("perf/sample.data").exists());
        assert!(candidates.iter().any(|entry| entry.bytes > 0));
    }

    #[test]
    fn source_gc_requires_explicit_opt_in() {
        let dir = tempdir().unwrap();
        let mut config = FixerConfig::default();
        config.service.state_dir = dir.path().to_path_buf();
        fs::create_dir_all(dir.path().join("sources/debian/pkg-1.0")).unwrap();

        let without_sources = collect_gc_candidates(
            &config,
            &GcOptions {
                retention_days: Some(0),
                ..GcOptions::default()
            },
        )
        .unwrap();
        let with_sources = collect_gc_candidates(
            &config,
            &GcOptions {
                include_sources: true,
                retention_days: Some(0),
                ..GcOptions::default()
            },
        )
        .unwrap();

        assert!(
            without_sources
                .iter()
                .all(|entry| entry.kind != GcEntryKind::SourceCheckout)
        );
        assert!(
            with_sources
                .iter()
                .any(|entry| entry.kind == GcEntryKind::SourceCheckout)
        );
    }

    #[test]
    fn proposal_gc_preserves_database_referenced_bundles() {
        let dir = tempdir().unwrap();
        let protected_bundle = dir.path().join("42-protected");
        let orphan_bundle = dir.path().join("42-orphan");
        fs::create_dir_all(&protected_bundle).unwrap();
        fs::write(protected_bundle.join("payload"), "published patch").unwrap();
        thread::sleep(Duration::from_millis(20));
        fs::create_dir_all(&orphan_bundle).unwrap();
        fs::write(orphan_bundle.join("payload"), "orphan").unwrap();

        let candidates = collect_proposal_candidates(
            dir.path(),
            0,
            1,
            &BTreeSet::from([protected_bundle.clone()]),
        )
        .unwrap();

        assert!(
            !candidates
                .iter()
                .any(|entry| entry.path == protected_bundle)
        );
        assert!(candidates.iter().any(|entry| entry.path == orphan_bundle));
    }
}
