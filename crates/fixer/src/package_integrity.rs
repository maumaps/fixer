//! Is the file that produced this evidence still the file its package shipped?
//!
//! For a distribution package Fixer derives the workspace from distribution
//! source: `apt-get source`, the packaging VCS, upstream git at the installed
//! version. That source is the code that produced the evidence only while the
//! installed files still match the package. On a developer machine they often do
//! not -- this host carries locally built PostGIS and Graphviz over the packaged
//! ones -- and then Codex reads source that never ran, patches it, and the patch
//! goes to a maintainer who cannot reproduce anything from it.

use crate::util::{command_exists, command_run_os_with_timeout};
use serde_json::Value;
use std::ffi::OsStr;
use std::path::{Path, PathBuf};
use std::time::Duration as StdDuration;

const DPKG_VERIFY_TIMEOUT_SECONDS: u64 = 60;
const DPKG_SEARCH_TIMEOUT_SECONDS: u64 = 15;

/// A file named by the evidence whose contents no longer match the package it
/// was installed from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DivergedFile {
    pub path: PathBuf,
    pub package: String,
    /// How the evidence named the file, for a message that points at the right
    /// thing: the artifact that ran, or a module in the recorded stack.
    pub role: &'static str,
}

/// Refuse to derive a workspace from distribution source when a file behind the
/// evidence has been rebuilt locally. Returns the operator-facing reason.
pub fn distribution_source_refusal(evidence: &Value) -> Option<String> {
    refusal_message(&diverged_evidence_files(evidence))
}

fn refusal_message(diverged: &[DivergedFile]) -> Option<String> {
    let first = diverged.first()?;
    let mut message = format!(
        "{} no longer matches package {} (dpkg -V reports a checksum mismatch), so the distribution source is not the code that produced this evidence",
        first.path.display(),
        first.package
    );
    if first.role == "stack module" {
        message.push_str("; the recorded stack runs through that locally built module");
    }
    message.push_str(&format!(
        ". Patch the tree that built the file, or reinstall it with `apt-get install --reinstall {}` and collect fresh evidence",
        first.package
    ));
    Some(message)
}

/// Every file the evidence points at that diverges from its package, artifacts
/// first so the message names the most direct one.
pub fn diverged_evidence_files(evidence: &Value) -> Vec<DivergedFile> {
    if !command_exists("dpkg") {
        return Vec::new();
    }
    let artifacts = evidence_artifact_paths(evidence);
    let mut checked: Vec<(PathBuf, &'static str)> =
        artifacts.iter().cloned().map(|p| (p, "artifact")).collect();
    for module in evidence_stack_modules(evidence) {
        if let Some((_, path)) = resolve_module_path(&module, &artifacts) {
            if !checked.iter().any(|(known, _)| known == &path) {
                checked.push((path, "stack module"));
            }
        }
    }

    let mut diverged = Vec::new();
    for (path, role) in checked {
        let Some(package) = owning_package(&path) else {
            // Not packaged at all: nothing claims this file, so nothing is being
            // contradicted, and the package-derived workspace path is not taken
            // for it either.
            continue;
        };
        if package_diverged_files(&package).iter().any(|p| p == &path) {
            diverged.push(DivergedFile { path, package, role });
        }
    }
    diverged
}

/// Absolute paths the evidence names directly.
fn evidence_artifact_paths(evidence: &Value) -> Vec<PathBuf> {
    let mut paths = Vec::new();
    let mut push = |value: Option<&Value>| {
        if let Some(text) = value.and_then(Value::as_str) {
            let text = text.trim();
            if text.starts_with('/') && !paths.iter().any(|p: &PathBuf| p.as_os_str() == text) {
                paths.push(PathBuf::from(text));
            }
        }
    };
    push(evidence.get("artifact_path"));
    let details = evidence.get("details");
    push(details.and_then(|details| details.get("executable")));
    push(details.and_then(|details| details.get("hot_path_dso_path")));
    paths
}

/// Shared objects the recorded stack names by soname only, as in
/// `geometry_type_from_string [postgis-3.so]`.
fn evidence_stack_modules(evidence: &Value) -> Vec<String> {
    let Some(details) = evidence.get("details") else {
        return Vec::new();
    };
    let mut modules: Vec<String> = Vec::new();
    for key in ["primary_stack", "stack", "backtrace"] {
        let Some(frames) = details.get(key).and_then(Value::as_array) else {
            continue;
        };
        for frame in frames {
            let Some(frame) = frame.as_str() else {
                continue;
            };
            let Some(module) = frame_module(frame) else {
                continue;
            };
            if !modules.iter().any(|known| known == module) {
                modules.push(module.to_string());
            }
        }
    }
    modules
}

fn frame_module(frame: &str) -> Option<&str> {
    let open = frame.rfind('[')?;
    let close = frame.rfind(']')?;
    if close <= open + 1 {
        return None;
    }
    let module = frame[open + 1..close].trim();
    // `n/a [postgres]` is a frame without a symbol, still a real module name;
    // an empty or path-shaped bracket is not what this collector writes.
    if module.is_empty() || module.contains('/') {
        return None;
    }
    Some(module)
}

fn owning_package(path: &Path) -> Option<String> {
    let output = command_run_os_with_timeout(
        "dpkg",
        &[OsStr::new("-S"), path.as_os_str()],
        StdDuration::from_secs(DPKG_SEARCH_TIMEOUT_SECONDS),
    )
    .ok()?;
    let text = String::from_utf8_lossy(&output.stdout);
    let matches = parse_dpkg_search_output(&text);
    matches
        .into_iter()
        .find(|(_, candidate)| candidate == path)
        .map(|(package, _)| package)
}

/// A bare soname can belong to several packages -- this host has `postgis-3.so`
/// from five PostgreSQL majors. Pick the one installed next to the artifact that
/// crashed, and only when one candidate is nearer than all the others.
fn resolve_module_path(module: &str, artifacts: &[PathBuf]) -> Option<(String, PathBuf)> {
    let output = command_run_os_with_timeout(
        "dpkg",
        &[OsStr::new("-S"), OsStr::new(module)],
        StdDuration::from_secs(DPKG_SEARCH_TIMEOUT_SECONDS),
    )
    .ok()?;
    let text = String::from_utf8_lossy(&output.stdout);
    let matches = parse_dpkg_search_output(&text);
    module_match_nearest_artifact(module, &matches, artifacts)
}

fn module_match_nearest_artifact(
    module: &str,
    matches: &[(String, PathBuf)],
    artifacts: &[PathBuf],
) -> Option<(String, PathBuf)> {
    let named: Vec<&(String, PathBuf)> = matches
        .iter()
        .filter(|(_, path)| path.file_name().and_then(OsStr::to_str) == Some(module))
        .collect();
    match named.as_slice() {
        [] => None,
        [only] => Some((*only).clone()),
        many => {
            let mut scored: Vec<(usize, &(String, PathBuf))> = many
                .iter()
                .map(|candidate| {
                    let score = artifacts
                        .iter()
                        .map(|artifact| shared_prefix_len(artifact, &candidate.1))
                        .max()
                        .unwrap_or(0);
                    (score, *candidate)
                })
                .collect();
            scored.sort_by(|left, right| right.0.cmp(&left.0));
            let (best_score, best) = scored.first()?;
            if *best_score == 0 || scored.get(1).is_some_and(|(next, _)| next == best_score) {
                // Ambiguous. Guessing which major's module ran would put Codex in
                // the wrong source tree just as surely as skipping the check.
                return None;
            }
            Some((*best).clone())
        }
    }
}

fn shared_prefix_len(left: &Path, right: &Path) -> usize {
    left.components()
        .zip(right.components())
        .take_while(|(left, right)| left == right)
        .count()
}

fn package_diverged_files(package: &str) -> Vec<PathBuf> {
    let Ok(output) = command_run_os_with_timeout(
        "dpkg",
        &[OsStr::new("-V"), OsStr::new(package)],
        StdDuration::from_secs(DPKG_VERIFY_TIMEOUT_SECONDS),
    ) else {
        return Vec::new();
    };
    parse_dpkg_verify_output(&String::from_utf8_lossy(&output.stdout))
}

/// `dpkg -V` prints one line per file that fails verification:
/// `??5??????   /usr/lib/postgresql/18/lib/postgis-3.so`. The third attribute is
/// the md5 check, which is the one that says "this is not the file we shipped".
fn parse_dpkg_verify_output(output: &str) -> Vec<PathBuf> {
    output
        .lines()
        .filter_map(|line| {
            let mut fields = line.split_whitespace();
            let attributes = fields.next()?;
            let rest: Vec<&str> = fields.collect();
            let (kind, path) = match rest.as_slice() {
                [path] => (None, *path),
                [kind, path] => (Some(*kind), *path),
                _ => return None,
            };
            // A conffile the operator edited is expected local state, not a
            // rebuilt binary, and it never carries executable code.
            if kind == Some("c") {
                return None;
            }
            if attributes.chars().nth(2) != Some('5') {
                return None;
            }
            Some(PathBuf::from(path))
        })
        .collect()
}

/// `dpkg -S` prints `package: /path`, and `package1, package2: /path` when a file
/// is shipped by several packages.
fn parse_dpkg_search_output(output: &str) -> Vec<(String, PathBuf)> {
    let mut found = Vec::new();
    for line in output.lines() {
        let Some((packages, path)) = line.rsplit_once(": ") else {
            continue;
        };
        let path = PathBuf::from(path.trim());
        for package in packages.split(',') {
            let package = package.trim();
            if package.is_empty() {
                continue;
            }
            // `dpkg -S` qualifies with the architecture when more than one is
            // installed; the package name is what apt and dpkg -V take.
            let package = package.split(':').next().unwrap_or(package);
            found.push((package.to_string(), path.clone()));
        }
    }
    found
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn postgis_crash_evidence() -> Value {
        json!({
            "artifact_name": "postgres",
            "artifact_path": "/usr/lib/postgresql/18/bin/postgres",
            "details": {
                "executable": "/usr/lib/postgresql/18/bin/postgres",
                "primary_stack": [
                    "geometry_type_from_string [postgis-3.so]",
                    "gserialized_typmod_in [postgis-3.so]",
                    "n/a [postgres]",
                    "evaluate_expr [postgres]"
                ]
            }
        })
    }

    #[test]
    fn the_crashing_module_is_checked_even_when_the_artifact_is_the_interpreter() {
        let evidence = postgis_crash_evidence();

        assert_eq!(
            evidence_artifact_paths(&evidence),
            vec![PathBuf::from("/usr/lib/postgresql/18/bin/postgres")]
        );
        assert_eq!(
            evidence_stack_modules(&evidence),
            vec!["postgis-3.so".to_string(), "postgres".to_string()]
        );
    }

    #[test]
    fn a_rebuilt_file_is_recognised_and_an_edited_conffile_is_not() {
        let verify_output = concat!(
            "??5??????   /usr/lib/postgresql/18/lib/postgis-3.so\n",
            "??5?????? c /etc/postgresql-common/createcluster.conf\n",
            "missing     /usr/share/doc/postgresql-18-postgis-3/changelog.gz\n",
            "??5??????   /usr/lib/postgresql/18/lib/bitcode/postgis-3/lwgeom_box.bc\n",
        );

        assert_eq!(
            parse_dpkg_verify_output(verify_output),
            vec![
                PathBuf::from("/usr/lib/postgresql/18/lib/postgis-3.so"),
                PathBuf::from("/usr/lib/postgresql/18/lib/bitcode/postgis-3/lwgeom_box.bc"),
            ]
        );
    }

    #[test]
    fn the_module_next_to_the_crashing_binary_wins_over_the_other_majors() {
        let matches = parse_dpkg_search_output(concat!(
            "postgresql-17-postgis-3: /usr/lib/postgresql/17/lib/postgis-3.so\n",
            "postgresql-16-postgis-3: /usr/lib/postgresql/16/lib/postgis-3.so\n",
            "postgresql-18-postgis-3: /usr/lib/postgresql/18/lib/postgis-3.so\n",
        ));
        let artifacts = vec![PathBuf::from("/usr/lib/postgresql/18/bin/postgres")];

        let resolved = module_match_nearest_artifact("postgis-3.so", &matches, &artifacts)
            .expect("the module installed next to the crashing binary should win");

        assert_eq!(resolved.0, "postgresql-18-postgis-3");
        assert_eq!(
            resolved.1,
            PathBuf::from("/usr/lib/postgresql/18/lib/postgis-3.so")
        );
    }

    #[test]
    fn a_module_that_could_be_any_of_several_installs_is_left_alone() {
        let matches = parse_dpkg_search_output(concat!(
            "postgresql-17-postgis-3: /usr/lib/postgresql/17/lib/postgis-3.so\n",
            "postgresql-16-postgis-3: /usr/lib/postgresql/16/lib/postgis-3.so\n",
        ));

        assert_eq!(
            module_match_nearest_artifact("postgis-3.so", &matches, &[]),
            None
        );
    }

    #[test]
    fn the_refusal_names_the_file_the_package_and_the_way_out() {
        let message = refusal_message(&[DivergedFile {
            path: PathBuf::from("/usr/lib/postgresql/18/lib/postgis-3.so"),
            package: "postgresql-18-postgis-3".to_string(),
            role: "stack module",
        }])
        .expect("a diverged file must produce a refusal");

        assert!(message.contains("/usr/lib/postgresql/18/lib/postgis-3.so"));
        assert!(message.contains("postgresql-18-postgis-3"));
        assert!(message.contains("the recorded stack runs through that locally built module"));
        assert!(message.ends_with("`apt-get install --reinstall postgresql-18-postgis-3` and collect fresh evidence"));
    }

    #[test]
    fn an_untouched_install_is_not_refused() {
        assert_eq!(refusal_message(&[]), None);
    }
}
