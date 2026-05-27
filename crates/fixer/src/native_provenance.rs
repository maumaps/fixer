use crate::util::{command_exists, command_output_os_with_timeout};
use serde_json::{Value, json};
use std::ffi::OsStr;
use std::path::Path;
use std::time::Duration as StdDuration;

const GO_VERSION_TIMEOUT_SECONDS: u64 = 2;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct NativeExecutableSourceHint {
    pub(crate) executable_name: String,
    pub(crate) source_name: Option<String>,
    pub(crate) source_repo_url: Option<String>,
}

pub(crate) fn enrich_runaway_native_executable_provenance(
    details: &mut Value,
    artifact_path: Option<&str>,
    include_sensitive_process_details: bool,
) {
    if details.get("subsystem").and_then(Value::as_str) != Some("runaway-process") {
        return;
    }
    if details
        .get("native_executable_provenance")
        .is_some_and(|value| !value.is_null())
    {
        return;
    }
    let Some(path) = native_executable_path_from_details(details, artifact_path) else {
        return;
    };
    if !local_non_dpkg_executable_path(path) {
        return;
    }
    let executable_name = executable_name_from_path(path)
        .unwrap_or("local executable")
        .to_string();
    let source_hint = native_source_hint_from_executable_path(path);
    let source_name = source_hint
        .as_ref()
        .and_then(|hint| hint.source_name.clone());
    let source_repo_url = source_hint
        .as_ref()
        .and_then(|hint| hint.source_repo_url.clone());
    let mut detection_signals = if include_sensitive_process_details {
        vec![format!(
            "sampled executable path is outside dpkg-owned system binary directories: {path}"
        )]
    } else {
        vec![format!(
            "sampled executable {executable_name} is outside dpkg-owned system binary directories"
        )]
    };
    if let Some(source_name) = source_name.as_ref() {
        detection_signals.push(format!("Go build metadata identifies module {source_name}"));
    }
    let recommended_next_steps = if let Some(repo_url) = source_repo_url.as_ref() {
        vec![
            format!(
                "Acquire the upstream source from {repo_url} and rerun Fixer against that repository before proposing a patch."
            ),
            format!(
                "Keep the retained perf/strace/backtrace bundle attached to the {executable_name} source investigation."
            ),
        ]
    } else {
        vec![
            format!(
                "Find the upstream project or local checkout that installed {executable_name} before asking Fixer for a source patch."
            ),
            "Attach that repository as the opportunity workspace or file an upstream issue with the retained perf/strace/backtrace bundle.".to_string(),
            "If the executable came from a container, manual install, or model runtime bundle, record that distribution channel so future runs can acquire the right source.".to_string(),
        ]
    };
    details["native_executable_provenance"] = json!({
        "detection_signals": detection_signals,
        "executable_name": executable_name,
        "executable_path": if include_sensitive_process_details { path.to_string() } else { executable_name.clone() },
        "resolved_executable_path": if include_sensitive_process_details { std::fs::canonicalize(path).ok().map(|path| path.display().to_string()) } else { None },
        "command_line": if include_sensitive_process_details { details.get("command_line").and_then(Value::as_str).map(ToString::to_string) } else { None },
        "ownership": "external-non-dpkg-application",
        "source_kind": source_name.as_ref().map(|_| "go-module"),
        "source_name": source_name,
        "source_repo_url": source_repo_url,
        "evidence_gap": if include_sensitive_process_details {
            format!("Fixer captured a native userspace process at {path}, but no Debian package or source package owns that executable.")
        } else {
            format!("Fixer captured native userspace executable {executable_name}, but no Debian package or source package owns that executable.")
        },
        "recommended_next_steps": recommended_next_steps,
    });
}

pub(crate) fn native_executable_source_hint(
    details: &Value,
    artifact_path: Option<&str>,
) -> Option<NativeExecutableSourceHint> {
    details
        .get("native_executable_provenance")
        .filter(|value| !value.is_null())
        .and_then(native_source_hint_from_provenance)
        .or_else(|| {
            native_executable_path_from_details(details, artifact_path)
                .filter(|path| local_non_dpkg_executable_path(path))
                .and_then(native_source_hint_from_executable_path)
        })
}

pub(crate) fn native_executable_path_from_details<'a>(
    details: &'a Value,
    artifact_path: Option<&'a str>,
) -> Option<&'a str> {
    details
        .get("native_executable_provenance")
        .filter(|value| !value.is_null())
        .and_then(|value| {
            value
                .get("resolved_executable_path")
                .and_then(Value::as_str)
                .or_else(|| value.get("executable_path").and_then(Value::as_str))
        })
        .or_else(|| details.get("executable").and_then(Value::as_str))
        .or_else(|| {
            details
                .get("profile_target")
                .and_then(|value| value.get("path"))
                .and_then(Value::as_str)
        })
        .or_else(|| {
            details
                .get("command_line")
                .and_then(Value::as_str)
                .and_then(first_command_token)
        })
        .or(artifact_path)
}

pub(crate) fn local_non_dpkg_executable_path(path: &str) -> bool {
    let normalized = normalize_deleted_file_marker(path);
    normalized.starts_with("/usr/local/")
        || normalized.starts_with("/opt/")
        || normalized.starts_with("/home/")
        || normalized.starts_with("/var/lib/flatpak/")
        || normalized.starts_with("/snap/")
}

fn native_source_hint_from_provenance(provenance: &Value) -> Option<NativeExecutableSourceHint> {
    let source_repo_url = provenance
        .get("source_repo_url")
        .and_then(Value::as_str)
        .filter(|value| !value.trim().is_empty())
        .map(ToString::to_string);
    let source_name = provenance
        .get("source_name")
        .and_then(Value::as_str)
        .filter(|value| !value.trim().is_empty())
        .map(ToString::to_string);
    let executable_name = provenance
        .get("executable_name")
        .and_then(Value::as_str)
        .filter(|value| !value.trim().is_empty())
        .unwrap_or("local executable")
        .to_string();
    if source_repo_url.is_none() && source_name.is_none() {
        return None;
    }
    Some(NativeExecutableSourceHint {
        executable_name,
        source_name,
        source_repo_url,
    })
}

fn native_source_hint_from_executable_path(path: &str) -> Option<NativeExecutableSourceHint> {
    let path = normalize_deleted_file_marker(path);
    if !command_exists("go") {
        return None;
    }
    let output = command_output_os_with_timeout(
        "go",
        &[OsStr::new("version"), OsStr::new("-m"), OsStr::new(&path)],
        StdDuration::from_secs(GO_VERSION_TIMEOUT_SECONDS),
    )
    .ok()?;
    let source_hint = parse_go_executable_source_hint(&output)?;
    let executable_name = executable_name_from_path(&path)
        .unwrap_or("local executable")
        .to_string();
    Some(NativeExecutableSourceHint {
        executable_name,
        ..source_hint
    })
}

fn executable_name_from_path(path: &str) -> Option<&str> {
    Path::new(path)
        .file_name()
        .and_then(|value| value.to_str())
        .filter(|value| !value.trim().is_empty())
}

fn normalize_deleted_file_marker(raw: &str) -> String {
    raw.trim()
        .trim_start_matches("(deleted) ")
        .trim_end_matches(" (deleted)")
        .to_string()
}

fn parse_go_executable_source_hint(output: &str) -> Option<NativeExecutableSourceHint> {
    let source_name = output
        .lines()
        .find_map(|line| {
            let line = line.trim();
            line.strip_prefix("mod\t")
                .and_then(|rest| rest.split('\t').next())
                .map(str::trim)
                .filter(|value| plausible_go_main_module_path(value))
                .map(ToString::to_string)
        })
        .or_else(|| {
            output.lines().find_map(|line| {
                let line = line.trim();
                line.strip_prefix("path\t")
                    .map(str::trim)
                    .filter(|value| plausible_go_main_module_path(value))
                    .map(ToString::to_string)
            })
        })?;
    let source_repo_url = go_module_repo_url(&source_name);
    Some(NativeExecutableSourceHint {
        executable_name: "local executable".to_string(),
        source_name: Some(source_name),
        source_repo_url,
    })
}

fn plausible_go_main_module_path(value: &str) -> bool {
    !value.is_empty()
        && value.contains('/')
        && value != "command-line-arguments"
        && !value.starts_with("_/")
        && !value.starts_with("./")
        && !value.starts_with("../")
        && !value.starts_with('/')
}

fn go_module_repo_url(module_path: &str) -> Option<String> {
    let mut parts = module_path.split('/');
    let host = parts.next()?;
    let owner = parts.next()?;
    let repo = parts.next()?;
    match host {
        "github.com" | "gitlab.com" | "bitbucket.org" => {
            Some(format!("https://{host}/{owner}/{repo}.git"))
        }
        _ => None,
    }
}

fn first_command_token(command_line: &str) -> Option<&str> {
    command_line.split_whitespace().next()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_go_module_repo_from_version_metadata() {
        let hint = parse_go_executable_source_hint(
            "path\tgithub.com/example/synthetic-runner\nmod\tgithub.com/example/synthetic-runner\t(devel)\n",
        )
        .expect("go module metadata should identify source");

        assert_eq!(
            hint.source_name.as_deref(),
            Some("github.com/example/synthetic-runner")
        );
        assert_eq!(
            hint.source_repo_url.as_deref(),
            Some("https://github.com/example/synthetic-runner.git")
        );
    }

    #[test]
    fn enriches_old_runaway_details_without_sensitive_path() {
        let mut details = json!({
            "subsystem": "runaway-process",
            "profile_target": {
                "name": "synthetic-runner",
                "path": "/usr/local/bin/synthetic-runner"
            }
        });

        enrich_runaway_native_executable_provenance(&mut details, None, false);

        let provenance = details
            .get("native_executable_provenance")
            .expect("provenance should be backfilled");
        assert_eq!(
            provenance.get("executable_name").and_then(Value::as_str),
            Some("synthetic-runner")
        );
        assert_eq!(
            provenance.get("executable_path").and_then(Value::as_str),
            Some("synthetic-runner")
        );
    }
}
