use crate::adapters::inspect_repo;
use crate::config::FixerConfig;
use crate::models::{InstalledPackageMetadata, OpportunityRecord, PreparedWorkspace};
use crate::native_provenance::native_executable_source_hint;
use crate::package_integrity::distribution_source_refusal;
use crate::util::{
    command_exists, command_output_in_dir_with_timeout, command_output_os_with_timeout,
    command_output_with_timeout, command_status_in_dir_with_timeout, command_status_with_timeout,
    maybe_canonicalize,
};
use anyhow::{Context, Result, anyhow};
use serde_json::Value;
use std::ffi::OsStr;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::Duration as StdDuration;
use url::Url;

const APT_QUERY_TIMEOUT_SECONDS: u64 = 10;
const DPKG_QUERY_TIMEOUT_SECONDS: u64 = 5;
const VERSION_COMPARE_TIMEOUT_SECONDS: u64 = 2;
const SOURCE_DOWNLOAD_TIMEOUT_SECONDS: u64 = 120;
const GIT_CLONE_TIMEOUT_SECONDS: u64 = 300;
const GIT_REFRESH_TIMEOUT_SECONDS: u64 = 120;
const CURL_DOWNLOAD_TIMEOUT_SECONDS: u64 = 120;
const DPKG_SOURCE_TIMEOUT_SECONDS: u64 = 120;

pub fn ensure_workspace_for_opportunity(
    config: &FixerConfig,
    opportunity: &OpportunityRecord,
) -> Result<PreparedWorkspace> {
    if let Some(repo_root) = &opportunity.repo_root {
        let repo_root = maybe_canonicalize(repo_root);
        let ecosystem = inspect_repo(&repo_root).map(|x| x.ecosystem);
        return Ok(PreparedWorkspace {
            repo_root,
            ecosystem,
            source_kind: "existing-repo".to_string(),
            package_name: package_name_from_opportunity(opportunity),
            source_package: None,
            homepage: None,
            acquisition_note: "Using repository already attached to the opportunity.".to_string(),
        });
    }

    if let Some(workspace_target) = native_executable_source_target(opportunity) {
        let repo_root = ensure_upstream_clone(
            config,
            &workspace_target.source_package,
            workspace_target
                .upstream_url
                .as_deref()
                .expect("native executable source target requires an upstream URL"),
        )?;
        let repo_root = maybe_canonicalize(&repo_root);
        let ecosystem = inspect_repo(&repo_root).map(|x| x.ecosystem);
        return Ok(PreparedWorkspace {
            repo_root,
            ecosystem,
            source_kind: "local-executable-upstream-git".to_string(),
            package_name: None,
            source_package: Some(workspace_target.source_package.clone()),
            homepage: workspace_target.upstream_url.clone(),
            acquisition_note: workspace_target.acquisition_note.unwrap_or_else(|| {
                "Cloned upstream git from local executable build metadata.".to_string()
            }),
        });
    }

    if let Some(workspace_target) = interpreter_source_target(opportunity) {
        if let Some(repo_path) = workspace_target.local_path.as_ref() {
            let repo_root = maybe_canonicalize(repo_path);
            let ecosystem = inspect_repo(&repo_root).map(|x| x.ecosystem);
            return Ok(PreparedWorkspace {
                repo_root,
                ecosystem,
                source_kind: "interpreter-local-repo".to_string(),
                package_name: None,
                source_package: Some(workspace_target.source_package.clone()),
                homepage: workspace_target.upstream_url.clone(),
                acquisition_note: workspace_target.acquisition_note.unwrap_or_else(|| {
                    "Using retained local interpreter workload repository.".to_string()
                }),
            });
        }
        let repo_root = ensure_upstream_clone(
            config,
            &workspace_target.source_package,
            workspace_target
                .upstream_url
                .as_deref()
                .expect("interpreter source target requires an upstream URL"),
        )?;
        let repo_root = maybe_canonicalize(&repo_root);
        let ecosystem = inspect_repo(&repo_root).map(|x| x.ecosystem);
        return Ok(PreparedWorkspace {
            repo_root,
            ecosystem,
            source_kind: "interpreter-upstream-git".to_string(),
            package_name: None,
            source_package: Some(workspace_target.source_package.clone()),
            homepage: workspace_target.upstream_url.clone(),
            acquisition_note: workspace_target.acquisition_note.unwrap_or_else(|| {
                "Cloned upstream git from interpreter module metadata.".to_string()
            }),
        });
    }

    if let Some(workspace_target) = local_artifact_source_target(opportunity) {
        let repo_path = workspace_target
            .local_path
            .as_ref()
            .expect("local artifact source target requires a local path");
        let repo_root = maybe_canonicalize(repo_path);
        let ecosystem = inspect_repo(&repo_root).map(|x| x.ecosystem);
        return Ok(PreparedWorkspace {
            repo_root,
            ecosystem,
            source_kind: "local-artifact-repo".to_string(),
            package_name: None,
            source_package: Some(workspace_target.source_package.clone()),
            homepage: None,
            acquisition_note: workspace_target
                .acquisition_note
                .unwrap_or_else(|| "Using retained local artifact repository.".to_string()),
        });
    }

    // Everything above resolves the workspace from the build that actually ran:
    // a repository attached to the opportunity, the executable's own provenance,
    // a retained local checkout. Everything below assumes the installed files are
    // the distribution's -- so before patching distribution source, check that
    // they still are.
    if let Some(reason) = distribution_source_refusal(&opportunity.evidence) {
        return Err(anyhow!("opportunity {}: {reason}", opportunity.id));
    }

    let package_name = package_name_from_opportunity(opportunity);
    let source_package_hint = source_package_from_opportunity(opportunity);
    let metadata = package_name
        .as_deref()
        .and_then(|name| resolve_installed_package_metadata(name).ok());
    let requested_source_package = source_package_hint
        .or_else(|| metadata.as_ref().map(|pkg| pkg.source_package.clone()))
        .or(package_name.clone())
        .ok_or_else(|| {
            anyhow!(
                "opportunity {} has no repo root, package name, or source package",
                opportunity.id
            )
        })?;
    let workspace_target = metadata
        .as_ref()
        .and_then(|pkg| workspace_source_alias(pkg, &requested_source_package))
        .or_else(|| upstream_source_alias(&requested_source_package))
        .unwrap_or_else(|| WorkspaceSourceTarget {
            source_package: requested_source_package,
            upstream_url: None,
            local_path: None,
            acquisition_note: None,
        });

    if let Some(upstream_url) = workspace_target
        .upstream_url
        .as_deref()
        .or_else(|| kernel_upstream_repo_url(&workspace_target.source_package))
    {
        let repo_root =
            ensure_upstream_clone(config, &workspace_target.source_package, upstream_url)?;
        let repo_root = maybe_canonicalize(&repo_root);
        let ecosystem = inspect_repo(&repo_root).map(|x| x.ecosystem);
        return Ok(PreparedWorkspace {
            repo_root,
            ecosystem,
            source_kind: if workspace_target.upstream_url.is_some() {
                "upstream-git".to_string()
            } else {
                "kernel-upstream-git".to_string()
            },
            package_name,
            source_package: Some(workspace_target.source_package.clone()),
            homepage: Some(upstream_url.to_string()),
            acquisition_note: workspace_target.acquisition_note.unwrap_or_else(|| {
                "Cloned upstream git default branch for a source patch; do not base upstream patches on the installed distro version branch.".to_string()
            }),
        });
    }

    if deb_src_enabled() {
        let installed_version = metadata
            .as_ref()
            .and_then(|pkg| pkg.installed_version.as_deref());
        if let Ok(repo_root) =
            ensure_debian_source_tree(config, &workspace_target.source_package, installed_version)
        {
            let repo_root = maybe_canonicalize(&repo_root);
            let ecosystem = inspect_repo(&repo_root).map(|x| x.ecosystem);
            return Ok(PreparedWorkspace {
                repo_root,
                ecosystem,
                source_kind: "debian-source".to_string(),
                package_name,
                source_package: Some(workspace_target.source_package.clone()),
                homepage: metadata.as_ref().and_then(|pkg| pkg.homepage.clone()),
                acquisition_note: workspace_target
                    .acquisition_note
                    .clone()
                    .unwrap_or_else(|| {
                        "Fetched Debian source package via apt-get source.".to_string()
                    }),
            });
        }
    }

    if let Some(vcs_url) = source_package_vcs_url(&workspace_target.source_package) {
        if is_cloneable_repo_url(&vcs_url) {
            let repo_root =
                ensure_upstream_clone(config, &workspace_target.source_package, &vcs_url)?;
            let repo_root = maybe_canonicalize(&repo_root);
            let ecosystem = inspect_repo(&repo_root).map(|x| x.ecosystem);
            return Ok(PreparedWorkspace {
                repo_root,
                ecosystem,
                source_kind: "debian-vcs-git".to_string(),
                package_name,
                source_package: Some(workspace_target.source_package.clone()),
                homepage: Some(vcs_url),
                acquisition_note: "Cloned Debian packaging VCS from source-package metadata because apt source indexes are unavailable.".to_string(),
            });
        }
    }

    if let Some(homepage) = metadata.as_ref().and_then(|pkg| pkg.homepage.clone()) {
        if is_cloneable_repo_url(&homepage) {
            let repo_root =
                ensure_upstream_clone(config, &workspace_target.source_package, &homepage)?;
            let repo_root = maybe_canonicalize(&repo_root);
            let ecosystem = inspect_repo(&repo_root).map(|x| x.ecosystem);
            return Ok(PreparedWorkspace {
                repo_root,
                ecosystem,
                source_kind: "upstream-git".to_string(),
                package_name,
                source_package: Some(workspace_target.source_package.clone()),
                homepage: Some(homepage),
                acquisition_note: "Cloned upstream repository from package homepage because Debian source indexes are unavailable.".to_string(),
            });
        }
    }

    if metadata
        .as_ref()
        .is_some_and(|pkg| is_external_binary_package_without_workspace(pkg, &workspace_target))
    {
        return Err(anyhow!(
            "could not acquire a workspace for external package {}; no Debian source package, Debian VCS metadata, or cloneable upstream repository is available",
            workspace_target.source_package
        ));
    }

    Err(anyhow!(
        "could not acquire a workspace for {}; enable deb-src, ensure apt-cache showsrc lists downloadable source files, or provide Debian VCS/cloneable upstream metadata",
        workspace_target.source_package
    ))
}

struct WorkspaceSourceTarget {
    source_package: String,
    upstream_url: Option<String>,
    local_path: Option<PathBuf>,
    acquisition_note: Option<String>,
}

pub fn resolve_installed_package_metadata(package_name: &str) -> Result<InstalledPackageMetadata> {
    let dpkg_output = command_output_os_with_timeout(
        "dpkg-query",
        &[
            OsStr::new("-W"),
            OsStr::new(
                "-f=${source:Package}\n${Version}\n${Architecture}\n${Maintainer}\n${Homepage}\n${db:Status-Status}\n",
            ),
            OsStr::new(package_name),
        ],
        StdDuration::from_secs(DPKG_QUERY_TIMEOUT_SECONDS),
    )
    .with_context(|| format!("failed to resolve installed package metadata for {package_name}"))?;
    let mut lines = dpkg_output.lines();
    let source_package = lines
        .next()
        .map(str::trim)
        .filter(|x| !x.is_empty())
        .unwrap_or(package_name)
        .to_string();
    let source_package = normalize_patchable_source_package(package_name, &source_package);
    let installed_version = lines
        .next()
        .map(str::trim)
        .filter(|x| !x.is_empty())
        .map(ToString::to_string);
    let architecture = lines
        .next()
        .map(str::trim)
        .filter(|x| !x.is_empty())
        .map(ToString::to_string);
    let maintainer = lines
        .next()
        .map(str::trim)
        .filter(|x| !x.is_empty())
        .map(ToString::to_string);
    let homepage = lines
        .next()
        .map(str::trim)
        .filter(|x| !x.is_empty())
        .map(ToString::to_string)
        .or_else(|| {
            apt_cache_output(&["show", package_name])
                .ok()
                .and_then(|raw| {
                    raw.lines().find_map(|line| {
                        let (name, value) = line.split_once(':')?;
                        if name.trim() == "Homepage" {
                            let value = value.trim();
                            if value.is_empty() {
                                None
                            } else {
                                Some(value.to_string())
                            }
                        } else {
                            None
                        }
                    })
                })
        });
    let status = lines
        .next()
        .map(str::trim)
        .filter(|x| !x.is_empty())
        .map(ToString::to_string);

    let apt_show = apt_cache_output(&["show", package_name]).unwrap_or_default();
    let candidate_version = parse_deb_field(&apt_show, "Version");
    let vendor = parse_deb_field(&apt_show, "Vendor");
    let bugs_url = parse_deb_field(&apt_show, "Bugs");
    let maintainer_url = maintainer.as_deref().and_then(parse_maintainer_url);
    let (report_url, report_url_source) = if let Some(url) = bugs_url {
        (Some(url), Some("apt-cache show:Bugs".to_string()))
    } else if let Some(url) = maintainer_url {
        (Some(url), Some("dpkg-query:Maintainer".to_string()))
    } else {
        (None, None)
    };
    let apt_policy_raw = apt_cache_output(&["policy", package_name]).ok();
    let apt_origins = apt_policy_raw
        .as_deref()
        .map(parse_apt_origins)
        .unwrap_or_default();
    let upgrade_available = installed_version
        .as_deref()
        .zip(candidate_version.as_deref())
        .map(|(installed, candidate)| version_is_newer(candidate, installed))
        .unwrap_or(false);
    let update_command =
        upgrade_available.then(|| format!("sudo apt-get install --only-upgrade {}", package_name));
    let cloneable_homepage = homepage
        .as_deref()
        .map(is_cloneable_repo_url)
        .unwrap_or(false);

    Ok(InstalledPackageMetadata {
        package_name: package_name.to_string(),
        source_package,
        installed_version,
        candidate_version,
        architecture,
        maintainer,
        vendor,
        homepage,
        report_url,
        report_url_source,
        status,
        apt_policy_raw,
        apt_origins,
        upgrade_available,
        update_command,
        cloneable_homepage,
    })
}

fn parse_deb_field(raw: &str, field_name: &str) -> Option<String> {
    raw.lines().find_map(|line| {
        let (name, value) = line.split_once(':')?;
        if name.trim() == field_name {
            let value = value.trim();
            (!value.is_empty()).then(|| value.to_string())
        } else {
            None
        }
    })
}

fn apt_cache_output(args: &[&str]) -> Result<String> {
    command_output_with_timeout(
        "apt-cache",
        args,
        StdDuration::from_secs(APT_QUERY_TIMEOUT_SECONDS),
    )
}

fn parse_apt_origins(raw: &str) -> Vec<String> {
    raw.lines()
        .filter_map(|line| {
            let line = line.trim();
            ["https://", "http://", "file:"]
                .iter()
                .find_map(|needle| line.find(needle).map(|index| line[index..].to_string()))
        })
        .collect()
}

fn parse_maintainer_url(raw: &str) -> Option<String> {
    let start = raw.find('<')?;
    let end = raw[start + 1..].find('>')?;
    let candidate = raw[start + 1..start + 1 + end].trim();
    (candidate.starts_with("https://") || candidate.starts_with("http://"))
        .then(|| candidate.to_string())
}

fn source_package_vcs_url(source_package: &str) -> Option<String> {
    let raw = apt_cache_output(&["showsrc", source_package]).ok()?;
    parse_deb_field(&raw, "Vcs-Git")
        .and_then(|value| vcs_git_clone_url(&value))
        .or_else(|| parse_deb_field(&raw, "Vcs-Browser"))
        .filter(|value| is_cloneable_repo_url(value))
}

fn vcs_git_clone_url(raw: &str) -> Option<String> {
    let url = raw.split_whitespace().next()?;
    is_cloneable_repo_url(url).then(|| url.to_string())
}

fn is_external_binary_package_without_workspace(
    metadata: &InstalledPackageMetadata,
    workspace_target: &WorkspaceSourceTarget,
) -> bool {
    if metadata.cloneable_homepage {
        return false;
    }
    if metadata
        .homepage
        .as_deref()
        .is_some_and(is_cloneable_repo_url)
    {
        return false;
    }
    let has_non_debian_origin = metadata
        .apt_origins
        .iter()
        .any(|origin| !origin_is_debian_source_friendly(origin));
    has_non_debian_origin
        && metadata.source_package == metadata.package_name
        && workspace_target.source_package == metadata.source_package
        && workspace_target.upstream_url.is_none()
}

fn workspace_source_alias(
    metadata: &InstalledPackageMetadata,
    source_package: &str,
) -> Option<WorkspaceSourceTarget> {
    chrome_workspace_alias(metadata, source_package)
}

fn upstream_source_alias(source_package: &str) -> Option<WorkspaceSourceTarget> {
    let (upstream_url, project_name) = match source_package {
        "systemd" => ("https://github.com/systemd/systemd.git", "systemd"),
        "PackageKit" | "packagekit" => {
            ("https://github.com/PackageKit/PackageKit.git", "PackageKit")
        }
        "htop" => ("https://github.com/htop-dev/htop.git", "htop"),
        pkg if pkg == "postgresql" || pkg.starts_with("postgresql-") => (
            "https://git.postgresql.org/git/postgresql.git",
            "PostgreSQL",
        ),
        _ => return None,
    };

    Some(WorkspaceSourceTarget {
        source_package: source_package.to_string(),
        upstream_url: Some(upstream_url.to_string()),
        local_path: None,
        acquisition_note: Some(format!(
            "Mapped `{source_package}` to the {project_name} upstream git default branch so source patches are prepared against upstream HEAD instead of the installed distro version."
        )),
    })
}

fn native_executable_source_target(
    opportunity: &OpportunityRecord,
) -> Option<WorkspaceSourceTarget> {
    let details = opportunity.evidence.get("details")?;
    let artifact_path = opportunity
        .evidence
        .get("artifact_path")
        .and_then(Value::as_str);
    let source_hint = match native_executable_source_hint(details, artifact_path) {
        Some(source_hint) => source_hint,
        None => return native_executable_handoff_source_target(opportunity),
    };
    let repo_url = source_hint
        .source_repo_url
        .as_deref()
        .filter(|value| is_cloneable_repo_url(value))
        .map(ToString::to_string)
        .or_else(|| native_executable_handoff_source_repo_url(opportunity, &source_hint))?;
    let source_name = source_hint
        .source_name
        .as_deref()
        .filter(|value| !value.trim().is_empty())
        .map(ToString::to_string)
        .or_else(|| source_name_from_repo_url(&repo_url))
        .unwrap_or_else(|| "local-executable-source".to_string());
    Some(WorkspaceSourceTarget {
        source_package: sanitize_dir_name(&source_name),
        upstream_url: Some(repo_url.clone()),
        local_path: None,
        acquisition_note: Some(format!(
            "Cloned {repo_url} from local executable build metadata for {}; rerun Fixer against upstream HEAD instead of discarding the retained local-executable evidence.",
            source_hint.executable_name
        )),
    })
}

fn native_executable_handoff_source_target(
    opportunity: &OpportunityRecord,
) -> Option<WorkspaceSourceTarget> {
    [
        opportunity.evidence.get("details")?.get("handoff"),
        opportunity.evidence.get("handoff"),
    ]
    .into_iter()
    .flatten()
    .find_map(|handoff| {
        handoff
            .get("classification")
            .and_then(Value::as_str)
            .filter(|classification| *classification == "external-local-executable")?;
        let target = handoff
            .get("target")
            .and_then(Value::as_str)
            .map(str::trim)
            .filter(|value| !value.is_empty())?;
        let repo_url = handoff
            .get("report_url")
            .and_then(Value::as_str)
            .map(str::trim)
            .filter(|value| is_cloneable_repo_url(value))?;
        let source_name = source_name_from_repo_url(repo_url)
            .unwrap_or_else(|| "local-executable-source".to_string());
        let executable = target
            .strip_prefix("local executable ")
            .unwrap_or(target)
            .trim();
        let acquisition_note = if executable.is_empty() {
            format!(
                "Cloned {repo_url} from retained {target} handoff; rerun Fixer against upstream HEAD instead of leaving the collected local-executable evidence as report-only."
            )
        } else {
            format!(
                "Cloned {repo_url} from retained local executable handoff for {executable}; rerun Fixer against upstream HEAD instead of leaving the collected local-executable evidence as report-only."
            )
        };
        Some(WorkspaceSourceTarget {
            source_package: sanitize_dir_name(&source_name),
            upstream_url: Some(repo_url.to_string()),
            local_path: None,
            acquisition_note: Some(acquisition_note),
        })
    })
}

fn native_executable_handoff_source_repo_url(
    opportunity: &OpportunityRecord,
    source_hint: &crate::native_provenance::NativeExecutableSourceHint,
) -> Option<String> {
    [
        opportunity.evidence.get("details")?.get("handoff"),
        opportunity.evidence.get("handoff"),
    ]
    .into_iter()
    .flatten()
    .find_map(|handoff| {
        handoff
            .get("classification")
            .and_then(Value::as_str)
            .filter(|classification| *classification == "external-local-executable")?;
        let target = handoff.get("target").and_then(Value::as_str)?;
        if !native_executable_handoff_target_matches(target, source_hint) {
            return None;
        }
        handoff
            .get("report_url")
            .and_then(Value::as_str)
            .map(str::trim)
            .filter(|value| is_cloneable_repo_url(value))
            .map(ToString::to_string)
    })
}

fn native_executable_handoff_target_matches(
    target: &str,
    source_hint: &crate::native_provenance::NativeExecutableSourceHint,
) -> bool {
    let normalized = target
        .trim()
        .strip_prefix("local executable ")
        .unwrap_or_else(|| target.trim())
        .trim()
        .to_ascii_lowercase();
    if normalized.is_empty() {
        return false;
    }
    if normalized == source_hint.executable_name.to_ascii_lowercase() {
        return true;
    }
    source_hint
        .source_name
        .as_deref()
        .and_then(|source_name| source_name.rsplit('/').next())
        .is_some_and(|name| normalized == name.to_ascii_lowercase())
}

fn source_name_from_repo_url(repo_url: &str) -> Option<String> {
    let parsed = Url::parse(repo_url).ok()?;
    let mut segments = parsed.path_segments()?;
    let owner = segments.next()?.trim_matches('/');
    let repo = segments.next()?.trim_matches('/').trim_end_matches(".git");
    (!owner.is_empty() && !repo.is_empty()).then(|| format!("{owner}/{repo}"))
}

fn interpreter_source_target(opportunity: &OpportunityRecord) -> Option<WorkspaceSourceTarget> {
    let process = opportunity
        .evidence
        .get("details")?
        .get("interpreter_process")?;
    let repo_url = process
        .get("source_repo_url")
        .and_then(Value::as_str)
        .filter(|value| is_cloneable_repo_url(value));
    let local_path = process
        .get("source_repo_path")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(PathBuf::from)
        .filter(|path| path.exists());
    if repo_url.is_none() && local_path.is_none() {
        return None;
    }
    let source_name = process
        .get("source_name")
        .and_then(Value::as_str)
        .or_else(|| process.get("suspected_entrypoint").and_then(Value::as_str))
        .filter(|value| !value.trim().is_empty())
        .unwrap_or("interpreter-workload-source");
    let interpreter = process
        .get("interpreter")
        .and_then(Value::as_str)
        .filter(|value| !value.trim().is_empty())
        .unwrap_or("interpreter");
    let entrypoint = process
        .get("suspected_entrypoint")
        .and_then(Value::as_str)
        .filter(|value| !value.trim().is_empty())
        .unwrap_or(source_name);
    Some(WorkspaceSourceTarget {
        source_package: sanitize_dir_name(source_name),
        upstream_url: repo_url.map(ToString::to_string),
        local_path,
        acquisition_note: Some(
            if let Some(path) = process
                .get("source_repo_path")
                .and_then(Value::as_str)
                .filter(|value| !value.trim().is_empty())
            {
                format!(
                    "Using retained local {interpreter} workload repository {path} for {entrypoint}; patch the application entrypoint before considering runtime changes."
                )
            } else {
                let repo_url = repo_url.unwrap_or("");
                format!(
                    "Cloned {repo_url} from {interpreter} module metadata for {entrypoint}; rerun Fixer against upstream HEAD instead of discarding the retained interpreter workload evidence."
                )
            },
        ),
    })
}

fn local_artifact_source_target(opportunity: &OpportunityRecord) -> Option<WorkspaceSourceTarget> {
    let artifact_path = opportunity
        .evidence
        .get("artifact_path")
        .and_then(Value::as_str)
        .or_else(|| {
            opportunity
                .evidence
                .get("details")?
                .get("hot_path_dso_path")?
                .as_str()
        })
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(PathBuf::from)?;
    let search_dir = if artifact_path.is_dir() {
        artifact_path.as_path()
    } else {
        artifact_path.parent()?
    };
    let repo_path = filesystem_git_repo_root_for_path(search_dir)?;
    let source_name = repo_path
        .file_name()
        .and_then(|value| value.to_str())
        .filter(|value| !value.is_empty())
        .unwrap_or("local-artifact-source");
    Some(WorkspaceSourceTarget {
        source_package: sanitize_dir_name(source_name),
        upstream_url: None,
        local_path: Some(repo_path.clone()),
        acquisition_note: Some(format!(
            "Using retained local source repository {} for artifact {}; patch the owning application before considering runtime package changes.",
            repo_path.display(),
            artifact_path.display()
        )),
    })
}

fn filesystem_git_repo_root_for_path(path: &Path) -> Option<PathBuf> {
    path.ancestors()
        .find(|candidate| {
            let git_marker = candidate.join(".git");
            git_marker.is_dir() || git_marker.is_file()
        })
        .map(maybe_canonicalize)
}

fn chrome_workspace_alias(
    metadata: &InstalledPackageMetadata,
    source_package: &str,
) -> Option<WorkspaceSourceTarget> {
    let package_name = metadata.package_name.as_str();
    let is_google_chrome = matches!(
        package_name,
        "google-chrome-stable" | "google-chrome-beta" | "google-chrome-unstable"
    );
    if !is_google_chrome {
        return None;
    }
    let has_google_chrome_origin = metadata.apt_origins.iter().any(|origin| {
        origin
            .to_ascii_lowercase()
            .contains("dl.google.com/linux/chrome")
    });
    let has_chromium_maintainer = metadata
        .maintainer
        .as_deref()
        .is_some_and(|maintainer| maintainer.to_ascii_lowercase().contains("chromium"));
    if !has_google_chrome_origin && !has_chromium_maintainer {
        return None;
    }
    Some(WorkspaceSourceTarget {
        source_package: if source_package == metadata.package_name {
            "chromium".to_string()
        } else {
            source_package.to_string()
        },
        upstream_url: Some("https://chromium.googlesource.com/chromium/src.git".to_string()),
        local_path: None,
        acquisition_note: Some(
            "Mapped Google Chrome to Chromium sources so Fixer can inspect the closest available upstream codebase.".to_string(),
        ),
    })
}

pub(crate) fn origin_is_debian_source_friendly(origin: &str) -> bool {
    let lower = origin.to_ascii_lowercase();
    origin_url(origin).is_some_and(|url| {
        let host = url.host_str().unwrap_or_default().to_ascii_lowercase();
        let path = url.path().to_ascii_lowercase();
        host == "debian.org"
            || host.ends_with(".debian.org")
            || host == "ubuntu.com"
            || host.ends_with(".ubuntu.com")
            || path.starts_with("/debian")
            || path.starts_with("/debian-security")
            || path.starts_with("/ubuntu")
            || path.starts_with("/ubuntu-ports")
    }) || lower.contains("debian.org/debian")
}

fn origin_url(origin: &str) -> Option<Url> {
    let candidate = origin.split_whitespace().next()?;
    Url::parse(candidate).ok()
}

fn version_is_newer(candidate: &str, installed: &str) -> bool {
    command_status_with_timeout(
        "dpkg",
        &["--compare-versions", candidate, "gt", installed],
        StdDuration::from_secs(VERSION_COMPARE_TIMEOUT_SECONDS),
    )
    .map(|status| status.success())
    .unwrap_or(false)
}

fn ensure_debian_source_tree(
    config: &FixerConfig,
    source_package: &str,
    version_hint: Option<&str>,
) -> Result<PathBuf> {
    let base_dir = config.service.state_dir.join("sources").join("debian");
    fs::create_dir_all(&base_dir)?;
    if let Some(existing) = find_unpacked_source_dir(&base_dir, source_package, version_hint) {
        return Ok(existing);
    }
    let source_result = command_output_in_dir_with_timeout(
        "apt-get",
        &["source", source_package],
        &base_dir,
        StdDuration::from_secs(SOURCE_DOWNLOAD_TIMEOUT_SECONDS),
    )
    .with_context(|| format!("failed to run apt-get source for {source_package}"));
    if let Err(source_error) = source_result {
        download_and_unpack_debian_source_from_showsrc(&base_dir, source_package, version_hint)
            .with_context(|| {
                format!(
                    "apt-get source failed for {source_package}: {source_error:#}; fallback download also failed"
                )
            })?;
    }
    find_unpacked_source_dir(&base_dir, source_package, version_hint)
        .ok_or_else(|| anyhow!("apt-get source finished but no unpacked source tree was found"))
}

fn ensure_upstream_clone(config: &FixerConfig, source_package: &str, url: &str) -> Result<PathBuf> {
    let base_dir = config.service.state_dir.join("sources").join("upstream");
    fs::create_dir_all(&base_dir)?;
    let dest = base_dir.join(sanitize_dir_name(source_package));
    if dest.join(".git").is_dir() {
        refresh_upstream_clone_default_branch(&dest)?;
        return Ok(dest);
    }
    if dest.exists() {
        fs::remove_dir_all(&dest)
            .with_context(|| format!("failed to replace stale workspace {}", dest.display()))?;
    }
    let status = command_status_with_timeout(
        "git",
        &[
            "clone",
            "--depth",
            "1",
            url,
            dest.to_string_lossy().as_ref(),
        ],
        StdDuration::from_secs(GIT_CLONE_TIMEOUT_SECONDS),
    )
    .with_context(|| format!("failed to clone upstream repository {}", url))?;
    if !status.success() {
        return Err(anyhow!("git clone failed for {}", url));
    }
    refresh_upstream_clone_default_branch(&dest)?;
    Ok(dest)
}

fn refresh_upstream_clone_default_branch(repo_root: &Path) -> Result<()> {
    let fetch_status = command_status_in_dir_with_timeout(
        "git",
        &["fetch", "--depth", "1", "--prune", "origin"],
        repo_root,
        StdDuration::from_secs(GIT_REFRESH_TIMEOUT_SECONDS),
    )
    .with_context(|| {
        format!(
            "failed to fetch upstream default branch in {}",
            repo_root.display()
        )
    })?;
    if !fetch_status.success() {
        return Err(anyhow!(
            "git fetch failed while refreshing upstream clone {}",
            repo_root.display()
        ));
    }

    let default_branch = upstream_default_branch(repo_root)?;
    let remote_ref = format!("origin/{default_branch}");
    let checkout_status = command_status_in_dir_with_timeout(
        "git",
        &["checkout", "-B", &default_branch, &remote_ref],
        repo_root,
        StdDuration::from_secs(GIT_REFRESH_TIMEOUT_SECONDS),
    )
    .with_context(|| {
        format!(
            "failed to checkout upstream default branch in {}",
            repo_root.display()
        )
    })?;
    if !checkout_status.success() {
        return Err(anyhow!(
            "git checkout failed while refreshing upstream clone {} to {}",
            repo_root.display(),
            remote_ref
        ));
    }

    let reset_status = command_status_in_dir_with_timeout(
        "git",
        &["reset", "--hard", &remote_ref],
        repo_root,
        StdDuration::from_secs(GIT_REFRESH_TIMEOUT_SECONDS),
    )?;
    if !reset_status.success() {
        return Err(anyhow!(
            "git reset failed while refreshing upstream clone {} to {}",
            repo_root.display(),
            remote_ref
        ));
    }

    let clean_status = command_status_in_dir_with_timeout(
        "git",
        &["clean", "-fdx"],
        repo_root,
        StdDuration::from_secs(GIT_REFRESH_TIMEOUT_SECONDS),
    )?;
    if !clean_status.success() {
        return Err(anyhow!(
            "git clean failed while refreshing upstream clone {}",
            repo_root.display()
        ));
    }

    Ok(())
}

fn upstream_default_branch(repo_root: &Path) -> Result<String> {
    if let Ok(raw) = command_output_in_dir_with_timeout(
        "git",
        &["symbolic-ref", "--short", "refs/remotes/origin/HEAD"],
        repo_root,
        StdDuration::from_secs(GIT_REFRESH_TIMEOUT_SECONDS),
    ) && let Some(branch) = raw.trim().strip_prefix("origin/").filter(|x| !x.is_empty())
    {
        return Ok(branch.to_string());
    }

    let set_head_status = command_status_in_dir_with_timeout(
        "git",
        &["remote", "set-head", "origin", "--auto"],
        repo_root,
        StdDuration::from_secs(GIT_REFRESH_TIMEOUT_SECONDS),
    )?;
    if !set_head_status.success() {
        return Err(anyhow!(
            "could not resolve origin default branch in {}",
            repo_root.display()
        ));
    }

    let raw = command_output_in_dir_with_timeout(
        "git",
        &["symbolic-ref", "--short", "refs/remotes/origin/HEAD"],
        repo_root,
        StdDuration::from_secs(GIT_REFRESH_TIMEOUT_SECONDS),
    )?;
    raw.trim()
        .strip_prefix("origin/")
        .filter(|branch| !branch.is_empty())
        .map(ToString::to_string)
        .ok_or_else(|| {
            anyhow!(
                "origin/HEAD did not resolve to a branch in {}",
                repo_root.display()
            )
        })
}

fn find_unpacked_source_dir(
    base_dir: &Path,
    source_package: &str,
    version_hint: Option<&str>,
) -> Option<PathBuf> {
    let mut candidates = fs::read_dir(base_dir)
        .ok()?
        .filter_map(|entry| entry.ok())
        .map(|entry| entry.path())
        .filter(|path| path.is_dir())
        .filter(|path| {
            path.file_name()
                .and_then(|x| x.to_str())
                .map(|name| name.starts_with(source_package))
                .unwrap_or(false)
        })
        .filter(|path| {
            version_hint.is_none_or(|version| {
                let dir_version_hint = source_dir_version_hint(version);
                path.file_name()
                    .and_then(|x| x.to_str())
                    .is_some_and(|name| name.contains(dir_version_hint))
            })
        })
        .filter(|path| path.join("debian").exists() || path.join("Cargo.toml").exists())
        .collect::<Vec<_>>();
    candidates.sort();
    candidates.pop()
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct DebianSourceRecord {
    version: String,
    directory: String,
    files: Vec<String>,
}

fn download_and_unpack_debian_source_from_showsrc(
    base_dir: &Path,
    source_package: &str,
    version_hint: Option<&str>,
) -> Result<()> {
    if !command_exists("curl") {
        return Err(anyhow!(
            "curl is required for Debian source fallback downloads"
        ));
    }
    let raw = apt_cache_output(&["showsrc", source_package])
        .with_context(|| format!("failed to query apt-cache showsrc for {source_package}"))?;
    let records = parse_showsrc_records(&raw);
    let record = select_showsrc_record(&records, version_hint).ok_or_else(|| {
        anyhow!("no matching apt-cache showsrc record found for {source_package}")
    })?;
    for file in &record.files {
        let dest = base_dir.join(file);
        if dest.exists() {
            continue;
        }
        let url = format!(
            "https://deb.debian.org/debian/{}/{}",
            record.directory, file
        );
        let status = command_status_with_timeout(
            "curl",
            &[
                "-fsSL",
                "--retry",
                "2",
                "--output",
                dest.to_string_lossy().as_ref(),
                &url,
            ],
            StdDuration::from_secs(CURL_DOWNLOAD_TIMEOUT_SECONDS),
        )
        .with_context(|| format!("failed to download Debian source file {url}"))?;
        if !status.success() {
            return Err(anyhow!("curl failed while downloading {}", url));
        }
    }
    let dsc = record
        .files
        .iter()
        .find(|name| name.ends_with(".dsc"))
        .ok_or_else(|| anyhow!("Debian source record for {source_package} is missing a .dsc"))?;
    let status = command_status_in_dir_with_timeout(
        "dpkg-source",
        &["-x", dsc],
        base_dir,
        StdDuration::from_secs(DPKG_SOURCE_TIMEOUT_SECONDS),
    )
    .with_context(|| format!("failed to unpack Debian source for {source_package}"))?;
    if !status.success() {
        return Err(anyhow!(
            "dpkg-source -x failed for {}",
            base_dir.join(dsc).display()
        ));
    }
    Ok(())
}

fn parse_showsrc_records(raw: &str) -> Vec<DebianSourceRecord> {
    raw.split("\n\n").filter_map(parse_showsrc_record).collect()
}

fn parse_showsrc_record(raw: &str) -> Option<DebianSourceRecord> {
    let mut version = None;
    let mut directory = None;
    let mut files = Vec::new();
    let mut in_files = false;
    for line in raw.lines() {
        if let Some(value) = line.strip_prefix("Version:") {
            version = Some(value.trim().to_string());
            in_files = false;
            continue;
        }
        if let Some(value) = line.strip_prefix("Directory:") {
            directory = Some(value.trim().to_string());
            in_files = false;
            continue;
        }
        if line.starts_with("Files:") {
            in_files = true;
            continue;
        }
        if in_files {
            if line.starts_with(' ') || line.starts_with('\t') {
                if let Some(file_name) = line.split_whitespace().last() {
                    files.push(file_name.to_string());
                }
                continue;
            }
            in_files = false;
        }
    }
    Some(DebianSourceRecord {
        version: version?,
        directory: directory?,
        files,
    })
}

fn select_showsrc_record<'a>(
    records: &'a [DebianSourceRecord],
    version_hint: Option<&str>,
) -> Option<&'a DebianSourceRecord> {
    if let Some(version_hint) = version_hint {
        let normalized_hint = trim_debian_epoch(version_hint);
        if let Some(record) = records
            .iter()
            .find(|record| trim_debian_epoch(&record.version) == normalized_hint)
        {
            return Some(record);
        }
    }
    records.first()
}

fn trim_debian_epoch(version: &str) -> &str {
    version
        .split_once(':')
        .map(|(_, rest)| rest)
        .unwrap_or(version)
}

fn source_dir_version_hint(version: &str) -> &str {
    let version = trim_debian_epoch(version);
    version
        .rsplit_once('-')
        .map(|(upstream, _)| upstream)
        .unwrap_or(version)
}

fn package_name_from_opportunity(opportunity: &OpportunityRecord) -> Option<String> {
    opportunity
        .evidence
        .get("details")
        .and_then(|details| details.get("interpreter_process"))
        .and_then(|process| process.get("entrypoint_package_name"))
        .and_then(Value::as_str)
        .filter(|value| !value.trim().is_empty())
        .map(ToString::to_string)
        .or_else(|| apparmor_profile_package_from_opportunity(opportunity))
        .or_else(|| {
            opportunity
                .evidence
                .get("package_name")
                .and_then(Value::as_str)
                .map(ToString::to_string)
        })
        .or_else(|| kernel_source_package_from_opportunity(opportunity))
}

fn source_package_from_opportunity(opportunity: &OpportunityRecord) -> Option<String> {
    let package_name = package_name_from_opportunity(opportunity);
    opportunity
        .evidence
        .get("details")
        .and_then(|details| details.get("interpreter_process"))
        .and_then(|process| process.get("entrypoint_package_metadata"))
        .and_then(|metadata| metadata.get("source_package"))
        .or_else(|| {
            opportunity
                .evidence
                .get("details")?
                .get("interpreter_process")?
                .get("entrypoint_package_name")
        })
        .or_else(|| opportunity.evidence.get("source_package"))
        .or_else(|| opportunity.evidence.get("details")?.get("source_package"))
        .or_else(|| {
            opportunity
                .evidence
                .get("details")?
                .get("profile_package_metadata")?
                .get("source_package")
        })
        .or_else(|| {
            opportunity
                .evidence
                .get("details")?
                .get("package_metadata")?
                .get("source_package")
        })
        .or_else(|| {
            opportunity
                .evidence
                .get("details")?
                .get("interpreter_process")?
                .get("runtime_package_metadata")?
                .get("source_package")
        })
        .and_then(Value::as_str)
        .filter(|value| !value.trim().is_empty())
        .map(|value| {
            package_name
                .as_deref()
                .map(|package_name| normalize_patchable_source_package(package_name, value))
                .unwrap_or_else(|| value.to_string())
        })
        .or_else(|| kernel_source_package_from_opportunity(opportunity))
}

fn apparmor_profile_package_from_opportunity(opportunity: &OpportunityRecord) -> Option<String> {
    let details = opportunity.evidence.get("details")?;
    if details.get("subsystem").and_then(Value::as_str) != Some("apparmor") {
        return None;
    }
    if let Some(package_name) = details
        .get("profile_package_name")
        .and_then(Value::as_str)
        .filter(|value| !value.trim().is_empty())
    {
        return Some(package_name.to_string());
    }
    let profile = details
        .get("profile")
        .and_then(Value::as_str)
        .filter(|value| !value.trim().is_empty())?;
    resolve_apparmor_profile_path(profile).and_then(|path| map_system_path_to_package(&path))
}

fn resolve_apparmor_profile_path(profile: &str) -> Option<PathBuf> {
    apparmor_profile_path_candidates(profile)
        .into_iter()
        .find(|candidate| candidate.exists())
}

fn apparmor_profile_path_candidates(profile: &str) -> Vec<PathBuf> {
    let profile = profile.trim();
    if profile.is_empty() {
        return Vec::new();
    }

    let mut candidates = Vec::new();
    let mut push_candidate = |path: PathBuf| {
        if !candidates.contains(&path) {
            candidates.push(path);
        }
    };

    let apparmor_dir = Path::new("/etc/apparmor.d");
    if Path::new(profile).is_absolute() {
        let normalized = profile.trim_start_matches('/').replace('/', ".");
        push_candidate(apparmor_dir.join(normalized));
        if let Some(file_name) = Path::new(profile)
            .file_name()
            .and_then(|value| value.to_str())
        {
            push_candidate(apparmor_dir.join(file_name));
        }
    } else {
        push_candidate(apparmor_dir.join(profile));
        if profile.contains('/') {
            push_candidate(apparmor_dir.join(profile.replace('/', ".")));
        }
    }
    candidates
}

fn map_system_path_to_package(path: &Path) -> Option<String> {
    let output = command_output_os_with_timeout(
        "dpkg-query",
        &[OsStr::new("-S"), path.as_os_str()],
        StdDuration::from_secs(DPKG_QUERY_TIMEOUT_SECONDS),
    )
    .ok()?;
    output
        .lines()
        .next()
        .and_then(|line| line.split_once(':'))
        .map(|(pkg, _)| pkg.to_string())
        .filter(|package_name| !path_is_obsolete_conffile(package_name, path))
}

fn path_is_obsolete_conffile(package_name: &str, path: &Path) -> bool {
    if !path.starts_with("/etc/") {
        return false;
    }
    let Ok(status) = command_output_with_timeout(
        "dpkg-query",
        &["-s", package_name],
        StdDuration::from_secs(DPKG_QUERY_TIMEOUT_SECONDS),
    ) else {
        return false;
    };
    package_status_marks_obsolete_conffile(&status, path)
}

fn package_status_marks_obsolete_conffile(status: &str, path: &Path) -> bool {
    let lookup = path.to_string_lossy();
    let mut in_conffiles = false;
    for line in status.lines() {
        if line == "Conffiles:" {
            in_conffiles = true;
            continue;
        }
        if in_conffiles && !line.starts_with(' ') {
            break;
        }
        if !in_conffiles {
            continue;
        }
        let mut fields = line.split_whitespace();
        if fields.next() == Some(lookup.as_ref()) && fields.any(|field| field == "obsolete") {
            return true;
        }
    }
    false
}

fn normalize_patchable_source_package(package_name: &str, source_package: &str) -> String {
    if (package_name.starts_with("linux-image-")
        || package_name.starts_with("linux-headers-")
        || package_name.starts_with("linux-modules-"))
        && source_package.starts_with("linux-signed")
    {
        return "linux".to_string();
    }
    if package_name.starts_with("linux-image-")
        || package_name.starts_with("linux-headers-")
        || package_name.starts_with("linux-modules-")
    {
        if source_package.starts_with("linux-image")
            || source_package.starts_with("linux-headers")
            || source_package.starts_with("linux-modules")
            || source_package == "linux"
        {
            return "linux".to_string();
        }
    }
    if package_name == "linux" {
        return "linux".to_string();
    }
    source_package.to_string()
}

fn sanitize_dir_name(name: &str) -> String {
    name.chars()
        .map(|ch| {
            if ch.is_ascii_alphanumeric() || ch == '-' || ch == '_' || ch == '.' {
                ch
            } else {
                '_'
            }
        })
        .collect()
}

fn is_cloneable_repo_url(url: &str) -> bool {
    url.starts_with("https://github.com/")
        || url.starts_with("https://gitlab.com/")
        || url.starts_with("https://git.kernel.org/")
        || url.ends_with(".git")
}

fn kernel_upstream_repo_url(source_package: &str) -> Option<&'static str> {
    (source_package == "linux")
        .then_some("https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git")
}

fn kernel_source_package_from_opportunity(opportunity: &OpportunityRecord) -> Option<String> {
    let details = opportunity.evidence.get("details")?;
    let target_name = details
        .get("profile_target")
        .and_then(|value| value.get("name"))
        .and_then(Value::as_str)
        .or_else(|| details.get("process_name").and_then(Value::as_str))
        .or_else(|| details.get("target_name").and_then(Value::as_str));
    target_name
        .filter(|value| is_kernelish_target_name(value))
        .map(|_| "linux".to_string())
}

fn is_kernelish_target_name(value: &str) -> bool {
    let normalized = value.trim().to_ascii_lowercase();
    normalized.starts_with("kworker")
        || normalized.starts_with("jbd2/")
        || normalized.starts_with("kswapd")
        || normalized.starts_with("kcompactd")
        || normalized.starts_with("ksoftirqd")
}

fn deb_src_enabled() -> bool {
    let apt_dir = Path::new("/etc/apt");
    let mut paths = vec![apt_dir.join("sources.list")];
    if let Ok(entries) = fs::read_dir(apt_dir.join("sources.list.d")) {
        for entry in entries.flatten() {
            let path = entry.path();
            if matches!(
                path.extension().and_then(|x| x.to_str()),
                Some("list" | "sources")
            ) {
                paths.push(path);
            }
        }
    }

    for path in paths {
        let Ok(raw) = fs::read_to_string(&path) else {
            continue;
        };
        if path.extension().and_then(|x| x.to_str()) == Some("list") {
            if raw.lines().any(|line| {
                let line = line.trim();
                !line.starts_with('#') && line.starts_with("deb-src ")
            }) {
                return true;
            }
        } else if path.extension().and_then(|x| x.to_str()) == Some("sources") {
            if raw
                .lines()
                .any(|line| line.trim_start().starts_with("Types:") && line.contains("deb-src"))
            {
                return true;
            }
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use super::{
        WorkspaceSourceTarget, apparmor_profile_path_candidates, chrome_workspace_alias,
        interpreter_source_target, is_cloneable_repo_url,
        is_external_binary_package_without_workspace, kernel_source_package_from_opportunity,
        kernel_upstream_repo_url, local_artifact_source_target, native_executable_source_target,
        normalize_patchable_source_package, origin_is_debian_source_friendly,
        package_name_from_opportunity, parse_apt_origins, parse_maintainer_url,
        parse_showsrc_records, sanitize_dir_name, select_showsrc_record, source_dir_version_hint,
        source_package_from_opportunity, source_package_vcs_url, trim_debian_epoch,
        upstream_source_alias, vcs_git_clone_url,
    };
    use crate::models::{InstalledPackageMetadata, OpportunityRecord};
    use serde_json::json;
    use std::fs;
    use std::path::{Path, PathBuf};
    use std::process::Command;

    #[test]
    fn detects_cloneable_urls() {
        assert!(is_cloneable_repo_url("https://github.com/uutils/coreutils"));
        assert!(is_cloneable_repo_url(
            "https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git"
        ));
        assert!(is_cloneable_repo_url("https://example.test/repo.git"));
        assert!(!is_cloneable_repo_url(
            "https://example.test/project-homepage"
        ));
    }

    #[test]
    fn linux_source_package_has_kernel_git_fallback() {
        assert_eq!(
            kernel_upstream_repo_url("linux"),
            Some("https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git")
        );
        assert_eq!(kernel_upstream_repo_url("postgresql-18"), None);
    }

    #[test]
    fn kwin_source_package_has_vcs_git_fallback() {
        let vcs_url = source_package_vcs_url("kwin");
        assert!(
            vcs_url.as_deref() == Some("https://salsa.debian.org/qt-kde-team/kde/kwin.git")
                || vcs_url.is_none()
        );
    }

    #[test]
    fn parses_vcs_git_clone_url_with_branch_options() {
        assert_eq!(
            vcs_git_clone_url("https://salsa.debian.org/postgresql/postgresql.git -b 18")
                .as_deref(),
            Some("https://salsa.debian.org/postgresql/postgresql.git")
        );
    }

    #[test]
    fn parses_showsrc_records_and_matches_version_without_epoch() {
        let raw = "\
Package: kwin
Version: 4:6.5.4-5
Files:
 1b5494 4981 kwin_6.5.4-5.dsc
 258443 8795408 kwin_6.5.4.orig.tar.xz
 b40c20 36120 kwin_6.5.4-5.debian.tar.xz
Directory: pool/main/k/kwin

Package: kwin
Version: 4:6.6.3-3
Files:
 71cd3d 5092 kwin_6.6.3-3.dsc
 61a2e0 8880260 kwin_6.6.3.orig.tar.xz
 c42abb 35708 kwin_6.6.3-3.debian.tar.xz
Directory: pool/main/k/kwin
";
        let records = parse_showsrc_records(raw);
        assert_eq!(records.len(), 2);
        assert_eq!(trim_debian_epoch("4:6.5.4-5"), "6.5.4-5");
        assert_eq!(source_dir_version_hint("4:6.5.4-5"), "6.5.4");
        let record = select_showsrc_record(&records, Some("4:6.5.4-5")).unwrap();
        assert_eq!(record.version, "4:6.5.4-5");
        assert_eq!(record.directory, "pool/main/k/kwin");
        assert_eq!(
            record.files,
            vec![
                "kwin_6.5.4-5.dsc",
                "kwin_6.5.4.orig.tar.xz",
                "kwin_6.5.4-5.debian.tar.xz"
            ]
        );
    }

    #[test]
    fn sanitizes_directory_names() {
        assert_eq!(sanitize_dir_name("pkg:name"), "pkg_name");
    }

    #[test]
    fn parses_apt_origin_lines() {
        let raw = "\
zoom:\n\
  Installed: 1\n\
  Candidate: 2\n\
 *** 2 500\n\
        500 https://example.invalid/deb stable/main amd64 Packages\n";
        assert_eq!(
            parse_apt_origins(raw),
            vec!["https://example.invalid/deb stable/main amd64 Packages".to_string()]
        );
    }

    #[test]
    fn detects_external_binary_package_without_workspace() {
        let metadata = InstalledPackageMetadata {
            package_name: "google-chrome-stable".to_string(),
            source_package: "google-chrome-stable".to_string(),
            installed_version: None,
            candidate_version: None,
            architecture: None,
            maintainer: Some("Chrome Linux Team <chromium-dev@chromium.org>".to_string()),
            vendor: None,
            homepage: None,
            report_url: None,
            report_url_source: None,
            status: Some("installed".to_string()),
            apt_policy_raw: None,
            apt_origins: vec![
                "http://dl.google.com/linux/chrome/deb stable/main amd64 Packages".to_string(),
            ],
            upgrade_available: false,
            update_command: None,
            cloneable_homepage: false,
        };

        let alias = chrome_workspace_alias(&metadata, &metadata.source_package)
            .expect("chrome should map to Chromium sources");
        assert_eq!(alias.source_package, "chromium");
        assert_eq!(
            alias.upstream_url.as_deref(),
            Some("https://chromium.googlesource.com/chromium/src.git")
        );
        assert!(!is_external_binary_package_without_workspace(
            &metadata, &alias
        ));
        assert!(!origin_is_debian_source_friendly(
            "http://dl.google.com/linux/chrome/deb stable/main amd64 Packages"
        ));
    }

    #[test]
    fn maps_systemd_to_upstream_default_branch_source() {
        let target = upstream_source_alias("systemd").expect("systemd should use upstream git");
        assert_eq!(target.source_package, "systemd");
        assert_eq!(
            target.upstream_url.as_deref(),
            Some("https://github.com/systemd/systemd.git")
        );
        assert!(
            target
                .acquisition_note
                .as_deref()
                .unwrap()
                .contains("upstream git default branch")
        );
    }

    #[test]
    fn maps_versioned_postgresql_packages_to_upstream_git() {
        let target =
            upstream_source_alias("postgresql-18").expect("PostgreSQL should use upstream git");
        assert_eq!(target.source_package, "postgresql-18");
        assert_eq!(
            target.upstream_url.as_deref(),
            Some("https://git.postgresql.org/git/postgresql.git")
        );
        assert!(
            target
                .acquisition_note
                .as_deref()
                .unwrap()
                .contains("PostgreSQL upstream git default branch")
        );
    }

    #[test]
    fn maps_local_go_executable_metadata_to_upstream_source() {
        let opportunity = OpportunityRecord {
            id: 1,
            finding_id: 1,
            kind: "investigation".to_string(),
            title: "ollama spins CPU".to_string(),
            score: 100,
            state: "open".to_string(),
            summary: "ollama spins".to_string(),
            evidence: json!({
                "details": {
                    "subsystem": "runaway-process",
                    "native_executable_provenance": {
                        "executable_name": "ollama",
                        "executable_path": "/usr/local/bin/ollama",
                        "source_kind": "go-module",
                        "source_name": "github.com/ollama/ollama",
                        "source_repo_url": "https://github.com/ollama/ollama.git"
                    }
                }
            }),
            repo_root: None,
            ecosystem: None,
            created_at: "2026-05-27T00:00:00Z".to_string(),
            updated_at: "2026-05-27T00:00:00Z".to_string(),
        };

        let target = native_executable_source_target(&opportunity)
            .expect("local executable metadata should map to an upstream source");

        assert_eq!(target.source_package, "github.com_ollama_ollama");
        assert_eq!(
            target.upstream_url.as_deref(),
            Some("https://github.com/ollama/ollama.git")
        );
        assert!(
            target
                .acquisition_note
                .as_deref()
                .is_some_and(|note| note.contains("local executable build metadata"))
        );
    }

    #[test]
    fn maps_local_executable_handoff_report_url_to_upstream_source() {
        let opportunity = OpportunityRecord {
            id: 1,
            finding_id: 1,
            kind: "investigation".to_string(),
            title: "ollama spins CPU".to_string(),
            score: 100,
            state: "open".to_string(),
            summary: "ollama spins".to_string(),
            evidence: json!({
                "details": {
                    "subsystem": "runaway-process",
                    "native_executable_provenance": {
                        "executable_name": "ollama",
                        "executable_path": "/usr/local/bin/ollama",
                        "source_kind": "go-module",
                        "source_name": "github.com/ollama/ollama"
                    },
                    "handoff": {
                        "classification": "external-local-executable",
                        "target": "local executable ollama",
                        "report_url": "https://github.com/ollama/ollama.git"
                    }
                }
            }),
            repo_root: None,
            ecosystem: None,
            created_at: "2026-05-27T00:00:00Z".to_string(),
            updated_at: "2026-05-27T00:00:00Z".to_string(),
        };

        let target = native_executable_source_target(&opportunity)
            .expect("handoff source URL should map to an upstream source");

        assert_eq!(target.source_package, "github.com_ollama_ollama");
        assert_eq!(
            target.upstream_url.as_deref(),
            Some("https://github.com/ollama/ollama.git")
        );
    }

    #[test]
    fn maps_handoff_only_local_executable_report_url_to_upstream_source() {
        let opportunity = OpportunityRecord {
            id: 1,
            finding_id: 1,
            kind: "investigation".to_string(),
            title: "ollama spins CPU".to_string(),
            score: 100,
            state: "open".to_string(),
            summary: "ollama spins".to_string(),
            evidence: json!({
                "details": {
                    "subsystem": "runaway-process",
                    "handoff": {
                        "classification": "external-local-executable",
                        "target": "local executable ollama",
                        "report_url": "https://github.com/ollama/ollama.git"
                    }
                }
            }),
            repo_root: None,
            ecosystem: None,
            created_at: "2026-05-28T00:00:00Z".to_string(),
            updated_at: "2026-05-28T00:00:00Z".to_string(),
        };

        let target = native_executable_source_target(&opportunity)
            .expect("handoff-only source URL should map to an upstream source");

        assert_eq!(target.source_package, "ollama_ollama");
        assert_eq!(
            target.upstream_url.as_deref(),
            Some("https://github.com/ollama/ollama.git")
        );
        assert!(
            target
                .acquisition_note
                .as_deref()
                .is_some_and(|note| note.contains("retained local executable handoff"))
        );
    }

    #[test]
    fn ignores_local_executable_handoff_url_for_mismatched_target() {
        let opportunity = OpportunityRecord {
            id: 1,
            finding_id: 1,
            kind: "investigation".to_string(),
            title: "ollama spins CPU".to_string(),
            score: 100,
            state: "open".to_string(),
            summary: "ollama spins".to_string(),
            evidence: json!({
                "details": {
                    "subsystem": "runaway-process",
                    "native_executable_provenance": {
                        "executable_name": "ollama",
                        "executable_path": "/usr/local/bin/ollama",
                        "source_kind": "go-module",
                        "source_name": "github.com/ollama/ollama"
                    },
                    "handoff": {
                        "classification": "external-local-executable",
                        "target": "local executable synthetic-runner",
                        "report_url": "https://github.com/ollama/ollama.git"
                    }
                }
            }),
            repo_root: None,
            ecosystem: None,
            created_at: "2026-05-27T00:00:00Z".to_string(),
            updated_at: "2026-05-27T00:00:00Z".to_string(),
        };

        assert!(native_executable_source_target(&opportunity).is_none());
    }

    #[test]
    fn maps_python_module_metadata_to_upstream_source() {
        let opportunity = OpportunityRecord {
            id: 1,
            finding_id: 1,
            kind: "investigation".to_string(),
            title: "python module spins CPU".to_string(),
            score: 100,
            state: "open".to_string(),
            summary: "python module spins".to_string(),
            evidence: json!({
                "details": {
                    "subsystem": "runaway-process",
                    "interpreter_process": {
                        "interpreter": "python",
                        "entrypoint_kind": "module",
                        "suspected_entrypoint": "wyoming_faster_whisper",
                        "source_kind": "python-distribution",
                        "source_name": "wyoming-faster-whisper",
                        "source_repo_url": "https://github.com/rhasspy/wyoming-faster-whisper.git"
                    }
                }
            }),
            repo_root: None,
            ecosystem: None,
            created_at: "2026-05-27T00:00:00Z".to_string(),
            updated_at: "2026-05-27T00:00:00Z".to_string(),
        };

        let target = interpreter_source_target(&opportunity)
            .expect("interpreter metadata should map to an upstream source");

        assert_eq!(target.source_package, "wyoming-faster-whisper");
        assert_eq!(
            target.upstream_url.as_deref(),
            Some("https://github.com/rhasspy/wyoming-faster-whisper.git")
        );
        assert!(
            target
                .acquisition_note
                .as_deref()
                .is_some_and(|note| note.contains("interpreter workload evidence"))
        );
    }

    #[test]
    fn maps_python_module_local_repo_path_to_existing_workspace() {
        let dir = tempfile::tempdir().unwrap();
        let repo = dir.path().join("audio-worker");
        fs::create_dir_all(repo.join("home_audio_mesh")).unwrap();
        fs::write(repo.join("home_audio_mesh").join("__init__.py"), "").unwrap();
        Command::new("git")
            .args(["init"])
            .arg(&repo)
            .output()
            .unwrap();
        let opportunity = OpportunityRecord {
            id: 1,
            finding_id: 1,
            kind: "investigation".to_string(),
            title: "python module spins CPU".to_string(),
            score: 100,
            state: "open".to_string(),
            summary: "python module spins".to_string(),
            evidence: json!({
                "details": {
                    "subsystem": "runaway-process",
                    "interpreter_process": {
                        "interpreter": "python",
                        "entrypoint_kind": "module",
                        "suspected_entrypoint": "home_audio_mesh.ml.live_enricher",
                        "source_kind": "local-python-workload",
                        "source_name": "audio-worker",
                        "source_repo_path": repo.display().to_string()
                    }
                }
            }),
            repo_root: None,
            ecosystem: None,
            created_at: "2026-05-27T00:00:00Z".to_string(),
            updated_at: "2026-05-27T00:00:00Z".to_string(),
        };

        let target = interpreter_source_target(&opportunity)
            .expect("local interpreter source should map to a workspace");

        assert_eq!(target.source_package, "audio-worker");
        assert_eq!(target.local_path.as_deref(), Some(repo.as_path()));
        assert!(target.upstream_url.is_none());
    }

    #[test]
    fn maps_local_artifact_path_to_containing_git_repo() {
        let dir = tempfile::tempdir().unwrap();
        let repo = dir.path().join("audio-worker");
        let artifact_path = repo
            .join(".venv")
            .join("lib")
            .join("python3.13")
            .join("site-packages")
            .join("numpy.libs")
            .join("libnative-worker.so");
        fs::create_dir_all(repo.join(".git")).unwrap();
        fs::create_dir_all(artifact_path.parent().unwrap()).unwrap();
        fs::write(
            repo.join("pyproject.toml"),
            "[project]\nname = \"audio-worker\"\n",
        )
        .unwrap();
        fs::write(&artifact_path, "").unwrap();
        let opportunity = OpportunityRecord {
            id: 1,
            finding_id: 1,
            kind: "hotspot".to_string(),
            title: "local extension is hot".to_string(),
            score: 79,
            state: "open".to_string(),
            summary: "local extension is hot".to_string(),
            evidence: json!({
                "artifact_path": artifact_path.display().to_string(),
                "details": {
                    "subsystem": "perf-hotspot",
                    "hot_path_package_name": null,
                    "hot_path_dso_path": artifact_path.display().to_string()
                },
                "package_name": null
            }),
            repo_root: None,
            ecosystem: None,
            created_at: "2026-05-28T00:00:00Z".to_string(),
            updated_at: "2026-05-28T00:00:00Z".to_string(),
        };

        let target = local_artifact_source_target(&opportunity)
            .expect("local artifact path should map to a containing source repo");

        assert_eq!(target.source_package, "audio-worker");
        assert_eq!(target.local_path.as_deref(), Some(repo.as_path()));
        assert!(
            target
                .acquisition_note
                .as_deref()
                .is_some_and(|note| note.contains("owning application"))
        );
    }

    #[test]
    fn maps_packaged_process_local_dso_to_containing_git_repo() {
        let dir = tempfile::tempdir().unwrap();
        let repo = dir.path().join("h3-pg");
        fs::create_dir_all(repo.join(".git")).unwrap();
        fs::create_dir_all(repo.join("build/h3_postgis")).unwrap();
        let artifact_path = repo.join("build/h3_postgis/h3_postgis.so");
        fs::write(&artifact_path, "").unwrap();
        let opportunity = OpportunityRecord {
            id: 1,
            finding_id: 1,
            kind: "hotspot".to_string(),
            title: "postgres extension is hot".to_string(),
            score: 79,
            state: "open".to_string(),
            summary: "postgres extension is hot".to_string(),
            evidence: json!({
                "artifact_path": artifact_path.display().to_string(),
                "details": {
                    "subsystem": "perf-hotspot",
                    "hot_path_package_name": "postgresql-14",
                    "hot_path_dso_path": artifact_path.display().to_string()
                },
                "package_name": "postgresql-14"
            }),
            repo_root: None,
            ecosystem: None,
            created_at: "2026-05-28T00:00:00Z".to_string(),
            updated_at: "2026-05-28T00:00:00Z".to_string(),
        };

        let target = local_artifact_source_target(&opportunity)
            .expect("local DSO path should beat the host process package");

        assert_eq!(target.source_package, "h3-pg");
        assert_eq!(target.local_path.as_deref(), Some(repo.as_path()));
        assert!(
            target
                .acquisition_note
                .as_deref()
                .is_some_and(|note| note.contains("owning application"))
        );
    }

    #[test]
    fn non_aliased_external_binary_package_still_requires_external_handoff() {
        let metadata = InstalledPackageMetadata {
            package_name: "zoom".to_string(),
            source_package: "zoom".to_string(),
            installed_version: None,
            candidate_version: None,
            architecture: None,
            maintainer: Some("Zoom Communications, Inc.".to_string()),
            vendor: None,
            homepage: None,
            report_url: None,
            report_url_source: None,
            status: Some("installed".to_string()),
            apt_policy_raw: None,
            apt_origins: vec![
                "https://zoom.us/linux/download stable/main amd64 Packages".to_string(),
            ],
            upgrade_available: false,
            update_command: None,
            cloneable_homepage: false,
        };

        let target = WorkspaceSourceTarget {
            source_package: metadata.source_package.clone(),
            upstream_url: None,
            local_path: None,
            acquisition_note: None,
        };
        assert!(is_external_binary_package_without_workspace(
            &metadata, &target
        ));
    }

    #[test]
    fn accepts_debian_mirror_paths_as_source_friendly() {
        assert!(origin_is_debian_source_friendly(
            "http://debian.grena.ge/debian stable/main amd64 Packages"
        ));
        assert!(origin_is_debian_source_friendly(
            "http://mirror.hetzner.com/debian/packages trixie/main amd64 Packages"
        ));
        assert!(origin_is_debian_source_friendly(
            "http://ftp.by.debian.org/debian sid/main amd64 Packages"
        ));
        assert!(!origin_is_debian_source_friendly(
            "https://packagecloud.io/slacktechnologies/slack/debian jessie/main amd64 Packages"
        ));
    }

    #[test]
    fn parses_url_from_maintainer_field() {
        assert_eq!(
            parse_maintainer_url("Zoom Communications, Inc. <https://support.zoom.com/hc>")
                .as_deref(),
            Some("https://support.zoom.com/hc")
        );
        assert_eq!(
            parse_maintainer_url("Example Maintainer <maintainer@example.test>"),
            None
        );
    }

    #[test]
    fn normalizes_signed_kernel_source_to_linux() {
        assert_eq!(
            normalize_patchable_source_package(
                "linux-image-6.19.8+deb14-amd64",
                "linux-signed-amd64"
            ),
            "linux"
        );
        assert_eq!(normalize_patchable_source_package("htop", "htop"), "htop");
    }

    #[test]
    fn reads_source_package_hint_from_opportunity_evidence() {
        let opportunity = OpportunityRecord {
            id: 1,
            finding_id: 1,
            kind: "investigation".to_string(),
            title: "kernel issue".to_string(),
            score: 100,
            state: "open".to_string(),
            summary: "summary".to_string(),
            evidence: json!({
                "source_package": "linux",
                "details": {
                    "source_package": "linux-ignored"
                }
            }),
            repo_root: None,
            ecosystem: None,
            created_at: "2026-03-31T00:00:00Z".to_string(),
            updated_at: "2026-03-31T00:00:00Z".to_string(),
        };
        assert_eq!(
            source_package_from_opportunity(&opportunity).as_deref(),
            Some("linux")
        );
    }

    #[test]
    fn reads_source_package_hint_from_package_metadata() {
        let opportunity = OpportunityRecord {
            id: 1,
            finding_id: 1,
            kind: "investigation".to_string(),
            title: "kernel issue".to_string(),
            score: 100,
            state: "open".to_string(),
            summary: "summary".to_string(),
            evidence: json!({
                "package_name": "linux-image-6.19.8+deb14-amd64",
                "details": {
                    "package_metadata": {
                        "source_package": "linux-signed-amd64"
                    }
                }
            }),
            repo_root: None,
            ecosystem: None,
            created_at: "2026-03-31T00:00:00Z".to_string(),
            updated_at: "2026-03-31T00:00:00Z".to_string(),
        };
        assert_eq!(
            source_package_from_opportunity(&opportunity).as_deref(),
            Some("linux")
        );
    }

    #[test]
    fn apparmor_profile_paths_cover_named_and_absolute_profiles() {
        assert_eq!(
            apparmor_profile_path_candidates("lsusb"),
            vec![PathBuf::from("/etc/apparmor.d/lsusb")]
        );
        assert_eq!(
            apparmor_profile_path_candidates("/usr/sbin/cupsd"),
            vec![
                PathBuf::from("/etc/apparmor.d/usr.sbin.cupsd"),
                PathBuf::from("/etc/apparmor.d/cupsd"),
            ]
        );
    }

    #[test]
    fn apparmor_profile_package_beats_mediated_binary_package() {
        let opportunity = OpportunityRecord {
            id: 1,
            finding_id: 1,
            kind: "warning".to_string(),
            title: "AppArmor denial in lsusb".to_string(),
            score: 64,
            state: "open".to_string(),
            summary: "AppArmor denied lsusb: open /".to_string(),
            evidence: json!({
                "package_name": "usbutils",
                "details": {
                    "subsystem": "apparmor",
                    "profile": "lsusb",
                    "profile_package_name": "apparmor",
                    "profile_package_metadata": {
                        "source_package": "apparmor"
                    }
                }
            }),
            repo_root: None,
            ecosystem: None,
            created_at: "2026-05-09T00:00:00Z".to_string(),
            updated_at: "2026-05-09T00:00:00Z".to_string(),
        };

        assert_eq!(
            package_name_from_opportunity(&opportunity).as_deref(),
            Some("apparmor")
        );
        assert_eq!(
            source_package_from_opportunity(&opportunity).as_deref(),
            Some("apparmor")
        );
    }

    #[test]
    fn package_status_detects_obsolete_conffiles() {
        let status = "\
Package: apparmor
Status: install ok installed
Conffiles:
 /etc/apparmor.d/lsb_release e658932af849b5084d780d69b792d6f6
 /etc/apparmor.d/lsusb e0b2a40a7f321065a99a684f576f598a obsolete
 /etc/apparmor.d/lsblk abb3e20c7baecf2177b3b72b0e1a3409 obsolete
Description: user-space parser utility for AppArmor
";

        assert!(super::package_status_marks_obsolete_conffile(
            status,
            Path::new("/etc/apparmor.d/lsusb")
        ));
        assert!(!super::package_status_marks_obsolete_conffile(
            status,
            Path::new("/etc/apparmor.d/lsb_release")
        ));
        assert!(!super::package_status_marks_obsolete_conffile(
            status,
            Path::new("/etc/apparmor.d/not-present")
        ));
    }

    #[test]
    fn prefers_interpreter_entrypoint_package_for_workspace_target() {
        let opportunity = OpportunityRecord {
            id: 1,
            finding_id: 1,
            kind: "investigation".to_string(),
            title: "python loop".to_string(),
            score: 100,
            state: "open".to_string(),
            summary: "python is burning CPU".to_string(),
            evidence: json!({
                "package_name": "python3.13-minimal",
                "details": {
                    "package_metadata": {
                        "source_package": "python3.13"
                    },
                    "interpreter_process": {
                        "interpreter": "python",
                        "suspected_entrypoint": "/usr/bin/fixer-worker",
                        "entrypoint_package_name": "fixer-worker",
                        "entrypoint_package_metadata": {
                            "source_package": "fixer"
                        },
                        "runtime_package_name": "python3.13-minimal",
                        "runtime_package_metadata": {
                            "source_package": "python3.13"
                        }
                    }
                }
            }),
            repo_root: None,
            ecosystem: None,
            created_at: "2026-05-09T00:00:00Z".to_string(),
            updated_at: "2026-05-09T00:00:00Z".to_string(),
        };

        assert_eq!(
            package_name_from_opportunity(&opportunity).as_deref(),
            Some("fixer-worker")
        );
        assert_eq!(
            source_package_from_opportunity(&opportunity).as_deref(),
            Some("fixer")
        );
    }

    #[test]
    fn infers_linux_source_package_from_kernelish_target_name() {
        let opportunity = OpportunityRecord {
            id: 1,
            finding_id: 1,
            kind: "investigation".to_string(),
            title: "stuck kernel thread".to_string(),
            score: 100,
            state: "open".to_string(),
            summary: "summary".to_string(),
            evidence: json!({
                "details": {
                    "profile_target": {
                        "name": "jbd2/sda3-8"
                    }
                }
            }),
            repo_root: None,
            ecosystem: None,
            created_at: "2026-03-31T00:00:00Z".to_string(),
            updated_at: "2026-03-31T00:00:00Z".to_string(),
        };
        assert_eq!(
            kernel_source_package_from_opportunity(&opportunity).as_deref(),
            Some("linux")
        );
        assert_eq!(
            source_package_from_opportunity(&opportunity).as_deref(),
            Some("linux")
        );
    }
}
