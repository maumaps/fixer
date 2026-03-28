use crate::adapters::inspect_repo;
use crate::config::FixerConfig;
use crate::models::{InstalledPackageMetadata, OpportunityRecord, PreparedWorkspace};
use crate::util::{command_output, command_output_os, maybe_canonicalize};
use anyhow::{Context, Result, anyhow};
use serde_json::Value;
use std::ffi::OsStr;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

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

    let package_name = package_name_from_opportunity(opportunity)
        .ok_or_else(|| anyhow!("opportunity {} has no repo root or package name", opportunity.id))?;
    let metadata = resolve_installed_package_metadata(&package_name)?;

    if deb_src_enabled() {
        if let Ok(repo_root) = ensure_debian_source_tree(config, &metadata.source_package) {
            let repo_root = maybe_canonicalize(&repo_root);
            let ecosystem = inspect_repo(&repo_root).map(|x| x.ecosystem);
            return Ok(PreparedWorkspace {
                repo_root,
                ecosystem,
                source_kind: "debian-source".to_string(),
                package_name: Some(package_name),
                source_package: Some(metadata.source_package),
                homepage: metadata.homepage,
                acquisition_note: "Fetched Debian source package via apt-get source.".to_string(),
            });
        }
    }

    if let Some(homepage) = metadata.homepage.clone() {
        if is_cloneable_repo_url(&homepage) {
            let repo_root = ensure_upstream_clone(config, &metadata.source_package, &homepage)?;
            let repo_root = maybe_canonicalize(&repo_root);
            let ecosystem = inspect_repo(&repo_root).map(|x| x.ecosystem);
            return Ok(PreparedWorkspace {
                repo_root,
                ecosystem,
                source_kind: "upstream-git".to_string(),
                package_name: Some(package_name),
                source_package: Some(metadata.source_package),
                homepage: Some(homepage),
                acquisition_note: "Cloned upstream repository from package homepage because Debian source indexes are unavailable.".to_string(),
            });
        }
    }

    Err(anyhow!(
        "could not acquire a workspace for package {}; enable deb-src or provide a cloneable homepage",
        package_name
    ))
}

pub fn resolve_installed_package_metadata(package_name: &str) -> Result<InstalledPackageMetadata> {
    let dpkg_output = command_output_os(
        "dpkg-query",
        &[
            OsStr::new("-W"),
            OsStr::new(
                "-f=${source:Package}\n${Version}\n${Architecture}\n${Maintainer}\n${Homepage}\n${db:Status-Status}\n",
            ),
            OsStr::new(package_name),
        ],
    )
    .with_context(|| format!("failed to resolve installed package metadata for {package_name}"))?;
    let mut lines = dpkg_output.lines();
    let source_package = lines
        .next()
        .map(str::trim)
        .filter(|x| !x.is_empty())
        .unwrap_or(package_name)
        .to_string();
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
            command_output("apt-cache", &["show", package_name])
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

    let apt_show = command_output("apt-cache", &["show", package_name]).unwrap_or_default();
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
    let apt_policy_raw = command_output("apt-cache", &["policy", package_name]).ok();
    let apt_origins = apt_policy_raw
        .as_deref()
        .map(parse_apt_origins)
        .unwrap_or_default();
    let upgrade_available = installed_version
        .as_deref()
        .zip(candidate_version.as_deref())
        .map(|(installed, candidate)| version_is_newer(candidate, installed))
        .unwrap_or(false);
    let update_command = upgrade_available.then(|| {
        format!("sudo apt-get install --only-upgrade {}", package_name)
    });
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

fn version_is_newer(candidate: &str, installed: &str) -> bool {
    Command::new("dpkg")
        .args(["--compare-versions", candidate, "gt", installed])
        .status()
        .map(|status| status.success())
        .unwrap_or(false)
}

fn ensure_debian_source_tree(config: &FixerConfig, source_package: &str) -> Result<PathBuf> {
    let base_dir = config.service.state_dir.join("sources").join("debian");
    fs::create_dir_all(&base_dir)?;
    if let Some(existing) = find_unpacked_source_dir(&base_dir, source_package) {
        return Ok(existing);
    }
    let output = Command::new("apt-get")
        .args(["source", source_package])
        .current_dir(&base_dir)
        .output()
        .with_context(|| format!("failed to run apt-get source for {source_package}"))?;
    if !output.status.success() {
        return Err(anyhow!(
            "apt-get source failed for {}: {}",
            source_package,
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }
    find_unpacked_source_dir(&base_dir, source_package)
        .ok_or_else(|| anyhow!("apt-get source finished but no unpacked source tree was found"))
}

fn ensure_upstream_clone(config: &FixerConfig, source_package: &str, url: &str) -> Result<PathBuf> {
    let base_dir = config.service.state_dir.join("sources").join("upstream");
    fs::create_dir_all(&base_dir)?;
    let dest = base_dir.join(sanitize_dir_name(source_package));
    if dest.join(".git").is_dir() {
        return Ok(dest);
    }
    if dest.exists() {
        fs::remove_dir_all(&dest)
            .with_context(|| format!("failed to replace stale workspace {}", dest.display()))?;
    }
    let status = Command::new("git")
        .args(["clone", "--depth", "1", url, dest.to_string_lossy().as_ref()])
        .status()
        .with_context(|| format!("failed to clone upstream repository {}", url))?;
    if !status.success() {
        return Err(anyhow!("git clone failed for {}", url));
    }
    Ok(dest)
}

fn find_unpacked_source_dir(base_dir: &Path, source_package: &str) -> Option<PathBuf> {
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
        .filter(|path| path.join("debian").exists() || path.join("Cargo.toml").exists())
        .collect::<Vec<_>>();
    candidates.sort();
    candidates.pop()
}

fn package_name_from_opportunity(opportunity: &OpportunityRecord) -> Option<String> {
    opportunity
        .evidence
        .get("package_name")
        .and_then(Value::as_str)
        .map(ToString::to_string)
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
        || url.ends_with(".git")
}

fn deb_src_enabled() -> bool {
    let apt_dir = Path::new("/etc/apt");
    let mut paths = vec![apt_dir.join("sources.list")];
    if let Ok(entries) = fs::read_dir(apt_dir.join("sources.list.d")) {
        for entry in entries.flatten() {
            let path = entry.path();
            if matches!(path.extension().and_then(|x| x.to_str()), Some("list" | "sources")) {
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
    use super::{is_cloneable_repo_url, parse_apt_origins, parse_maintainer_url, sanitize_dir_name};

    #[test]
    fn detects_cloneable_urls() {
        assert!(is_cloneable_repo_url("https://github.com/uutils/coreutils"));
        assert!(is_cloneable_repo_url("https://example.test/repo.git"));
        assert!(!is_cloneable_repo_url("https://example.test/project-homepage"));
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
    fn parses_url_from_maintainer_field() {
        assert_eq!(
            parse_maintainer_url("Zoom Communications, Inc. <https://support.zoom.com/hc>").as_deref(),
            Some("https://support.zoom.com/hc")
        );
        assert_eq!(
            parse_maintainer_url("Example Maintainer <maintainer@example.test>"),
            None
        );
    }
}
