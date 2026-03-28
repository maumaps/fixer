use crate::models::{RepoInsight, ValidationCommand};
use crate::util::{command_output, maybe_canonicalize, read_text};
use serde_json::{Value, json};
use std::path::{Path, PathBuf};

pub trait EcosystemAdapter {
    fn name(&self) -> &'static str;
    fn detect(&self, repo_root: &Path) -> bool;
    fn inspect_repo(&self, repo_root: &Path) -> Option<RepoInsight>;
}

pub fn inspect_repo(repo_root: &Path) -> Option<RepoInsight> {
    default_adapters()
        .into_iter()
        .find(|adapter| adapter.detect(repo_root))
        .and_then(|adapter| adapter.inspect_repo(repo_root))
}

fn default_adapters() -> Vec<Box<dyn EcosystemAdapter>> {
    vec![
        Box::new(DebianAdapter),
        Box::new(CargoAdapter),
        Box::new(NpmAdapter),
        Box::new(PythonAdapter),
        Box::new(PgxnAdapter),
    ]
}

struct DebianAdapter;
struct CargoAdapter;
struct NpmAdapter;
struct PythonAdapter;
struct PgxnAdapter;

impl EcosystemAdapter for DebianAdapter {
    fn name(&self) -> &'static str {
        "debian"
    }

    fn detect(&self, repo_root: &Path) -> bool {
        repo_root.join("debian/control").is_file() || repo_root.join("debian/changelog").is_file()
    }

    fn inspect_repo(&self, repo_root: &Path) -> Option<RepoInsight> {
        let control = read_text(&repo_root.join("debian/control"))?;
        let source = parse_debian_field(&control, "Source").unwrap_or_else(|| {
            repo_root
                .file_name()
                .and_then(|x| x.to_str())
                .unwrap_or("debian-package")
                .to_string()
        });
        let homepage = parse_debian_field(&control, "Homepage");
        let vcs_git = parse_debian_field(&control, "Vcs-Git");
        let vcs_browser = parse_debian_field(&control, "Vcs-Browser");
        let upstream = vcs_git.or(vcs_browser.clone()).or(homepage.clone());
        let owners = collect_git_owners(repo_root);
        Some(RepoInsight {
            ecosystem: self.name().to_string(),
            display_name: source.clone(),
            upstream_url: upstream.clone(),
            bug_tracker_url: vcs_browser,
            owners,
            summary: format!("Debian packaging repo for {source}"),
            validation: vec![ValidationCommand {
                program: "dpkg-buildpackage".to_string(),
                args: vec!["-us".to_string(), "-uc".to_string(), "-b".to_string()],
            }],
            metadata: json!({
                "homepage": homepage,
                "upstream_url": upstream,
                "source": source,
            }),
        })
    }
}

impl EcosystemAdapter for NpmAdapter {
    fn name(&self) -> &'static str {
        "npm"
    }

    fn detect(&self, repo_root: &Path) -> bool {
        repo_root.join("package.json").is_file()
    }

    fn inspect_repo(&self, repo_root: &Path) -> Option<RepoInsight> {
        let raw = read_text(&repo_root.join("package.json"))?;
        let value: Value = serde_json::from_str(&raw).ok()?;
        let display_name = value
            .get("name")
            .and_then(Value::as_str)
            .unwrap_or_else(|| repo_root.file_name().and_then(|x| x.to_str()).unwrap_or("npm-repo"))
            .to_string();
        let upstream = parse_package_json_url(value.get("repository"));
        let bug_tracker = parse_package_json_url(value.get("bugs"));
        let mut validation = Vec::new();
        if value
            .get("scripts")
            .and_then(|x| x.get("test"))
            .is_some()
        {
            validation.push(ValidationCommand {
                program: "npm".to_string(),
                args: vec!["test".to_string()],
            });
        }
        if value
            .get("scripts")
            .and_then(|x| x.get("lint"))
            .is_some()
        {
            validation.push(ValidationCommand {
                program: "npm".to_string(),
                args: vec!["run".to_string(), "lint".to_string()],
            });
        }
        Some(RepoInsight {
            ecosystem: self.name().to_string(),
            display_name,
            upstream_url: upstream.clone(),
            bug_tracker_url: bug_tracker.clone(),
            owners: collect_git_owners(repo_root),
            summary: "npm workspace or package".to_string(),
            validation,
            metadata: json!({
                "upstream_url": upstream,
                "bug_tracker_url": bug_tracker,
                "package_json": value,
            }),
        })
    }
}

impl EcosystemAdapter for CargoAdapter {
    fn name(&self) -> &'static str {
        "cargo"
    }

    fn detect(&self, repo_root: &Path) -> bool {
        repo_root.join("Cargo.toml").is_file()
    }

    fn inspect_repo(&self, repo_root: &Path) -> Option<RepoInsight> {
        let raw = read_text(&repo_root.join("Cargo.toml"))?;
        let value: toml::Value = toml::from_str(&raw).ok()?;
        let package = value.get("package");
        let display_name = package
            .and_then(|x| x.get("name"))
            .and_then(toml::Value::as_str)
            .or_else(|| repo_root.file_name().and_then(|x| x.to_str()))
            .unwrap_or("cargo-project")
            .to_string();
        let upstream = package
            .and_then(|x| x.get("repository"))
            .and_then(toml::Value::as_str)
            .map(ToString::to_string)
            .or_else(|| {
                package
                    .and_then(|x| x.get("homepage"))
                    .and_then(toml::Value::as_str)
                    .map(ToString::to_string)
            });

        Some(RepoInsight {
            ecosystem: self.name().to_string(),
            display_name,
            upstream_url: upstream.clone(),
            bug_tracker_url: upstream.clone(),
            owners: collect_git_owners(repo_root),
            summary: "Rust Cargo project".to_string(),
            validation: vec![ValidationCommand {
                program: "cargo".to_string(),
                args: vec!["test".to_string(), "--quiet".to_string()],
            }],
            metadata: json!({
                "cargo_toml": value,
                "upstream_url": upstream,
            }),
        })
    }
}

impl EcosystemAdapter for PythonAdapter {
    fn name(&self) -> &'static str {
        "pip"
    }

    fn detect(&self, repo_root: &Path) -> bool {
        repo_root.join("pyproject.toml").is_file()
            || repo_root.join("requirements.txt").is_file()
            || repo_root.join("setup.cfg").is_file()
    }

    fn inspect_repo(&self, repo_root: &Path) -> Option<RepoInsight> {
        let pyproject = repo_root.join("pyproject.toml");
        let pyproject_value = read_text(&pyproject)
            .and_then(|x| toml::from_str::<toml::Value>(&x).ok());
        let display_name = pyproject_value
            .as_ref()
            .and_then(|x| x.get("project"))
            .and_then(|x| x.get("name"))
            .and_then(toml::Value::as_str)
            .map(ToString::to_string)
            .or_else(|| {
                repo_root
                    .file_name()
                    .and_then(|x| x.to_str())
                    .map(ToString::to_string)
            })
            .unwrap_or_else(|| "python-repo".to_string());
        let urls = pyproject_value
            .as_ref()
            .and_then(|x| x.get("project"))
            .and_then(|x| x.get("urls"));
        let upstream = parse_toml_url(urls, &["Repository", "Source", "Homepage", "Home"]);
        let bug_tracker = parse_toml_url(urls, &["Bug Tracker", "Issues", "Bugs"]);
        let validation = if repo_root.join("tests").exists() || repo_root.join("test").exists() {
            vec![ValidationCommand {
                program: "python3".to_string(),
                args: vec!["-m".to_string(), "pytest".to_string(), "-q".to_string()],
            }]
        } else {
            vec![ValidationCommand {
                program: "python3".to_string(),
                args: vec!["-m".to_string(), "compileall".to_string(), ".".to_string()],
            }]
        };
        Some(RepoInsight {
            ecosystem: self.name().to_string(),
            display_name,
            upstream_url: upstream.clone(),
            bug_tracker_url: bug_tracker.clone(),
            owners: collect_git_owners(repo_root),
            summary: "Python package or application".to_string(),
            validation,
            metadata: json!({
                "upstream_url": upstream,
                "bug_tracker_url": bug_tracker,
            }),
        })
    }
}

impl EcosystemAdapter for PgxnAdapter {
    fn name(&self) -> &'static str {
        "pgxn"
    }

    fn detect(&self, repo_root: &Path) -> bool {
        repo_root.join("META.json").is_file()
    }

    fn inspect_repo(&self, repo_root: &Path) -> Option<RepoInsight> {
        let raw = read_text(&repo_root.join("META.json"))?;
        let value: Value = serde_json::from_str(&raw).ok()?;
        let resources = value.get("resources").cloned().unwrap_or_else(|| json!({}));
        let upstream = resources
            .get("repository")
            .and_then(|x| x.get("web"))
            .or_else(|| resources.get("repository").and_then(|x| x.get("url")))
            .and_then(Value::as_str)
            .map(ToString::to_string);
        let bug_tracker = resources
            .get("bugtracker")
            .and_then(|x| x.get("web"))
            .or_else(|| resources.get("bugtracker").and_then(|x| x.get("url")))
            .and_then(Value::as_str)
            .map(ToString::to_string);
        let display_name = value
            .get("name")
            .and_then(Value::as_str)
            .unwrap_or_else(|| repo_root.file_name().and_then(|x| x.to_str()).unwrap_or("pgxn"))
            .to_string();
        let validation = if repo_root.join("t").exists() {
            vec![ValidationCommand {
                program: "prove".to_string(),
                args: vec!["-r".to_string(), "t".to_string()],
            }]
        } else {
            vec![ValidationCommand {
                program: "psql".to_string(),
                args: vec!["--help".to_string()],
            }]
        };
        Some(RepoInsight {
            ecosystem: self.name().to_string(),
            display_name,
            upstream_url: upstream.clone(),
            bug_tracker_url: bug_tracker.clone(),
            owners: collect_git_owners(repo_root),
            summary: "PGXN extension repo".to_string(),
            validation,
            metadata: json!({
                "upstream_url": upstream,
                "bug_tracker_url": bug_tracker,
                "meta": value,
            }),
        })
    }
}

fn parse_debian_field(control: &str, field: &str) -> Option<String> {
    control.lines().find_map(|line| {
        let (name, value) = line.split_once(':')?;
        if name.trim() == field {
            Some(value.trim().to_string())
        } else {
            None
        }
    })
}

fn parse_package_json_url(value: Option<&Value>) -> Option<String> {
    value.and_then(|item| match item {
        Value::String(text) => Some(text.to_string()),
        Value::Object(map) => map
            .get("url")
            .or_else(|| map.get("web"))
            .and_then(Value::as_str)
            .map(ToString::to_string),
        _ => None,
    })
}

fn parse_toml_url(value: Option<&toml::Value>, keys: &[&str]) -> Option<String> {
    let table = value?.as_table()?;
    keys.iter()
        .find_map(|key| table.get(*key))
        .and_then(toml::Value::as_str)
        .map(ToString::to_string)
}

fn collect_git_owners(repo_root: &Path) -> Vec<String> {
    let repo_root = maybe_canonicalize(repo_root);
    let repo_arg = repo_root.to_string_lossy().to_string();
    let output = command_output(
        "git",
        &["-C", &repo_arg, "shortlog", "-sn", "--all", "--no-merges"],
    )
    .unwrap_or_default();
    output
        .lines()
        .take(3)
        .filter_map(|line| {
            let (_, name) = line.trim().split_once('\t')?;
            Some(name.trim().to_string())
        })
        .collect()
}

pub fn resolve_repo_root(path: &Path) -> PathBuf {
    let candidate = maybe_canonicalize(path);
    let arg = candidate.to_string_lossy().to_string();
    command_output("git", &["-C", &arg, "rev-parse", "--show-toplevel"])
        .map(PathBuf::from)
        .unwrap_or(candidate)
}

#[cfg(test)]
mod tests {
    use super::parse_debian_field;

    #[test]
    fn parses_debian_fields() {
        let control = "Source: fixer\nHomepage: https://example.test\n";
        assert_eq!(parse_debian_field(control, "Source").as_deref(), Some("fixer"));
        assert_eq!(
            parse_debian_field(control, "Homepage").as_deref(),
            Some("https://example.test")
        );
    }
}
