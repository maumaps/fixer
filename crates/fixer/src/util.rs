use anyhow::{Context, Result, anyhow};
use chrono::Utc;
use sha2::{Digest, Sha256};
use std::env;
use std::ffi::OsStr;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

pub fn now_rfc3339() -> String {
    Utc::now().to_rfc3339()
}

pub fn hash_text(input: impl AsRef<[u8]>) -> String {
    let digest = Sha256::digest(input.as_ref());
    format!("{digest:x}")
}

pub fn maybe_canonicalize(path: &Path) -> PathBuf {
    path.canonicalize().unwrap_or_else(|_| path.to_path_buf())
}

pub fn find_in_path(binary: &str) -> Option<PathBuf> {
    let path = env::var_os("PATH")?;
    env::split_paths(&path).find_map(|dir| {
        let candidate = dir.join(binary);
        if candidate.is_file() {
            Some(candidate)
        } else {
            None
        }
    })
}

pub fn command_output(program: &str, args: &[&str]) -> Result<String> {
    let output = Command::new(program)
        .args(args)
        .output()
        .with_context(|| format!("failed to run `{program}`"))?;
    command_output_from_status(program, output)
}

pub fn command_output_with_timeout(
    program: &str,
    args: &[&str],
    timeout: Duration,
) -> Result<String> {
    let mut child = Command::new(program)
        .args(args)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .with_context(|| format!("failed to run `{program}`"))?;
    let deadline = Instant::now() + timeout;
    loop {
        if child.try_wait()?.is_some() {
            let output = child
                .wait_with_output()
                .with_context(|| format!("failed to collect `{program}` output"))?;
            return command_output_from_status(program, output);
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            return Err(anyhow!(
                "`{program}` timed out after {}s",
                timeout.as_secs()
            ));
        }
        thread::sleep(Duration::from_millis(50));
    }
}

fn command_output_from_status(program: &str, output: std::process::Output) -> Result<String> {
    if output.status.success() {
        Ok(String::from_utf8_lossy(&output.stdout).trim().to_string())
    } else {
        Err(anyhow!(
            "`{program}` exited with status {}: {}",
            output
                .status
                .code()
                .map(|x| x.to_string())
                .unwrap_or_else(|| "signal".to_string()),
            String::from_utf8_lossy(&output.stderr).trim()
        ))
    }
}

pub fn command_output_os(program: &str, args: &[&OsStr]) -> Result<String> {
    let output = Command::new(program)
        .args(args)
        .output()
        .with_context(|| format!("failed to run `{program}`"))?;
    if output.status.success() {
        Ok(String::from_utf8_lossy(&output.stdout).trim().to_string())
    } else {
        Err(anyhow!(
            "`{program}` exited with status {}: {}",
            output
                .status
                .code()
                .map(|x| x.to_string())
                .unwrap_or_else(|| "signal".to_string()),
            String::from_utf8_lossy(&output.stderr).trim()
        ))
    }
}

pub fn read_text(path: &Path) -> Option<String> {
    std::fs::read_to_string(path).ok()
}

pub fn command_exists(binary: &str) -> bool {
    find_in_path(binary).is_some()
}

pub fn find_postgres_binary(binary: &str) -> Option<PathBuf> {
    if let Some(path) = find_in_path(binary) {
        return Some(path);
    }
    let base = Path::new("/usr/lib/postgresql");
    let mut versions = fs::read_dir(base)
        .ok()?
        .filter_map(|entry| entry.ok())
        .map(|entry| entry.path())
        .filter(|path| path.is_dir())
        .filter_map(|path| {
            let version = path.file_name()?.to_str()?.parse::<i64>().ok()?;
            Some((version, path))
        })
        .collect::<Vec<_>>();
    versions.sort_by(|left, right| right.0.cmp(&left.0));
    versions
        .into_iter()
        .map(|(_, path)| path.join("bin").join(binary))
        .find(|candidate| candidate.is_file())
}
