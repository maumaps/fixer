use anyhow::{Context, Result, anyhow};
use chrono::Utc;
use sha2::{Digest, Sha256};
use std::env;
use std::ffi::OsStr;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitStatus, Output, Stdio};
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
    let os_args = args.iter().map(OsStr::new).collect::<Vec<_>>();
    command_output_os_with_timeout(program, &os_args, timeout)
}

pub fn command_output_os_with_timeout(
    program: &str,
    args: &[&OsStr],
    timeout: Duration,
) -> Result<String> {
    let output = run_command_os_with_timeout(program, args, None, timeout)?;
    command_output_from_status(program, output)
}

pub fn command_output_in_dir_with_timeout(
    program: &str,
    args: &[&str],
    current_dir: &Path,
    timeout: Duration,
) -> Result<String> {
    let os_args = args.iter().map(OsStr::new).collect::<Vec<_>>();
    let output = run_command_os_with_timeout(program, &os_args, Some(current_dir), timeout)?;
    command_output_from_status(program, output)
}

pub fn command_status_with_timeout(
    program: &str,
    args: &[&str],
    timeout: Duration,
) -> Result<ExitStatus> {
    let os_args = args.iter().map(OsStr::new).collect::<Vec<_>>();
    command_status_os_with_timeout(program, &os_args, timeout)
}

pub fn command_status_in_dir_with_timeout(
    program: &str,
    args: &[&str],
    current_dir: &Path,
    timeout: Duration,
) -> Result<ExitStatus> {
    let os_args = args.iter().map(OsStr::new).collect::<Vec<_>>();
    Ok(run_command_os_with_timeout(program, &os_args, Some(current_dir), timeout)?.status)
}

fn command_status_os_with_timeout(
    program: &str,
    args: &[&OsStr],
    timeout: Duration,
) -> Result<ExitStatus> {
    Ok(run_command_os_with_timeout(program, args, None, timeout)?.status)
}

fn run_command_os_with_timeout(
    program: &str,
    args: &[&OsStr],
    current_dir: Option<&Path>,
    timeout: Duration,
) -> Result<Output> {
    let timeout = timeout.max(Duration::from_secs(1));
    if program != "timeout" && command_exists("timeout") {
        let mut command = Command::new("timeout");
        command
            .arg("--kill-after=2s")
            .arg(format!("{}s", timeout.as_secs()))
            .arg(program)
            .args(args);
        if let Some(current_dir) = current_dir {
            command.current_dir(current_dir);
        }
        let output = command
            .output()
            .with_context(|| format!("failed to run `{program}` with timeout"))?;
        if output.status.code() == Some(124) || output.status.code() == Some(137) {
            return Err(anyhow!(
                "`{program}` timed out after {}s",
                timeout.as_secs()
            ));
        }
        return Ok(output);
    }

    let mut command = Command::new(program);
    command
        .args(args)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    if let Some(current_dir) = current_dir {
        command.current_dir(current_dir);
    }
    let mut child = command
        .spawn()
        .with_context(|| format!("failed to run `{program}`"))?;
    let deadline = Instant::now() + timeout;
    loop {
        if child.try_wait()?.is_some() {
            let output = child
                .wait_with_output()
                .with_context(|| format!("failed to collect `{program}` output"))?;
            return Ok(output);
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

#[cfg(test)]
mod tests {
    use super::{
        command_output_in_dir_with_timeout, command_output_os_with_timeout,
        command_output_with_timeout, command_status_with_timeout,
    };
    use std::ffi::OsStr;
    use std::time::{Duration, Instant};

    #[test]
    fn command_output_with_timeout_bounds_slow_commands() {
        let started = Instant::now();
        let error = command_output_with_timeout("sh", &["-c", "sleep 10"], Duration::from_secs(1))
            .expect_err("slow command should time out");

        assert!(error.to_string().contains("timed out after 1s"));
        assert!(started.elapsed() < Duration::from_secs(5));
    }

    #[test]
    fn command_output_os_with_timeout_collects_stdout() {
        let output = command_output_os_with_timeout(
            "sh",
            &[OsStr::new("-c"), OsStr::new("printf ok")],
            Duration::from_secs(5),
        )
        .expect("command should complete");

        assert_eq!(output, "ok");
    }

    #[test]
    fn command_status_with_timeout_returns_nonzero_status() {
        let status = command_status_with_timeout("sh", &["-c", "exit 7"], Duration::from_secs(5))
            .expect("command should run");

        assert_eq!(status.code(), Some(7));
    }

    #[test]
    fn command_output_in_dir_with_timeout_uses_current_dir() {
        let dir = tempfile::tempdir().expect("tempdir");
        let output = command_output_in_dir_with_timeout(
            "sh",
            &["-c", "pwd"],
            dir.path(),
            Duration::from_secs(5),
        )
        .expect("command should run");

        assert_eq!(output, dir.path().display().to_string());
    }
}
