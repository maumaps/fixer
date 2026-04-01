use crate::models::Capability;
use crate::util::{find_in_path, find_postgres_binary};

const CAPABILITIES: [(&str, &str, &str); 26] = [
    (
        "apt-get",
        "apt-get",
        "APT source retrieval and package download",
    ),
    (
        "addr2line",
        "addr2line",
        "Local symbol lookup from binary offsets",
    ),
    ("apt-cache", "apt-cache", "Debian metadata enrichment"),
    (
        "coredumpctl",
        "coredumpctl",
        "Crash inventory from systemd-coredump",
    ),
    ("cargo", "cargo", "Rust project validation"),
    ("codex", "codex", "AI patch proposal engine"),
    ("bpftrace", "bpftrace", "Optional eBPF probe runtime"),
    ("dkms", "dkms", "Out-of-tree kernel module inventory"),
    ("gdb", "gdb", "Debugger-backed crash inspection"),
    ("git", "git", "Repo discovery and upstream metadata"),
    (
        "journalctl",
        "journalctl",
        "Kernel and service warning ingestion",
    ),
    (
        "dpkg-query",
        "dpkg-query",
        "Debian package ownership lookup",
    ),
    (
        "llvm-symbolizer",
        "llvm-symbolizer",
        "Fallback symbol lookup from binary offsets",
    ),
    ("nm", "nm", "Dynamic symbol table lookup"),
    ("npm", "npm", "npm validation and metadata"),
    (
        "pg_amcheck",
        "pg_amcheck",
        "PostgreSQL index verification utility",
    ),
    ("perf", "perf", "System profiler for hotspot sampling"),
    (
        "pg_lsclusters",
        "pg_lsclusters",
        "PostgreSQL cluster inventory",
    ),
    ("pip-audit", "pip-audit", "Python dependency auditing"),
    ("psql", "psql", "PostgreSQL diagnostics and validation"),
    ("python3", "python3", "Python validation fallback"),
    ("prove", "prove", "PGXN and TAP validation"),
    (
        "runuser",
        "runuser",
        "Privilege drop for service-owned database queries",
    ),
    (
        "systemctl",
        "systemctl",
        "Service management and install target",
    ),
    (
        "strace",
        "strace",
        "Userspace syscall tracing for runaway-process investigations",
    ),
    (
        "ethtool",
        "ethtool",
        "Network interface driver info and EEE status for driver hang investigations",
    ),
];

pub fn detect_capabilities() -> Vec<Capability> {
    CAPABILITIES
        .into_iter()
        .map(|(name, binary, notes)| {
            let path = if name == "pg_amcheck" {
                find_postgres_binary(binary)
            } else {
                find_in_path(binary)
            };
            Capability {
                name: name.to_string(),
                binary: binary.to_string(),
                available: path.is_some(),
                path,
                notes: Some(notes.to_string()),
            }
        })
        .collect()
}
