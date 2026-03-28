use crate::models::Capability;
use crate::util::find_in_path;

const CAPABILITIES: [(&str, &str, &str); 19] = [
    ("apt-get", "apt-get", "APT source retrieval and package download"),
    ("addr2line", "addr2line", "Local symbol lookup from binary offsets"),
    ("apt-cache", "apt-cache", "Debian metadata enrichment"),
    ("coredumpctl", "coredumpctl", "Crash inventory from systemd-coredump"),
    ("cargo", "cargo", "Rust project validation"),
    ("codex", "codex", "AI patch proposal engine"),
    ("bpftrace", "bpftrace", "Optional eBPF probe runtime"),
    ("gdb", "gdb", "Debugger-backed crash inspection"),
    ("git", "git", "Repo discovery and upstream metadata"),
    ("journalctl", "journalctl", "Kernel and service warning ingestion"),
    ("dpkg-query", "dpkg-query", "Debian package ownership lookup"),
    ("llvm-symbolizer", "llvm-symbolizer", "Fallback symbol lookup from binary offsets"),
    ("nm", "nm", "Dynamic symbol table lookup"),
    ("npm", "npm", "npm validation and metadata"),
    ("perf", "perf", "System profiler for hotspot sampling"),
    ("pip-audit", "pip-audit", "Python dependency auditing"),
    ("python3", "python3", "Python validation fallback"),
    ("prove", "prove", "PGXN and TAP validation"),
    ("systemctl", "systemctl", "Service management and install target"),
];

pub fn detect_capabilities() -> Vec<Capability> {
    CAPABILITIES
        .into_iter()
        .map(|(name, binary, notes)| {
            let path = find_in_path(binary);
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
