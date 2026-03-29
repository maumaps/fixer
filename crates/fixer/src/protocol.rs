use semver::Version;

pub const CURRENT_PROTOCOL_VERSION: u32 = 1;
pub const MIN_SUPPORTED_PROTOCOL_VERSION: u32 = 1;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProtocolStatus {
    pub latest_client_version: String,
    pub upgrade_available: bool,
    pub upgrade_required: bool,
    pub upgrade_message: String,
}

pub fn current_binary_version() -> &'static str {
    env!("CARGO_PKG_VERSION")
}

pub fn default_protocol_version() -> u32 {
    CURRENT_PROTOCOL_VERSION
}

pub fn default_server_protocol_version() -> u32 {
    CURRENT_PROTOCOL_VERSION
}

pub fn default_min_supported_protocol_version() -> u32 {
    MIN_SUPPORTED_PROTOCOL_VERSION
}

pub fn default_latest_client_version() -> String {
    current_binary_version().to_string()
}

pub fn evaluate_client_compatibility(
    client_protocol_version: u32,
    client_version: &str,
) -> ProtocolStatus {
    let latest_client_version = default_latest_client_version();
    let upgrade_available = is_binary_upgrade_available(client_version, &latest_client_version);
    if client_protocol_version < MIN_SUPPORTED_PROTOCOL_VERSION {
        return ProtocolStatus {
            latest_client_version: latest_client_version.clone(),
            upgrade_available,
            upgrade_required: true,
            upgrade_message: format!(
                "Fixer protocol v{client_protocol_version} is no longer supported by this server. Upgrade fixer to {latest_client_version} or newer before syncing."
            ),
        };
    }
    if client_protocol_version > CURRENT_PROTOCOL_VERSION {
        return ProtocolStatus {
            latest_client_version,
            upgrade_available: false,
            upgrade_required: true,
            upgrade_message: format!(
                "This client speaks Fixer protocol v{client_protocol_version}, but this server supports up to v{CURRENT_PROTOCOL_VERSION}. Upgrade the server before syncing."
            ),
        };
    }
    if upgrade_available {
        return ProtocolStatus {
            latest_client_version: latest_client_version.clone(),
            upgrade_available: true,
            upgrade_required: false,
            upgrade_message: format!(
                "Fixer {latest_client_version} is available. This client is running {client_version}; please upgrade soon."
            ),
        };
    }
    ProtocolStatus {
        latest_client_version,
        upgrade_available: false,
        upgrade_required: false,
        upgrade_message: String::new(),
    }
}

pub fn is_binary_upgrade_available(client_version: &str, latest_client_version: &str) -> bool {
    let Some(client) = parse_semver(client_version) else {
        return false;
    };
    let Some(latest) = parse_semver(latest_client_version) else {
        return false;
    };
    client < latest
}

fn parse_semver(raw: &str) -> Option<Version> {
    Version::parse(raw.trim().trim_start_matches('v')).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn older_binary_versions_get_upgrade_notice() {
        let status = evaluate_client_compatibility(CURRENT_PROTOCOL_VERSION, "0.0.1");
        assert!(status.upgrade_available);
        assert!(!status.upgrade_required);
        assert!(status.upgrade_message.contains(current_binary_version()));
    }

    #[test]
    fn unsupported_older_protocol_requires_upgrade() {
        let status = evaluate_client_compatibility(MIN_SUPPORTED_PROTOCOL_VERSION - 1, "0.0.1");
        assert!(status.upgrade_required);
        assert!(status.upgrade_message.contains("no longer supported"));
    }

    #[test]
    fn newer_protocol_requires_server_upgrade() {
        let status =
            evaluate_client_compatibility(CURRENT_PROTOCOL_VERSION + 1, current_binary_version());
        assert!(status.upgrade_required);
        assert!(status.upgrade_message.contains("Upgrade the server"));
    }

    #[test]
    fn semver_comparison_handles_two_digit_components() {
        assert!(is_binary_upgrade_available("1.9.0", "1.10.0"));
        assert!(!is_binary_upgrade_available("1.10.0", "1.9.0"));
    }
}
