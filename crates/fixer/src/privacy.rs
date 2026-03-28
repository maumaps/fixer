use crate::models::ParticipationState;
use crate::util::hash_text;
use regex::Regex;
use serde_json::Value;

pub const PRIVACY_WARNING: &str = "Fixer may unintentionally collect private or sensitive data, including local paths, package metadata, command lines, stack traces, warning lines, and other evidence gathered to diagnose issues. Uploading findings to a server is opt-in. Richer evidence such as raw coredumps or whole repositories requires a second explicit approval.";

pub fn consent_policy_text(policy_version: &str) -> String {
    format!(
        "Fixer Network Participation Policy\nVersion: {policy_version}\n\n{PRIVACY_WARNING}\n\nBy opting in, you allow this machine to submit structured finding bundles to a Fixer server for aggregation and ranking. Known secret patterns are redacted best-effort before upload, but redaction is not perfect. If a worker later requests richer evidence, that requires a second explicit approval."
    )
}

pub fn consent_policy_digest(policy_version: &str) -> String {
    hash_text(consent_policy_text(policy_version))
}

pub fn describe_participation(state: &ParticipationState) -> String {
    format!(
        "mode={:?}, consented_at={}, policy_version={}, richer_evidence_allowed={}",
        state.mode,
        state.consented_at.as_deref().unwrap_or("never"),
        state
            .consented_at
            .as_ref()
            .and(state.consent_policy_version.as_deref())
            .unwrap_or("none"),
        state.richer_evidence_allowed
    )
}

pub fn redact_value(value: &Value) -> (Value, Vec<String>) {
    let mut redactions = Vec::new();
    let redacted = redact_json_value(value, &mut redactions);
    redactions.sort();
    redactions.dedup();
    (redacted, redactions)
}

pub fn redact_string(input: &str) -> (String, Vec<String>) {
    let mut output = input.to_string();
    let mut redactions = Vec::new();
    for (label, regex, replacement) in string_redactions() {
        if regex.is_match(&output) {
            output = regex.replace_all(&output, replacement).to_string();
            redactions.push(label.to_string());
        }
    }
    redactions.sort();
    redactions.dedup();
    (output, redactions)
}

fn redact_json_value(value: &Value, redactions: &mut Vec<String>) -> Value {
    match value {
        Value::String(text) => {
            let (text, notes) = redact_string(text);
            redactions.extend(notes);
            Value::String(text)
        }
        Value::Array(items) => Value::Array(
            items
                .iter()
                .map(|item| redact_json_value(item, redactions))
                .collect(),
        ),
        Value::Object(map) => {
            let mut result = serde_json::Map::with_capacity(map.len());
            for (key, value) in map {
                if sensitive_key(key) {
                    result.insert(key.clone(), Value::String("[redacted]".to_string()));
                    redactions.push(format!("field:{key}"));
                } else {
                    result.insert(key.clone(), redact_json_value(value, redactions));
                }
            }
            Value::Object(result)
        }
        _ => value.clone(),
    }
}

fn sensitive_key(key: &str) -> bool {
    matches!(
        key.to_ascii_lowercase().as_str(),
        "password"
            | "passcode"
            | "pwd"
            | "token"
            | "secret"
            | "access_token"
            | "api_key"
            | "apikey"
            | "authorization"
            | "confid"
            | "confno"
    )
}

fn string_redactions() -> Vec<(&'static str, Regex, &'static str)> {
    vec![
        (
            "query-param-secret",
            Regex::new(
                r"(?i)\b(confno|confid|pwd|passcode|password|token|secret|key|access_token)=([^&\s]+)",
            )
            .expect("valid regex"),
            "$1=[redacted]",
        ),
        (
            "authorization-bearer",
            Regex::new(r"(?i)\b(authorization:\s*bearer)\s+[A-Za-z0-9._~+/=-]+")
                .expect("valid regex"),
            "$1 [redacted]",
        ),
        (
            "inline-secret",
            Regex::new(r"(?i)\b(api[-_]?key|secret|token|password)\b\s*[:=]\s*([^\s,;]+)")
                .expect("valid regex"),
            "$1=[redacted]",
        ),
    ]
}

#[cfg(test)]
mod tests {
    use super::{redact_string, redact_value};
    use serde_json::json;

    #[test]
    fn redacts_common_query_secrets() {
        let (value, notes) = redact_string(
            "zoommtg://zoom.us/join?action=join&browser=chrome&confno=123&pwd=secret",
        );
        assert!(value.contains("action=join"));
        assert!(value.contains("browser=chrome"));
        assert!(value.contains("confno=[redacted]"));
        assert!(value.contains("pwd=[redacted]"));
        assert!(notes.iter().any(|note| note == "query-param-secret"));
    }

    #[test]
    fn redacts_sensitive_json_keys() {
        let (value, notes) = redact_value(&json!({
            "command_line": "token=abc",
            "password": "secret",
        }));
        assert_eq!(value["password"], "[redacted]");
        assert_eq!(value["command_line"], "token=[redacted]");
        assert!(notes.iter().any(|note| note == "field:password"));
    }
}
