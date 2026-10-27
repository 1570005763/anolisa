//! Redact credential literals while preserving the source expressions needed for attribution.

use std::sync::LazyLock;

use regex::{Captures, Regex};
use serde_json::Value;

static SHAPES: LazyLock<Vec<Regex>> = LazyLock::new(|| {
    [
        r"(?s)-----BEGIN(?: [A-Z0-9]+)? PRIVATE KEY-----.*?-----END(?: [A-Z0-9]+)? PRIVATE KEY-----",
        r"(?i)\b(?:proxy-)?authorization[^\S\r\n]*:[^\S\r\n]*[^\r\n]+",
        r"(?i)\b(?:set-cookie|cookie)[^\S\r\n]*:[^\S\r\n]*[^\r\n]+",
        r"(?i)\bbearer\s+[A-Za-z0-9._~+/=-]{8,}",
        r"\bsk-ant-[A-Za-z0-9_-]{8,}\b",
        r"\bsk-(?:proj-)?[A-Za-z0-9_-]{16,}\b",
        r"\bgh[pousr]_[A-Za-z0-9]{20,}\b",
        r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b",
        r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b",
        r"(?i)\bhttps?://[^\s/:@]+:[^\s/@]+@",
    ].into_iter().map(|pattern| {
        // All patterns are compile-time constants exercised by the redaction tests.
        Regex::new(pattern).expect("fixed credential expression must compile")
    }).collect()
});

static ASSIGNMENT: LazyLock<Regex> = LazyLock::new(|| {
    // Keep the leading delimiter in the replacement; Rust regex does not need lookbehind.
    Regex::new(r#"(?i)(^|[^A-Za-z0-9_])(["']?(?:agent_sec_model_api_key|anthropic_api_key|anthropic_auth_token|openai_api_key|api[_-]?key|access[_-]?token|refresh[_-]?token|session[_-]?token|client[_-]?secret|authorization|proxy[_-]?authorization|cookie|set[_-]?cookie|token|secret|password|passwd)["']?[^\S\r\n\x1c-\x1e\x85\x{2028}\x{2029}]*[:=][^\S\r\n\x1c-\x1e\x85\x{2028}\x{2029}]*)(["']?)([^\s,;"'}]{4,})"#)
        .expect("fixed credential assignment expression must compile")
});

pub(crate) fn text(input: &str) -> String {
    let mut result = input.to_owned();
    for pattern in SHAPES.iter() {
        result = pattern.replace_all(&result, "[REDACTED]").into_owned();
    }
    ASSIGNMENT
        .replace_all(&result, |captures: &Captures<'_>| {
            let quote = &captures[3];
            let value = &captures[4];
            let identifier = value.contains('.')
                && value
                    .chars()
                    .next()
                    .is_some_and(|c| c.is_ascii_alphabetic() || c == '_')
                && value
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '.'));
            if value.starts_with("[REDACTED]")
                || (quote.is_empty() && (identifier || value.contains(['(', ')', '[', ']'])))
            {
                captures[0].to_owned()
            } else if quote.is_empty() {
                format!("{}{}\"[REDACTED]\"", &captures[1], &captures[2])
            } else {
                format!("{}{}{}[REDACTED]", &captures[1], &captures[2], quote)
            }
        })
        .into_owned()
}

fn sensitive(key: &str) -> bool {
    let canonical = key
        .chars()
        .filter(char::is_ascii_alphanumeric)
        .flat_map(char::to_lowercase)
        .collect::<String>();
    matches!(
        canonical.as_str(),
        "authorization"
            | "proxyauthorization"
            | "cookie"
            | "setcookie"
            | "apikey"
            | "agentsecmodelapikey"
            | "anthropicapikey"
            | "anthropicauthtoken"
            | "openaiapikey"
            | "token"
            | "accesstoken"
            | "refreshtoken"
            | "sessiontoken"
            | "password"
            | "passwd"
            | "secret"
            | "clientsecret"
            | "credential"
            | "credentials"
    )
}

pub(crate) fn value(value: &mut Value) {
    match value {
        Value::String(content) => *content = text(content),
        Value::Array(items) => {
            for item in items {
                self::value(item);
            }
        }
        Value::Object(items) => {
            for (key, item) in items {
                if sensitive(key) {
                    *item = Value::String("[REDACTED]".into());
                } else {
                    self::value(item);
                }
            }
        }
        _ => {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn source_expressions_survive_but_literals_do_not() {
        for expression in [
            "Path('/app/guard/token').read_text()",
            "os.environ['TOKEN']",
            "get_secret()",
            "config.token",
        ] {
            let source = format!("token = {expression}\n");
            assert_eq!(text(&source), source);
        }
        assert_eq!(
            text("api_key = concrete-secret-value"),
            "api_key = \"[REDACTED]\""
        );
        assert_eq!(
            text("token = \"literal-secret-value\""),
            "token = \"[REDACTED]\""
        );
        assert_eq!(
            text("if not api_key:\n  stop()"),
            "if not api_key:\n  stop()"
        );
    }

    #[test]
    fn structured_redaction_remains_valid_json_and_idempotent() -> Result<(), serde_json::Error> {
        let mut evidence = json!({"AGENT_SEC_MODEL_API_KEY":"arbitrary-secret", "headers":{"cookie":"sid=secret"},"code":"token = Path('input').read_text()","n_input_tokens":100});
        value(&mut evidence);
        assert_eq!(evidence["headers"]["cookie"], "[REDACTED]");
        assert_eq!(evidence["AGENT_SEC_MODEL_API_KEY"], "[REDACTED]");
        assert_eq!(evidence["code"], "token = Path('input').read_text()");
        let saved = evidence.clone();
        value(&mut evidence);
        assert_eq!(evidence, saved);
        let encoded = serde_json::to_string(&evidence)?;
        assert_eq!(serde_json::from_str::<Value>(&encoded)?, evidence);
        Ok(())
    }
}
