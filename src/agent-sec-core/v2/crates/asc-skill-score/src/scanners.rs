//! Reuse local scanner engines as audit signals; only the Judge and scoring rules make deductions.

use std::collections::BTreeMap;

use asc_capability_code_scan::Language;
use asc_capability_pii_scan::{PiiScanOptions, PiiScanner};
use asc_capability_prompt_scan::{PromptScanner, ScanConfig, ScanMode};
use asc_model_client::remote::RemoteModel;
use serde_json::{Value, json};

use crate::{
    Error, Result,
    contracts::{array, text},
};

pub(crate) fn redact_value(value: &mut Value, model: &RemoteModel) {
    crate::redaction::value(value);
    match value {
        Value::String(text) => *text = model.redact(text),
        Value::Array(items) => {
            for item in items {
                redact_value(item, model);
            }
        }
        Value::Object(items) => {
            for item in items.values_mut() {
                redact_value(item, model);
            }
        }
        _ => {}
    }
}

pub(crate) fn scan(
    files: &mut BTreeMap<String, String>,
    model: &RemoteModel,
    source: bool,
) -> Result<Value> {
    let pii = PiiScanner::new().map_err(|e| Error::Runtime(e.to_string()))?;
    let prompt = PromptScanner::new(ScanConfig::preset(ScanMode::Fast))
        .map_err(|e| Error::Runtime(e.to_string()))?;
    let masb = crate::masb::Detector::new()?;
    let mut signals = Vec::new();
    for (reference, content) in files {
        *content = crate::redaction::text(&model.redact(content));
        if content.trim().is_empty() {
            continue;
        }
        if source {
            signals.extend(masb.scan(reference, content));
        }
        if !source
            && reference.starts_with("event:")
            && let Ok(event) = serde_json::from_str::<Value>(content)
            && matches!(text(&event, "kind"), "file" | "process_exit")
        {
            continue;
        }
        let pii_result = pii
            .scan(
                content,
                &PiiScanOptions {
                    redact_output: true,
                    ..PiiScanOptions::default()
                },
            )
            .map_err(|e| Error::Runtime(e.to_string()))?;
        if !pii_result.ok
            || pii_result.summary.truncated
            || pii_result.summary.coverage.status
                != asc_capability_pii_scan::CoverageStatus::Complete
            || pii_result.summary.execution_status != asc_capability_pii_scan::ScanStatus::Completed
        {
            return Err(Error::Runtime(
                "PII scanner returned incomplete coverage".into(),
            ));
        }
        for hit in &pii_result.findings {
            signals.push(json!({"scanner":"pii","ref":reference,"detail":hit}));
        }
        if source {
            if pii_result.summary.findings_truncated {
                return Err(Error::Runtime(
                    "source PII findings exceeded safe redaction coverage".into(),
                ));
            }
            *content = redact_source_pii(content, &pii_result.findings)?;
        } else if let Some(redacted) = pii_result.redacted_text {
            *content = redacted;
        }
        let result = prompt
            .scan(content, Some(reference))
            .map_err(|e| Error::Runtime(e.to_string()))?
            .to_json_value();
        if !matches!(text(&result, "verdict"), "pass" | "warn" | "deny")
            || result["degraded"] != false
            || result["input_truncated"] != false
            || !array(&result, "layers_failed").is_empty()
            || !result["findings"].is_array()
        {
            return Err(Error::Runtime(
                "prompt scanner failed or returned incomplete coverage".into(),
            ));
        }
        for hit in array(&result, "findings") {
            signals.push(json!({"scanner":"prompt","ref":reference,"detail":hit}));
        }
        if let Some(language) = code_language(reference) {
            let result = asc_capability_code_scan::scan(content, language, None, "regex");
            if !result.ok {
                return Err(Error::Runtime(result.summary));
            }
            for hit in result.findings {
                signals.push(json!({"scanner":"code","ref":reference,"detail":hit}));
            }
        }
    }
    let mut result = json!({"signals":signals,"scanners":["prompt:fast","code:regex","pii:local","masb:frozen"]});
    redact_value(&mut result, model);
    Ok(result)
}

fn code_language(reference: &str) -> Option<Language> {
    if reference
        .rsplit_once('.')
        .is_some_and(|(_, extension)| extension == "py")
        || reference.contains(":code-python-")
    {
        Some(Language::Python)
    } else if reference
        .rsplit_once('.')
        .is_some_and(|(_, extension)| extension == "sh")
        || reference.contains(":code-bash-")
    {
        Some(Language::Bash)
    } else {
        None
    }
}

fn redact_source_pii(
    content: &str,
    findings: &[asc_capability_pii_scan::PiiFinding],
) -> Result<String> {
    let offsets = content
        .char_indices()
        .map(|(index, _)| index)
        .chain(std::iter::once(content.len()))
        .collect::<Vec<_>>();
    let mut ranges = Vec::new();
    for finding in findings {
        let start = *offsets
            .get(finding.span.start)
            .ok_or_else(|| Error::Runtime("PII source span outside input".into()))?;
        let end = *offsets
            .get(finding.span.end)
            .ok_or_else(|| Error::Runtime("PII source span outside input".into()))?;
        if start > end {
            return Err(Error::Runtime("PII source span reversed".into()));
        }
        let candidate = &content[start..end];
        // Credential literals were already removed; preserve executable expressions for attribution.
        if matches!(
            finding.pii_type.as_str(),
            "generic_secret_field" | "api_key" | "aliyun_access_key_secret"
        ) && (candidate.contains(['(', ')', '[', ']'])
            || (candidate.contains('.')
                && candidate
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '.')))
        {
            continue;
        }
        ranges.push((start, end));
    }
    ranges.sort_unstable();
    let mut merged: Vec<(usize, usize)> = Vec::new();
    for (start, end) in ranges {
        if let Some(last) = merged.last_mut().filter(|(_, last_end)| *last_end >= start) {
            last.1 = last.1.max(end);
        } else {
            merged.push((start, end));
        }
    }
    let mut output = content.to_owned();
    for (start, end) in merged.into_iter().rev() {
        let replacement = format!(
            "[REDACTED]{}",
            "\n".repeat(content[start..end].bytes().filter(|b| *b == b'\n').count())
        );
        output.replace_range(start..end, &replacement);
    }
    Ok(output)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn source_redaction_keeps_security_relevant_expressions_and_removes_pii() -> Result<()> {
        let model = RemoteModel::resolve(
            std::path::Path::new("/nonexistent/score-test"),
            &BTreeMap::from([
                ("ANTHROPIC_API_KEY".into(), "local-test-model-secret".into()),
                (
                    "ANTHROPIC_BASE_URL".into(),
                    "https://dashscope.aliyuncs.com/apps/anthropic".into(),
                ),
            ]),
        )?;
        let source = "token = Path('/app/guard/token').read_text()\nother = os.environ['TOKEN']\nphone = '13812345678'\n";
        let mut files = BTreeMap::from([("run.py".into(), source.into())]);
        let _ = scan(&mut files, &model, true)?;
        let clean = &files["run.py"];
        assert!(clean.contains("token = Path('/app/guard/token').read_text()"));
        assert!(clean.contains("os.environ['TOKEN']"));
        assert!(!clean.contains("13812345678"));
        assert_eq!(clean.lines().count(), source.lines().count());
        Ok(())
    }
}
