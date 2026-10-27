//! Frozen oracle schemas plus evidence and execution invariants at the JSON boundary.

use std::collections::{BTreeMap, BTreeSet};

use base64::Engine as _;
use serde_json::{Value, json};

use crate::{Error, Result, source::contained_relative};

pub(crate) fn text<'a>(value: &'a Value, field: &str) -> &'a str {
    value.get(field).and_then(Value::as_str).unwrap_or_default()
}
pub(crate) fn array<'a>(value: &'a Value, field: &str) -> &'a [Value] {
    value
        .get(field)
        .and_then(Value::as_array)
        .map_or(&[], Vec::as_slice)
}
pub(crate) fn strings<'a>(value: &'a Value, field: &str) -> Vec<&'a str> {
    array(value, field)
        .iter()
        .filter_map(Value::as_str)
        .collect()
}
pub(crate) fn flag(value: &Value, field: &str) -> bool {
    value[field].as_bool().unwrap_or(false)
}
pub(crate) fn safe_id(id: &str) -> bool {
    !id.is_empty()
        && id.len() <= 80
        && id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
}
pub(crate) fn schema(stage: &str) -> Result<Value> {
    Ok(serde_json::from_str(if stage == "audit" {
        include_str!("../assets/audit-schema.json")
    } else {
        include_str!("../assets/adjudication-schema.json")
    })?)
}
pub(crate) fn rules() -> Result<Value> {
    Ok(serde_json::from_str(include_str!(
        "../assets/hygiene.json"
    ))?)
}
pub(crate) fn risk_catalog() -> Result<Value> {
    Ok(serde_json::from_str(include_str!(
        "../assets/risk-catalog.json"
    ))?)
}

fn invalid(path: &str, message: &str) -> Error {
    Error::Contract(format!("{path}: {message}"))
}

// Only constructs present in the frozen Pydantic schemas are accepted, including their defaults.
pub(crate) fn normalize(value: &mut Value, schema: &Value, root: &Value, path: &str) -> Result<()> {
    if let Some(reference) = schema["$ref"].as_str() {
        let definition = reference
            .strip_prefix("#/$defs/")
            .and_then(|name| root["$defs"].get(name))
            .ok_or_else(|| invalid(path, "invalid schema reference"))?;
        return normalize(value, definition, root, path);
    }
    if let Some(options) = schema["anyOf"].as_array() {
        for option in options {
            let mut candidate = value.clone();
            if normalize(&mut candidate, option, root, path).is_ok() {
                *value = candidate;
                return Ok(());
            }
        }
        return Err(invalid(path, "invalid union value"));
    }
    if schema["enum"]
        .as_array()
        .is_some_and(|allowed| !allowed.contains(value))
    {
        return Err(invalid(path, "unsupported enum value"));
    }
    match schema["type"].as_str() {
        Some("object") => normalize_object(value, schema, root, path)?,
        Some("array") => {
            let items = value
                .as_array_mut()
                .ok_or_else(|| invalid(path, "expected array"))?;
            let min = schema["minItems"].as_u64().unwrap_or(0);
            let max = schema["maxItems"].as_u64().unwrap_or(8192);
            if (items.len() as u64) < min || items.len() as u64 > max {
                return Err(invalid(path, "invalid array length"));
            }
            for (index, item) in items.iter_mut().enumerate() {
                normalize(item, &schema["items"], root, &format!("{path}[{index}]"))?;
            }
        }
        Some("string") => {
            let string = value
                .as_str()
                .ok_or_else(|| invalid(path, "expected string"))?;
            if string.len() > 2_000_000
                || (string.chars().count() as u64) < schema["minLength"].as_u64().unwrap_or(0)
            {
                return Err(invalid(path, "invalid string length"));
            }
            if let Some(pattern) = schema["pattern"].as_str()
                && !regex::Regex::new(pattern)
                    .map_err(|e| invalid(path, &e.to_string()))?
                    .is_match(string)
            {
                return Err(invalid(path, "invalid string pattern"));
            }
        }
        Some("null") if !value.is_null() => return Err(invalid(path, "expected null")),
        Some("number") if !value.is_number() => return Err(invalid(path, "expected number")),
        Some("boolean") if !value.is_boolean() => return Err(invalid(path, "expected boolean")),
        Some("integer") => {
            let number = value
                .as_i64()
                .ok_or_else(|| invalid(path, "expected integer"))?;
            if number < schema["minimum"].as_i64().unwrap_or(i64::MIN)
                || number > schema["maximum"].as_i64().unwrap_or(i64::MAX)
            {
                return Err(invalid(path, "integer outside bounds"));
            }
        }
        _ => {}
    }
    Ok(())
}

fn normalize_object(value: &mut Value, schema: &Value, root: &Value, path: &str) -> Result<()> {
    let object = value
        .as_object_mut()
        .ok_or_else(|| invalid(path, "expected object"))?;
    if object.len() > 8192 {
        return Err(invalid(path, "too many fields"));
    }
    if let Some(props) = schema["properties"].as_object() {
        if schema["additionalProperties"] == false
            && object.keys().any(|key| !props.contains_key(key))
        {
            return Err(invalid(path, "unknown field"));
        }
        for (key, sub) in props {
            if !object.contains_key(key) {
                if let Some(default) = sub.get("default") {
                    object.insert(key.clone(), default.clone());
                } else if schema["required"]
                    .as_array()
                    .is_some_and(|required| required.iter().any(|v| v == key))
                {
                    return Err(invalid(path, &format!("missing {key}")));
                }
            }
            if let Some(item) = object.get_mut(key) {
                normalize(item, sub, root, &format!("{path}.{key}"))?;
            }
        }
    } else if schema["additionalProperties"].is_object() {
        for (key, item) in object {
            normalize(
                item,
                &schema["additionalProperties"],
                root,
                &format!("{path}.{key}"),
            )?;
        }
    }
    Ok(())
}

pub(crate) fn validate_claims(
    value: &Value,
    catalog: &BTreeMap<String, String>,
    source_only: bool,
) -> Result<()> {
    for collection in ["findings", "control_gaps"] {
        let mut seen = BTreeSet::new();
        for item in array(value, collection) {
            let id = text(item, "id");
            if !safe_id(id) || !seen.insert(id) {
                return Err(invalid(collection, "IDs must be unique safe names"));
            }
            for field in ["refs", "control_refs", "control_test_refs"] {
                for reference in strings(item, field) {
                    if !catalog.contains_key(reference)
                        || (source_only && !reference.starts_with("source:"))
                    {
                        return Err(invalid(id, "unavailable or non-source evidence reference"));
                    }
                }
            }
            if matches!(text(item, "status"), "material_risk" | "unresolved")
                && text(item, "boundary").trim().is_empty()
            {
                return Err(invalid(id, "concrete security boundary is required"));
            }
            if text(item, "status") == "control_gap" {
                let linked = array(value, "control_gaps")
                    .iter()
                    .find(|gap| text(gap, "id") == text(item, "control_gap_id"));
                if text(item, "severity") == "Critical"
                    || linked.is_none_or(|gap| {
                        !matches!(text(gap, "status"), "confirmed" | "uncertain")
                            || !strings(gap, "refs")
                                .iter()
                                .chain(strings(gap, "control_refs").iter())
                                .any(|r| strings(item, "refs").contains(r))
                    })
                {
                    return Err(invalid(
                        id,
                        "control_gap requires matching active non-Critical gap evidence",
                    ));
                }
            }
        }
    }
    if let Some(missing) = value["missing_implementation"].as_object() {
        for (path, refs) in missing {
            if !contained_relative(path)
                || catalog
                    .keys()
                    .any(|r| r.starts_with(&format!("source:{path}:")))
            {
                return Err(invalid(path, "invalid missing implementation"));
            }
            let refs = refs
                .as_array()
                .ok_or_else(|| invalid(path, "missing implementation refs must be an array"))?;
            if refs.is_empty()
                || refs.iter().any(|r| {
                    r.as_str()
                        .is_none_or(|r| !r.starts_with("source:") || !catalog.contains_key(r))
                })
                || !refs.iter().any(|r| {
                    r.as_str()
                        .and_then(|r| catalog.get(r))
                        .is_some_and(|line| line.contains(path))
                })
            {
                return Err(invalid(
                    path,
                    "missing implementation requires source naming that path",
                ));
            }
        }
    }
    Ok(())
}

pub(crate) fn validate_reviews(
    value: &Value,
    catalog: &BTreeMap<String, String>,
    planning: bool,
) -> Result<()> {
    let rules = rules()?;
    let topics = risk_catalog()?;
    for (field, required) in [("hygiene_review", &rules), ("pattern_checks", &topics)] {
        if !planning && field == "pattern_checks" {
            continue;
        }
        let review = value[field]
            .as_object()
            .ok_or_else(|| invalid(field, "review is missing"))?;
        let keys = required
            .as_object()
            .ok_or_else(|| invalid(field, "invalid embedded rules"))?;
        if review.len() != keys.len() || keys.keys().any(|key| !review.contains_key(key)) {
            return Err(invalid(
                field,
                "all catalog rules must be reviewed exactly once",
            ));
        }
        for (id, item) in review {
            let refs = strings(item, "refs");
            if refs.iter().any(|r| !catalog.contains_key(*r))
                || text(item, "reason").trim().is_empty()
                || (field == "hygiene_review"
                    && text(item, "status") == "checked"
                    && (refs.is_empty()
                        || (planning && !refs.iter().any(|r| r.starts_with("source:")))))
            {
                return Err(invalid(
                    id,
                    "review requires reason and applicable evidence",
                ));
            }
        }
    }
    Ok(())
}

pub(crate) fn validate_probes(
    audit: &mut Value,
    files: &BTreeMap<String, String>,
    normalize_ids: bool,
) -> Result<()> {
    select_probes(audit, files, normalize_ids, true)
}

pub(crate) fn select_probes(
    audit: &mut Value,
    files: &BTreeMap<String, String>,
    normalize_ids: bool,
    require_coverage: bool,
) -> Result<()> {
    let findings = array(audit, "findings").to_vec();
    if array(audit, "probes").is_empty()
        && audit["planning_errors"]["baseline"]
            .as_str()
            .is_some_and(|reason| !reason.trim().is_empty())
    {
        if require_coverage
            && findings.iter().any(|f| {
                text(f, "scope") == "skill"
                    && matches!(text(f, "severity"), "Critical" | "High")
                    && matches!(text(f, "status"), "material_risk" | "unresolved")
                    && text(f, "dynamic") != "unsupported"
            })
        {
            return Err(invalid(
                "audit",
                "missing baseline requires explicit unsupported risk paths",
            ));
        }
        return Ok(());
    }
    let probes = audit["probes"]
        .as_array_mut()
        .ok_or_else(|| invalid("audit", "probes missing"))?;
    if probes.len() > 24 {
        return Err(invalid("audit", "more than 24 probes"));
    }
    let baseline_count = probes
        .iter()
        .filter(|p| text(p, "template") == "baseline")
        .count();
    if baseline_count != 1 {
        return Err(invalid("audit", "exactly one baseline is required"));
    }
    let mut ids = BTreeSet::new();
    for probe in probes.iter_mut() {
        if text(probe, "template") == "baseline" && normalize_ids {
            probe["id"] = "baseline".into();
        }
        let id = text(probe, "id").to_owned();
        if !safe_id(&id) || !ids.insert(id.clone()) {
            return Err(invalid("probe", "IDs must be safe and unique"));
        }
        validate_probe_execution(probe, files, &findings)?;
        validate_probe_fixtures(probe)?;
        validate_probe_input(probe)?;
        validate_probe_prerequisites(probe)?;
        validate_probe_observations(probe, &findings)?;
    }
    select_eligible_probes(probes, &findings, normalize_ids)?;
    if require_coverage {
        validate_required_coverage(probes, &findings)?;
    }
    Ok(())
}

fn validate_probe_execution(
    probe: &mut Value,
    files: &BTreeMap<String, String>,
    findings: &[Value],
) -> Result<()> {
    let id = text(probe, "id").to_owned();
    if !contained_relative(text(probe, "entry_path"))
        || !files.contains_key(text(probe, "entry_path"))
    {
        return Err(invalid(
            &id,
            "entry must name an existing reviewed source file",
        ));
    }
    if !matches!(array(probe, "turns").len(), 1 | 3)
        || text(probe, "expected_result").trim().is_empty()
    {
        return Err(invalid(
            &id,
            "one or three turns and concrete expected_result are required",
        ));
    }
    let targeted = strings(probe, "finding_ids");
    if targeted.len() > 1
        || targeted
            .iter()
            .any(|id| !findings.iter().any(|f| text(f, "id") == *id))
    {
        return Err(invalid(&id, "probe must target at most one existing root"));
    }
    let baseline = text(probe, "template") == "baseline";
    if baseline && (!targeted.is_empty() || id != "baseline") {
        return Err(invalid(&id, "baseline cannot target a finding"));
    }
    let required = baseline
        || findings.iter().any(|f| {
            targeted.contains(&text(f, "id"))
                && text(f, "scope") == "skill"
                && matches!(text(f, "severity"), "Critical" | "High")
                && matches!(text(f, "status"), "material_risk" | "unresolved")
        });
    probe["required"] = required.into();
    let target = match text(probe, "template") {
        "filesystem_boundary" => "/app/guard/protected.txt",
        "process_marker" => "/app/guard/command-marker",
        "mock_boundary" => "/forbidden",
        _ => "",
    };
    if !target.is_empty() {
        if !text(probe, "target").is_empty() && text(probe, "target") != target {
            return Err(invalid(&id, "wrong fixed observation target"));
        }
        probe["target"] = target.into();
        if text(probe, "expected_result").contains(target) {
            return Err(invalid(
                &id,
                "business expectation cannot be the security effect",
            ));
        }
    }
    if !baseline && !text(probe, "input_preparation").is_empty() {
        return Err(invalid(
            &id,
            "targeted input must be supplied as fixtures or mocks",
        ));
    }
    Ok(())
}

fn validate_probe_fixtures(probe: &Value) -> Result<()> {
    let id = text(probe, "id");
    let fixtures = probe["fixtures"]
        .as_object()
        .ok_or_else(|| invalid(id, "invalid fixtures"))?;
    for (name, fixture) in fixtures {
        if !contained_relative(name) {
            return Err(invalid(id, "fixture path escapes work directory"));
        }
        for parent in std::path::Path::new(name).ancestors().skip(1) {
            if let Some(parent) = parent.to_str().and_then(|p| fixtures.get(p))
                && text(parent, "kind") != "directory"
            {
                return Err(invalid(id, "fixture parent is not a directory"));
            }
        }
        match text(fixture, "kind") {
            "binary" => {
                let bytes = base64::engine::general_purpose::STANDARD
                    .decode(text(fixture, "content"))
                    .map_err(|_| invalid(id, "fixture base64 invalid"))?;
                if bytes.len() > 1_048_576 {
                    return Err(invalid(id, "fixture binary exceeds 1 MiB"));
                }
                if name
                    .rsplit_once('.')
                    .is_some_and(|(_, extension)| extension == "deb")
                {
                    crate::fixtures::validate_deb(&bytes)?;
                }
            }
            "directory" if !text(fixture, "content").is_empty() => {
                return Err(invalid(id, "directory fixture contains data"));
            }
            "symlink" => {
                let dest = text(fixture, "content");
                if dest != "/app/guard/protected.txt"
                    && !dest
                        .strip_prefix("/app/work/")
                        .is_some_and(contained_relative)
                {
                    return Err(invalid(id, "fixture symlink target is not permitted"));
                }
                if let Some(dest) = dest.strip_prefix("/app/work/")
                    && (dest == name
                        || std::path::Path::new(dest).ancestors().any(|p| {
                            p.to_str()
                                .and_then(|p| fixtures.get(p))
                                .is_some_and(|f| text(f, "kind") == "symlink")
                        }))
                {
                    return Err(invalid(id, "fixture symlink chains are unsupported"));
                }
            }
            "deb" => {
                return Err(invalid(
                    id,
                    "Debian fixture must be materialized before validation",
                ));
            }
            _ => {}
        }
    }
    Ok(())
}

fn validate_probe_input(probe: &Value) -> Result<()> {
    let id = text(probe, "id");
    let baseline = text(probe, "template") == "baseline";
    let fixtures = probe["fixtures"]
        .as_object()
        .ok_or_else(|| invalid(id, "invalid fixtures"))?;
    let input = text(probe, "input_path");
    if input.is_empty()
        && (!fixtures.is_empty() || !text(probe, "input_preparation").is_empty() || !baseline)
    {
        return Err(invalid(
            id,
            "task requires the actual consumption input_path",
        ));
    }
    if let Some(relative) = input.strip_prefix("/app/work/") {
        if !contained_relative(relative) {
            return Err(invalid(id, "input path is not contained"));
        }
        let directory = fixtures
            .get(relative)
            .is_some_and(|f| text(f, "kind") == "directory")
            || fixtures
                .keys()
                .any(|f| f.starts_with(&format!("{relative}/")));
        if !fixtures.contains_key(relative)
            && !directory
            && text(probe, "input_preparation").is_empty()
        {
            return Err(invalid(id, "input is absent from fixtures"));
        }
        let payload = text(probe, "payload_path");
        if !baseline && directory && payload.is_empty() {
            return Err(invalid(id, "directory probe needs payload_path"));
        }
        if !payload.is_empty() {
            let valid = payload.strip_prefix("/app/work/").is_some_and(|p| {
                fixtures.contains_key(p)
                    && (p == relative || p.starts_with(&format!("{relative}/")))
                    && text(&fixtures[p], "kind") != "directory"
            });
            if !valid {
                return Err(invalid(
                    id,
                    "payload_path must name a supplied file or link within input_path",
                ));
            }
        }
    } else if !input.is_empty()
        && input != "/allowed"
        && probe["mock_responses"].get(input).is_none()
    {
        return Err(invalid(
            id,
            "input must be a work path or configured mock route",
        ));
    }
    Ok(())
}

fn validate_probe_prerequisites(probe: &Value) -> Result<()> {
    let id = text(probe, "id");
    let input = text(probe, "input_path");
    if strings(probe, "required_tools").iter().any(|v| {
        v.is_empty()
            || !v.starts_with(|c: char| c.is_ascii_alphanumeric())
            || !v
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"._+-".contains(&b))
    }) {
        return Err(invalid(id, "invalid tool name"));
    }
    if strings(probe, "required_modules").iter().any(|v| {
        v.split('.').any(|part| {
            part.is_empty()
                || !part.starts_with(|c: char| c.is_ascii_alphabetic() || c == '_')
                || !part.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_')
        })
    }) {
        return Err(invalid(id, "invalid module name"));
    }
    if !input.starts_with("/app/work/") && !text(probe, "payload_path").is_empty() {
        return Err(invalid(id, "mock input cannot use a file payload_path"));
    }
    Ok(())
}

fn validate_probe_observations(probe: &Value, findings: &[Value]) -> Result<()> {
    let id = text(probe, "id");
    if text(probe, "entry_path") == "SKILL.md"
        && strings(probe, "finding_ids").iter().any(|id| {
            findings
                .iter()
                .find(|f| text(f, "id") == *id)
                .is_some_and(|f| {
                    strings(f, "refs").iter().any(|r| {
                        r.strip_prefix("source:")
                            .and_then(|r| r.rsplit_once(':'))
                            .is_some_and(|(p, _)| {
                                [".py", ".sh", ".js", ".ts"]
                                    .iter()
                                    .any(|extension| p.ends_with(extension))
                            })
                    })
                })
        })
    {
        return Err(invalid(
            id,
            "risk cites executable source; use its actual script entry",
        ));
    }
    for path in strings(probe, "observe_paths") {
        if !(path.starts_with("/app/") || path.starts_with("/tmp/"))
            || path.split('/').any(|p| p == "..")
        {
            return Err(invalid(id, "observation path escapes disposable paths"));
        }
    }
    if probe["mock_responses"].as_object().is_some_and(|routes| {
        routes
            .keys()
            .any(|p| !p.starts_with('/') || p.contains('?') || p == "/forbidden")
    }) {
        return Err(invalid(id, "invalid or reserved mock route"));
    }
    Ok(())
}

fn select_eligible_probes(
    probes: &mut Vec<Value>,
    findings: &[Value],
    normalize_ids: bool,
) -> Result<()> {
    let active = findings.iter().any(|f| {
        text(f, "scope") == "skill" && matches!(text(f, "status"), "material_risk" | "unresolved")
    });
    let mut exploration = 0;
    let mut optional = 0;
    let mut roots = BTreeSet::new();
    let mut selected = Vec::new();
    for probe in probes.iter() {
        let targeted = strings(probe, "finding_ids");
        let keep = if text(probe, "id") == "baseline" {
            true
        } else if targeted.is_empty() {
            exploration += 1;
            !active && exploration == 1
        } else if targeted.iter().all(|id| {
            findings.iter().any(|f| {
                text(f, "id") == *id
                    && (text(f, "severity") == "Low"
                        || text(f, "scope") == "environment"
                        || matches!(text(f, "status"), "accepted" | "refuted"))
            })
        }) {
            false
        } else if !flag(probe, "required") {
            optional += 1;
            optional == 1 && roots.insert(targeted[0].to_owned())
        } else {
            roots.insert(targeted[0].to_owned())
        };
        if keep {
            selected.push(probe.clone());
        } else if !normalize_ids {
            return Err(invalid(
                text(probe, "id"),
                "task contains an ineligible or redundant probe; create a new plan",
            ));
        }
    }
    *probes = selected;
    if normalize_ids {
        probes.sort_by_key(|p| (text(p, "id") != "baseline", !flag(p, "required")));
    }
    if probes.first().is_none_or(|p| text(p, "id") != "baseline") {
        return Err(invalid("audit", "baseline must be first"));
    }
    Ok(())
}

fn validate_required_coverage(probes: &[Value], findings: &[Value]) -> Result<()> {
    for finding in findings {
        if text(finding, "scope") == "skill"
            && matches!(text(finding, "severity"), "Critical" | "High")
            && matches!(text(finding, "status"), "material_risk" | "unresolved")
            && text(finding, "dynamic") != "unsupported"
            && !probes
                .iter()
                .any(|p| strings(p, "finding_ids").contains(&text(finding, "id")))
        {
            return Err(invalid(
                text(finding, "id"),
                "necessary probe missing without explicit unsupported status",
            ));
        }
    }
    Ok(())
}

pub(crate) fn public_task(skill: &std::path::Path, hash: &str, audit: &Value) -> Value {
    let mut audit = audit.clone();
    if let Some(fields) = audit.as_object_mut() {
        fields.retain(|k, _| {
            matches!(
                k.as_str(),
                "objective"
                    | "allowed_boundary"
                    | "findings"
                    | "probes"
                    | "control_gaps"
                    | "limitations"
                    | "omitted_sources"
                    | "planning_errors"
                    | "missing_implementation"
            )
        });
    }
    if let Some(findings) = audit["findings"].as_array_mut() {
        for finding in findings {
            if let Some(fields) = finding.as_object_mut() {
                for key in ["critical_confirmed", "control_test_refs", "dynamic_target"] {
                    fields.remove(key);
                }
                if fields.get("dynamic").is_none_or(|v| v != "unsupported") {
                    fields.remove("dynamic");
                }
            }
        }
    }
    if let Some(probes) = audit["probes"].as_array_mut() {
        for probe in probes {
            if let Some(fields) = probe.as_object_mut() {
                fields.remove("target");
                fields.remove("required");
            }
        }
    }
    json!({"schema_version":"agent-sec-skill-score/task-v1","skill_path":skill,"content_hash":hash,"audit":audit})
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn optional_schema_branch_cannot_bypass_type_validation() -> Result<()> {
        let schema = json!({"anyOf":[{"type":"string"},{"type":"null"}]});
        assert!(
            normalize(
                &mut json!({"unexpected":"object"}),
                &schema,
                &schema,
                "input"
            )
            .is_err()
        );
        normalize(&mut Value::Null, &schema, &schema, "input")?;
        Ok(())
    }

    #[test]
    fn every_hygiene_rule_and_topic_is_required() -> Result<()> {
        let rules = rules()?;
        let topics = risk_catalog()?;
        assert_eq!(rules.as_object().map(serde_json::Map::len), Some(23));
        let checked =
            json!({"status":"not_applicable","reason":"Not present in supplied source","refs":[]});
        let review = |items: &Value| {
            items
                .as_object()
                .into_iter()
                .flat_map(|o| o.keys())
                .map(|id| (id.clone(), checked.clone()))
                .collect::<serde_json::Map<_, _>>()
        };
        let mut value = json!({"hygiene_review":review(&rules),"pattern_checks":review(&topics)});
        validate_reviews(&value, &BTreeMap::new(), true)?;
        value["hygiene_review"]
            .as_object_mut()
            .map(|o| o.remove("CTRL-001"));
        // Remove an actual key independently of the frozen identifier spelling.
        if let Some(object) = value["hygiene_review"].as_object_mut()
            && let Some(key) = object.keys().next().cloned()
        {
            object.remove(&key);
        }
        assert!(validate_reviews(&value, &BTreeMap::new(), true).is_err());
        Ok(())
    }
}
