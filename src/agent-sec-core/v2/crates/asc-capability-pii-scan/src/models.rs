//! Typed scan contracts and the compatible public result projection.

pub use asc_action_types::{PiiScanOptions, Source};

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// Finding severity retained from v1.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    /// Personal information or a custom warning rule.
    Warn,
    /// Credentials or a custom denial rule.
    Deny,
}

/// Classification of findings, distinct from enforcement.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Verdict {
    /// No retained findings in the scanned coverage.
    Pass,
    /// Warning findings only.
    Warn,
    /// At least one denial finding.
    Deny,
    /// Execution could not produce a report.
    Error,
}

/// Whether scan execution completed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ScanStatus {
    /// Execution produced findings and coverage.
    Completed,
    /// Execution failed.
    Failed,
}

/// Whether evidence covers all supplied text and configured rules.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum CoverageStatus {
    /// All supplied text and valid configured rules were evaluated.
    Complete,
    /// Some input or configured detection was omitted.
    Partial,
    /// No usable scan could be performed.
    Unavailable,
}

/// Coverage is independent of a pass/warn/deny classification.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Coverage {
    /// Completeness of the evidence.
    pub status: CoverageStatus,
    /// Stable reason codes, containing no input or rule text.
    pub reasons: Vec<String>,
}

/// Half-open Unicode scalar offsets, matching Python string indices.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct Span {
    /// Inclusive character offset.
    pub start: usize,
    /// Exclusive character offset.
    pub end: usize,
}

/// Client-visible finding; raw evidence is opt-in and never audit-safe.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PiiFinding {
    /// Stable builtin type or validated custom type.
    #[serde(rename = "type")]
    pub pii_type: String,
    /// `personal_data`, credential, or custom.
    pub category: String,
    /// Existing v1 severity.
    pub severity: Severity,
    /// Heuristic score rounded to three decimal places, not a probability.
    pub confidence: f64,
    /// Type-specific redacted evidence.
    pub evidence_redacted: String,
    /// Character offsets into scanned input.
    pub span: Span,
    /// Detector-owned provenance fields.
    pub metadata: BTreeMap<String, serde_json::Value>,
    /// Returned only when explicitly requested; excluded from audit projections.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub raw_evidence: Option<String>,
}

/// Typed aggregation with additive evidence metadata under v1's summary key.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PiiSummary {
    /// Number of retained findings.
    pub total: usize,
    /// Counts by type.
    pub by_type: BTreeMap<String, usize>,
    /// Counts by category.
    pub by_category: BTreeMap<String, usize>,
    /// Counts by severity.
    pub by_severity: BTreeMap<String, usize>,
    /// Caller-declared origin.
    pub source: Source,
    /// Legacy prefix byte counter, including a discarded partial UTF-8 tail.
    pub bytes_scanned: usize,
    /// Whether the supplied input was shortened.
    pub truncated: bool,
    /// Execution status independent of finding verdict.
    pub execution_status: ScanStatus,
    /// Input and detector completeness.
    pub coverage: Coverage,
    /// SHA-256 of exactly the UTF-8 text received by the scanner, before its limit.
    pub input_sha256: String,
    /// SHA-256 of exactly the UTF-8 prefix examined by detectors.
    pub scanned_input_sha256: String,
    /// Actual bytes examined, excluding any partial UTF-8 tail.
    pub scanned_bytes: usize,
    /// Detection semantics version, independent of package and schema versions.
    pub scanner_version: String,
    /// Identifies this detector revision and active rule content.
    pub ruleset_id: String,
}

/// Stable public scan response, compatible with v1 Hook consumers.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PiiScanReport {
    /// Whether execution produced a report, not an authorization result.
    pub ok: bool,
    /// Aggregated finding classification.
    pub verdict: Verdict,
    /// Counts and completeness metadata.
    pub summary: PiiSummary,
    /// Ordered findings.
    pub findings: Vec<PiiFinding>,
    /// Scan duration in whole milliseconds.
    pub elapsed_ms: u64,
    /// Full redacted prefix, returned only on request and never audit-safe.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub redacted_text: Option<String>,
}

/// Bounded, input-independent scan errors suitable for adapter projection.
#[derive(Debug, thiserror::Error)]
pub enum ScanError {
    /// A zero byte limit cannot describe a meaningful prefix.
    #[error("max_bytes must be greater than zero")]
    InvalidLimit,
    /// A shipped pattern did not compile.
    #[error("builtin PII rules are invalid")]
    InvalidBuiltin,
    /// A builtin engine failed during matching.
    #[error("builtin PII matching failed")]
    Matching,
}

#[derive(Debug, Clone)]
pub(crate) struct Candidate {
    pub kind: String,
    pub category: String,
    pub severity: Severity,
    pub confidence: f64,
    pub value: String,
    pub span: Span,
    pub metadata: BTreeMap<String, serde_json::Value>,
}
