"""Activation resolver for SkillFS-style consumers.

``resolve`` answers one narrow question: which skill directory should a runtime
expose right now?  It does not execute scans or mutate policy.  The returned
JSON is intentionally small and stable so callers can make filesystem mapping
decisions without reading ``.skill-meta`` directly.
"""

import json
from pathlib import Path
from typing import Any

from agent_sec_cli.skill_ledger.core.checker import check
from agent_sec_cli.skill_ledger.core.file_hasher import (
    compute_file_hashes,
    diff_file_hashes,
)
from agent_sec_cli.skill_ledger.core.version_chain import (
    list_version_ids,
    load_version_manifest,
    snapshot_dir_path,
)
from agent_sec_cli.skill_ledger.errors import SignatureInvalidError
from agent_sec_cli.skill_ledger.models.manifest import SignedManifest
from agent_sec_cli.skill_ledger.signing.base import SigningBackend

SCHEMA_VERSION = 1
TARGET_KIND_RELATIVE_TO_SKILL_DIR = "relative_to_skill_dir"


def snapshot_path(version_id: str) -> str:
    """Return the stable relative snapshot path for *version_id*."""
    return f".skill-meta/versions/{version_id}.snapshot"


def _empty_findings_summary() -> dict[str, int]:
    return {"high": 0, "medium": 0, "low": 0}


def _empty_diff_summary() -> dict[str, list[str]]:
    return {"added": [], "removed": [], "modified": []}


def _manifest_verifies(manifest: SignedManifest, backend: SigningBackend) -> bool:
    """Return true when the manifest hash and digital signature verify."""
    if manifest.manifestHash != manifest.compute_manifest_hash():
        return False
    if manifest.signature is None:
        return False
    try:
        backend.verify(
            manifest.manifestHash.encode("utf-8"),
            manifest.signature.value,
            manifest.signature.keyFingerprint,
        )
    except SignatureInvalidError:
        return False
    return True


def _snapshot_matches_manifest(skill_dir: str, manifest: SignedManifest) -> bool:
    """Return true when the version snapshot exists and matches file hashes."""
    snap_path = snapshot_dir_path(skill_dir, manifest.versionId)
    if not snap_path.is_dir():
        return False
    snapshot_hashes = compute_file_hashes(str(snap_path))
    return diff_file_hashes(manifest.fileHashes, snapshot_hashes)["match"]


def find_latest_trusted_version(
    skill_dir: str,
    backend: SigningBackend,
) -> dict[str, str] | None:
    """Find the newest signed pass version with an intact snapshot."""
    for version_id in reversed(list_version_ids(skill_dir)):
        try:
            manifest = load_version_manifest(skill_dir, version_id)
        except (json.JSONDecodeError, ValueError):
            continue
        if manifest is None:
            continue
        if manifest.scanStatus != "pass":
            continue
        if not _manifest_verifies(manifest, backend):
            continue
        if not _snapshot_matches_manifest(skill_dir, manifest):
            continue
        return {"versionId": manifest.versionId, "target": snapshot_path(manifest.versionId)}
    return None


def _finding_bucket(finding: dict[str, Any]) -> str | None:
    metadata = finding.get("metadata")
    severity = ""
    if isinstance(metadata, dict):
        severity = str(metadata.get("severity", "")).lower()
    if severity in {"critical", "high"}:
        return "high"
    if severity == "medium":
        return "medium"
    if severity == "low":
        return "low"

    level = str(finding.get("level", "")).lower()
    if level == "deny":
        return "high"
    if level == "warn":
        return "medium"
    return None


def _findings_summary(findings: list[dict[str, Any]]) -> dict[str, int]:
    summary = _empty_findings_summary()
    for finding in findings:
        bucket = _finding_bucket(finding)
        if bucket is not None:
            summary[bucket] += 1
    return summary


def _diff_summary(status_result: dict[str, Any]) -> dict[str, list[str]]:
    summary = _empty_diff_summary()
    for key in summary:
        value = status_result.get(key, [])
        summary[key] = list(value) if isinstance(value, list) else []
    return summary


def _reason(status: str, decision: str, trusted_version: str | None) -> str:
    if decision == "current":
        return "current version is signed, unchanged, and scanStatus=pass"
    if decision == "fallback":
        return f"current status is {status}; serving trusted snapshot {trusted_version}"
    if status == "none":
        return "skill has no certified pass version yet"
    return f"current status is {status}; no certified pass version is available"


def resolve_activation(skill_dir: str, backend: SigningBackend) -> dict[str, Any]:
    """Resolve the runtime exposure decision for *skill_dir*."""
    status_result = check(skill_dir, backend)
    status = str(status_result.get("status", "error"))
    trusted = find_latest_trusted_version(skill_dir, backend)

    trusted_version = trusted["versionId"] if trusted is not None else None
    if status == "pass":
        decision = "current"
        target: str | None = "."
    elif trusted is not None:
        decision = "fallback"
        target = trusted["target"]
    else:
        decision = "hidden"
        target = None

    result = {
        "schemaVersion": SCHEMA_VERSION,
        "skillName": status_result.get("skillName") or Path(skill_dir).name,
        "status": status,
        "currentVersion": status_result.get("versionId"),
        "trustedVersion": trusted_version,
        "decision": decision,
        "target": target,
        "reason": _reason(status, decision, trusted_version),
        "findingsSummary": _findings_summary(status_result.get("findings", [])),
        "diffSummary": _diff_summary(status_result),
    }
    if decision == "fallback":
        result["targetKind"] = TARGET_KIND_RELATIVE_TO_SKILL_DIR
    return result
