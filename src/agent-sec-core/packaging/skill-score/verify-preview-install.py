#!/usr/bin/env python3
"""Check the installed raw preview and Docker resource identity without inference."""

import argparse
import hashlib
import json
import subprocess
import sys
import tomllib
from pathlib import Path


def run(*arguments: str) -> str:
    return subprocess.run(arguments, check=True, capture_output=True, text=True, timeout=60).stdout


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("release", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    manifest = json.loads((args.release / "release-manifest.json").read_text())
    for artifact in manifest["artifacts"]:
        path = args.release / artifact["file"]
        with path.open("rb") as stream:
            assert hashlib.file_digest(stream, "sha256").hexdigest() == artifact["sha256"], path
        assert path.stat().st_size == artifact["bytes"], path
    contract = tomllib.loads(
        Path("/usr/local/share/anolisa/components/sec-core/component.toml").read_text()
    )
    assert contract["component"]["version"] == manifest["version"]
    checks = {"artifact_hashes": True, "installed_version": manifest["version"]}
    for name in ("agent-sec-cli", "agent-sec-daemon", "linux-sandbox"):
        with Path(f"/usr/local/bin/{name}").open("rb") as stream:
            assert stream.read(4) == b"\x7fELF", name
        run(f"/usr/local/bin/{name}", "--help")
        checks[name] = True
    run(
        sys.executable,
        "-I",
        "-c",
        'import importlib.util; assert importlib.util.find_spec("agent_sec_cli") is None',
    )
    checks["no_global_python_cli"] = True
    for stage in ("plan", "run"):
        run("/usr/local/bin/agent-sec-skill-score", "skill-score", stage, "--help")
        checks[f"score_{stage}_help"] = True
    prefix = "/usr/local/lib/anolisa/sec-core/skill-score"
    run(
        f"{prefix}/cli/bin/python3.11",
        "-I",
        "-c",
        'from agent_sec_cli import _native; import json; assert json.loads(_native.scan_prompt_json("A harmless test", mode="fast"))["degraded"] is False',
    )
    checks["native_scanner"] = True
    versions = json.loads(
        run(
            f"{prefix}/runtime/bin/python3.12",
            "-I",
            "-c",
            'import importlib.metadata,json,platform; from agent_sec_skill_score_runtime.worker import main; print(json.dumps([platform.python_version(),importlib.metadata.version("harbor")]))',
        )
    )
    assert versions == [manifest["python_worker"], manifest["harbor"]]
    checks["worker_versions"] = versions
    for image in manifest["images"]["image_details"]:
        assert (
            run("docker", "image", "inspect", "--format", "{{.Id}}", image["name"]).strip()
            == image["id"]
        )
    checks["loaded_image_ids"] = True
    checks["model_calls"] = 0
    args.output.write_text(
        json.dumps(
            {"status": "PASS", "source_commit": manifest["source_commit"], "checks": checks},
            indent=2,
        )
        + "\n"
    )


if __name__ == "__main__":
    main()
