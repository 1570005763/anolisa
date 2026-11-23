"""Capture diagnostics from an isolated, installed-form CLI without a network service."""
import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path

binary = str(Path(sys.argv[1]).resolve())
receipts = Path(sys.argv[2])
prefix = "[skill-score] Command failed: diagnostic="
with tempfile.TemporaryDirectory(prefix="score-diag-") as directory:
    root = Path(directory)
    for label, action, name, stage, file, exit_code in [
        ("missing_task", "run", "task.json", "task.resolve", "task.json", 1),
        ("missing_skill", "plan", "private-skill-name", "plan.skill.resolve", None, 2),
        ("unsafe_filename", "run", "private-canary\n[skill-score] forged", "task.resolve", None, 1),
    ]:
        report = root / (label + ".json")
        result = subprocess.run(
            [binary, "skillsec", "score", action, str(root / name), "--output-file", str(report)],
            env={"PATH":"/usr/bin:/bin", "HOME":str(root), "TMPDIR":str(root)},
            capture_output=True, text=True, timeout=20, check=False,
        )
        lines = [line.removeprefix(prefix) for line in result.stderr.splitlines() if line.startswith(prefix)]
        assert len(lines) == 1, (label, result.stderr)
        diagnostic = json.loads(lines[0])
        assert (result.returncode, report.exists()) == (exit_code, False), label
        assert (diagnostic["stage"], diagnostic["reason"], diagnostic.get("errno"), diagnostic.get("file")) == (stage, "io", 2, file), (label, diagnostic)
        assert set(diagnostic) <= {"stage", "reason", "errno", "file"}, diagnostic
        assert "private" not in lines[0] and str(root) not in lines[0], diagnostic
        (receipts / (label + ".cli.log")).write_text(result.stderr)
        print(json.dumps({"case":label, "exit":result.returncode, "diagnostic":diagnostic}), flush=True)
