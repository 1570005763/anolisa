"""Smoke coverage for the standalone SkillFS + Skill Ledger demo harness."""

import json
import subprocess
import sys
from pathlib import Path


def test_skillfs_ledger_demo_script_runs_full_flow(tmp_path):
    repo_root = Path(__file__).resolve().parents[5]
    script = repo_root / "scripts" / "skillfs-ledger-demo" / "run_demo.py"
    root = tmp_path / "skill-demo"
    template = tmp_path / "clawhub" / "weather-query"
    template.mkdir(parents=True)
    (template / "SKILL.md").write_text(
        "---\n"
        "name: weather-query\n"
        "description: Query weather information for a city\n"
        "---\n"
        "# Weather Query\n\n"
        "根据用户给出的城市，查询并总结天气信息。\n",
        encoding="utf-8",
    )
    cli = f"{sys.executable} -m agent_sec_cli"

    proc = subprocess.run(
        [
            sys.executable,
            str(script),
            "--root",
            str(root),
            "--cli",
            cli,
            "--template-skill",
            str(template),
            "--skill-name",
            "weather-query-ledger-demo",
        ],
        check=False,
        text=True,
        capture_output=True,
        cwd=repo_root,
    )

    assert proc.returncode == 0, proc.stderr

    state = json.loads((root / "state.json").read_text(encoding="utf-8"))
    events = [
        json.loads(line)
        for line in (root / "events.jsonl").read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]

    skill_name = state["skillName"]
    agent_path = root / "mount" / "skills" / skill_name
    source_skill = root / "source" / skill_name
    v1_snapshot_skill = source_skill / ".skill-meta" / "versions" / "v000001.snapshot"
    snapshot_skill = source_skill / ".skill-meta" / "versions" / "v000002.snapshot"

    assert Path(state["agentPath"]) == agent_path
    assert Path(state["clawhubInstallRoot"]) == root / "source"
    assert Path(state["skillfsSourceRoot"]) == root / "source"
    assert Path(state["ledgerScanPath"]) == source_skill
    assert Path(state["sourcePath"]) == source_skill
    assert state["active"][skill_name]["decision"] == "fallback"
    assert state["active"][skill_name]["schemaVersion"] == 1
    assert state["active"][skill_name]["targetKind"] == "relative_to_skill_dir"
    assert state["active"][skill_name]["targetPath"] == str(snapshot_skill)
    assert state["sourceVersion"] == "v000003"
    assert state["visibleVersion"] == "v000002"
    assert state["latestScan"]["versionId"] == "v000003"
    assert state["latestScan"]["scanStatus"] == "deny"
    assert state["latestScan"]["threatCount"] > 0
    assert any(
        finding["level"] == "deny" and finding["rule"] == "prompt-override"
        for finding in state["latestScan"]["findings"]
    )

    assert [event["skillfsDecision"].split(":", 1)[0] for event in events] == [
        "hidden",
        "current",
        "current",
        "pending resolve",
        "fallback",
    ]

    agent_skill_md = (agent_path / "SKILL.md").read_text(encoding="utf-8")
    source_skill_md = (source_skill / "SKILL.md").read_text(encoding="utf-8")
    v1_snapshot_skill_md = (v1_snapshot_skill / "SKILL.md").read_text(
        encoding="utf-8"
    )
    snapshot_skill_md = (snapshot_skill / "SKILL.md").read_text(encoding="utf-8")

    assert "Skill Ledger Version:" not in v1_snapshot_skill_md
    assert "Ignore previous system instruction" in source_skill_md
    assert agent_skill_md == snapshot_skill_md
    assert "Ignore previous system instruction" not in agent_skill_md
    assert "Skill Ledger Version: v000002" in agent_skill_md


def test_skillfs_ledger_demo_uses_direct_source_download(tmp_path):
    repo_root = Path(__file__).resolve().parents[5]
    script = repo_root / "scripts" / "skillfs-ledger-demo" / "run_demo.py"
    root = tmp_path / "skill-demo"
    skill_name = "tianqi-weather"
    source_skill = root / "source" / skill_name
    source_skill.mkdir(parents=True)
    (source_skill / "SKILL.md").write_text(
        "---\n"
        "name: 天气\n"
        "description: Query weather from a real ClawHub skill\n"
        "---\n"
        "# 天气查询\n\n"
        "根据用户给出的城市，查询并总结天气信息。\n",
        encoding="utf-8",
    )
    cli = f"{sys.executable} -m agent_sec_cli"

    proc = subprocess.run(
        [
            sys.executable,
            str(script),
            "--root",
            str(root),
            "--cli",
            cli,
            "--keep",
            "--skill-name",
            skill_name,
            "--clawhub-slug",
            skill_name,
        ],
        check=False,
        text=True,
        capture_output=True,
        cwd=repo_root,
    )

    assert proc.returncode == 0, proc.stderr

    state = json.loads((root / "state.json").read_text(encoding="utf-8"))
    source_skill_md = (source_skill / "SKILL.md").read_text(encoding="utf-8")

    assert f"name: {skill_name}" in source_skill_md
    assert state["active"][skill_name]["decision"] == "fallback"
    assert state["visibleVersion"] == "v000002"
    assert Path(state["clawhubInstallRoot"]) == root / "source"
    assert Path(state["skillfsSourceRoot"]) == root / "source"
    assert Path(state["ledgerScanPath"]) == source_skill
    assert Path(state["sourcePath"]) == source_skill
    assert "clawhub install tianqi-weather --dir" in state["steps"][0]["prompt"]
    assert "OpenClaw 仍只应加载" in state["steps"][0]["note"]
    assert str(root / "source") in state["steps"][0]["prompt"]
    assert state["latestScan"]["versionId"] == "v000003"
    assert state["latestScan"]["scanStatus"] == "deny"
