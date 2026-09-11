#!/usr/bin/env python3
"""Publish a checked demo directory without replacing existing release bytes."""

import argparse
import json
import pathlib
import re
import subprocess

from package import REPOSITORY, VERSION, digest


def gh(*args: str) -> str:
    return subprocess.check_output(["gh", *args], text=True)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("directory", type=pathlib.Path)
    parser.add_argument("commit", help="Exact tested commit SHA")
    args = parser.parse_args()
    assert re.fullmatch(r"[0-9a-f]{40}", args.commit), "Use an immutable commit SHA"
    directory = args.directory.resolve()
    listed = {
        line.split("  ", 1)[1] for line in (directory / "SHA256SUMS").read_text().splitlines()
    }
    assert {p.name for p in directory.iterdir()} == listed | {
        "SHA256SUMS"
    }, "Unexpected release files"
    subprocess.run(["sha256sum", "--check", "SHA256SUMS"], cwd=directory, check=True)
    tag = f"agentseccore-demo-{VERSION}"
    refs = json.loads(gh("api", f"repos/{REPOSITORY}/git/matching-refs/tags/{tag}"))
    ref = next((r for r in refs if r["ref"] == f"refs/tags/{tag}"), None)
    if ref is not None:
        assert ref["object"]["sha"] == args.commit, "Release tag points to a different commit"
    releases = json.loads(gh("api", f"repos/{REPOSITORY}/releases?per_page=100"))
    release = next((r for r in releases if r["tag_name"] == tag), None)
    if release is None:
        gh(
            "release",
            "create",
            tag,
            "--repo",
            REPOSITORY,
            "--target",
            args.commit,
            "--draft",
            "--title",
            "AgentSecCore：护航 Skill 安全｜上手体验",
            "--notes-file",
            str(directory / "release-notes.md"),
        )
    elif ref is None:
        assert (
            release["draft"] and release["target_commitish"] == args.commit
        ), "Unexpected draft source"
    assets = {a["name"]: a for a in (release or {}).get("assets", [])}
    files = sorted(p for p in directory.iterdir() if p.is_file())
    # Check all conflicts before uploading anything, allowing retries of identical bytes only.
    for path in files:
        if path.name in assets:
            assert assets[path.name]["digest"] == "sha256:" + digest(
                path
            ), f"Refusing to replace {path.name}"
    for path in files:
        if path.name not in assets:
            gh("release", "upload", tag, str(path), "--repo", REPOSITORY)
    gh(
        "release",
        "edit",
        tag,
        "--repo",
        REPOSITORY,
        "--draft=false",
        "--latest",
        "--notes-file",
        str(directory / "release-notes.md"),
    )
    print(f"https://github.com/{REPOSITORY}/releases/tag/{tag}")


if __name__ == "__main__":
    main()
