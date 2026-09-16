#!/usr/bin/env python3
"""Update the single demo release with checked, immutable versioned assets."""

import argparse
import json
import pathlib
import re
import subprocess

from package import RELEASE_TAG, REPOSITORY, VERSION, digest


def gh(*args: str) -> str:
    return subprocess.check_output(["gh", *args], text=True)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("directory", type=pathlib.Path)
    parser.add_argument("commit", help="Exact tested commit SHA")
    args = parser.parse_args()
    assert re.fullmatch(r"[0-9a-f]{40}", args.commit), "Use an immutable commit SHA"
    directory = args.directory.resolve()
    checksums = f"SHA256SUMS-{VERSION}"
    listed = {line.split("  ", 1)[1] for line in (directory / checksums).read_text().splitlines()}
    assert {p.name for p in directory.iterdir()} == listed | {checksums}, "Unexpected release files"
    subprocess.run(["sha256sum", "--check", checksums], cwd=directory, check=True)
    tag = f"agentseccore-demo-{VERSION}"
    refs = json.loads(gh("api", f"repos/{REPOSITORY}/git/matching-refs/tags/{tag}"))
    ref = next((r for r in refs if r["ref"] == f"refs/tags/{tag}"), None)
    if ref is not None:
        assert ref["object"]["sha"] == args.commit, "Release tag points to a different commit"
    release = json.loads(gh("api", f"repos/{REPOSITORY}/releases/tags/{RELEASE_TAG}"))
    assets = {a["name"]: a for a in release["assets"]}
    files = sorted(p for p in directory.iterdir() if p.is_file())
    # Check all conflicts before uploading anything, allowing retries of identical bytes only.
    for path in files:
        if path.name in assets:
            assert assets[path.name]["digest"] == "sha256:" + digest(
                path
            ), f"Refusing to replace {path.name}"
    if ref is None:
        gh(
            "api",
            f"repos/{REPOSITORY}/git/refs",
            "--method",
            "POST",
            "-f",
            f"ref=refs/tags/{tag}",
            "-f",
            f"sha={args.commit}",
        )
    for path in files:
        if path.name not in assets:
            gh("release", "upload", RELEASE_TAG, str(path), "--repo", REPOSITORY)
    gh(
        "release",
        "edit",
        RELEASE_TAG,
        "--repo",
        REPOSITORY,
        "--draft=false",
        "--latest",
        "--title",
        f"AgentSecCore：护航 Skill 安全｜上手体验 {VERSION}",
        "--notes-file",
        str(directory / f"release-notes-{VERSION}.md"),
    )
    # The dedicated release retains only current delivery files and its accepted source image.
    for name in sorted(assets.keys() - {p.name for p in files} - {"image.tar.gz"}):
        gh("release", "delete-asset", RELEASE_TAG, name, "--repo", REPOSITORY, "--yes")
    print(f"https://github.com/{REPOSITORY}/releases/tag/{RELEASE_TAG}")


if __name__ == "__main__":
    main()
