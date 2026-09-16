#!/usr/bin/env python3
"""Check release consistency, retry safety, and immutable publication with local fixtures."""

import json
import os
import pathlib
import re
import subprocess
import sys
import tarfile
import tempfile

import package
import publish


def check_links(directory: pathlib.Path) -> None:
    for document in directory.rglob("*.md"):
        for target in re.findall(r"\]\(([^)]+)\)", document.read_text()):
            if "://" not in target and not target.startswith("#"):
                path = document.parent / target.split("#", 1)[0]
                assert path.is_file(), (document, target)


def main() -> None:
    root = pathlib.Path(__file__).resolve().parent
    repo = root.parents[1]
    for name in (
        "container-demo.md",
        "container-demo-card.md",
        "container-demo-ssh.md",
    ):
        docs = [
            repo / f"docs/user-guide/{lang}/agent-security/agent-sec-core/{name}"
            for lang in ("en", "zh")
        ]
        blocks = [
            re.findall(
                r"```(?:bash|text|dotenv|powershell|sshconfig)\n(.*?)```",
                p.read_text(),
                re.S,
            )
            for p in docs
        ]
        assert blocks[0] == blocks[1], name
        for document in docs:
            for target in re.findall(r"\]\(([^)]+)\)", document.read_text()):
                if "://" not in target:
                    assert (document.parent / target.split("#", 1)[0]).is_file(), target
    with tempfile.TemporaryDirectory(prefix="demo-release-check-") as directory:
        work = pathlib.Path(directory)
        bundle = work / "determinism"
        bundle.mkdir()
        (bundle / "demo.sh").write_text("# fixture\n")
        first = package.archive_bundle(bundle, work / "first.tar.gz")
        os.utime(bundle / "demo.sh", (100, 200))
        (bundle / "demo.sh").chmod(0o600)
        second = package.archive_bundle(bundle, work / "second.tar.gz")
        assert first == second
        assert package.digest(work / "first.tar.gz") == package.digest(work / "second.tar.gz")
        image = work / "image.tar.gz"
        image.write_bytes(b"Archive fixture, not a runnable image\n")
        reference = work / "image.ref"
        reference.write_text(package.IMAGE_REFERENCE + "\n")
        # Exercise the real packager's file/link contract, not image acceptance.
        old_sha, old_argv = package.IMAGE_SHA256, sys.argv
        package.IMAGE_SHA256 = package.digest(image)
        output = work / "release"
        sys.argv = ["package.py", str(image), str(reference), str(output)]
        try:
            package.main()
        finally:
            package.IMAGE_SHA256, sys.argv = old_sha, old_argv
        for path in output.glob("*.sh"):
            subprocess.run(["bash", "-n", str(path)], check=True)
        manifests = []
        for index, archive_path in enumerate(sorted(output.glob("*.tar.gz"))):
            target = work / f"unpacked-{index}"
            with tarfile.open(archive_path) as archive:
                # These archives were generated above from trusted fixture files.
                archive.extractall(target)
            installation = target / "agentseccore-demo"
            check_links(installation)
            manifests.append(package.digest(installation / "SHA256SUMS"))
            assert (
                not list(installation.rglob(".auth")) and not (installation / "demo.env").exists()
            )
        connector = (output / f"ecs-demo-{package.VERSION}.sh").read_text()
        installer = (output / f"install-{package.VERSION}.sh").read_text()
        assert all(value in connector and value in installer for value in manifests)
        assert package.digest(output / f"install-{package.VERSION}.sh") in connector
        assert "__VERSION__" not in installer
        assert f"releases/download/{package.RELEASE_TAG}/install-{package.VERSION}.sh" in connector
        assert f"release={package.RELEASE_TAG}" in installer
        subprocess.run(
            ["sha256sum", "--check", f"SHA256SUMS-{package.VERSION}"],
            cwd=output,
            check=True,
            stdout=subprocess.DEVNULL,
        )

        # Run the actual documented download-and-execute commands with a failing zero-byte curl.
        fake_bin = work / "bin"
        fake_bin.mkdir()
        (fake_bin / "curl").write_text("#!/bin/sh\nexit 22\n")
        (fake_bin / "curl").chmod(0o755)
        env = {**os.environ, "PATH": f"{fake_bin}:{os.environ['PATH']}"}
        guide = (
            repo / "docs/user-guide/zh/agent-security/agent-sec-core/container-demo.md"
        ).read_text()
        commands = re.findall(r"```bash\n(curl .*?)```", guide, re.S)
        assert len(commands) == 2
        for command in commands:
            result = subprocess.run(["bash", "-c", command], cwd=work, env=env)
            assert result.returncode == 22
        assert not (work / "install.sh").exists() and not (work / "ecs-demo.sh").exists()

        # The publisher must reject all conflicting bytes before any upload.
        commit = "a" * 40
        files = sorted(p for p in output.iterdir() if p.is_file())
        assets = [{"name": p.name, "digest": "sha256:" + package.digest(p)} for p in files]
        assets += [
            {"name": "image.tar.gz", "digest": "sha256:" + package.IMAGE_SHA256},
            {"name": "install-20260914.1.sh", "digest": "sha256:" + "1" * 64},
        ]
        calls = []
        refs = []

        def fake_gh(*args: str) -> str:
            calls.append(args)
            if args[0] == "api" and "/releases/tags/" in args[1]:
                assert args[1].endswith("/" + package.RELEASE_TAG)
                return json.dumps({"tag_name": package.RELEASE_TAG, "assets": assets})
            if args[0] == "api" and "/git/matching-refs/" in args[1]:
                return json.dumps(refs)
            return ""

        saved_gh, old_argv = publish.gh, sys.argv
        publish.gh = fake_gh
        sys.argv = ["publish.py", str(output), commit]
        try:
            publish.main()
            assert not any(c[:2] == ("release", "upload") for c in calls)
            assert not any(c[:2] == ("release", "create") for c in calls)
            assert any(f"ref=refs/tags/agentseccore-demo-{package.VERSION}" in c for c in calls)
            removed = [c[3] for c in calls if c[:2] == ("release", "delete-asset")]
            assert removed == ["install-20260914.1.sh"]
            assert next(i for i, c in enumerate(calls) if c[:2] == ("release", "edit")) < next(
                i for i, c in enumerate(calls) if c[:2] == ("release", "delete-asset")
            )
            refs.append(
                {
                    "ref": f"refs/tags/agentseccore-demo-{package.VERSION}",
                    "object": {"sha": commit},
                }
            )
            calls.clear()
            assets[0]["digest"] = "sha256:" + "0" * 64
            try:
                publish.main()
            except AssertionError as error:
                assert "Refusing to replace" in str(error)
            else:
                raise AssertionError("Publisher replaced conflicting content")
            assert not any(c[0] == "release" or "POST" in c for c in calls)
        finally:
            publish.gh, sys.argv = saved_gh, old_argv
    print(
        "PASS: deterministic archives, bilingual commands, bundled links, generated pins, download failures, immutable publication"
    )


if __name__ == "__main__":
    main()
