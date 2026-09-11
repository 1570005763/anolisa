#!/usr/bin/env python3
"""Check SSH argument boundaries without accessing a host or credentials."""

import json
import os
import shlex
import subprocess
import sys
import tempfile
from pathlib import Path


def main() -> None:
    source = Path(__file__).with_name("ecs-demo.sh").read_text()
    subprocess.run(["bash", "-n"], input=source, text=True, check=True)
    with tempfile.TemporaryDirectory(prefix="demo-ssh-check-") as directory:
        root = Path(directory)
        capture = root / "arguments.json"
        ssh = root / "ssh"
        ssh.write_text(
            f"#!{sys.executable}\n"
            "import json, os, sys\n"
            "with open(os.environ['SSH_CAPTURE'], 'w') as stream:\n"
            "    json.dump(sys.argv[1:], stream)\n"
            "sys.exit(42)\n"
        )
        ssh.chmod(0o755)
        env = {**os.environ, "PATH": f"{root}:{os.environ['PATH']}", "SSH_CAPTURE": str(capture)}
        env.pop("LOCAL_PORT", None)

        def run(
            *args: str, script: str = source, port: str = "17396"
        ) -> subprocess.CompletedProcess:
            capture.unlink(missing_ok=True)
            return subprocess.run(
                ["bash", "-s", "--", *args],
                input=script,
                text=True,
                capture_output=True,
                env={**env, "LOCAL_PORT": port},
            )

        expected_script = (
            source.split("<<'REMOTE' || true\n", 1)[1].split("\nREMOTE\n", 1)[0] + "\n"
        )
        for action in ("prepare", "doctor", "tamper", "reset", "down"):
            result = run("demo-user@ecs-host", action)
            assert result.returncode == 42, result.stderr
            arguments = json.loads(capture.read_text())
            assert arguments[-3:-1] == ["--", "demo-user@ecs-host"]
            assert "-T" in arguments and "-L" not in arguments
            assert "ControlPath=none" in arguments
            assert shlex.split(arguments[-1]) == ["bash", "-c", expected_script, "--", action]
            subprocess.run(["bash", "-n", "-c", expected_script], check=True)

        for args in (
            (),
            ("-oProxyCommand=touch", "prepare"),
            ("host;touch /tmp/unexpected", "prepare"),
            ("host", "reset;echo unexpected"),
            ("host", "prepare", "extra"),
            ("host", "qoder"),
            ("host", "control"),
        ):
            assert run(*args).returncode != 0
            assert not capture.exists(), args
        for port in ("0", "017396", "65536", "1:evil", "$(touch unexpected)"):
            assert run("host", "prepare", port=port).returncode != 0
            assert not capture.exists(), port
        assert run("host", "prepare", script=source.rsplit('ecs_demo "$@"', 1)[0]).returncode == 0
        assert not capture.exists(), "A truncated download executed SSH"
    print(
        "PASS: SSH arguments, remote quoting, error propagation, input guards, and piped-download guard"
    )


if __name__ == "__main__":
    main()
