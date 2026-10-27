"""Explicit maintainer build: image, inventory and offline Docker archive."""

import argparse
import hashlib
import json
import re
import shutil
import subprocess
import tarfile
import tempfile
from pathlib import Path


def archive_image_identities(archive_path: Path, names: tuple[str, ...]) -> list[dict]:
    """Bind classic config IDs and containerd manifest IDs to the same saved images."""
    with tarfile.open(archive_path) as archive:
        members = {member.name: member for member in archive.getmembers()}
        if len(members) != len(archive.getmembers()):
            raise ValueError("image archive contains duplicate members")

        def read_json(name: str, descriptor: dict | None = None) -> dict | list:
            member = members.get(name)
            if member is None or not member.isfile() or member.size > 1024 * 1024:
                raise ValueError("image archive metadata is missing or invalid")
            with archive.extractfile(member) as stream:
                data = stream.read()
            if descriptor is not None and (
                descriptor.get("size") != len(data)
                or descriptor.get("digest")
                != "sha256:" + hashlib.sha256(data).hexdigest()
            ):
                raise ValueError("image archive descriptor checksum/size mismatch")
            return json.loads(data)

        def blob(descriptor: dict) -> str:
            identity = descriptor.get("digest", "")
            if not re.fullmatch(r"sha256:[a-f0-9]{64}", identity):
                raise ValueError("image archive descriptor must use SHA256")
            return "blobs/sha256/" + identity.removeprefix("sha256:")

        index = read_json("index.json")
        legacy = read_json("manifest.json")
        if (
            index.get("schemaVersion") != 2
            or len(index.get("manifests", [])) != len(names)
            or len(legacy) != len(names)
        ):
            raise ValueError("image archive must contain exactly the release images")
        records = {}
        for descriptor in index["manifests"]:
            annotations = descriptor.get("annotations", {})
            name = annotations.get("io.containerd.image.name", "")
            name = name.removeprefix("docker.io/library/")
            if name not in names or name in records:
                raise ValueError("image archive tag is unexpected or ambiguous")
            if (
                descriptor.get("mediaType")
                != "application/vnd.oci.image.manifest.v1+json"
            ):
                raise ValueError(
                    "image archive must bind a single-platform OCI manifest"
                )
            manifest = read_json(blob(descriptor), descriptor)
            if manifest.get("schemaVersion") != 2:
                raise ValueError("image archive manifest schema is unsupported")
            config = read_json(blob(manifest["config"]), manifest["config"])
            if (config.get("os"), config.get("architecture")) != ("linux", "amd64"):
                raise ValueError("image archive platform must be linux/amd64")
            layers = [blob(layer) for layer in manifest["layers"]]
            matches = [item for item in legacy if item.get("RepoTags") == [name]]
            if (
                len(matches) != 1
                or matches[0].get("Config") != blob(manifest["config"])
                or matches[0].get("Layers") != layers
            ):
                raise ValueError("classic and OCI archive image identities disagree")
            for layer, path in zip(manifest["layers"], layers, strict=True):
                member = members.get(path)
                if (
                    member is None
                    or not member.isfile()
                    or member.size != layer.get("size")
                ):
                    raise ValueError(
                        "image archive layer is missing or has a different size"
                    )
            records[name] = {
                "name": name,
                "id": manifest["config"]["digest"],
                "manifest_id": descriptor["digest"],
                "platform": "linux/amd64",
            }
        return [records[name] for name in names]


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("output", type=Path)
    parser.add_argument(
        "--build-network", choices=("default", "host"), default="default"
    )
    parser.add_argument(
        "--version", required=True, help="Component version used for both image tags"
    )
    args = parser.parse_args()
    if not re.fullmatch(r"[A-Za-z0-9_][A-Za-z0-9_.-]{0,127}", args.version):
        parser.error("version is not a Docker tag")
    component = Path(__file__).resolve().parents[2]
    image = f"agent-sec-skill-score:{args.version}"
    args.output.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="skill-score-image-") as temporary:
        context = Path(temporary)
        for name in ("Dockerfile", "observe.py", "claude-observed"):
            shutil.copy2(Path(__file__).parent / name, context / name)
        source = component / "agent-sec-cli/src/agent_sec_cli"
        target = context / "scanner-source/agent_sec_cli"
        target.mkdir(parents=True)
        shutil.copy2(source / "__init__.py", target / "__init__.py")
        # Only genuine code-scanner modules needed by the subject scanner Skill, not CLI/ML.
        for name in ("code_scanner", "model_service"):
            shutil.copytree(
                source / name,
                target / name,
                ignore=shutil.ignore_patterns("__pycache__"),
            )
        subprocess.run(
            [
                "docker",
                "build",
                "--network",
                args.build_network,
                "--pull=false",
                "-t",
                image,
                str(context),
            ],
            check=True,
        )
    sidecar = f"agent-sec-skill-score-egress:{args.version}"
    subprocess.run(
        [
            "docker",
            "build",
            "--network",
            args.build_network,
            "--pull=false",
            "-t",
            sidecar,
            str(component / "skill-score-runtime/egress"),
        ],
        check=True,
    )
    output = subprocess.run(
        [
            "docker",
            "run",
            "--rm",
            "--pull",
            "never",
            "--network",
            "none",
            "--entrypoint",
            "python",
            image,
            "/opt/poc/observe.py",
            "inventory",
        ],
        check=True,
        capture_output=True,
        text=True,
    )
    inventory = json.loads(output.stdout)
    inventory.update(
        docker_image=image,
        network="ASC static model-host allowlist for proxied TCP; local destinations and ICMP remain direct",
        mock="http://127.0.0.1:8765; static routes, no downstream model inference",
    )
    text = json.dumps(inventory, ensure_ascii=False, indent=2) + "\n"
    (args.output / "tool-inventory.json").write_text(text)
    subprocess.run(
        [
            "docker",
            "save",
            "-o",
            str(args.output / "skill-score-images.tar"),
            image,
            sidecar,
        ],
        check=True,
    )
    details = json.loads(
        subprocess.run(
            ["docker", "image", "inspect", image, sidecar],
            check=True,
            capture_output=True,
            text=True,
        ).stdout
    )
    identities = archive_image_identities(
        args.output / "skill-score-images.tar", (image, sidecar)
    )
    for identity, detail in zip(identities, details, strict=True):
        if detail["Id"] not in (identity["id"], identity["manifest_id"]) or (
            detail["Os"],
            detail["Architecture"],
        ) != ("linux", "amd64"):
            raise ValueError("built image differs from its saved immutable identities")
        identity["repo_digests"] = detail.get("RepoDigests", [])
    claude = subprocess.run(
        [
            "docker",
            "run",
            "--rm",
            "--pull",
            "never",
            "--network",
            "none",
            "--entrypoint",
            "/usr/bin/claude",
            image,
            "--version",
        ],
        check=True,
        capture_output=True,
        text=True,
    )
    gost = subprocess.run(
        [
            "docker",
            "run",
            "--rm",
            "--pull",
            "never",
            "--network",
            "none",
            "--entrypoint",
            "/bin/gost",
            sidecar,
            "-V",
        ],
        check=True,
        capture_output=True,
        text=True,
    )
    (args.output / "images.json").write_text(
        json.dumps(
            {
                "images": [image, sidecar],
                "image_details": identities,
                "versions": {
                    "harbor": "0.22.0",
                    "claude": claude.stdout.strip(),
                    "gost": gost.stdout.strip(),
                    "observer_sha256": hashlib.sha256(
                        (Path(__file__).parent / "observe.py").read_bytes()
                    ).hexdigest(),
                },
            },
            indent=2,
        )
        + "\n"
    )


if __name__ == "__main__":
    main()
