#!/usr/bin/env python3
"""Package the accepted image and public demo materials without instance data."""

import argparse
import gzip
import hashlib
import json
import pathlib
import re
import shutil
import tarfile
import tempfile

VERSION = "20260914.1"
REPOSITORY = "1570005763/anolisa"
IMAGE_SHA256 = "750ad2e3bb66d3d11a146370e99be93c4917f95edfb8e7fcba046139980b5495"
IMAGE_REFERENCE = "ghcr.io/1570005763/agentseccore-demo@sha256:3994fdfbe477ade58937f13bc76263cf174450b6f734b0aa7b462074e0424319"
PREVIOUS_MANIFESTS = (
    "f3c820caba596098dfe6f67d56ac2066d1ed692253586a08b758bd876d40ed6d",
    "e53da378f578295819298c538f3a0eee43910af0234774af81274eac83797066",
)


def digest(path: pathlib.Path) -> str:
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def archive_bundle(bundle: pathlib.Path, target: pathlib.Path) -> str:
    files = sorted(p for p in bundle.rglob("*") if p.is_file() and p.name != "SHA256SUMS")
    manifest = {str(p.relative_to(bundle)): digest(p) for p in files}
    sums = bundle / "SHA256SUMS"
    sums.write_text("".join(f"{value}  {name}\n" for name, value in manifest.items()))
    with target.open("wb") as raw:
        with gzip.GzipFile(filename="", mode="wb", fileobj=raw, compresslevel=1, mtime=0) as zipped:
            with tarfile.open(fileobj=zipped, mode="w", format=tarfile.USTAR_FORMAT) as archive:
                for path in files + [sums]:
                    info = archive.gettarinfo(
                        path, arcname=f"agentseccore-demo/{path.relative_to(bundle)}"
                    )
                    info.uid = info.gid = info.mtime = 0
                    info.uname = info.gname = ""
                    info.mode = 0o755 if path.suffix == ".sh" else 0o644
                    with path.open("rb") as stream:
                        archive.addfile(info, stream)
    with tarfile.open(target) as archive:
        assert len(archive.getmembers()) == len(manifest) + 1
        for name, expected in manifest.items():
            with archive.extractfile(f"agentseccore-demo/{name}") as stream:
                assert hashlib.file_digest(stream, "sha256").hexdigest() == expected, name
    return digest(sums)


def render(template: str, values: dict[str, str]) -> str:
    for name, value in values.items():
        template = template.replace(f"__{name}__", value)
    assert not re.search(r"__[A-Z_0-9]+__", template), "Unresolved release template"
    return template


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("image", type=pathlib.Path)
    parser.add_argument("reference", type=pathlib.Path)
    parser.add_argument("output", type=pathlib.Path)
    args = parser.parse_args()
    assert args.reference.read_text().strip() == IMAGE_REFERENCE
    assert digest(args.image) == IMAGE_SHA256, "Use the accepted image archive"
    source = pathlib.Path(__file__).resolve().parent
    repo = source.parents[1]
    args.output.mkdir(parents=True, exist_ok=True)
    assert not any(args.output.iterdir()), "Use an empty output directory"
    public = f"https://github.com/{REPOSITORY}/blob/agentseccore-demo-{VERSION}/docs/user-guide"
    names = {
        "container-demo.md": "guide",
        "container-demo-card.md": "operation-card",
        "container-demo-ssh.md": "ssh-guide",
    }
    with tempfile.TemporaryDirectory(prefix="demo-bundle-", dir=args.output) as temporary:
        bundle = pathlib.Path(temporary) / "agentseccore-demo"
        for name in ("demo.sh", "demo.env.example", "versions.json", "image.id"):
            bundle.mkdir(exist_ok=True)
            shutil.copy2(source / name, bundle / name)
        (bundle / "image.ref").write_text(IMAGE_REFERENCE + "\n")
        (bundle / "image.tar.gz.sha256").write_text(f"{IMAGE_SHA256}  image.tar.gz\n")
        for language in ("en", "zh"):
            directory = repo / f"docs/user-guide/{language}/agent-security/agent-sec-core"
            destination = bundle / "guides" / language
            destination.mkdir(parents=True)
            for filename, kind in names.items():
                document = (directory / filename).read_text()
                versions = re.findall(r"releases/download/agentseccore-demo-([0-9.]+)/", document)
                versions += re.findall(
                    r"agentseccore-demo-(?:starter-)?linux-amd64-([0-9.]+)\.tar\.gz",
                    document,
                )
                assert all(
                    version == VERSION for version in versions
                ), "Update documented release commands"
                document = document.replace(
                    "../../../en/agent-security/agent-sec-core/", "../en/"
                ).replace("../../../zh/agent-security/agent-sec-core/", "../zh/")
                document = document.replace(
                    "](QUICKSTART.md)",
                    f"]({public}/{language}/agent-security/agent-sec-core/QUICKSTART.md)",
                )
                (destination / filename).write_text(document)
                online = document
                for lang in ("en", "zh"):
                    online = online.replace(
                        f"](../{lang}/",
                        f"]({public}/{lang}/agent-security/agent-sec-core/",
                    )
                for target in names:
                    online = online.replace(
                        f"]({target}",
                        f"]({public}/{language}/agent-security/agent-sec-core/{target}",
                    )
                suffix = "_zh" if language == "zh" else ""
                (args.output / f"agentseccore-demo-{kind}{suffix}.md").write_text(online)
                if kind == "guide" and language == "zh":
                    (args.output / "release-notes.md").write_text(
                        online.split("<!-- release-entry-end -->", 1)[0]
                    )
        (bundle / "README.md").write_text(
            "# AgentSecCore hands-on demo\n\n"
            "Staff: follow the [English guide](guides/en/container-demo.md) or "
            "[中文指南](guides/zh/container-demo.md). Participants: use the "
            "[operation card](guides/en/container-demo-card.md) or "
            "[操作卡](guides/zh/container-demo-card.md).\n\n"
            "On the Linux amd64 host, `./demo.sh up` reuses, imports, or pulls the accepted image. "
            "The offline bundle includes the image; authentication and model requests need network.\n"
        )
        starter = args.output / f"agentseccore-demo-starter-linux-amd64-{VERSION}.tar.gz"
        starter_manifest = archive_bundle(bundle, starter)
        shutil.copy2(args.image, bundle / "image.tar.gz")
        offline_manifest = archive_bundle(
            bundle, args.output / f"agentseccore-demo-linux-amd64-{VERSION}.tar.gz"
        )
        current = "|".join((starter_manifest, offline_manifest))
        values = {
            "VERSION": VERSION,
            "STARTER_SHA256": digest(starter),
            "CURRENT_MANIFESTS": current,
            "SUPPORTED_MANIFESTS": "|".join((current, *PREVIOUS_MANIFESTS)),
        }
        installer = args.output / "install.sh"
        installer.write_text(render((source / "install.sh").read_text(), values))
        values["INSTALLER_SHA256"] = digest(installer)
        (args.output / "ecs-demo.sh").write_text(
            render((source / "ecs-demo.sh").read_text(), values)
        )
        for name in ("install.sh", "ecs-demo.sh"):
            (args.output / name).chmod(0o755)
        shutil.copy2(bundle / "image.ref", args.output / "image.ref")
    files = sorted(p for p in args.output.iterdir() if p.is_file())
    (args.output / "SHA256SUMS").write_text("".join(f"{digest(p)}  {p.name}\n" for p in files))
    print(json.dumps({p.name: p.stat().st_size for p in files}, indent=2))


if __name__ == "__main__":
    main()
