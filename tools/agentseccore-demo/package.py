#!/usr/bin/env python3
"""Package the accepted image and public demo materials without instance data."""

import argparse
import hashlib
import json
import pathlib
import re
import shutil
import tarfile
import tempfile

VERSION = "20260910.1"
IMAGE_SHA256 = "750ad2e3bb66d3d11a146370e99be93c4917f95edfb8e7fcba046139980b5495"


def digest(path: pathlib.Path) -> str:
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def archive_bundle(bundle: pathlib.Path, target: pathlib.Path) -> None:
    files = sorted(p for p in bundle.rglob("*") if p.is_file() and p.name != "SHA256SUMS")
    manifest = {str(p.relative_to(bundle)): digest(p) for p in files}
    sums = bundle / "SHA256SUMS"
    sums.write_text("".join(f"{value}  {name}\n" for name, value in manifest.items()))
    with tarfile.open(target, "w:gz", compresslevel=1) as archive:
        for path in files + [sums]:
            archive.add(
                path, arcname=f"agentseccore-demo/{path.relative_to(bundle)}", recursive=False
            )
    # Validate the delivery bytes, including the image when present, before uploading.
    with tarfile.open(target) as archive:
        assert len(archive.getmembers()) == len(manifest) + 1
        for name, expected in manifest.items():
            with archive.extractfile(f"agentseccore-demo/{name}") as stream:
                assert hashlib.file_digest(stream, "sha256").hexdigest() == expected, name


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("image", type=pathlib.Path)
    parser.add_argument("reference", type=pathlib.Path)
    parser.add_argument("output", type=pathlib.Path)
    args = parser.parse_args()
    reference = args.reference.read_text().strip()
    assert re.fullmatch(r"ghcr\.io/1570005763/agentseccore-demo@sha256:[0-9a-f]{64}", reference)
    assert digest(args.image) == IMAGE_SHA256, "Use the accepted image archive"
    source = pathlib.Path(__file__).resolve().parent
    repo = source.parents[1]
    args.output.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="demo-bundle-", dir=args.output) as temporary:
        bundle = pathlib.Path(temporary) / "agentseccore-demo"
        (bundle / "guides").mkdir(parents=True)
        for name in ("demo.sh", "demo.env.example", "versions.json", "image.id"):
            shutil.copy2(source / name, bundle / name)
        (bundle / "image.ref").write_text(reference + "\n")
        for language, other in (("en", "zh"), ("zh", "en")):
            directory = repo / f"docs/user-guide/{language}/agent-security/agent-sec-core"
            guide = (directory / "container-demo.md").read_text()
            guide = guide.replace(
                f"../../../{other}/agent-security/agent-sec-core/container-demo.md", f"{other}.md"
            )
            (bundle / "guides" / f"{language}.md").write_text(guide)
            card = (directory / "container-demo-card.md").read_text()
            if language == "zh":
                card = card.replace("container-demo.md", "guides/zh.md")
                card = card.replace(
                    "../../../en/agent-security/agent-sec-core/container-demo-card.md",
                    "guides/card-en.md",
                )
                (bundle / "AgentSecCore上手体验操作卡.md").write_text(card)
            else:
                card = card.replace("container-demo.md", "en.md")
                card = card.replace(
                    "../../../zh/agent-security/agent-sec-core/container-demo-card.md",
                    "../AgentSecCore上手体验操作卡.md",
                )
                (bundle / "guides/card-en.md").write_text(card)
        (bundle / "README.md").write_text(
            "# AgentSecCore hands-on demo\n\n"
            "Linux amd64 with Docker. Follow the [English guide](guides/en.md) or "
            "[中文指南](guides/zh.md) for startup and Qoder CLI authentication.\n\n"
            "Use `./demo.sh pull` for the starter bundle. The offline bundle includes the image, "
            "which `./demo.sh up` imports automatically. Neither bundle contains credentials.\n"
        )
        starter = args.output / f"agentseccore-demo-starter-linux-amd64-{VERSION}.tar.gz"
        archive_bundle(bundle, starter)
        installer = args.output / "install.sh"
        template = (source / "install.sh").read_text()
        assert template.count("__STARTER_SHA256__") == 1
        assert f"release=agentseccore-demo-{VERSION}\n" in template
        assert f"asset={starter.name}\n" in template
        installer.write_text(template.replace("__STARTER_SHA256__", digest(starter)))
        installer.chmod(0o755)
        shutil.copy2(args.image, bundle / "image.tar.gz")
        archive_bundle(bundle, args.output / f"agentseccore-demo-linux-amd64-{VERSION}.tar.gz")
        shutil.copy2(bundle / "image.ref", args.output / "image.ref")
        # GitHub strips non-ASCII asset names, which can make distinct names collide.
        card = args.output / "agentseccore-demo-operation-card_zh.md"
        guide = args.output / "agentseccore-demo-guide_zh.md"
        shutil.copy2(bundle / "AgentSecCore上手体验操作卡.md", card)
        shutil.copy2(bundle / "guides/zh.md", guide)
        public_docs = "https://github.com/1570005763/anolisa/blob/codex/agentseccore-demo-ghcr/docs/user-guide"
        card.write_text(
            card.read_text()
            .replace(
                "guides/zh.md", f"{public_docs}/zh/agent-security/agent-sec-core/container-demo.md"
            )
            .replace(
                "guides/card-en.md",
                f"{public_docs}/en/agent-security/agent-sec-core/container-demo-card.md",
            )
        )
        guide.write_text(
            guide.read_text().replace(
                "](en.md)", f"]({public_docs}/en/agent-security/agent-sec-core/container-demo.md)"
            )
        )
    files = sorted(p for p in args.output.iterdir() if p.is_file() and p.name != "SHA256SUMS")
    assert all(p.name.isascii() for p in files), "Release asset names must use ASCII"
    (args.output / "SHA256SUMS").write_text("".join(f"{digest(p)}  {p.name}\n" for p in files))
    print(json.dumps({p.name: p.stat().st_size for p in files}, indent=2))


if __name__ == "__main__":
    main()
