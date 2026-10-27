"""Saved images bind their classic and containerd identities without using tags at run time."""

import hashlib
import importlib.util
import io
import json
import tarfile
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location(
    "image_build", ROOT / "skill-score-runtime/image/build.py"
)
assert SPEC and SPEC.loader
BUILD = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(BUILD)
NAMES = ("agent-sec-skill-score:test", "agent-sec-skill-score-egress:test")
OCI = "application/vnd.oci.image."


class ImageArchiveTests(unittest.TestCase):
    def archive(self, root: Path, failure: str = "") -> tuple[Path, list[dict]]:
        members = {}

        def store(data, media_type):
            raw = json.dumps(data).encode() if not isinstance(data, bytes) else data
            identity = hashlib.sha256(raw).hexdigest()
            members["blobs/sha256/" + identity] = raw
            return {
                "mediaType": media_type,
                "digest": "sha256:" + identity,
                "size": len(raw),
            }

        index = {"schemaVersion": 2, "manifests": []}
        legacy = []
        expected = []
        for name in NAMES:
            config = store(
                {
                    "os": "linux",
                    "architecture": "arm64" if failure == "platform" else "amd64",
                    "fixture": name,
                },
                OCI + "config.v1+json",
            )
            layer = store(b"fixture layer", OCI + "layer.v1.tar")
            manifest = store(
                {"schemaVersion": 2, "config": config, "layers": [layer]},
                OCI + "manifest.v1+json",
            )
            manifest["annotations"] = {
                "io.containerd.image.name": "docker.io/library/" + name
            }
            index["manifests"].append(manifest)
            legacy.append(
                {
                    "RepoTags": [name],
                    "Config": "blobs/sha256/" + config["digest"][7:],
                    "Layers": ["blobs/sha256/" + layer["digest"][7:]],
                }
            )
            expected.append(
                {
                    "name": name,
                    "id": config["digest"],
                    "manifest_id": manifest["digest"],
                    "platform": "linux/amd64",
                }
            )
        if failure == "tag":
            index["manifests"][0]["annotations"][
                "io.containerd.image.name"
            ] = "unbound:tag"
        elif failure == "ambiguous":
            index["manifests"][1]["annotations"] = index["manifests"][0]["annotations"]
        elif failure == "legacy-config":
            legacy[0]["Config"] = legacy[1]["Config"]
        elif failure == "legacy-layers":
            legacy[0]["Layers"] = []
        elif failure == "nested-index":
            index["manifests"][0]["mediaType"] = OCI + "index.v1+json"
        elif failure == "manifest-size":
            index["manifests"][0]["size"] += 1
        elif failure in ("manifest-sha", "config-sha"):
            item = expected[0]["id" if failure == "config-sha" else "manifest_id"]
            path = "blobs/sha256/" + item[7:]
            members[path] = b" " + members[path][1:]
        elif failure == "missing-layer":
            del members[legacy[0]["Layers"][0]]
        members["index.json"] = json.dumps(index).encode()
        members["manifest.json"] = json.dumps(legacy).encode()
        target = root / "images.tar"
        with tarfile.open(target, "w") as archive:
            for name, data in members.items():
                member = tarfile.TarInfo(name)
                member.size = len(data)
                archive.addfile(member, io.BytesIO(data))
            if failure == "duplicate-member":
                archive.addfile(member, io.BytesIO(data))
        return target, expected

    def test_archive_binds_config_manifest_tag_and_platform(self):
        with tempfile.TemporaryDirectory() as directory:
            archive, expected = self.archive(Path(directory))
            self.assertEqual(BUILD.archive_image_identities(archive, NAMES), expected)

    def test_archive_rejects_tampered_or_ambiguous_identity_chain(self):
        for failure in (
            "platform",
            "tag",
            "ambiguous",
            "legacy-config",
            "legacy-layers",
            "nested-index",
            "manifest-size",
            "manifest-sha",
            "config-sha",
            "missing-layer",
            "duplicate-member",
        ):
            with self.subTest(
                failure=failure
            ), tempfile.TemporaryDirectory() as directory:
                archive, _ = self.archive(Path(directory), failure)
                with self.assertRaises(ValueError):
                    BUILD.archive_image_identities(archive, NAMES)


if __name__ == "__main__":
    unittest.main()
