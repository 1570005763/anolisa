#!/usr/bin/env bash
# Build on Linux amd64 from fixed official artifacts, then export an offline bundle.
set -euo pipefail
cd -- "$(dirname -- "${BASH_SOURCE[0]}")"
[[ "$(uname -s)/$(uname -m)" == Linux/x86_64 ]] || { echo 'Build on Linux amd64.' >&2; exit 1; }
unset DOCKER_HOST DOCKER_CONTEXT
mkdir -p packages dist
python3 - <<'PY'
import base64, hashlib, json, pathlib, urllib.request
d = json.loads(pathlib.Path('versions.json').read_text())
for name, digest in d['packages'].items():
    path = pathlib.Path('packages') / name
    if not path.exists():
        urllib.request.urlretrieve(d['rpm_base_url'] + name, path)
    assert hashlib.sha256(path.read_bytes()).hexdigest() == digest, name
name = f'qodercli-{d["qoder_version"]}.tgz'
path = pathlib.Path('packages') / name
if not path.exists():
    urllib.request.urlretrieve(f'https://registry.npmjs.org/@qoder-ai/qodercli/-/{name}', path)
assert 'sha512-' + base64.b64encode(hashlib.sha512(path.read_bytes()).digest()).decode() == d['qoder_npm_integrity']
PY
DOCKER_BUILDKIT=0 docker --host unix:///var/run/docker.sock build -t agentseccore-demo:20260909 .
docker --host unix:///var/run/docker.sock image inspect --format '{{.Id}}' agentseccore-demo:20260909 > dist/image.id
docker --host unix:///var/run/docker.sock save agentseccore-demo:20260909 | gzip -1 > dist/image.tar.gz
python3 check.py dist/image.tar.gz
cp demo.sh demo.env.example versions.json dist/
(cd dist && sha256sum image.tar.gz image.id demo.sh demo.env.example versions.json > SHA256SUMS)
echo 'Offline runtime bundle exported to dist/. Add the operation card and user guides before delivery.'
