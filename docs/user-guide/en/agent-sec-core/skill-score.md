# Skill safety assessment

[中文版](../../zh/agent-sec-core/skill-score.md)

The optional assessment component plans probes for one Skill, executes them in Docker, and produces an evidence-qualified safety score. Planning and judging call a supported Bailian Anthropic-compatible model endpoint and consume tokens. The local scanner and daemon installation remains separate.

## Install the optional component

The normal `anolisa --install-mode system install sec-core` installation does not install this assessment add-on. Use the add-on release produced by `packaging/skill-score/build-rpms.sh`; this source change does not publish a release or cloud template.

On compatible RPM distributions, install the two artifacts from the same verified release:

```sh
sudo yum install ./agent-sec-skill-score-cli-*.rpm ./agent-sec-skill-score-runtime-*.rpm
```

The CLI is `/opt/agent-sec/skill-score-cli/bin/agent-sec-cli`; its worker uses `/opt/agent-sec/skill-score-runtime/bin/python3.12`. Neither package replaces `/usr/bin/agent-sec-cli` nor registers a systemd service. The release also provides `skill-score-payload.tar.gz` containing the same two prefixes for image builders, including Ubuntu. Prefix extraction does not prove an Ubuntu RPM installation transaction. Match the target CPU and the release's glibc baseline, verify the release manifest, and use a clean image build directory.

Load the matching `skill-score-images.tar` into Docker and verify its image IDs against `images.json`. Both the work image and the ASC egress sidecar are required; runtime startup does not build or pull missing images. A Linux x86_64 host, Docker Compose, usable network namespaces, the packaged firewall/conntrack rules, and ptrace/strace support are required. Reserve memory outside the inner container's 4096 MiB allocation for Docker, the CLI, worker and sidecar. An image build alone is not runtime acceptance.

## Plan and execute

Provide `ANTHROPIC_API_KEY` and, when needed, `ANTHROPIC_BASE_URL` through the process environment or your platform's secret injection. Do not put credentials into command arguments, task JSON, templates or release manifests.

```sh
/opt/agent-sec/skill-score-cli/bin/agent-sec-cli skill-score plan \
  /work/input/skill --output-file /work/output/task.json

/opt/agent-sec/skill-score-cli/bin/agent-sec-cli skill-score run \
  /work/output/task.json --output-file /work/output/report.json \
  --evidence-dir /work/output/evidence
```

`plan` accepts one directory containing `SKILL.md`. Its task uses `agent-sec-skill-score/task-v1`, records the resolved Skill path and content hash, and carries the audit and probes. Keep the exact content and absolute path available to `run`. `run` rejects content drift before invoking the worker. A task can also be read from stdin with `run -`.

Output files must not already exist. Evidence directories must be absent or empty. Outputs must be outside the evaluated Skill, and may not conflict with internal evidence paths. Prefer new output directories for every attempt. Standard output also contains the public JSON; file transfer is recommended when a platform limits command output.

## Interpret results

| Exit | Meaning |
|---|---|
| `0` | The requested stage completed without a reported execution/persistence failure. Validate the report's coverage as well. |
| `1` | Dependency, execution, model or persistence failure. A partial report may exist and should be retained. |
| `2` | Invalid input or contract, including content drift. |

A public report uses `agent-sec-skill-score/report-v1` and binds `content_hash` to the task. `score` and `decision` describe the safety assessment; they do not establish dynamic completeness. Verify that `execution` accounts for every planned probe and each entry is `completed: true`; nonempty `limitations` means incomplete coverage. Missing evidence or an unsupported environment must remain visible. A high score with incomplete execution is not a passed dynamic assessment.

Retain the public task/report and evidence directory together, including `environment.json`, `internal-report.json` and `evidence-catalog.json`. Collect partial evidence before deleting a failed sandbox. Evidence may contain sensitive Skill content; the platform controls access and retention.

## Runtime ownership

Harbor 0.22.0 is consumed without editing its source. ASC supplies a task Compose definition and its own sidecar image through the public environment API. The sidecar enforces a static model-host TCP allowlist; local destinations and ICMP remain direct, and other traffic is rejected. This is not a general-purpose domain firewall or Harbor phase-dependent policy implementation.

The sidecar's read-only policy holds the allowlist and resolved IPv4 addresses. GOST uses that mapping and an explicit empty fallback resolver, so changes to the work container's shared `/etc/hosts` cannot redirect the proxy. A differently cased TLS name that misses the mapping fails closed. Proxy failure leaves filtering rules installed; startup failure prevents the work container from starting. IPv6 acceptance requires a separate IPv6-enabled test environment.

A deployment platform creates the outer sandbox, uploads an immutable Skill snapshot, invokes these commands, downloads bounded artifacts and deletes the exact sandbox. ASC does not receive cloud credentials or implement FC lifecycle APIs. For FC, install both prefixes, Docker and the images inside the FC template; the SkillEval service only orchestrates them.

## Build and verify

Developers build on Linux x86_64 with Rust 1.93.0, uv, RPM tooling, Docker and Compose:

```sh
bash src/agent-sec-core/packaging/skill-score/build-rpms.sh /absolute/empty/release
```

Release builds require a clean checkout. `--allow-dirty` creates an explicitly marked development artifact. The release includes both RPMs, prefix payload, offline images, tool inventory, source archive, source commit and artifact hashes. The CI workflow builds and tests the component; publishing and platform template release remain separate operations.

Run the Linux egress regression against the installed worker and freshly built images:

```sh
PYTHONPATH=src/agent-sec-core/agent-sec-cli/src:src/agent-sec-core/skill-score-runtime/src \
python src/agent-sec-core/tests/integration-test/skill-score/validate_egress.py \
  --output /absolute/new/egress-validation
```

This network regression does not call a real model and does not replace full `plan → run → report` acceptance with normal, violating, environment-failure and timeout samples.

If the builder cannot reach package sources through its Docker bridge, explicitly set `ASC_IMAGE_BUILD_NETWORK=host` for the build command. This changes only trusted Docker build steps; assessment containers retain their independent network policy.
