# SkillFS + Skill Ledger Demo

Standalone demo for the SkillFS and Skill Ledger activation flow. The script
does not import `agent_sec_cli`; it only calls `agent-sec-cli` as a subprocess.

For the no-UI presentation runbook used on the test host, see
[`RUNBOOK_CN.md`](./RUNBOOK_CN.md). For the broader Chinese design brief, see
[`DESIGN_CN.md`](./DESIGN_CN.md).

The simulator is a local harness, not production SkillFS code. A real SkillFS
integration should consume the same `skill-ledger resolve <skill_dir> --json`
contract: `schemaVersion`, `status`, `decision`, `trustedVersion`, and, for
fallback decisions, `target` plus `targetKind`.

`resolve` is a policy query. `hidden`, `current`, and `fallback` decisions all
return exit code `0` when the command itself succeeds. Consumers must parse the
JSON `decision` field to decide whether a skill should be exposed; exit code is
reserved for CLI, IO, parsing, or other execution failures.

## ClawHub Weather Skill

The demo should use a real ClawHub tianqi-weather skill, not a hand-written fixture.
The presentation flow asks OpenClaw/ClawHub to install into the SkillFS source
root `/root/skillfs-demo/source`. The `clawhub install` command writes
`<dir>/<slug>`, so the real skill lands exactly at
`/root/skillfs-demo/source/tianqi-weather`. The demo UI shows this as the first
suggested OpenClaw prompt:

```text
请只执行安装命令：
`clawhub install tianqi-weather --dir /root/skillfs-demo/source
--registry https://cn.clawhub-mirror.com --no-input`。不要修改 OpenClaw 配置，
也不要把 `/root/skillfs-demo/source` 加到 `skills.load.extraDirs`。
如果环境没有独立
clawhub 命令，请使用 OpenClaw/ClawHub 的等价安装方式，但最终目录必须相同。
完成后确认
`/root/skillfs-demo/source/tianqi-weather/SKILL.md` 存在。
```

After OpenClaw completes that prompt, the runbook demonstrates that the source
skill exists while the SkillFS mount entry stays hidden until the scan step
publishes it. The old Web UI is now only a diagnostic aid; the formal demo uses
OpenClaw plus terminal evidence from SkillFS and Skill Ledger.

`--template-skill` is still available as a local smoke-test fallback, but it is
not the intended presentation path.

## Run Locally

From the repository root, using the OpenClaw-prompt install flow:

```bash
python3 scripts/skillfs-ledger-demo/run_demo.py \
  --serve \
  --root /root/skillfs-demo \
  --skill-name tianqi-weather \
  --clawhub-slug tianqi-weather
```

With that root, the path contract is:

- ClawHub install dir: `/root/skillfs-demo/source`
- SkillFS source root: `/root/skillfs-demo/source`
- Ledger scan / UI watch skill:
  `/root/skillfs-demo/source/tianqi-weather`
- SkillFS mount root: `/root/skillfs-demo/mount`
- OpenClaw skill entry: `/root/skillfs-demo/mount/skills/tianqi-weather`

The script auto-detects the source-tree CLI and uses:

```bash
uv run --project src/agent-sec-core/agent-sec-cli agent-sec-cli
```

Override it when needed:

```bash
python3 scripts/skillfs-ledger-demo/run_demo.py \
  --cli "agent-sec-cli" \
  --root /root/skillfs-demo \
  --skill-name tianqi-weather \
  --clawhub-slug tianqi-weather \
  --serve
```

## Run With OpenClaw

OpenClaw should stay in its own dashboard. Do not iframe it into this demo UI.

OpenClaw's own `openclaw skills list --json` reports its managed skills
directory as `/root/.openclaw/skills`. Do not use `/usr/share/anolisa/skills`
for this demo; that is not the OpenClaw runtime skill directory on the test
host.

For the demo, keep SkillFS on a dedicated root and configure OpenClaw to load
the SkillFS-controlled mount path as an extra skill directory:

```json
{
  "skills": {
    "load": {
      "extraDirs": ["/root/skillfs-demo/mount/skills"],
      "watch": true
    }
  }
}
```

Then run the demo UI:

```bash
python3 scripts/skillfs-ledger-demo/run_demo.py \
  --serve \
  --host 127.0.0.1 \
  --port 8877 \
  --root /root/skillfs-demo \
  --openclaw-skills /root/skillfs-demo/mount/skills \
  --skill-name tianqi-weather \
  --clawhub-slug tianqi-weather \
  --mount-refresh-command /root/anolisa-demo/scripts/skillfs-ledger-demo/restart_skillfs_demo.sh \
  --openclaw-url http://127.0.0.1:<openclaw-dashboard-port>
```

The simulator refuses to overwrite an existing OpenClaw skill unless that skill
was created by the demo and contains `.skillfs-ledger-demo-owned`.

Current normal-mode SkillFS does not watch direct writes to the source root.
That matters because the first demo step intentionally asks ClawHub to install
the real skill into `/root/skillfs-demo/source`, not through the FUSE mount.
The demo harness therefore uses `--mount-refresh-command` as a deterministic
bridge: after `skill-ledger scan` publishes `current`, if
`/root/skillfs-demo/mount/skills/tianqi-weather/SKILL.md` is still missing, it
restarts the same normal SkillFS mount so the newly installed source skill is
loaded. Later v2/v3 edits go through the mount path and use SkillFS's own write
hook refresh.

## Outputs

- ClawHub install dir: `/root/skillfs-demo/source`
- SkillFS source root: `/root/skillfs-demo/source`
- Source skill: `/root/skillfs-demo/source/tianqi-weather`
- OpenClaw-visible entry:
  `/root/skillfs-demo/mount/skills/tianqi-weather` when
  `--openclaw-skills /root/skillfs-demo/mount/skills` is used
- Local fallback entry: `/root/skillfs-demo/mount/skills/tianqi-weather`
  when `--openclaw-skills` is omitted
- Event JSONL: `/root/skillfs-demo/events.jsonl`
- State JSON: `/root/skillfs-demo/state.json`
- Web UI: `http://127.0.0.1:8877` when `--serve --port 8877` is used

## Flow

1. In OpenClaw, use the suggested Chinese prompt to download the real ClawHub
   tianqi-weather skill directly into `/root/skillfs-demo/source`.
2. The dashboard detects the new source skill under
   `/root/skillfs-demo/source/tianqi-weather` and shows it hidden from
   OpenClaw until scan publishes it.
3. Run `skill-ledger scan` and `skill-ledger resolve`; expose the original
   downloaded `v000001` snapshot. On the test host, the harness remounts
   SkillFS here if the source-direct install has not appeared under
   `/mount/skills` yet. This original version does not need to print a version
   marker.
4. Safely evolve `SKILL.md` through the mount-path demo script; the first demo modification adds a Chinese
   instruction requiring the answer's first line to print `Skill Ledger Version`.
   Scan passes and OpenClaw reads `v000002`.
5. Inject malicious text through the mount-path demo script; scan creates risky `v000003` but does not expose it.
6. Run `resolve`; OpenClaw path is unchanged but serves `v000002.snapshot`.

The UI names these as presentation-friendly actions: detect the downloaded
ClawHub skill, scan and publish v1, evolve and publish v2, inject a malicious
update, then auto-recover the trusted version. OpenClaw always consumes the
SkillFS-controlled entry path.

From v2 onward, the demo writes an explicit runtime marker into `SKILL.md`:

```text
Skill Ledger Version: v000002
```

Ask OpenClaw to print that marker as the first line of the answer. After the
malicious v3 update, the source skill contains `v000003`, but OpenClaw should
still answer with `Skill Ledger Version: v000002`.

This standalone UI is a demo harness. In the test-host flow it observes the
real SkillFS event JSONL and can run the normal-mount refresh command above; it
does not replace SkillFS's FUSE read/write path or production policy logic.
