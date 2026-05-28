# SkillFS + Skill Ledger Demo

Standalone demo for the SkillFS and Skill Ledger activation flow. The script
does not import `agent_sec_cli`; it only calls `agent-sec-cli` as a subprocess.

The simulator is a local harness, not production SkillFS code. A real SkillFS
integration should consume the same `skill-ledger resolve <skill_dir> --json`
contract: `schemaVersion`, `status`, `decision`, `trustedVersion`, and, for
fallback decisions, `target` plus `targetKind`.

`resolve` is a policy query. `hidden`, `current`, and `fallback` decisions all
return exit code `0` when the command itself succeeds. Consumers must parse the
JSON `decision` field to decide whether a skill should be exposed; exit code is
reserved for CLI, IO, parsing, or other execution failures.

## ClawHub Weather Skill

The demo should be seeded from a real ClawHub weather-query skill, not a local
hand-written fixture. First download a weather skill with ClawHub, for example:

```bash
clawhub search 天气 \
  --dir ~/.copilot-shell/skills \
  --registry https://cn.clawhub-mirror.com

clawhub install <weather-skill-slug> \
  --dir ~/.copilot-shell/skills \
  --registry https://cn.clawhub-mirror.com \
  --no-input
```

Then pass the installed skill directory as the template:

```bash
python3 scripts/skillfs-ledger-demo/run_demo.py \
  --serve \
  --port 8877 \
  --template-skill ~/.copilot-shell/skills/<weather-skill-slug> \
  --skill-name <weather-skill-slug>-ledger-demo
```

The script can also install the ClawHub skill when the exact slug is known:

```bash
python3 scripts/skillfs-ledger-demo/run_demo.py \
  --serve \
  --port 8877 \
  --clawhub-slug <weather-skill-slug> \
  --skill-name <weather-skill-slug>-ledger-demo
```

The demo copy filters package-manager and build metadata such as `.clawhub`,
`.git`, `.skill-meta`, `node_modules`, and `dist`. The skill instructions still
come from the downloaded ClawHub skill, but metadata that is not part of the
runtime skill contract is removed so the security scan focuses on the skill
content being served to OpenClaw.

## Run Locally

From the repository root, using an already downloaded ClawHub weather skill:

```bash
python3 scripts/skillfs-ledger-demo/run_demo.py \
  --serve \
  --template-skill ~/.copilot-shell/skills/<weather-skill-slug> \
  --skill-name <weather-skill-slug>-ledger-demo
```

The script auto-detects the source-tree CLI and uses:

```bash
uv run --project src/agent-sec-core/agent-sec-cli agent-sec-cli
```

Override it when needed:

```bash
python3 scripts/skillfs-ledger-demo/run_demo.py \
  --cli "agent-sec-cli" \
  --root /tmp/skill-demo \
  --template-skill ~/.copilot-shell/skills/<weather-skill-slug> \
  --skill-name <weather-skill-slug>-ledger-demo \
  --serve
```

## Run With OpenClaw

OpenClaw should stay in its own dashboard. Do not iframe it into this demo UI.

Use OpenClaw's real skills directory as the visible SkillFS entry point:

```bash
python3 scripts/skillfs-ledger-demo/run_demo.py \
  --serve \
  --host 127.0.0.1 \
  --port 8877 \
  --openclaw-skills /usr/share/anolisa/skills \
  --template-skill ~/.copilot-shell/skills/<weather-skill-slug> \
  --skill-name <weather-skill-slug>-ledger-demo \
  --openclaw-url http://127.0.0.1:<openclaw-dashboard-port>
```

The simulator refuses to overwrite an existing OpenClaw skill unless that skill
was created by the demo and contains `.skillfs-ledger-demo-owned`.

## Outputs

- Source skill: `/tmp/skill-demo/source/<weather-skill-slug>-ledger-demo`
- OpenClaw-visible entry:
  `/usr/share/anolisa/skills/<weather-skill-slug>-ledger-demo` when
  `--openclaw-skills /usr/share/anolisa/skills` is used
- Local fallback entry: `/tmp/skill-demo/mount/skills/<weather-skill-slug>-ledger-demo`
  when `--openclaw-skills` is omitted
- Event JSONL: `/tmp/skill-demo/events.jsonl`
- State JSON: `/tmp/skill-demo/state.json`
- Web UI: `http://127.0.0.1:8877` when `--serve --port 8877` is used

## Flow

1. Install a real ClawHub weather skill copy and keep it hidden before
   certification.
2. Run `skill-ledger scan` and `skill-ledger resolve`; expose the original
   downloaded `v000001` snapshot. This original version does not need to print
   a version marker.
3. Safely evolve `SKILL.md`; the first demo modification adds a Chinese
   instruction requiring the answer's first line to print `Skill Ledger Version`.
   Scan passes and OpenClaw reads `v000002`.
4. Inject malicious text; scan creates risky `v000003` but does not expose it.
5. Run `resolve`; OpenClaw path is unchanged but serves `v000002.snapshot`.

The UI names these as presentation-friendly actions: install the ClawHub skill,
scan and certify v1, evolve and certify v2, inject a malicious update, then
auto-recover the trusted version.

From v2 onward, the demo writes an explicit runtime marker into `SKILL.md`:

```text
Skill Ledger Version: v000002
```

Ask OpenClaw to print that marker as the first line of the answer. After the
malicious v3 update, the source skill contains `v000003`, but OpenClaw should
still answer with `Skill Ledger Version: v000002`.

This is a local simulator only. It does not implement FUSE, process
authentication, `.skill-meta` policy, or source-directory watcher fallback.
