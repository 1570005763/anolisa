# SkillFS + Skill Ledger Demo Runbook

本 runbook 是正式演示台本。演示时不使用 demo UI 作为主呈现层，而是在
OpenClaw dashboard 中执行真实用户指令，并在终端展示 SkillFS / Skill Ledger
产生的真实状态和效果。

核心故事：

```text
安装隔离 -> 扫描上线 v1 -> 安全演进 v2 -> 风险注入 v3 -> 同名入口 fallback 到 v2
```

核心价值：

```text
把可信记录变成可执行的运行边界。
```

## 0. 路径约定

测试机固定使用以下路径：

```text
Demo root:
  /root/skillfs-demo

SkillFS source root:
  /root/skillfs-demo/source

真实 ClawHub skill:
  /root/skillfs-demo/source/tianqi-weather

SkillFS mount root:
  /root/skillfs-demo/mount

OpenClaw skill dir:
  /root/skillfs-demo/mount/skills

OpenClaw 实际 skill 入口:
  /root/skillfs-demo/mount/skills/tianqi-weather

SkillFS event stream:
  /root/skillfs-demo/events.jsonl

Ledger CLI:
  /usr/local/bin/agent-sec-cli-demo

SkillFS binary:
  /root/skillfs-demo-ledger-hot-refresh-rsync/target/debug/skillfs
```

OpenClaw 只能加载 SkillFS mount 视图：

```text
/root/skillfs-demo/mount/skills
```

不要把下面的 source 目录加入 OpenClaw `skills.load.extraDirs`：

```text
/root/skillfs-demo/source
```

否则 OpenClaw 会绕过 SkillFS，直接读到未认证或风险版本。

## 1. 准备阶段

### 1.1 确认 Skill Ledger CLI

Skill Ledger 是 CLI，不是 daemon；这里不需要启动后台服务。

在测试机执行：

```bash
command -v /usr/local/bin/agent-sec-cli-demo
/usr/local/bin/agent-sec-cli-demo skill-ledger --help
/usr/local/bin/agent-sec-cli-demo skill-ledger list-scanners
```

预期效果：

- 能找到 `/usr/local/bin/agent-sec-cli-demo`。
- `skill-ledger` 下有 `scan`、`check`、`resolve` 等命令。
- 默认 scanner 可用。

演示口径：

```text
Skill Ledger 提供可信记录、扫描、签名、版本快照和 resolve 决策能力。
它不是一个常驻服务；SkillFS 需要判断入口时调用它的 CLI。
```

### 1.2 初始化 demo 目录并启动 SkillFS

如果是全新环境，只需要创建 source / logs，然后直接启动 SkillFS。SkillFS 会自动
创建 mountpoint。

```bash
mkdir -p /root/skillfs-demo/source /root/skillfs-demo/logs

nohup /root/skillfs-demo-ledger-hot-refresh-rsync/target/debug/skillfs \
  --log-file /root/skillfs-demo/logs/skillfs.log \
  mount \
  /root/skillfs-demo/source \
  /root/skillfs-demo/mount \
  --foreground \
  --pid-file /root/skillfs-demo/skillfs.pid \
  --ledger-demo-mode \
  --decision-command "/usr/local/bin/agent-sec-cli-demo skill-ledger" \
  --trusted-ledger-writer agent-sec-cli-demo \
  --demo-events /root/skillfs-demo/events.jsonl \
  >/dev/null 2>&1 &
disown

sleep 1
mountpoint -q /root/skillfs-demo/mount
```

如果要从旧 demo 状态重新开始，必须先停掉旧 SkillFS 并 unmount，再删除目录：

```bash
if [ -f /root/skillfs-demo/skillfs.pid ]; then
  kill -TERM "$(cat /root/skillfs-demo/skillfs.pid)" 2>/dev/null || true
  sleep 1
fi

fusermount3 -u /root/skillfs-demo/mount 2>/dev/null || \
  umount -l /root/skillfs-demo/mount 2>/dev/null || true

rm -rf /root/skillfs-demo
```

不要在未 unmount 的情况下执行 `rm -rf /root/skillfs-demo`。否则会进入 FUSE
mount 视图，尝试删除受 SkillFS 控制的 `/root/skillfs-demo/mount/skills`，常见
报错是 `Read-only file system`。

预期效果：

- `/root/skillfs-demo/mount` 是 FUSE mountpoint。
- SkillFS event 会写入 `/root/skillfs-demo/events.jsonl`。
- SkillFS 会通过 `resolve <skill_dir> --json` 初始化和刷新 active mapping。

演示口径：

```text
SkillFS 是运行边界执行层。它决定 OpenClaw 看到的是 current、trusted snapshot，
还是看不到这个 skill。
```

### 1.3 配置并启动 OpenClaw

确认 OpenClaw 配置中包含 SkillFS mount 视图；如果没有，就补写进去。不要把
`/root/skillfs-demo/source` 写进 `extraDirs`。

在测试机执行：

```bash
python3 - <<'PY'
import json
from pathlib import Path

config_path = Path("/root/.openclaw/openclaw.json")
config = json.loads(config_path.read_text(encoding="utf-8"))
load = config.setdefault("skills", {}).setdefault("load", {})
extra_dirs = load.setdefault("extraDirs", [])
mount_dir = "/root/skillfs-demo/mount/skills"
source_dir = "/root/skillfs-demo/source"

if mount_dir not in extra_dirs:
    extra_dirs.append(mount_dir)
if source_dir in extra_dirs:
    extra_dirs.remove(source_dir)
load["watch"] = True

config_path.write_text(
    json.dumps(config, ensure_ascii=False, indent=2) + "\n",
    encoding="utf-8",
)
print(json.dumps(load, ensure_ascii=False, indent=2))
PY
```

然后确认 OpenClaw 状态：

```bash
nohup openclaw gateway run --force \
  > /root/skillfs-demo/logs/openclaw-gateway.log 2>&1 &
sleep 2
openclaw status
openclaw gateway status
```

`--force` 会替换同端口上的旧 gateway 监听，确保刚写入的 `extraDirs` 配置生效。

预期效果：

- OpenClaw gateway 是 local loopback。
- 测试机 dashboard 地址是 `http://127.0.0.1:18789/`。
- OpenClaw 的 skill 加载目录包含 `/root/skillfs-demo/mount/skills`。

演示口径：

```text
OpenClaw 是真实 Agent 交互界面。它始终通过同一个 skill 名称 tianqi-weather
访问能力，不直接关心背后是 current 目录还是 trusted snapshot。
```

### 1.4 打开本机 SSH tunnel

在本机执行：

```bash
ssh -f -N \
  -o ExitOnForwardFailure=yes \
  -o ServerAliveInterval=30 \
  -L 127.0.0.1:18790:127.0.0.1:18789 \
  ECS-alinux-test-agentOS
```

然后在本机浏览器打开：

```text
http://127.0.0.1:18790/
```

正式演示不需要转发 demo UI 的 `8877`。只有排查旧 UI 辅助页时，才临时转发
`8877`。

### 1.5 准备观察终端

演示现场只保留两个观察终端。

终端 A：观察 SkillFS event。

```bash
while [ ! -f /root/skillfs-demo/events.jsonl ]; do
  sleep 0.5
done
tail -f /root/skillfs-demo/events.jsonl
```

`events.jsonl` 不需要手动创建。SkillFS 启动时带了 `--demo-events`，会在第一次
打开 writer 时创建这个文件。上面的循环只是避免文件尚未出现时 `tail -f` 直接
报错退出。

这个文件由 SkillFS 写，不是 OpenClaw 或 Skill Ledger 写。当前 demo hook 逻辑是：
OpenClaw 通过 mount 路径触发 `mkdir/create/write/rename/unlink/rmdir/setattr`
等 FUSE 回调后，SkillFS 按 skill 做 debounce，然后调用
`skill-ledger scan <skill_dir> --json` 更新可信记录，再调用
`skill-ledger resolve <skill_dir> --json` 刷新 active mapping，并向
`events.jsonl` 追加一条 JSONL 事件。通过 mount 路径发生的 skill 修改，不需要
演示者额外手动触发 scan。

注意：SkillFS 启动时初始化 active mapping 的 `current/hidden/fallback` 目前只写
SkillFS log，不写入 `events.jsonl`。因此 Step 2 通过重启 SkillFS 暴露 v1 时，
终端 A 可能没有新事件；从 Step 3 开始通过 mount 路径写 `SKILL.md`，终端 A 才会
稳定出现 hook / resolve / decision 事件。

终端 B：观察 Skill Ledger 对 `tianqi-weather` 的最新扫描结果和 resolve 后的暴露目录。

```bash
last=""
cleared=""
while true; do
  snapshot="$(python3 -c 'import json, pathlib, subprocess
skill_dir = "/root/skillfs-demo/source/tianqi-weather"
skill_path = pathlib.Path(skill_dir)
p = skill_path / ".skill-meta/latest.json"
if not skill_path.exists():
    print("skillDir= not installed")
    print("scanStatus= no scan result yet")
    print("")
    print("decision= (not installed)")
    print("exposedSkillDir= (hidden)")
    raise SystemExit
if not p.exists():
    print("scanStatus= no scan result yet")
else:
    d = json.load(open(p))
    print("version=", d.get("versionId"))
    print("scanStatus=", d.get("scanStatus"))
    scans = d.get("scans") or []
    print("scanCount=", len(scans))
    findings = []
    for s in scans[-1:]:
        findings.extend(s.get("findings") or [])
    if not findings:
        print("findings= none")
    else:
        print("findings=")
        for f in findings:
            print("-", f.get("level") or f.get("severity") or "", f.get("rule") or f.get("id") or "", f.get("file") or f.get("path") or "")
print("")
try:
    r = subprocess.run(
        ["/usr/local/bin/agent-sec-cli-demo", "skill-ledger", "resolve", skill_dir, "--json"],
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=5,
    )
    if r.returncode != 0:
        print("resolve error=", r.stderr.strip() or r.returncode)
    else:
        x = json.loads(r.stdout)
        target = x.get("target")
        decision = x.get("decision")
        if decision == "current":
            exposed = skill_dir
        elif target:
            exposed = str(pathlib.Path(skill_dir) / target)
        else:
            exposed = "(hidden)"
        print("decision=", decision)
        print("currentVersion=", x.get("currentVersion"))
        print("trustedVersion=", x.get("trustedVersion"))
        print("exposedSkillDir=", exposed)
except Exception as e:
    print("resolve error=", e)')"
  if [ "$snapshot" != "$last" ]; then
    if [ -z "$cleared" ]; then
      clear
      cleared="1"
    fi
    if [ -n "$last" ]; then
      lines="$(printf "%s\n" "$last" | wc -l)"
      printf "\033[%sA\033[J" "$((lines + 2))"
    fi
    printf -- "--- %s ---\n%s\n" "$(date '+%H:%M:%S')" "$snapshot"
    last="$snapshot"
  fi
  sleep 2
done
```

这个终端展示两件事：Skill Ledger 对当前 skill 的扫描状态和 finding，以及
`resolve` 后建议 SkillFS 暴露的目录。它第一次输出前会清屏，把复制进去的长命令
刷掉；之后只在状态变化时原地刷新，不保留旧状态，也避免每 2 秒整屏闪烁。
`decision=current` 时暴露 source 当前目录；
`decision=fallback` 时暴露 `.skill-meta/versions/<version>.snapshot`；`hidden`
时不暴露给 OpenClaw。

## 2. Demo Flow

### Step 1：安装真实 ClawHub skill，但不暴露

复制到 OpenClaw dashboard：

```text
帮我安装 ClawHub 的 `tianqi-weather`：`clawhub install tianqi-weather --dir /root/skillfs-demo/source --registry https://cn.clawhub-mirror.com --no-input`。
```

SkillFS 证据（观察终端 A）：

```text
终端 A 不应出现 current/fallback 暴露事件。
```

解释：

```text
触发：这一步是 source-direct ClawHub install，没有经过 FUSE write hook。
动作：SkillFS 没有把新目录加入 active mapping。
效果：tianqi-weather 安装到了 source，但未进入 OpenClaw 可用入口，入场先隔离。
```

Skill Ledger 证据（观察终端 B）：

```text
终端 B 显示 no scan result yet；
decision=hidden，exposedSkillDir=(hidden)。
```

解释：

```text
触发：还没有执行 skill-ledger scan。
动作：Skill Ledger 尚未生成 latest.json、签名 manifest 或版本快照。
效果：当前 skill 没有可信扫描结果，不能成为 Agent 可用入口。
```

预期效果：

```text
ClawHub install 完成；
OpenClaw 不能调用 tianqi-weather。
```

演示口径：

```text
文件进入目录不等于 Agent 立刻可用。入场第一步是隔离。
```

### Step 2：扫描并上线 v1

这里需要重启一次 SkillFS normal mount。原因是 Step 1 的 ClawHub install 是
source-direct 写入 `/root/skillfs-demo/source`，没有经过 FUSE mount。当前 normal
mount 启动时加载一次 source 中已有 skill，不会自动把后续 source-direct 新增的
skill 目录加入 active mapping；重启后 SkillFS 会重新加载 source，并根据新的
Ledger `resolve` 结果暴露 current 版本。

终端执行：

```bash
/usr/local/bin/agent-sec-cli-demo skill-ledger scan \
  /root/skillfs-demo/source/tianqi-weather --json

if [ -f /root/skillfs-demo/skillfs.pid ]; then
  kill -TERM "$(cat /root/skillfs-demo/skillfs.pid)" 2>/dev/null || true
  sleep 1
fi

fusermount3 -u /root/skillfs-demo/mount 2>/dev/null || \
  umount -l /root/skillfs-demo/mount 2>/dev/null || true

nohup /root/skillfs-demo-ledger-hot-refresh-rsync/target/debug/skillfs \
  --log-file /root/skillfs-demo/logs/skillfs.log \
  mount \
  /root/skillfs-demo/source \
  /root/skillfs-demo/mount \
  --foreground \
  --pid-file /root/skillfs-demo/skillfs.pid \
  --ledger-demo-mode \
  --decision-command "/usr/local/bin/agent-sec-cli-demo skill-ledger" \
  --trusted-ledger-writer agent-sec-cli-demo \
  --demo-events /root/skillfs-demo/events.jsonl \
  >/dev/null 2>&1 &
disown

sleep 1
mountpoint -q /root/skillfs-demo/mount
```

复制到 OpenClaw dashboard：

```text
请调用 `tianqi-weather` skill 查询 Hangzhou 天气。
```

OpenClaw 证据：

```text
dashboard 中能够调用 tianqi-weather，并返回 Hangzhou 天气总结。
```

SkillFS 证据（观察终端 A）：

```text
终端 A 可能没有新事件；这是启动初始化 mapping，不是运行中的 FUSE write hook。
```

解释：

```text
触发：SkillFS 重启后重新加载 source 中已有 skill，并调用 resolve。
动作：SkillFS 根据 Ledger 决策把 active mapping 指向当前 skill 目录。
效果：OpenClaw dashboard 已能通过 tianqi-weather 返回 Hangzhou 天气；current 状态看终端 B。
```

Skill Ledger 证据（观察终端 B）：

```text
终端 B 显示 version=v000001、scanStatus=pass、findings=none；
decision=current，exposedSkillDir=/root/skillfs-demo/source/tianqi-weather。
```

解释：

```text
触发：演示者执行 skill-ledger scan。
动作：Skill Ledger 运行默认 scanner，写入 signed manifest，并记录 v000001。
效果：v000001 成为可上线的可信版本。
```

预期效果：

```text
OpenClaw 可以调用 tianqi-weather；
resolve.decision 是 current；
currentVersion 是 v000001。
```

演示口径：

```text
认证上线之后，Agent 使用的是经过扫描、签名、建版的可信 skill。
```

### Step 3：安全演进 v2

终端执行：

```bash
/root/anolisa-demo/scripts/skillfs-ledger-demo/evolve_skill_v2.sh
```

v2 脚本只做一件事：

```text
通过 /root/skillfs-demo/mount/skills/tianqi-weather/SKILL.md 写入一次 v000002
安全演进规则；不操作 source，不调用 scan，不调用 resolve。
```

等待观察终端 A / B 自动更新。这里不需要手动执行 `skill-ledger scan` 或
`skill-ledger resolve`；写入 mount 路径后，SkillFS hook 会自动触发
`scan -> resolve`。

复制到 OpenClaw dashboard：

```text
请调用 `tianqi-weather` skill 查询 Shanghai 天气。
```

SkillFS 证据（观察终端 A）：

```text
终端 A 先出现 write(SKILL.md) / fallback:v000001；
扫描通过后再出现 current:v000002。
```

解释：

```text
触发：v2 演进脚本通过 mount 路径修改 SKILL.md。
动作：SkillFS write hook 触发 scan -> resolve；扫描通过前先回退到 v000001。
效果：v2 未认证期间不直接暴露；扫描通过后同名入口切到 current v000002。
```

Skill Ledger 证据（观察终端 B）：

```text
写入后终端 B 可能短暂显示上一版 v000001/pass；
SkillFS 自动 scan 后刷新为 version=v000002、scanStatus=pass、findings=none；
最终 decision=current，exposedSkillDir=/root/skillfs-demo/source/tianqi-weather。
```

解释：

```text
触发：SkillFS hook 对已修改 skill 自动执行 skill-ledger scan。
动作：Skill Ledger 扫描新内容，写入 v000002 的可信记录。
效果：安全演进版成为新的最新 pass 版本。
```

预期效果：

```text
OpenClaw 仍调用 tianqi-weather；
回答第一行是 Skill Ledger Version: v000002；
resolve.decision 是 current。
```

演示口径：

```text
安全演进不是绕过边界，而是重新扫描后成为新的可信版本。
```

### Step 4：注入风险版本 v3

终端执行：

```bash
/root/anolisa-demo/scripts/skillfs-ledger-demo/inject_attack_v3.sh
```

v3 脚本只做一件事：

```text
通过 /root/skillfs-demo/mount/skills/tianqi-weather/SKILL.md 写入一次 v000003
测试 payload；不操作 source，不调用 scan，不调用 resolve。
```

等待观察终端 A / B 自动更新。这里同样不需要手动执行 `skill-ledger scan` 或
`skill-ledger resolve`；风险写入通过 mount 路径进入后，SkillFS hook 会自动触发
`scan -> resolve`。

SkillFS 证据（观察终端 A）：

```text
终端 A 出现 write(SKILL.md) / fallback:v000002；
风险扫描后仍保持 fallback:v000002。
```

解释：

```text
触发：v3 风险脚本通过 mount 路径写入风险内容。
动作：SkillFS write hook 触发 scan -> resolve，把 active mapping 指向最近可信 v000002 snapshot。
效果：同名入口不中断，但风险版本不会成为运行入口。
```

Skill Ledger 证据（观察终端 B）：

```text
写入后终端 B 可能短暂显示上一版 v000002/pass；
SkillFS 自动 scan 后刷新为 version=v000003、scanStatus=deny 或 warn，
findings 中出现 prompt injection / secret exfiltration 相关规则；
decision=fallback，exposedSkillDir 指向 v000002.snapshot。
```

解释：

```text
触发：SkillFS hook 对风险修改自动执行 skill-ledger scan。
动作：Skill Ledger 扫描 v3 风险内容，记录 finding 和风险状态。
效果：v3 被保留用于审计，但最新可信版本仍是 v000002。
```

预期效果：

```text
source 中保留 v000003 风险内容；
resolve.decision 是 fallback；
trustedVersion 是 v000002。
```

演示口径：

```text
风险版本不会被删除，因为它需要保留用于审计；但它不会成为 Agent 的运行入口。
```

### Step 5：同名调用自动回退

在 OpenClaw dashboard 新开会话，或先单独发送：

```text
/clear
```

然后复制到 OpenClaw dashboard：

```text
请调用 `tianqi-weather` skill 查询 Beijing 天气。
```

终端验证：

```bash
grep -n "Skill Ledger Version" \
  /root/skillfs-demo/source/tianqi-weather/SKILL.md
grep -n "Skill Ledger Version" \
  /root/skillfs-demo/mount/skills/tianqi-weather/SKILL.md
```

SkillFS 证据（观察终端 A）：

```text
终端 A 保持最近一次 fallback:v000002 决策；没有新的 current 事件。
```

解释：

```text
触发：OpenClaw 读取同一个 tianqi-weather 入口。
动作：SkillFS 按现有 active mapping 从 v000002 snapshot 读取内容。
效果：Agent 无感继续调用同名 skill，实际执行最近可信版本。
```

Skill Ledger 证据（观察终端 B）：

```text
终端 B 仍显示 version=v000003、scanStatus=deny 或 warn，
findings 仍是上一轮记录的风险 finding；
decision=fallback，exposedSkillDir 仍指向 v000002.snapshot。
```

解释：

```text
触发：这一步没有新增扫描。
动作：Skill Ledger 状态保持 v3 风险记录；resolve 策略仍应选择 trustedVersion v000002。
效果：风险版本留在 source 中审计，运行边界继续回退到 v000002。
```

预期效果：

```text
source/SKILL.md 中可以看到 v000003；
mount/skills/tianqi-weather/SKILL.md 中看到 v000002；
OpenClaw 仍调用同一个 tianqi-weather；
回答不执行风险指令。
```

演示口径：

```text
Agent 入口没有变化，但运行边界已经自动回退到最近可信版本。
```

## 3. 现场讲解主线

```text
1. 入场隔离：新 skill 进入 source，但未认证前不可见。
2. 认证上线：扫描通过后，SkillFS 暴露 current 版本。
3. 漂移感知：通过 mount 修改后，未认证区间先 fallback。
4. 风险回退：风险版本被扫描发现后，不删除、不暴露。
5. 无感调用：OpenClaw 使用同名 tianqi-weather，背后读到可信 snapshot。
```

一句话总结：

```text
Skill Ledger 记录可信状态，SkillFS 把这个状态执行成 Agent 的运行边界。
```

## 4. 验收清单

- Step 1：source 存在，mount 不可见，`decision=hidden`。
- Step 2：scan pass，`decision=current`，OpenClaw 可调用。
- Step 3：v2 修改后先 fallback，scan 后 `current:v000002`。
- Step 4：v3 风险扫描后 `fallback:v000002`。
- Step 5：OpenClaw 同名调用返回 v2 行为，source 保留 v3。
- 所有复制块只包含 OpenClaw prompt 或终端命令，演示说明不混入复制块。

## 5. 备注

- Skill Ledger 当前作为 CLI 使用，不启动 daemon。
- OpenClaw gateway 默认使用测试机 loopback `127.0.0.1:18789`。
- 正式演示不启动 `run_demo.py --serve`；`8877` UI 只作为可选诊断工具。
- Step 1 是 source-direct ClawHub install；因此 Step 2 扫描后需要重启一次
  SkillFS normal mount，确保它读取到新认证结果。
