# SkillFS + Skill Ledger Demo SDD

## 1. 文档目的

本文档描述当前可演示版本的 **SkillFS + Skill Ledger Demo** 设计。它面向演示讲解、联调实现和后续产品化拆分，目标是让团队明确：

- 这个 demo 要讲什么故事；
- OpenClaw、SkillFS、Skill Ledger、Demo UI 分别承担什么职责；
- 当前测试机上的真实路径和事件流是什么；
- `hidden / current / fallback` 如何从可信记录落实为 Agent 的运行边界；
- 后续 daemon 化的 Skill Ledger 应如何与 SkillFS 解耦协作。

## 2. 通俗设计说明

这个 demo 展示的是：**Skill 不是“文件存在就可以被 Agent 使用”，而是必须先形成可信记录，再由 SkillFS 把这份可信记录变成 Agent 实际可见、可读、可执行的运行边界。**

演示过程中，OpenClaw 始终调用同一个 skill 名称：

```text
tianqi-weather
```

但这个入口背后的真实内容会由 SkillFS 根据 Skill Ledger 的结论动态切换：

| Skill Ledger 结论 | SkillFS 行为 | Agent 看到的效果 |
| --- | --- | --- |
| `hidden` | 不暴露 skill | Agent 无法调用 |
| `current` | 暴露当前 source 版本 | Agent 调用最新可信版本 |
| `fallback` | 暴露最近 pass 快照 | Agent 入口不变，但读到旧可信版本 |

因此 demo 的核心故事是：

```text
入场先隔离
  -> 扫描通过后上线
  -> 修改后先回退到旧可信版本
  -> 扫描通过再切到新版本
  -> 扫描失败则继续回退
```

这就是“把可信记录变成可执行运行边界”。

## 3. Skill Ledger 与 SkillFS 的解耦设计

Skill Ledger 和 SkillFS 在设计上保持职责解耦。

Skill Ledger 是**可信判定层**：

- 扫描 skill 内容；
- 维护版本链；
- 生成 signed manifest 和 snapshot；
- 判断当前版本是否可信；
- 输出 `resolve` 结论。

SkillFS 是**执行边界层**：

- 接收 Agent 对 skill 的文件系统访问；
- 识别 skill 目录、文件和写入事件；
- 根据 Skill Ledger 的结论更新 active mapping；
- 决定某个 skill 是否出现在 Agent 可见入口；
- 决定可见时透出 current 版本还是 trusted snapshot。

当前 demo 中，SkillFS 通过 CLI 调用 Skill Ledger：

```text
agent-sec-cli-demo skill-ledger scan <skill_dir> --json
agent-sec-cli-demo skill-ledger resolve <skill_dir> --json
```

未来产品化形态会演进成 daemon：

```text
SkillFS
  -> 输出 hook/event stream
     mkdir/create/write/rename/unlink/rmdir/setattr

Skill Ledger daemon
  -> 订阅 SkillFS hook event stream
  -> 对受影响 skill 执行 check/scan/certify/resolve
  -> 写入 manifest / snapshot / version chain
  -> 输出稳定处理结论

SkillFS
  -> 消费 Skill Ledger 处理结论
  -> 更新 active mapping
  -> 对 Agent 落实 hidden/current/fallback
```

这个方向下，SkillFS 不需要内置复杂扫描逻辑；Skill Ledger 也不需要接管 FUSE 路径。两者通过事件流和 `resolve` 合约协作。

## 4. Demo 范围

### 4.1 当前 demo 覆盖

当前 demo 覆盖以下能力：

- 使用真实 OpenClaw dashboard 作为 Agent 交互界面；
- 使用真实 ClawHub tianqi-weather skill：`tianqi-weather`；
- 使用真实 SkillFS normal mount；
- 使用真实 Skill Ledger `scan` 和 `resolve`；
- OpenClaw 始终加载 SkillFS 控制后的 mount 入口；
- 新 skill 未扫描前隐藏；
- 扫描通过后暴露当前版本；
- 安全修改期间先 fallback 到旧可信版本；
- 安全修改扫描通过后切换到新版本；
- 恶意修改扫描失败后继续 fallback 到最近可信版本；
- Demo UI 展示 Lifecycle Board、Event Chain、Runtime State 和推荐中文 prompt。

### 4.2 当前 demo 不覆盖

当前 demo 不覆盖：

- OpenClaw dashboard iframe 嵌入；
- `.skill-meta` 对 Agent 的完整隐藏展示；
- 完整 agent-sec-cli 进程鉴权；
- 跨 skill 访问拦截；
- 网络、环境变量、进程级沙箱；
- eBPF / WASM / seccomp；
- Skill Ledger daemon；
- 外部目录变更的实时 watcher 兜底。

这些属于后续 Phase 2 / Phase 3。

## 5. 运行拓扑

### 5.1 测试机路径

当前测试机 demo 使用以下固定路径：

```text
Demo root:
  /root/skillfs-demo

SkillFS source root:
  /root/skillfs-demo/source

真实 ClawHub skill:
  /root/skillfs-demo/source/tianqi-weather

SkillFS mount root:
  /root/skillfs-demo/mount

OpenClaw 加载目录:
  /root/skillfs-demo/mount/skills

OpenClaw 实际 skill 入口:
  /root/skillfs-demo/mount/skills/tianqi-weather

Demo event stream:
  /root/skillfs-demo/events.jsonl

Demo state:
  /root/skillfs-demo/state.json
```

OpenClaw 只应加载 SkillFS mount 视图：

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

不要把 `/root/skillfs-demo/source` 加到 OpenClaw `extraDirs`。否则 OpenClaw 会绕过 SkillFS 的可见性控制，直接读到 source 中的风险版本。

### 5.2 服务进程

当前 demo 涉及三个运行面：

| 进程 | 职责 |
| --- | --- |
| OpenClaw gateway/dashboard | 真实 Agent 交互界面 |
| SkillFS normal mount | Agent skill 文件系统入口与 active mapping 执行层 |
| Demo UI | 展示 prompt、Lifecycle Board、Event Chain、Runtime State |

Demo UI 是展示与演示辅助层，不是 Agent，不替代 SkillFS 的 FUSE 读写路径。

## 6. 组件职责

### 6.1 OpenClaw

OpenClaw 负责模拟真实 Agent 使用方式：

- 从 dashboard 接收演示者输入；
- 执行 ClawHub install；
- 调用 `tianqi-weather`；
- 修改当前加载的 `SKILL.md`；
- 始终通过同一个 skill 名称访问能力。

OpenClaw 只加载：

```text
/root/skillfs-demo/mount/skills
```

### 6.2 ClawHub

ClawHub 负责提供真实 tianqi-weather skill。

安装命令：

```bash
clawhub install tianqi-weather \
  --dir /root/skillfs-demo/source \
  --registry https://cn.clawhub-mirror.com \
  --no-input
```

安装结果：

```text
/root/skillfs-demo/source/tianqi-weather
```

### 6.3 Skill Ledger

Skill Ledger 负责可信记录：

- `scan`：扫描 skill，生成版本状态和 snapshot；
- `resolve`：回答 SkillFS 应该暴露哪个运行入口；
- version chain：维护 `.skill-meta/latest.json` 和 `.skill-meta/versions/*`；
- snapshot：保存可信版本快照；
- findings summary：汇总风险发现；
- diff summary：汇总相对可信版本的差异。

当前 demo 没有单独展示 `certify` 命令。演示中的 `scan` 已经承担生成版本记录与快照的职责，随后由 `resolve` 给出运行入口决策。

### 6.4 SkillFS

SkillFS 负责执行边界：

- 以 normal mount 暴露 `/mount/skills/<skill>`；
- 根据 `resolve` 结论控制 active mapping；
- `hidden` 时不在 readdir 中展示 skill；
- `current` 时读取 source 当前版本；
- `fallback` 时读取 `.skill-meta/versions/<version>.snapshot`；
- 对 mount 路径中的写操作触发扫描与决策刷新；
- 将 demo event 写入 JSONL。

### 6.5 Demo UI

Demo UI 负责展示：

- 当前推荐中文 prompt；
- Lifecycle Board；
- Event Chain；
- Runtime State；
- OpenClaw URL 和关键路径。

Demo UI 只承担演示编排和状态展示职责。它不模拟 Agent，也不替代 SkillFS 的文件系统读写路径。

## 7. Demo 主流程

### 7.1 Step 1：安装真实 skill，入场隔离

演示者在 OpenClaw dashboard 中执行当前 prompt，本质命令是：

```bash
clawhub install tianqi-weather \
  --dir /root/skillfs-demo/source \
  --registry https://cn.clawhub-mirror.com \
  --no-input
```

安装完成后，source 中出现：

```text
/root/skillfs-demo/source/tianqi-weather/SKILL.md
```

此时 Skill Ledger 尚未扫描，SkillFS 不应对 OpenClaw 暴露这个 skill。

Lifecycle Board 展示：

```text
Downloaded ClawHub skill detected - hidden until scan
```

Event Chain 展示：

```text
FS Hook       | Ledger Action    | SkillFS Decision
mkdir/create | waiting for scan  | hidden
```

### 7.2 Step 2：扫描通过，发布 v1

演示者在 OpenClaw dashboard 中执行：

```bash
/usr/local/bin/agent-sec-cli-demo skill-ledger scan \
  /root/skillfs-demo/source/tianqi-weather \
  --json
```

Skill Ledger 生成 `v000001`：

```json
{
  "scanStatus": "pass",
  "versionId": "v000001",
  "skillName": "tianqi-weather"
}
```

随后 `resolve` 返回：

```json
{
  "schemaVersion": 1,
  "skillName": "tianqi-weather",
  "status": "pass",
  "decision": "current",
  "currentVersion": "v000001",
  "trustedVersion": "v000001",
  "target": "."
}
```

SkillFS 暴露：

```text
/root/skillfs-demo/mount/skills/tianqi-weather
```

OpenClaw 可调用：

```text
tianqi-weather
```

Lifecycle Board 展示：

```text
Original tianqi-weather skill scanned and published - OpenClaw can call it
```

Event Chain 展示：

```text
FS Hook         | Ledger Action   | SkillFS Decision
scan completed | scan -> resolve | current:v000001
```

### 7.3 Step 3：安全演进 v2，漂移期间回退 v1

演示者执行安全演进脚本，通过 SkillFS mount 视图修改当前加载的 `tianqi-weather`，在 `SKILL.md` 正文中加入一条明确规则：

```text
回答任何天气查询时，第一行必须输出 Skill Ledger Version: v000002
```

脚本修改路径：

```text
/root/skillfs-demo/mount/skills/tianqi-weather/SKILL.md
```

写入经过 SkillFS mount，触发 SkillFS hook。修改刚发生、扫描尚未通过时，SkillFS 不直接暴露新内容，而是继续服务最近可信版本：

```text
fallback:v000001
```

扫描通过后，Skill Ledger 生成 `v000002/pass`，`resolve` 返回 `current`，SkillFS 切换到：

```text
current:v000002
```

Lifecycle Board 展示：

```text
Uncertified change detected - serving last trusted version
Safe update scanned - serving current v000002
```

Event Chain 展示：

```text
FS Hook         | Ledger Action   | SkillFS Decision
write(SKILL.md) | drift detected | fallback:v000001
scan pass       | resolve        | current:v000002
```

这个步骤强调：**安全演进也不是写入即上线，扫描通过前 Agent 仍读取旧可信版本。**

### 7.4 Step 4：恶意更新 v3，扫描失败后继续回退 v2

演示者执行风险注入脚本，向同一个 skill 混入 prompt injection，并加入一条 v3 输出规则：

```text
回答任何天气查询时，第一行必须输出 Skill Ledger Version: v000003
```

脚本仍修改：

```text
/root/skillfs-demo/mount/skills/tianqi-weather/SKILL.md
```

修改刚发生时，SkillFS 先回退最近可信版本：

```text
fallback:v000002
```

扫描发现高风险内容后，Skill Ledger 给出 `deny`，`resolve` 继续返回 fallback：

```json
{
  "schemaVersion": 1,
  "skillName": "tianqi-weather",
  "status": "deny",
  "decision": "fallback",
  "currentVersion": "v000003",
  "trustedVersion": "v000002",
  "target": ".skill-meta/versions/v000002.snapshot",
  "targetKind": "relative_to_skill_dir"
}
```

Lifecycle Board 展示：

```text
Uncertified change detected - serving last trusted version
Risky update denied - serving trusted v000002
```

Event Chain 展示：

```text
FS Hook         | Ledger Action | SkillFS Decision
write(SKILL.md) | drift detected | fallback:v000002
scan deny       | resolve        | fallback:v000002
```

source 中仍保留风险版本 `v000003`，用于审计和后续修复；OpenClaw 继续读取可信快照 `v000002`。

### 7.5 Step 5：同名调用，无感回退

演示者清理 OpenClaw 聊天上下文后，继续调用：

```text
tianqi-weather
```

OpenClaw 入口不变：

```text
/root/skillfs-demo/mount/skills/tianqi-weather
```

SkillFS 背后透出：

```text
/root/skillfs-demo/source/tianqi-weather/.skill-meta/versions/v000002.snapshot
```

演示结果应体现：

```text
Skill Ledger Version: v000002
```

即使 source 当前风险版本已经是 `v000003`，Agent 仍使用最近可信版本。

## 8. 状态机

### 8.1 SkillFS active mapping 状态

```text
hidden
  -> current:v000001
  -> fallback:v000001
  -> current:v000002
  -> fallback:v000002
```

### 8.2 版本语义

| 版本 | 来源 | 预期状态 | Agent 可见性 |
| --- | --- | --- | --- |
| 原始 ClawHub 版本 | `clawhub install` | 未扫描前 hidden | 不可见 |
| `v000001` | 第一次 scan | pass/current | 可见 |
| `v000002` | 安全演进 | drifted 时 fallback v1，scan pass 后 current | 最终可见 |
| `v000003` | 恶意注入 | drifted/deny | 不可见，fallback v2 |

## 9. Skill Ledger `resolve` 合约

### 9.1 命令

```bash
agent-sec-cli-demo skill-ledger resolve <skill_dir> --json
```

### 9.2 输出字段

```json
{
  "schemaVersion": 1,
  "skillName": "tianqi-weather",
  "status": "deny",
  "currentVersion": "v000003",
  "trustedVersion": "v000002",
  "decision": "fallback",
  "target": ".skill-meta/versions/v000002.snapshot",
  "targetKind": "relative_to_skill_dir",
  "reason": "current version has high-risk findings",
  "findingsSummary": {
    "high": 1,
    "medium": 0,
    "low": 0
  },
  "diffSummary": {
    "modified": ["SKILL.md"]
  }
}
```

### 9.3 exit code 语义

以下策略性结果均返回 exit code `0`：

- `hidden`
- `current`
- `fallback`

非 0 只表示命令执行失败，例如 IO 错误、参数错误、JSON 解析错误或内部异常。

### 9.4 决策规则

| 当前状态 | 最近 pass 版本 | decision | target |
| --- | --- | --- | --- |
| `pass` | 任意 | `current` | 当前 skill 目录 |
| `warn` | 有 | `fallback` | 最近 pass snapshot |
| `deny` | 有 | `fallback` | 最近 pass snapshot |
| `drifted` | 有 | `fallback` | 最近 pass snapshot |
| `tampered` | 有 | `fallback` | 最近 pass snapshot |
| `none` | 无 | `hidden` | 无 |
| `warn/deny/drifted/tampered` | 无 | `hidden` | 无 |

## 10. SkillFS 执行规则

SkillFS 根据 `resolve` 结果维护 active mapping：

| decision | mapping | FUSE 行为 |
| --- | --- | --- |
| `hidden` | 无 active target | readdir 不展示，lookup 返回 ENOENT |
| `current` | `source/<skill>` | read/open/getattr 来自 source 当前目录 |
| `fallback` | `source/<skill>/.skill-meta/versions/<version>.snapshot` | read/open/getattr 来自 snapshot |

写入规则：

- OpenClaw 对 `/mount/skills/tianqi-weather/SKILL.md` 的修改落到 source 当前目录；
- fallback snapshot 只读，不被写入覆盖；
- `.skill-meta/**` 的 Ledger 写入不应触发重复扫描循环；
- symlink/link/mknod 被拒绝。

## 11. Event Chain 设计

### 11.1 事件文件

当前 demo event stream：

```text
/root/skillfs-demo/events.jsonl
```

### 11.2 事件格式

```json
{
  "time": "15:54:21",
  "skill": "tianqi-weather",
  "fsHook": "scan deny",
  "ledgerAction": "resolve",
  "ledgerResult": "deny",
  "skillfsDecision": "fallback:v000002",
  "message": "Risky update denied - serving trusted v000002"
}
```

### 11.3 展示口径

Event Chain 只展示三段核心因果：

```text
FS Hook -> Ledger Action -> SkillFS Decision
```

Lifecycle Board 展示面向演示的状态句子。

事件展示会按演示故事做轻量归并，重点呈现状态变化，而不是暴露每一次底层写入细节。

## 12. Demo UI 设计

Demo UI 不模拟 Agent。它只负责展示和提示。

页面内容：

- Current Prompt：当前建议复制到 OpenClaw 的中文 prompt；
- Demo Steps：折叠显示 5 步 prompt；
- Runtime State：当前 decision、trusted version、Agent entry、serving target；
- Lifecycle Board：生命周期时间线；
- Event Chain：三段式事件链。

OpenClaw dashboard 与 demo UI 分开打开，避免 iframe 带来的 CSP、登录态、WebSocket 和路径代理问题。

## 13. 演示编排原则

Demo 页面只做编排和展示，不把自己伪装成 Agent。演示者从 Demo UI 复制当前 prompt 到 OpenClaw dashboard 执行，随后回到 Demo UI 观察状态变化。

编排原则：

- Agent 交互只发生在 OpenClaw dashboard；
- OpenClaw 始终加载 SkillFS mount 入口；
- Demo UI 不接管 skill 调用；
- Demo UI 不改变 Skill Ledger 的判定结果；
- Demo UI 不绕过 SkillFS 的可见性控制；
- 所有面向观众的变化都落在 `hidden / current / fallback` 主线中。

测试机上的启动脚本会保证演示开始时路径、配置和事件文件处于干净状态。具体启动细节属于运行手册，不作为 SDD 主流程展开。

## 14. 测试与验收

### 14.1 演示验收点

演示成功需要满足：

- Step 1 后，source 有 `tianqi-weather`，OpenClaw 不可调用；
- Step 2 后，OpenClaw 可通过同名 `tianqi-weather` 调用 v1；
- Step 3 写入后，先出现 `fallback:v000001`，扫描通过后出现 `current:v000002`；
- Step 4 写入后，先出现 `fallback:v000002`，扫描 deny 后继续 `fallback:v000002`；
- Step 5 调用同名 skill，回答体现 `Skill Ledger Version: v000002`；
- source 中风险版本 `v000003` 保留；
- OpenClaw `extraDirs` 不包含 source。

### 14.2 自动化测试

当前仓库测试覆盖：

```text
src/agent-sec-core/tests/integration-test/skill-ledger/test_skillfs_ledger_demo_script.py
```

重点验证：

- demo 脚本完整流程；
- ClawHub 真实 skill 安装路径；
- `scan --json` 兼容；
- `resolve` JSON 合约；
- fallback target 为 `.skill-meta/versions/<version>.snapshot`。

## 15. 后续演进

后续产品化建议：

- Skill Ledger daemon 订阅 SkillFS hook event stream；
- SkillFS 不再通过 subprocess 同步调用 CLI；
- 安装入口事件化或由 watcher 覆盖；
- `.skill-meta` 对 Agent 完整隐藏；
- trusted ledger writer 使用更强身份机制；
- 增加跨 skill 访问控制；
- 增加进程、网络、环境变量等运行时安全边界；
- 将 demo event schema 与正式审计日志关系进一步明确。
