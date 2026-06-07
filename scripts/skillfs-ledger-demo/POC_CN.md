# SkillFS + Skill Ledger PoC 说明文档

## 1. PoC 定位

本 PoC 展示 SkillFS 与 Skill Ledger 结合后的核心能力：

```text
把可信记录变成可执行的运行边界。
```

它不是一个普通的文件扫描 demo，也不是一个单纯的 Agent skill 安装 demo。它要证明的是：

- Skill 进入文件系统后，不会因为“文件已经存在”就立刻被 Agent 使用。
- Skill 只有经过扫描、签名、建版之后，才会成为 Agent 可见入口。
- Skill 运行中发生变化时，文件系统层可以感知漂移并触发重新决策。
- 当新版本存在风险时，Agent 不需要更换 skill 名称，运行入口会自动回退到最近可信版本。

演示中的 Agent 交互界面使用 OpenClaw dashboard。OpenClaw 始终调用同一个 skill 名称：

```text
tianqi-weather
```

对外呈现的是同名 skill 的连续调用；背后的隐藏、上线、漂移、回退由 SkillFS 和 Skill Ledger 完成。

## 2. 适用范围

本文档用于说明 PoC 的价值、能力边界和验证逻辑，适用于以下场景：

- Agent 平台或系统安全方案评估。
- 关注 skill 供应链安全的工程团队。
- 判断 SkillFS / Skill Ledger 是否具备落地价值的产品和架构讨论。

如果需要逐条复制命令完成现场演示，请使用同目录下的 [RUNBOOK_CN.md](./RUNBOOK_CN.md)。

## 3. 一句话故事

```text
一个真实 ClawHub 天气 skill 被安装、认证、演进、污染；Agent 始终调用同一个 tianqi-weather，
但 SkillFS 根据 Skill Ledger 的可信记录，在 hidden、current、fallback 之间自动切换运行入口。
```

完整故事线：

```text
安装隔离 -> 扫描上线 v1 -> 安全演进 v2 -> 风险注入 v3 -> 同名入口 fallback 到 v2
```

## 4. 参与组件

### OpenClaw

OpenClaw 是真实 Agent 交互界面。PoC 通过 dashboard 输入自然语言指令：

- 安装真实 ClawHub skill。
- 调用 `tianqi-weather` 查询天气。
- 修改 skill 内容，模拟安全演进或供应链污染。

OpenClaw 只加载 SkillFS 的 mount 视图：

```text
/root/skillfs-demo/mount/skills
```

它不应直接加载 source 目录：

```text
/root/skillfs-demo/source
```

否则会绕过 SkillFS 的运行边界。

### SkillFS

SkillFS 是运行边界执行层。它负责决定 `/skills/<skill>` 当前是否对 Agent 可见，以及可见时读取哪个物理目录：

- `hidden`：不暴露给 Agent。
- `current`：读取 source 当前目录。
- `fallback`：读取最近可信 snapshot。

演示中，SkillFS 通过 FUSE hook 感知 mount 路径上的写操作，并触发：

```text
scan -> resolve -> update active mapping
```

SkillFS 的演示事件写入：

```text
/root/skillfs-demo/events.jsonl
```

### Skill Ledger

Skill Ledger 是可信记录和决策提供方。当前 PoC 中它以 CLI 形式运行，不是 daemon。

关键能力：

- `scan`：扫描 skill 内容，生成 signed manifest、版本记录和 snapshot。
- `resolve`：回答当前 skill 应该暴露为哪个运行入口。

核心决策：

| 状态 | 决策 | Agent 看到的效果 |
| --- | --- | --- |
| 未扫描 | hidden | skill 不可见 |
| pass | current | 使用当前版本 |
| drifted / warn / deny / tampered 且有可信版本 | fallback | 使用最近可信 snapshot |
| 风险状态且没有可信版本 | hidden | skill 不可见 |

### tianqi-weather

PoC 使用真实 ClawHub skill：

```text
tianqi-weather
```

它不是手写 fixture。演示中会在原始 skill 基础上制造两个版本变化：

- `v000002`：安全演进，要求回答天气前输出版本号。
- `v000003`：风险污染，加入 prompt injection 测试 payload。

## 5. PoC 边界

本 PoC 重点证明 SkillFS 与 Skill Ledger 的联动边界，不覆盖以下能力：

- 真实生产 daemon 化。
- 进程级沙箱、网络隔离、环境变量隔离。
- eBPF、seccomp、WASM 等运行时隔离技术。
- OpenClaw dashboard iframe 嵌入。
- 绕过 SkillFS 直接写 source 的实时 watcher 兜底。

这些能力可以作为后续阶段展开。本 PoC 的核心是证明：

```text
可信状态可以被文件系统层执行成 Agent 可见的运行边界。
```

## 6. 演示流程与证明点

### 阶段 1：安装隔离

演示动作：

```text
通过 OpenClaw 安装 ClawHub 的 tianqi-weather 到 source 目录。
```

预期现象：

- source 中出现 `tianqi-weather`。
- OpenClaw 不能调用该 skill。
- Skill Ledger 尚无扫描结果。
- `resolve` 决策为 `hidden`。

证明点：

```text
文件出现不等于 Agent 可用。新 skill 入场时先隔离。
```

### 阶段 2：扫描上线 v1

演示动作：

```text
执行 Skill Ledger scan，生成 v000001/pass，并让 SkillFS 重新加载 active mapping。
```

预期现象：

- Skill Ledger 记录 `v000001`，`scanStatus=pass`。
- `resolve` 决策为 `current`。
- OpenClaw 可以调用 `tianqi-weather` 查询天气。

证明点：

```text
只有经过扫描、签名、建版的版本，才会成为 Agent 可用入口。
```

### 阶段 3：安全演进 v2

演示动作：

```text
执行安全演进脚本，通过 SkillFS mount 视图修改 tianqi-weather 的 SKILL.md，加入 v000002 输出规则。
```

终端命令：

```bash
/root/anolisa-demo/scripts/skillfs-ledger-demo/evolve_skill_v2.sh
```

预期现象：

- SkillFS 观察到 `write(SKILL.md)`。
- 修改尚未认证时，SkillFS 先 fallback 到 `v000001`。
- 自动扫描通过后，Skill Ledger 记录 `v000002/pass`。
- `resolve` 决策回到 `current`。
- OpenClaw 再次调用同名 skill 时，回答第一行体现 `Skill Ledger Version: v000002`。

证明点：

```text
安全演进也不是写入即上线；新内容需要再次通过可信记录，才会成为 current。
```

### 阶段 4：风险注入 v3

演示动作：

```text
执行风险注入脚本，通过 SkillFS mount 视图修改 tianqi-weather 的 SKILL.md，加入 v000003 输出规则和 prompt injection 测试 payload。
```

终端命令：

```bash
/root/anolisa-demo/scripts/skillfs-ledger-demo/inject_attack_v3.sh
```

两个修改脚本都只通过 SkillFS mount 视图写入一次版本内容，不操作 source，不主动调用 scan 或 resolve。

预期现象：

- SkillFS 观察到 `write(SKILL.md)`。
- Skill Ledger 自动扫描后记录 `v000003`，状态为 `deny` 或 `warn`。
- findings 中出现 prompt injection 或敏感信息外泄相关规则。
- `resolve` 决策为 `fallback`。
- trusted version 是 `v000002`。
- source 中保留风险 v3 内容。
- mount 视图读取到的是 v2 snapshot。

证明点：

```text
风险版本不会被删除，因为需要保留审计证据；但它也不会成为 Agent 的运行入口。
```

### 阶段 5：同名调用自动回退

演示动作：

```text
清理 OpenClaw 会话上下文后，继续调用同一个 tianqi-weather 查询天气。
```

建议 OpenClaw prompt：

```text
请调用 `tianqi-weather` skill 查询 Beijing 天气。
```

预期现象：

- OpenClaw 调用的 skill 名称没有变化。
- Skill Ledger 当前最新版本仍是风险 v3。
- `resolve` 决策仍为 `fallback`。
- SkillFS mount 视图读取的是 `v000002.snapshot`。
- OpenClaw 的回答不执行 v3 的风险指令。

证明点：

```text
Agent 入口无感保持不变；运行边界自动回退到最近可信版本。
```

## 7. 证据矩阵

| 阶段 | OpenClaw 侧证据 | SkillFS 侧证据 | Skill Ledger 侧证据 |
| --- | --- | --- | --- |
| 安装隔离 | 不能调用 `tianqi-weather` | 没有 current 暴露事件 | no scan result，decision=hidden |
| v1 上线 | 可以调用天气 skill | active mapping 指向 current | version=v000001，scanStatus=pass |
| v2 安全演进 | 同名调用返回 v2 规则 | `write(SKILL.md)`，随后 current:v000002 | version=v000002，scanStatus=pass |
| v3 风险注入 | 不应执行风险指令 | `write(SKILL.md)`，fallback:v000002 | version=v000003，scanStatus=deny/warn |
| 自动回退 | 仍调用同名 skill | mount 读取 v2 snapshot | decision=fallback，trustedVersion=v000002 |

## 8. 观察终端

PoC 展示时建议只保留两个观察终端，避免命令细节分散注意力。

### 终端 A：SkillFS 事件流

观察文件：

```text
/root/skillfs-demo/events.jsonl
```

它展示：

```text
FS Hook -> Ledger Action -> SkillFS Decision
```

示例：

```json
{"fsHook":"write(SKILL.md)","ledgerAction":"scan -> resolve","ledgerStatus":"deny","skillfsDecision":"fallback:v000002"}
```

### 终端 B：Skill Ledger 当前状态

终端 B 展示两个结果：

- 最新版本的扫描状态和 findings。
- `resolve` 后 SkillFS 应暴露的目录。

核心观察点：

```text
decision=current     -> OpenClaw 读取 source 当前版本
decision=fallback    -> OpenClaw 读取 trusted snapshot
decision=hidden      -> OpenClaw 看不到该 skill
```

## 9. 核心表达

推荐主线：

```text
这个 PoC 不是证明我们能扫描一个文件，而是证明扫描结果能控制 Agent 的实际运行入口。

OpenClaw 始终调用同一个 tianqi-weather。用户侧没有换路径、换名字、换命令。
但背后 SkillFS 根据 Skill Ledger 的可信记录，把这个入口切换为 hidden、current 或 fallback。

所以可信记录不只是审计报告，而是可以变成运行时边界。
```

每个阶段的核心表达：

| 阶段 | 核心表达 |
| --- | --- |
| 安装隔离 | 新文件出现了，但未认证前 Agent 看不到。 |
| v1 上线 | 扫描通过后，当前版本成为可信运行入口。 |
| v2 演进 | 安全修改也要重新认证，认证前先回退旧可信版本。 |
| v3 风险 | 风险内容保留在 source 审计，但不会被 Agent 执行。 |
| 同名回退 | Agent 仍调用同名 skill，背后自动读最近可信 snapshot。 |

## 10. 成功标准

PoC 成功需要同时满足：

- OpenClaw 只加载 `/root/skillfs-demo/mount/skills`。
- Step 1 安装后，未扫描 skill 不可见。
- Step 2 扫描后，`tianqi-weather` 可被 OpenClaw 调用。
- Step 3 修改后，SkillFS 能观察到 write hook，并最终上线 `v000002/pass`。
- Step 4 风险注入后，Skill Ledger 记录风险 finding，SkillFS 决策为 `fallback:v000002`。
- Step 5 同名调用仍可用，但读取的是 `v000002.snapshot`，source 中保留 `v000003` 风险内容。

## 11. 附录：关键路径

```text
Demo root:
  /root/skillfs-demo

Source:
  /root/skillfs-demo/source

真实 skill source:
  /root/skillfs-demo/source/tianqi-weather

SkillFS mount:
  /root/skillfs-demo/mount

OpenClaw skill dir:
  /root/skillfs-demo/mount/skills

OpenClaw skill entry:
  /root/skillfs-demo/mount/skills/tianqi-weather

SkillFS event stream:
  /root/skillfs-demo/events.jsonl

Ledger CLI:
  /usr/local/bin/agent-sec-cli-demo
```

## 12. 附录：与 Runbook 的关系

本文档用于说明 PoC 的价值、边界和演示故事。

实际现场执行请使用：

```text
scripts/skillfs-ledger-demo/RUNBOOK_CN.md
```

二者分工：

| 文档 | 用途 |
| --- | --- |
| `POC_CN.md` | 说明 PoC 证明什么、价值是什么、如何观察证据 |
| `RUNBOOK_CN.md` | 提供完整操作台本 |
