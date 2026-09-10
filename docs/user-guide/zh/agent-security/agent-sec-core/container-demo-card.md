# AgentSecCore：护航 Skill 安全

[English](../../../en/agent-security/agent-sec-core/container-demo-card.md)

**谁动了我的 Skill？** · 上手体验操作卡

工作人员先按[完整指南中的首次准备步骤](container-demo.md)完成环境启动、Qoder CLI 登录和预演，再将终端交给参与者。指南包含 Token 获取、启动命令、登录检查和远程主机的 Chrome 访问方式。

| 窗口 | 用途 |
| --- | --- |
| A | Qoder CLI，输入体验请求 |
| B | 体验包目录下的 Linux 终端，执行修改和复位命令 |
| C | AgentSight 浏览器，查看安全事件 |

## 1. 扫描并建立基线

在窗口 A 输入；若请求运行扫描命令，核对为本次目标后允许：

```text
请使用 skill-ledger Skill，对 ledger-demo-target 执行快速扫描认证。目标是当前项目下的 .qoder/skills/ledger-demo-target。只执行快速扫描，不执行深度扫描。
```

预期：目标状态为 `pass`。

## 2. 正常调用 Skill

在窗口 A 输入：

```text
请调用名为 ledger-demo-target 的 Skill，并严格按其说明执行。
```

预期：Qoder CLI 实际调用 `Skill` 工具，并输出 `LEDGER_DEMO_OK`。

若没有出现 `Skill` 工具调用，本步未通过。先单独输入 `/clear`，再重发本步请求；仍未出现时，请工作人员排查后继续。

## 3. 修改后重新调用，选择 No

在窗口 B 执行：

```bash
./demo.sh tamper
```

回到窗口 A，先单独输入：

```text
/clear
```

再发送步骤 2 的调用请求。看到 `drifted` 和确认提示后，选择 **No**，取消调用。

`drifted` 表示文件与签名版本不同；此时还没有重新判断新增内容的风险。

## 4. 重扫并查看风险

在窗口 A 再次发送步骤 1 的扫描请求。

预期：状态为 `deny`，发现以下风险：

- `prompt-override`：要求覆盖原有指令。
- `prompt-secret-exfiltration`：要求向外发送 system prompt。

## 5. 查看这一轮的安全记录

在窗口 C 打开 [AgentSight 安全事件页面](http://127.0.0.1:17396/#/security)。

1. 打开 **安全事件（Security Events）**。
2. 选择 **最近 1h（Last 1h）**、**类别（Category）= skill_ledger**。
3. 将 **Verdict** 和 **结果（Result）** 设为 **全部（All）**，清空 **Session ID**。
4. 点击 **查询（Query）**，按时间和目标路径找到本轮 `pass → drifted → deny`。后续有新事件时，重新点击 **最近 1h**，再点 **查询**，让结束时间覆盖最新操作。
5. 打开调用前的 `check` 事件，查看 **Session ID** 和 **工具调用（Tool Call）** 关联详情。直接扫描产生的事件可能没有这些关联字段。

## 工作人员复位

在窗口 B 执行：

```bash
./demo.sh reset
./demo.sh qoder
```

复位会结束本实例的 Qoder CLI 会话、恢复原始 Skill 并重新扫描到 `pass`，历史事件和签名密钥保留。

活动结束时执行：

```bash
./demo.sh down
```

本轮使用 `ask` 策略：异常时请求确认，由参与者选择 **No** 取消调用。修改命令只追加模拟文本。实际耗时受网络、模型响应和命令确认影响，工作人员应根据预演记录安排每轮时长。
