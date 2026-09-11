# 工作人员：从本机连接 ECS 体验环境

[English](../../../en/agent-security/agent-sec-core/container-demo-ssh.md)

工作人员在本机准备三个窗口，参与者继续使用同一张[操作卡](container-demo-card.md)。容器、Skill、账号与历史位于 ECS；本机只运行 SSH 客户端和 Chrome。

## 前置条件

- 本机 macOS/Linux 有 Bash、curl、OpenSSH；Windows 使用 WSL，未提供原生 PowerShell 支持。
- `ssh user@ecs-host` 能连接 Linux amd64 ECS。自定义端口、私钥和跳板机使用现有 `~/.ssh/config` 的 SSH 别名；首次确认主机身份由工作人员完成。
- ECS 上 Docker 已启动且登录用户可访问。GitHub/GHCR 用于在线安装；Qoder 服务网络和有效活动账号用于登录及模型请求。
- 一个 ECS 运行一个体验实例，参与者轮流使用；无需新增公网 AgentSight 端口。

## 窗口 A：Qoder CLI 和页面隧道

在**本机终端 A**执行，将 `user@ecs-host` 替换为实际地址或 SSH 别名：

```bash
curl -fSL --retry 3 --connect-timeout 15 --max-time 180 \
  https://github.com/1570005763/anolisa/releases/download/agentseccore-demo-20260911.1/ecs-demo.sh -o ecs-demo.sh && \
  bash ecs-demo.sh user@ecs-host
```

首次准备或已知旧版更新均自动完成；文件已就绪但镜像缺失时会补拉镜像，已有正确镜像直接复用。脚本保存在本机当前目录。准备完成后，工作人员按[准备指南](container-demo.md#staff)完成原生 `/login`、模型检查和预演。

后续进入同一环境，在本机保存脚本的目录运行：

```bash
bash ecs-demo.sh user@ecs-host
```

## 窗口 B：远端控制终端

在**另一个本机终端 B**、保存脚本的目录运行：

```bash
bash ecs-demo.sh user@ecs-host control
```

现在 B 已通过 SSH 进入 ECS 的 `~/agentseccore-demo`。参与者直接执行操作卡中的 `./demo.sh tamper`，无需自行替换命令或填写主机地址。B 保持连接；退出 B 不会停止容器。

## 窗口 C 和下一轮

用本机 Chrome 打开 A 打印的实际地址，默认 `http://127.0.0.1:17396/#/security`。保持 A 连接；退出 Qoder CLI 或 B 执行 `./demo.sh reset` 后，A 的 SSH 隧道关闭。工作人员在 **A** 重跑上述进入命令，B 继续作为控制终端。

| 工作人员任务（以下命令在本机执行） | 命令 |
| --- | --- |
| 只准备并自检 | `bash ecs-demo.sh user@ecs-host prepare` |
| 查看服务状态 | `bash ecs-demo.sh user@ecs-host doctor` |
| 无控制窗口时复位 | `bash ecs-demo.sh user@ecs-host reset` |
| 活动结束停止容器 | `bash ecs-demo.sh user@ecs-host down` |

`prepare` 不登录或请求模型；无人值守执行还需要既有 SSH 免交互认证和可信主机记录。其他动作 `tamper`、`reset`、`down` 保留兼容。`down` 保留数据卷。

## 排查

- **本机端口被占用**：运行 `LOCAL_PORT=17397 bash ecs-demo.sh user@ecs-host`，Chrome 使用对应地址。脚本会报告隧道建立失败，不会静默使用错误端口。
- **SSH 失败或转发不允许**：先检查原生 SSH 登录及 SSH 服务的本地转发配置；脚本保留主机身份校验。
- **下载或拉取失败**：恢复网络后重试。也可按[准备指南](container-demo.md#staff)在 ECS 默认目录准备本版离线包，再使用同一个连接器。
- **目录或文件校验失败**：未知安装、修改过的文件和符号链接会被拒绝；不要关闭校验。入口使用默认目录，不管理自定义路径。
- **提示需要终端**：`qoder` 和 `control` 在真实交互终端执行，自动化任务使用 `prepare`。

账号登录、交接和活动结束由工作人员处理；参与者只使用操作卡。
