# 从本机一键连接 ECS 体验环境

[English](../../../en/agent-security/agent-sec-core/container-demo-ssh.md)

在本机执行连接脚本，自动准备 ECS 上的体验环境、建立 AgentSight 页面隧道并进入 Qoder CLI。脚本复用已发布的容器镜像；体验流程仍按[操作卡](container-demo-card.md)进行。

## 准备条件

- 本机使用 macOS 或 Linux，具备 Bash、curl 和 OpenSSH；Windows 可在 WSL 中执行，未提供原生 PowerShell 脚本。
- `ssh user@ecs-host` 已能连接目标 ECS。自定义端口、私钥或跳板机写入本机 `~/.ssh/config`，命令中的地址可直接替换为 SSH 别名。
- ECS 为 Linux amd64，已安装并启动 Docker，SSH 登录用户可访问 Docker。首次安装需要 ECS 能访问 GitHub 和 GHCR；Qoder CLI 登录与模型调用还需要其服务网络和有效账号。
- 本机准备 Chrome。一个 ECS 只运行一个本体验实例，由参与者轮流使用。

## 一条命令连接

在**本机终端**执行，将 `user@ecs-host` 替换为实际 SSH 地址或别名：

```bash
curl -fsSL --retry 3 --connect-timeout 15 --max-time 60 \
  https://github.com/1570005763/anolisa/releases/download/agentseccore-demo-20260910.1/ecs-demo.sh \
  | bash -s -- user@ecs-host
```

首次使用时，脚本在 ECS 的 `~/agentseccore-demo` 安装启动包、校验文件、拉取固定镜像并启动容器。已有同版启动包时，校验后直接启动和自检，不再下载安装包或拉取镜像，也不会自动复位 Skill。

进入 Qoder CLI 后，首次按提示确认演示目录，并输入 `/login` 完成本人的账号认证。SSH 主机身份确认、密码输入和 Qoder CLI 登录仍使用各自原生交互。远程浏览器登录回调失败时，按[账号认证说明](container-demo.md#2-配置-qoder-cli-登录推荐-token)在 ECS 配置 Personal Access Token；修改 `demo.env` 后先停止容器，再重新连接使其生效。

本机 Chrome 打开 <http://127.0.0.1:17396/#/security>。保持 Qoder CLI 所在终端连接；退出 Qoder CLI 后，SSH 隧道关闭，远端容器、账号状态和记录保留。

## 工作人员常用命令

需要反复操作时，把连接脚本保存到本机当前目录：

```bash
curl -fsSL --retry 3 --connect-timeout 15 --max-time 60 \
  https://github.com/1570005763/anolisa/releases/download/agentseccore-demo-20260910.1/ecs-demo.sh \
  -o ecs-demo.sh
```

下面命令均在**本机终端**执行；省略动作默认进入 Qoder CLI。

| 目的 | 命令 |
| --- | --- |
| 提前准备环境并自检，不打开 Qoder CLI | `bash ecs-demo.sh user@ecs-host prepare` |
| 打开 Qoder CLI 和页面隧道 | `bash ecs-demo.sh user@ecs-host` |
| 检查环境状态 | `bash ecs-demo.sh user@ecs-host doctor` |
| 在第二个终端修改演示 Skill | `bash ecs-demo.sh user@ecs-host tamper` |
| 为下一位参与者复位 | `bash ecs-demo.sh user@ecs-host reset` |
| 活动结束，停止远端容器 | `bash ecs-demo.sh user@ecs-host down` |

`prepare` 可用于无人值守的环境准备，前提是 SSH 已配置免交互认证和可信主机记录。它不执行 Qoder CLI 登录或模型请求。`reset` 会结束本实例的 Qoder CLI 会话并恢复到 `pass`，相应隧道也会关闭；下一轮重新执行默认连接命令。`down` 保留实例数据。

演示时，窗口 A 保持默认连接；窗口 B 执行上表的 `tamper` 或 `reset`；窗口 C 使用 Chrome。窗口 A 的提示词、确认选择和预期结果见[操作卡](container-demo-card.md)。

## 排查

- **本机 17396 被占用**：换一个本机端口，例如 `LOCAL_PORT=17397 bash ecs-demo.sh user@ecs-host`，Chrome 对应访问 `http://127.0.0.1:17397/#/security`。ECS 仍使用 17396。
- **SSH 失败或转发不允许**：先运行 `ssh user@ecs-host` 检查登录；隧道需要 SSH 服务允许本地转发。脚本使用现有 SSH 配置和主机身份校验。
- **缺少 Docker 或权限不足**：先在 ECS 准备 Docker 并确认登录用户可使用本地 Docker，再运行 `prepare`。脚本不会安装 Docker。
- **下载失败**：网络恢复后重试。已成功安装的同版环境可直接重复连接；Qoder CLI 仍需要服务网络。
- **目录版本或文件校验不符**：入口支持本版 `.1` 轻量启动包的默认目录；会保留并拒绝执行其他文件。手工目录、离线包或旧版环境按[完整指南](container-demo.md)直接 SSH 操作，避免混用安装目录。
- **Qoder CLI 提示需要终端**：在本机交互终端运行默认连接命令；自动化任务使用 `prepare`。

脚本只通过 SSH 转发页面到本机回环地址，不要求将 AgentSight 端口暴露到公网。完整安装、账号配置和体验边界见[准备指南](container-demo.md)。
