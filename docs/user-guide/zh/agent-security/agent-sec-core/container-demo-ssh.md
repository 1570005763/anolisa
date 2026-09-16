# 工作人员：从本机连接 ECS 体验环境

[English](../../../en/agent-security/agent-sec-core/container-demo-ssh.md)

工作人员在本机准备三个窗口，参与者继续使用同一张[操作卡](container-demo-card.md)。容器、Skill、账号与历史位于 ECS；本机只运行 SSH 客户端和 Chrome。

## 前置条件

- 本机 macOS/Linux 有 Bash、curl、OpenSSH；Windows 使用 WSL，未提供原生 PowerShell 支持。
- `ssh user@ecs-host` 能连接 Linux amd64 ECS。自定义端口、私钥和跳板机使用现有 `~/.ssh/config` 的 SSH 别名；首次确认主机身份由工作人员完成。
- ECS 上 Docker 已启动且登录用户可访问。GitHub/GHCR 用于在线安装；Qoder 服务网络和有效活动账号用于登录及模型请求。
- 一个 ECS 运行一个体验实例，参与者轮流使用；无需新增公网 AgentSight 端口。

<a id="windows"></a>
## Windows：活动前准备一次

现场 Windows 使用 WSL Ubuntu 运行 SSH，使用 Windows Chrome 查看页面；本机无需 Docker 或 Qoder CLI。以下适用于 Windows 11，或 Windows 10 2004 / Build 19041 及以上。工作人员提前完成安装、重启和首次初始化；受管机器遵循单位要求。已有可用 Ubuntu 时跳过安装。详见 [Microsoft WSL 安装说明](https://learn.microsoft.com/windows/wsl/install)。

在 **Windows 管理员 PowerShell** 执行，完成后重启：

```powershell
wsl --install -d Ubuntu
```

从开始菜单打开 Ubuntu，创建 WSL 本地用户名和密码；这不是 ECS 的 SSH 用户。后续在 Windows Terminal 选择 **Ubuntu**，或在普通 PowerShell 输入 `wsl -d Ubuntu`。除明确标注 PowerShell 外，本页客户端命令均在 Ubuntu 内执行。

在 **WSL Ubuntu** 检查工具。只有缺少 curl 或 ssh 时才执行下面的安装命令：

```bash
command -v bash curl ssh
```

```bash
sudo apt-get update && sudo apt-get install -y curl openssh-client
```

A、B 两个窗口使用同一 WSL 用户。每次打开 Ubuntu 后先进入固定客户端目录：

```bash
mkdir -p "$HOME/agentseccore-client"
cd "$HOME/agentseccore-client"
```

### 配置 SSH

工作人员通过内部渠道取得 ECS 地址、SSH 用户、端口、主机指纹及活动专用凭据。云账号用于管理 ECS，SSH 凭据用于连接，Qoder CLI 活动账号在 ECS 容器中登录。实际凭据不放进公开页面或操作卡。Mac 上的 SSH 别名不会自动同步到 WSL。

```bash
mkdir -p "$HOME/.ssh"
chmod 700 "$HOME/.ssh"
```

使用密钥时，将工作人员提供的活动密钥复制进 WSL。以下示例需替换 Windows 用户名和源文件路径；保留路径两侧引号以支持空格：

```bash
install -m 600 "/mnt/c/Users/WINDOWS_USER/Downloads/agentseccore-demo.pem" "$HOME/.ssh/agentseccore-demo"
```

在 WSL 的 `~/.ssh/config` 加入下列配置，替换地址、用户和端口；已有同名条目时修改原条目。密码认证省略 `IdentityFile` 与 `IdentitiesOnly`，由工作人员在 SSH 提示中输入密码。

```sshconfig
Host agentseccore-demo-ecs
    HostName ecs-host
    User demo
    Port 22
    IdentityFile ~/.ssh/agentseccore-demo
    IdentitiesOnly yes
```

```bash
chmod 600 "$HOME/.ssh/config"
ssh agentseccore-demo-ecs 'uname -sm; docker --host unix:///var/run/docker.sock info >/dev/null'
```

首次连接核对工作人员提供的主机指纹；预期显示 `Linux x86_64` 且 Docker 检查无错误。不要跳过主机身份校验。下文 `user@ecs-host` 均可替换为 `agentseccore-demo-ecs`。

<a id="prestage"></a>
## 工作人员：提前准备 ECS

选用专用 Linux amd64 ECS。复用现有机器前先确认用途、容器和数据；不要重装共享开发机来获得“干净”环境。实例创建和网络配置按单位流程及[阿里云 ECS 官方文档](https://help.aliyun.com/zh/ecs/)办理。管理员提前安装 Docker Engine 并确认 SSH 用户可访问，见 [Docker 安装说明](https://docs.docker.com/engine/install/)。

通过内部渠道交接主机、使用时间、负责人和 SSH 连接信息。准备客户端需能下载连接器；ECS 需能访问 GitHub/GHCR 和 Qoder；现场网络需允许 SSH 及本地端口转发。提前下载镜像，现场无需拉取大文件；客户端无 GitHub 网络时，可提前保存本版 `ecs-demo.sh`。离线镜像准备见[准备指南](container-demo.md#staff)。

在准备客户端下载连接器，先执行服务准备：

```bash
curl -fSL --retry 3 --connect-timeout 15 --max-time 180 \
  https://github.com/1570005763/anolisa/releases/download/agentseccore-demo-20260910.1/ecs-demo-20260916.1.sh -o ecs-demo.sh && \
  bash ecs-demo.sh user@ecs-host prepare
```

`prepare` 不会登录或请求模型。随后打开下文 A/B/C，按[准备指南](container-demo.md#staff)登录、验证实际模型请求、预演和复位。离开准备机器前正常退出 A，释放 Qoder CLI 单会话；ECS 容器继续运行。现场连接同一 ECS，复用数据卷中的登录状态，无需复制 Qoder 登录文件。

## 窗口 A：Qoder CLI 和页面隧道

Windows 在 WSL Ubuntu 的 `~/agentseccore-client` 中操作。连接器已下载时直接使用下面的后续进入命令。

在**本机终端 A**执行，将 `user@ecs-host` 替换为实际地址或 SSH 别名：

```bash
curl -fSL --retry 3 --connect-timeout 15 --max-time 180 \
  https://github.com/1570005763/anolisa/releases/download/agentseccore-demo-20260910.1/ecs-demo-20260916.1.sh -o ecs-demo.sh && \
  bash ecs-demo.sh user@ecs-host
```

首次准备或已知旧版更新均自动完成；文件已就绪但镜像缺失时会补拉镜像，已有正确镜像直接复用。脚本保存在本机当前目录。准备完成后，工作人员按[准备指南](container-demo.md#staff)完成原生 `/login`、模型检查和预演。

后续进入同一环境，在本机保存脚本的目录运行：

```bash
bash ecs-demo.sh user@ecs-host
```

## 窗口 B：远端控制终端

Windows 再开一个 WSL Ubuntu 窗口，先进入 `~/agentseccore-client`。在**另一个本机终端 B**、保存脚本的目录运行：

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

## Windows 现场交接与排查

C 使用 **Windows Chrome**，无需在 WSL 内安装浏览器。Windows 通过 localhost 访问 WSL 的机制见 [Microsoft WSL 网络说明](https://learn.microsoft.com/windows/wsl/networking#accessing-linux-networking-apps-from-windows-localhost)。标记窗口 A / Qoder CLI、B / 控制终端；A 退出后回到本机 WSL，B 的 `./demo.sh` 命令在 ECS 目录执行。

在实际 Windows 和现场网络完整预演操作卡，检查中文粘贴、真实 `Skill` 调用、人工 No 和新事件；再验证 B reset 后 A 重进、Chrome 恢复访问。macOS/Linux 的验收不能替代 Windows 实测。最后保持 A 已登录待输入、B 位于 ECS 体验目录、C 可查询事件、目标为 `pass`，再交接给参与者。确保仅有一个使用中的 Qoder CLI 会话；多台客户端连接同一实例不提供独立体验。

- **PowerShell 报 bash 不存在或语法错误**：先进入 WSL Ubuntu。PowerShell 中的 `wsl --list --verbose` 可查看发行版。
- **B 找不到 ecs-demo.sh**：使用相同 WSL 用户，并进入 `~/agentseccore-client`；脚本只需下载一次。
- **密钥权限错误**：使用 WSL `~/.ssh/` 下权限 600 的密钥，不直接引用 `/mnt/c/` 上的密钥；SSH 用户须匹配 ECS 配置。
- **Chrome 访问失败**：保持 A 连接，在另一个本机 WSL 窗口运行 `curl -I --max-time 5 http://127.0.0.1:17396/`。WSL 也失败时检查 A 的隧道报错；只有 Windows 失败时检查 Windows 端口占用、代理、WSL localhost 转发及单位网络策略。不要用公网监听绕过故障。

## 排查

- **本机端口被占用**：运行 `LOCAL_PORT=17397 bash ecs-demo.sh user@ecs-host`，Chrome 使用对应地址。脚本会报告隧道建立失败，不会静默使用错误端口。
- **SSH 失败或转发不允许**：先检查原生 SSH 登录及 SSH 服务的本地转发配置；脚本保留主机身份校验。
- **下载或拉取失败**：恢复网络后重试。也可按[准备指南](container-demo.md#staff)在 ECS 默认目录准备本版离线包，再使用同一个连接器。
- **目录或文件校验失败**：未知安装、修改过的文件和符号链接会被拒绝；不要关闭校验。入口使用默认目录，不管理自定义路径。
- **提示需要终端**：`qoder` 和 `control` 在真实交互终端执行，自动化任务使用 `prepare`。

账号登录、交接和活动结束由工作人员处理；参与者只使用操作卡。
