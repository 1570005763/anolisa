# AgentSecCore：护航 Skill 安全

[English](../../../en/agent-security/agent-sec-core/container-demo.md)

**谁动了我的 Skill？** 工作人员完成一次准备和预演，参与者使用已就绪的窗口体验 Skill 的 `pass → drifted → deny`。对外只需转发[这个入口页](https://github.com/1570005763/anolisa/releases/tag/agentseccore-demo-20260910.1)。

**现场使用 Windows 台式机、ECS 提供环境时**：工作人员先完成 [WSL 与 SSH 准备](container-demo-ssh.md#windows)，再[提前准备 ECS](container-demo-ssh.md#prestage)。现场打开 A/B/C 后，参与者直接使用操作卡；Windows 无需安装 Docker 或 Qoder CLI。

## 选择部署方式

| 容器运行位置 | 工作人员执行安装命令的位置 | 前置条件 |
| --- | --- | --- |
| 本机 Linux | 该 Linux 机器的终端 | Linux amd64；Docker 已启动且当前用户可使用 |
| ECS | 本机 macOS/Linux 终端；Windows 使用 WSL | 本机有 Bash、curl、OpenSSH；SSH 可连接 Linux amd64 ECS，远端 Docker 可用 |

本机 Linux 安装命令：

```bash
curl -fSL --retry 3 --connect-timeout 15 --max-time 180 \
  https://github.com/1570005763/anolisa/releases/download/agentseccore-demo-20260914.1/install.sh -o install.sh && bash install.sh
```

Windows 请先进入 WSL Ubuntu 的 `~/agentseccore-client`，再执行下面的 ECS 命令；已保存连接器时直接运行 `bash ecs-demo.sh user@ecs-host`。

从本机连接 ECS：将 `user@ecs-host` 替换为实际地址或 SSH 别名。

```bash
curl -fSL --retry 3 --connect-timeout 15 --max-time 180 \
  https://github.com/1570005763/anolisa/releases/download/agentseccore-demo-20260914.1/ecs-demo.sh -o ecs-demo.sh && \
  bash ecs-demo.sh user@ecs-host
```

脚本会校验下载内容、复用或准备固定镜像、启动容器并检查服务。默认目录是**容器宿主机**的 `~/agentseccore-demo`。下载或拉取失败后直接重试同一命令；脚本会保存到执行命令的当前目录，供后续重复使用。

| 我想做什么 | 对应材料 |
| --- | --- |
| 工作人员：完成登录、预演和交接 | [准备指南](container-demo.md#staff) |
| 工作人员：配置 ECS 窗口或排查 SSH | [ECS 指南](container-demo-ssh.md) |
| 参与者：开始五步体验 | [Markdown 操作卡](container-demo-card.md) |
| 工作人员：下载离线包 | [本版全部文件](https://github.com/1570005763/anolisa/releases/tag/agentseccore-demo-20260914.1) |

一个宿主机运行一个实例，参与者轮流使用。Chrome 查看安全事件；ECS 模式只需 SSH 隧道，无需开放 AgentSight 公网端口。Docker 由工作人员预装，脚本不会修改系统安装；缺项时参考 [Docker 官方安装说明](https://docs.docker.com/engine/install/)及单位的机器管理要求。

<!-- release-entry-end -->

<a id="staff"></a>
## 工作人员操作

### 1. 准备环境和三个窗口

在线安装需要容器宿主机可访问 GitHub/GHCR；登录和模型调用需要 Qoder 服务网络及有效活动账号。镜像固定为 Linux amd64，AgentSecCore 0.11.1、AgentSight 0.11.2、Qoder CLI 1.1.48。此教程针对专用体验容器，产品常规安装见[AgentSecCore 指南](QUICKSTART.md)。

先检查 Docker：在容器宿主机执行 `docker --host unix:///var/run/docker.sock info`。失败时启动 Docker 或由管理员配置当前用户访问权限，然后重试安装。ECS 的 SSH 前置及端口排查见 [ECS 指南](container-demo-ssh.md)。

本机部署在窗口 A 执行：

```bash
cd "$HOME/agentseccore-demo" && ./demo.sh qoder
```

在窗口 B 执行：

```bash
cd "$HOME/agentseccore-demo"
```

ECS 部署按 ECS 指南打开 A 和 B；B 已经在远端体验目录。窗口 C 用 Chrome 打开脚本输出的实际地址，默认 `http://127.0.0.1:17396/#/security`。保持 A 连接，退出 Qoder CLI 会关闭该 SSH 隧道。

### 2. 登录活动账号并预演

阿里云测试账号用于管理 ECS，SSH 凭据用于连接，Qoder CLI 活动账号用于模型服务，三者分别由工作人员准备。已有有效登录时先检查 `/status` 和下方实际模型请求，无需重新登录。需要登录时，工作人员在窗口 A 确认本次演示目录后输入 `/login`。使用 Qoder CLI 原生登录；ECS 优先选择 **Personal Access Token**，按原生提示粘贴从活动账号获取的 PAT。本机也可以选择浏览器登录。账号认证及首次 SSH 主机确认由工作人员完成，详见 [Qoder CLI 官方认证说明](https://docs.qoder.com/cli/authentication)。

PAT 是 Qoder 账号令牌，不是模型供应商 API Key。原生登录状态保存在本实例数据卷中；常规流程无需编辑 `demo.env` 或重建容器。不要把凭据写入公开脚本、操作卡或截图。

登录后输入 `/status` 检查账号，再发送以下请求验证模型实际可用：

```text
不要调用工具，只回复 READY。
```

`./demo.sh doctor` 只检查服务及凭据存在性，不能证明凭据有效或模型调用成功。模型请求通过后输入 `/clear`，完整预演一次[操作卡](container-demo-card.md)。只有真实 `Skill` 调用、异常确认和对应安全事件均出现，才交给参与者；根据实际耗时安排轮次。

### 3. 交接和下一轮

交接三个已就绪窗口：A 输入提示词，B 执行修改命令，C 查看安全事件。参与者只需操作卡，不再安装或登录。

每轮结束，工作人员在 B 执行：

```bash
./demo.sh reset
```

这会结束 A 的 Qoder CLI、恢复原始 Skill 并扫描到 `pass`，保留账号、签名密钥和历史事件。随后**回到 A**重新进入：本机运行 `./demo.sh qoder`，ECS 在本机保存连接器的目录重新运行 `bash ecs-demo.sh user@ecs-host`（Windows 为 WSL 的 `~/agentseccore-client`）。B 继续保留原控制终端，不在 B 启动 Qoder CLI。

活动结束时在 B 执行 `./demo.sh down`，再退出终端。`down` 停止并删除容器，保留数据卷中的账号和历史；专用活动机器及账号由工作人员继续管理。

### 4. 离线镜像与排查

从本版文件页下载离线包及 `SHA256SUMS`，带到容器宿主机同一目录，执行：

```bash
sha256sum --check --ignore-missing SHA256SUMS && \
  tar -xzf agentseccore-demo-linux-amd64-20260914.1.tar.gz -C "$HOME"
cd "$HOME/agentseccore-demo" && ./demo.sh up && ./demo.sh doctor
```

仅在默认安装目录尚不存在时解压；已有当前版环境时，只将已校验离线包中的 `image.tar.gz` 放进该目录，再运行 `./demo.sh up`。两种来源准备好后使用相同命令，ECS 也继续使用同一个连接器。离线包只解决镜像交付，登录和模型调用仍需网络。

- **拉取失败**：恢复网络后重试；已有正确镜像不需要访问 GHCR。
- **文件校验失败**：停止使用被修改的安装文件，排查原因。安装器只接受当前版或已知未修改的 `20260911.1`，更新时保留私密配置、离线镜像和数据卷，成功后清理临时文件。
- **登录失效**：由工作人员在 A 重新 `/login`；已有 `demo.env` 的 PAT 会优先于原生登录，切换原生登录前须从该私密文件移除 PAT，再 `down`、`up`。
- **未出现 Skill 调用**：按操作卡 `/clear` 后仅重试一次；直接 `Read` 不能算通过。
- **找不到新事件**：在 Chrome 重新选择 `Last 1h` 后点击 `Query`。

本次不提供 BYOK 配置流程，也不支持多人独立并发实例。
