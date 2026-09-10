# AgentSecCore 容器上手体验

[English](../../../en/agent-security/agent-sec-core/container-demo.md)

使用专用体验包，在已准备好的 Qoder CLI 中运行、修改和重新扫描一个 Skill，观察调用前的状态变化，再到 AgentSight 查看记录。主题为 **AgentSecCore：护航 Skill 安全**，口号为 **谁动了我的 Skill？**。

镜像内使用 **Qoder CLI 1.1.48**；`./demo.sh qoder` 启动其命令行交互界面。

## 工作人员：首次准备

使用 Linux x86_64 主机，提前安装并启动 Docker。镜像包包含产品和扫描依赖，导入与本地扫描无需联网；Qoder CLI 认证和模型调用需要可用网络及有效账号。第一版只支持单机单实例体验。

### 一条命令安装并启动（推荐）

在已安装并启动 Docker、且当前用户可访问 Docker 的 Linux amd64 主机执行：

```bash
curl -fsSL https://github.com/1570005763/anolisa/releases/download/agentseccore-demo-20260910.1/install.sh | bash
```

脚本自动下载启动包、校验 SHA-256、按固定 digest 拉取公开镜像、启动容器并运行 `doctor`。默认目录为 `$HOME/agentseccore-demo`，无需 GitHub 登录。脚本检查 Docker 是否可用；缺少 Docker 时会退出并提示先安装、启动 Docker。

安装完成后执行：

```bash
cd "$HOME/agentseccore-demo"
./demo.sh qoder
```

首次在 Qoder CLI 输入 `/login`，按提示用 Chrome 完成本人的账号认证。`doctor` 在登录前显示 `Authentication: missing` 属于预期。容器位于远程主机时按下方步骤 5 建立 SSH 隧道；浏览器登录回调失败时，使用步骤 2 的 Token 方式，保存 `demo.env` 后先执行 `./demo.sh down`，再按步骤 3 启动，让配置生效。

可通过 `bash -s -- /path/to/demo` 指定安装目录：

```bash
curl -fsSL https://github.com/1570005763/anolisa/releases/download/agentseccore-demo-20260910.1/install.sh | bash -s -- /path/to/demo
```

重复执行会校验并复用同版文件与已有实例，保留 `demo.env`、登录状态和体验记录，不会自动复位 Skill。目录中已有其他版本或分发文件被修改时，脚本停止并提示换一个目录。需要手工安装或离线使用时，继续下面的步骤。

### 1. 准备体验目录和镜像

打开[本版 Release](https://github.com/1570005763/anolisa/releases/tag/agentseccore-demo-20260910.1)，选择轻量启动包或完整离线包。在 Linux 主机的空目录中选择以下一种方式，后续 shell 命令均在包含 `demo.sh` 的目录运行。

**方式 A：拉取镜像。** 轻量启动包包含启动脚本、Markdown 操作卡和镜像版本信息：

```bash
curl -fL -o agentseccore-demo-starter.tar.gz https://github.com/1570005763/anolisa/releases/download/agentseccore-demo-20260910.1/agentseccore-demo-starter-linux-amd64-20260910.1.tar.gz
tar -xzf agentseccore-demo-starter.tar.gz
cd agentseccore-demo
sha256sum --check SHA256SUMS
./demo.sh pull
```

`pull` 读取包内 `image.ref`，从 `ghcr.io/1570005763/agentseccore-demo` 按固定 digest 拉取公开镜像，并核对 `image.id`。参与者不需要 GitHub 账号或 `docker login`。镜像拉取成功后继续步骤 2。

**方式 B：离线导入。** 从同一 Release 下载完整离线包后，在空目录中执行：

```bash
tar -xzf agentseccore-demo-linux-amd64-20260910.1.tar.gz
cd agentseccore-demo
sha256sum --check SHA256SUMS
```

继续步骤 2，稍后的 `up` 会自动校验并加载包内 `image.tar.gz`，无需执行 `pull`。

### 2. 配置 Qoder CLI 登录（推荐 Token）

在 Chrome 打开 [Qoder 账号集成页](https://qoder.com/account/integrations)，登录活动使用的账号并创建 Personal Access Token。然后在 Linux 终端创建私有配置文件：

```bash
umask 077
cp demo.env.example demo.env
chmod 600 demo.env
${EDITOR:-vi} demo.env
```

将文件中这一行的等号后填写为实际 Token，不要加引号或 `export`：

```dotenv
QODER_PERSONAL_ACCESS_TOKEN=YOUR_TOKEN
```

保存并退出编辑器。启动脚本会将配置传入容器，Qoder CLI 自动使用 Token 认证。Token 不随镜像分发，不要将 `demo.env` 加入交付包。该方式适合远程主机和容器。[Qoder CLI 官方认证说明](https://docs.qoder.com/cli/authentication)

### 3. 启动环境并进入 Qoder CLI

```bash
./demo.sh up
./demo.sh doctor
./demo.sh qoder
```

`up` 等待服务就绪后显示页面地址；`doctor` 应显示服务可达、签名密钥就绪和认证已配置。首次进入 Qoder CLI 时，仅信任本次演示目录 `/home/demo/agentseccore-lab`。

在 Qoder CLI 中单独输入 `/status` 查看账号与用量状态，再发送：

```text
不要调用工具，只回复 READY。
```

收到正常响应后，单独输入 `/clear`，再开始五步体验。`doctor` 只检查认证配置是否存在；模型响应才说明本次请求可用。

### 4. 备选：在 Qoder CLI 内登录

如果不用 Token，跳过步骤 2，直接启动并进入 Qoder CLI，输入 `/login`，按提示选择浏览器登录。容器不能自动打开浏览器时，将终端显示的登录链接复制到 Chrome，完成后返回终端检查状态。远程环境若回调失败，使用步骤 2 的 Token 方式。[Qoder CLI 登录排查说明](https://docs.qoder.com/cli/troubleshoot-auth)

已配置的 `QODER_PERSONAL_ACCESS_TOKEN` 优先于 `/login` 保存的登录状态。切换方式时，从 `demo.env` 删除该行，依次执行 `./demo.sh down`、`./demo.sh up`、`./demo.sh qoder`，再 `/login`。不要把宿主机的 Qoder CLI 认证文件复制进镜像。

#### 模型 API Key 与登录 Token 的区别

`QODER_PERSONAL_ACCESS_TOKEN` 是 Qoder 账号的访问令牌。模型厂商提供的 API Key 用于调用该厂商的模型，不能填入这个字段。

Qoder CLI 支持 BYOK：先完成 Qoder 账号认证，再进入 `/model`，切换到 **Custom**，选择 **Add custom model...**，按向导选择厂商、模型并填写 API Key。可用入口与账号、套餐有关，厂商和模型以当前向导为准。镜像固定版本 `1.1.48` 的 BYOK 配置和校验流程仍要求 Qoder 身份认证，不能仅用模型厂商 API Key 替代。[Qoder CLI 自定义模型说明](https://docs.qoder.com/cli/custom-models)

本包的三轮体验验收使用 Qoder 账号原生认证；模型厂商 API Key 的完整体验流程尚未实测，不能将其视为已验收的替代配置。

### 5. 打开安全事件页面

准备三个窗口：A 为 Qoder CLI；B 为体验包目录下的 Linux 终端；C 为 Chrome，打开 [AgentSight 安全事件页面](http://127.0.0.1:17396/#/security)。容器运行在远程主机时，先在体验电脑另开终端建立 SSH 隧道并保持运行，将 `DEMO_SSH_HOST` 替换为实际主机别名或 `用户名@主机地址`：

```bash
ssh -N -L 17396:127.0.0.1:17396 DEMO_SSH_HOST
```

## 参与者：五步体验

### 1. 扫描并建立基线

在窗口 A 输入：

```text
请使用 skill-ledger Skill，对 ledger-demo-target 执行快速扫描认证。目标是当前项目下的 .qoder/skills/ledger-demo-target。只执行快速扫描，不执行深度扫描。
```

若 Qoder CLI 请求允许运行扫描命令，核对为本次目标目录后允许。应该看到目标状态为 `pass`。签名记录保存该版本的文件哈希和扫描结果；`pass` 表示本次扫描和校验通过。

### 2. 正常调用

在窗口 A 输入：

```text
请调用名为 ledger-demo-target 的 Skill，并严格按其说明执行。
```

应该看到一次实际的 `Skill` 工具调用，随后输出 `LEDGER_DEMO_OK`。若没有出现 `Skill` 工具调用，本步未通过；先单独输入 `/clear`，再重发本步请求。仍未出现时，请工作人员排查后继续。

### 3. 修改后重新调用，并拒绝继续

在窗口 B 执行：

```bash
./demo.sh tamper
```

该命令只向本次示例追加固定模拟提示注入文本，不执行文本中的指令。回到窗口 A，单独输入 `/clear`，再发送步骤 2 的调用请求。

应该看到 `drifted` 和是否继续的提示。选择 **No**，取消这次调用。`drifted` 表示当前文件与签名版本不同；下一步再判断新增内容的风险。

### 4. 重新扫描

在窗口 A 再次发送步骤 1 的扫描请求。应该看到 `deny`，并发现 `prompt-override` 和 `prompt-secret-exfiltration`。它们分别指出覆盖原有指令和向外发送 system prompt 的要求。

### 5. 查看安全事件

在窗口 C 打开 Security Events，时间范围选 `Last 1h`，Category 选 `skill_ledger`，Verdict 和 Result 设为全部，并清空 Session ID 筛选。点击 Query，按时间和目标路径找到本轮 `pass → drifted → deny`；后续有新事件时，重新点击 `Last 1h`，再点击 Query，以更新查询时间范围。

打开 Qoder CLI 调用前的 `check` 事件，查看 Session ID 和 Tool Call 关联。扫描事件不一定带有同样的调用关联字段。可选加试：再次 `/clear` 并调用目标，看到 `deny` 后仍选 **No**，再查看这次对应的 `check / deny` 事件。

## 工作人员：每轮复位

在窗口 B 执行：

```bash
./demo.sh reset
./demo.sh qoder
```

复位结束本实例内的 Qoder CLI 会话、恢复原始示例并重新扫描到 `pass`。签名密钥与历史事件保留；下一轮根据时间和会话识别记录，不要求版本号从 `v000001` 重新开始。

活动结束时执行：

```bash
./demo.sh down
```

`down` 停止容器并保留实例数据。重新 `up` 不会自动恢复已修改的 Skill，需要时显式运行 `reset`。

## 排查与边界

- **没有就绪**：运行 `./demo.sh doctor`，按具体错误检查 Docker、17396 端口、服务或插件。保留原有服务，先解决端口冲突。
- **认证或模型请求失败**：检查 `demo.env`、账号有效性和网络；修改认证后依次执行 `./demo.sh down` 和 `./demo.sh up`，再进入 Qoder CLI。
- **修改后仍直接回答**：先 `/clear`，确认发生新的 `Skill` 工具调用，避免复述已缓存的回答。
- **没有本轮事件**：扩大时间范围并清空筛选；检查的是本实例的 17396 页面。

本体验使用 `ask` 策略：发现异常后请求确认，参与者拒绝后取消调用。它展示本地 Skill 调用前的检查和扫描，不代表所有 Agent 行为均受相同保护。本轮实测包含多次模型响应和终端确认，完整流程超过三分钟；请按验收报告中的实际耗时安排活动，并预留网络和操作等待时间。

具体组件版本、镜像校验值及验收结果以体验包附带的版本清单和报告为准。
