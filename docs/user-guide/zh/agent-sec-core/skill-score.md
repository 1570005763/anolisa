# Skill 安全评测

[English](../../en/agent-sec-core/skill-score.md)

可选安全评测组件为一个 Skill 生成探针，在 Docker 中执行并给出有证据支撑的安全分。计划生成和裁决调用所支持的百炼 Anthropic 兼容模型端点，会消耗 Token。本地扫描器与 daemon 仍独立安装。

## 安装可选组件

常规 `anolisa --install-mode system install sec-core` 不安装此评测扩展。请使用 `packaging/skill-score/build-rpms.sh` 生成的专用制品；本次源码改动本身不代表已经发布版本或云模板。

在兼容的 RPM 发行版上，安装同一份已核验发布中的两个包：

```sh
sudo yum install ./agent-sec-skill-score-cli-*.rpm ./agent-sec-skill-score-runtime-*.rpm
```

CLI 位于 `/opt/agent-sec/skill-score-cli/bin/agent-sec-cli`，worker 使用 `/opt/agent-sec/skill-score-runtime/bin/python3.12`。两个包均不覆盖 `/usr/bin/agent-sec-cli`，不注册 systemd 服务。发布还包含相同两个 prefix 的 `skill-score-payload.tar.gz`，供 Ubuntu 等环境制作镜像。解包 prefix 不等于验证了 Ubuntu 的 RPM 安装事务。目标 CPU 与 glibc 必须满足发布要求；核验清单后在干净镜像构建环境安装。

将配套 `skill-score-images.tar` 加载到 Docker，按 `images.json` 核对不可变 image ID。工作镜像和 ASC 网络侧车缺一不可；运行时不构建或拉取缺失镜像。需要 Linux x86_64、Docker Compose、可用网络 namespace、包内使用的防火墙/conntrack 规则以及 ptrace/strace。内层容器申请 4096 MiB，外层还需为 Docker、CLI、worker 和侧车留出内存。镜像构建成功不代表运行验收通过。

## 生成计划并执行

通过进程环境或平台密钥注入提供 `ANTHROPIC_API_KEY`，按需设置 `ANTHROPIC_BASE_URL`。凭据不要放入命令参数、任务 JSON、模板或发布清单。

```sh
/opt/agent-sec/skill-score-cli/bin/agent-sec-cli skill-score plan \
  /work/input/skill --output-file /work/output/task.json

/opt/agent-sec/skill-score-cli/bin/agent-sec-cli skill-score run \
  /work/output/task.json --output-file /work/output/report.json \
  --evidence-dir /work/output/evidence
```

`plan` 接受一个含 `SKILL.md` 的目录，输出 `agent-sec-skill-score/task-v1`，记录 Skill 的绝对路径、内容 hash、审计结果和探针。执行 `run` 时必须保留相同内容与绝对路径；内容发生变化会在调用 worker 前拒绝。也可通过 `run -` 从 stdin 读取任务。

输出文件必须尚不存在，证据目录必须不存在或为空。输出须位于被测 Skill 目录之外，不能占用内部证据路径。每次尝试使用独立输出目录。stdout 同样包含公开 JSON；平台有命令输出上限时，建议通过文件接口传输。

## 理解结果

| 退出码 | 含义 |
|---|---|
| `0` | 当前阶段未报告执行或持久化失败；仍须检查报告中的动态覆盖。 |
| `1` | 依赖、执行、模型或持久化失败；可能已有部分报告，应予保留。 |
| `2` | 输入或契约无效，包括内容发生变化。 |

公开报告使用 `agent-sec-skill-score/report-v1`，通过 `content_hash` 绑定任务。`score` 和 `decision` 表达安全评测结论，不证明动态执行完整。检查 `execution` 是否覆盖全部计划探针，且每项均为 `completed: true`；非空 `limitations` 表示覆盖不完整。证据缺失或环境不支持应明确显示。高安全分加上不完整执行，不等于动态评测通过。

一起保存公开 task/report 和证据目录，包括 `environment.json`、`internal-report.json`、`evidence-catalog.json`。失败时先收集部分证据，再删除沙箱。证据可能包含敏感 Skill 内容，访问和留存由平台控制。

## 运行职责

直接使用 Harbor 0.22.0，不修改其依赖源码。ASC 通过公开环境 API 提供任务 Compose 和自有网络侧车镜像。侧车对模型主机执行静态 TCP 白名单；本地目标和 ICMP 保持直连，其余流量拒绝。这不是通用域名防火墙，也不自动实现 Harbor 的分阶段网络策略。

侧车只读策略包含白名单及解析出的 IPv4 地址。GOST 使用该映射与显式空的备用 resolver，工作容器修改共享 `/etc/hosts` 不会改变代理解析。大小写不同、无法命中映射的 TLS 名称保守拒绝。代理失效时保留过滤规则；侧车启动失败时工作容器不得启动。IPv6 验收需要另外提供已启用 IPv6 的测试环境。

部署平台创建外层沙箱、上传不可变 Skill 快照、调用以上命令、下载有界产物并删除精确沙箱。ASC 不接收云管理凭据，也不实现 FC 生命周期 API。采用 FC 时，两个 prefix、Docker 和镜像均安装在 FC 模板内，SkillEval 服务只负责编排。

## 构建与验证

开发者在 Linux x86_64 上准备 Rust 1.93.0、uv、RPM 工具、Docker 和 Compose：

```sh
bash src/agent-sec-core/packaging/skill-score/build-rpms.sh /absolute/empty/release
```

正式构建要求干净 checkout。`--allow-dirty` 生成明确标记的开发制品。发布内容包括两个 RPM、prefix payload、离线镜像、工具清单、源码归档、源码提交和制品摘要。CI 负责构建与测试；正式发布及平台模板发布是另外的操作。

安装 worker 并构建最新镜像后，执行 Linux 网络回归：

```sh
PYTHONPATH=src/agent-sec-core/agent-sec-cli/src:src/agent-sec-core/skill-score-runtime/src \
python src/agent-sec-core/tests/integration-test/skill-score/validate_egress.py \
  --output /absolute/new/egress-validation
```

该网络回归不调用真实模型，不能替代正常、违规、环境失败和超时样本的完整 `plan → run → report` 验收。

构建机的 Docker bridge 无法访问包源时，可为构建命令显式设置 `ASC_IMAGE_BUILD_NETWORK=host`。它只影响可信的 Docker 构建步骤；评测容器仍使用独立网络策略。
