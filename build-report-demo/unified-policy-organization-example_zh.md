# 统一 Policy 组织样稿：源策略、执行映射与三端派生

本文面向方案落地讨论，用 build-report 的 R1–R4 展示 Cedar 正文如何组织、同一规则如何映射到不同环境，以及派生配置如何追溯来源。执行机制与生效边界见[三个执行面的边界说明](sandbox-os-harness-boundaries_zh.md)；具体 Cedar 和 YAML 样稿集中维护在本文。

**适用前提：这是统一 schema 与三端适配完成后的目标设计，不是现有 CLI 的可执行配置或运行验收结果。** 下文的策略身份、版本和环境名称均为示例；不会创建真实策略、凭据或部署。仓库的[本地验收任务](task.txt)仍要求禁网、不上报，不能用本文的完整上报场景替换该任务的授权。

## 1. 一份源策略，加一份本次执行映射

```text
任务意图
  ↓
统一源策略 task.cedar
  ├── R1：构建写入范围
  ├── R2：回滚包删除保护
  ├── R3：GitHub 凭据使用限制
  └── R4：敏感文件读取保护
  ↓ 确认后发布
源策略版本 + 本次执行映射
  ├── 使用哪个源策略版本
  ├── 保护哪个任务作用域
  ├── 每条规则由哪些执行端承担
  └── 执行前置条件与能力缺口
  ↓ 按能力转译
Sandbox 配置 / OS Harness 配置 / Gateway 配置
```

| 对象 | 回答的问题 | 维护方式 |
| --- | --- | --- |
| 统一源策略 | 允许什么、禁止什么、保护什么？ | 业务授权的统一来源，修改后发布新版本 |
| 本次执行映射 | 本次由谁、在哪个作用域执行？ | 引用源规则，不能另行增加或放宽授权 |
| 派生执行配置 | 具体后端如何落实？ | 根据源策略与映射生成，不手工维护另一套授权 |

Intent 生成一份候选，确认后才成为发布输入；不分别独立生成三套安全政策。派生结果可以是三个文件，也可以通过 API 下发，物理文件数量不等于独立 Policy 数量。

R1–R4 是本文的安全要求编号：R1–R3 分别对应 [Skill](skill/build-report/SKILL.md) 已有的越界写、删回滚包、打印 Authorization 头风险；R4 表示本地任务的 `deploy.env` 禁读要求，不表示 Skill 已新增 R4 风险编号，也不等同于 README 的 Case 编号。

一项要求可以由多条 Cedar 语句及部署约束共同落实。下面为便于追踪，每项核心要求先用一条主规则表示，不能推导出“一项要求只能有一条语句”。

## 2. 按 R1–R4 组织 Cedar 正文

### 核心规则样稿

下面四条规则放在同一份 `task.cedar` 中，而不是按 Sandbox、OS Harness、Gateway 分成互斥的源策略区域。`@id` 用于示意稳定的规则标识，名称体现安全要求，不包含固定执行归属。

**这只是四项核心规则的完整样稿，不是完整启动策略。** 项目与运行库读取、解释器启动等基础授权仍需根据任务要求列入同一源策略；上报还需要受控网络通道。不要为了让样稿运行，临时补上无限制的读、写、执行或网络权限。现有转译器尚不能直接接受这份混合文本，具体差异见第 6 节。

```cedar
// ============================================================
// R1：构建写入范围
// 只允许写构建产物目录和报告目录。
// ============================================================

@id("R1-output-write")
permit(
    principal,
    action == SecCore::Action::"file.write",
    resource is SecCore::File
)
when {
    resource.path == "/srv/br-demo/releases" ||
    resource.path like "/srv/br-demo/releases/*" ||
    resource.path == "/srv/br-demo/out" ||
    resource.path like "/srv/br-demo/out/*"
};

// ============================================================
// R2：回滚包删除保护
// 禁止删除 previous.zip，不额外禁止正常原地写入。
// ============================================================

@id("R2-protect-rollback")
forbid(
    principal,
    action == SecCore::Action::"file.write",
    resource is SecCore::File
)
when {
    resource.path == "/srv/br-demo/releases/previous.zip" &&
    context.input.operation == SecCore::WriteOperation::"delete"
};

// ============================================================
// R3：GitHub 凭据使用限制
// 指定凭据仅能用于向指定 Issue 提交评论。
// 文件路径是受信凭据引用，不是真实 token 的值。
// ============================================================

@id("R3-github-report")
@modify("inject_credential")
@real_token_file("/secure/github-real")
@fake_token_file("/secure/github-fake")
@inject_header("Authorization")
@inject_format("auto")
@response_rewrite("true")
permit(
    principal,
    action == SecCore::Action::"network.send",
    resource is SecCore::HttpEndpoint
)
when {
    resource.host == "api.github.com" &&
    context.input.scheme == "https" &&
    context.input.method == "POST" &&
    context.input.path ==
        "/repos/demo/project-a/issues/42/comments"
};

// ============================================================
// R4：敏感文件读取保护
// 禁止读取任务目录中的模拟凭据文件。
// ============================================================

@id("R4-deny-sensitive-read")
forbid(
    principal,
    action == SecCore::Action::"file.read",
    resource is SecCore::File
)
when {
    resource.path == "/srv/br-demo/project/deploy.env"
};
```

### R1 与 R2：允许范围和禁止操作共同生效

R1 允许在 `releases/` 工作，R2 从中排除对回滚包的删除。下面是源策略语义说明，不是本机测试结果：

| 操作 | 源策略语义 |
| --- | --- |
| 写 `releases/new.zip` | R1 允许 |
| 普通原地写入 `releases/previous.zip` | R1 允许，R2 不额外禁止 |
| 删除 `releases/previous.zip` | R2 禁止，不能被 R1 的允许覆盖 |
| 写目录范围外的 shell 配置 | 没有匹配写授权时拒绝 |

最后一行的前提是本次有效授权集中没有其他更宽的写入许可。普通 `permit` 不会限制其他 `permit`；不能只看到 R1 就断言所有外部写入都被拒绝。

Cedar 的 `forbid` 优先是策略求值语义，多端执行还必须确保禁止要求真正交给承接端。不能因为某个文件保护后端跳过 `permit`，就把它当成独立执行完整 Cedar 默认拒绝语义的引擎。

普通原地写入不等于通过临时文件加 rename 替换目标。现有删除保护可能约束部分替换或重命名路径，需单独核对合法写入语义；单独禁删也不代表内容不可篡改。若 Sandbox 只能把整个目录设为只读，就不能视为完整满足“禁删但保留正常写入”。

### R3：请求条件与凭据托管一起落实

R3 的 HTTP 条件取自[上报脚本](skill/build-report/scripts/report.sh)的目标；注入 annotations 沿用[Gateway Cedar 示例](../src/agent-sec-core/v2/crates/asc-gateway-plan/policies/github.cedar)的表达方式，但将凭据使用范围收窄到一个 POST 接口。

- `@modify` 等 annotations 是 Gateway 的执行约定，Cedar 的 `permit` 本身不会替换 token。
- `/secure/github-real`、`/secure/github-fake` 是示例引用，真实值不进入 Intent、策略正文或演示输出；受信存储必须提供有效凭据绑定。
- 任务只持有受管 fake token，所以脚本打印的也是 fake token；不是网关事后清除已泄露的日志。
- 响应回显保护需启用并验证，只能承诺覆盖实现支持的形式；Gateway 自身日志也不能泄露真实值。
- `network.send` 不建立网络可达性；粗粒度 `network.use` 也不能单独表达“只允许经过 Gateway”。受控通道与旁路限制需要相应执行机制承接。
- [现有 Gateway Plan](../src/agent-sec-core/v2/crates/asc-gateway-plan/src/plan.rs)允许无受管凭据的请求在安全检查后原样转发；这条凭据规则不是所有外联的默认拒绝防火墙，也不验证正文只能包含构建摘要。

### R4：基础读取授权不能覆盖明确禁读

完整策略即使允许读取项目目录，也不能绕过 R4。当前[留档策略](policies/task.cedar)采用全局读取上限（程序生成的基础授权，[任务文本](task.txt)不写）加 `deploy.env` 精确禁读，不再要求读取目录白名单；实际读取仍受命令申请、执行投影和文件保护作用域约束。

如果沿用这种宽读取上限，真实 Gateway 凭据必须隔离在任务不可见或不可读的受信边界内。R4 只保护 `deploy.env`，不会自动保护所有真实 token 文件。

本例使用裸 `principal`，并不自带任务身份隔离。部署层必须将策略可靠地绑定到目标进程、资源和请求作用域；下文的 `scopeRef` 只是对这个绑定的引用。

## 3. 同一份源策略，在环境 A／B／C 中如何映射

假设发布身份为 `build-report-task@7`。这里的 `7` 是业务策略 revision，与 schema revision 不是同一个版本号。三个环境使用同一源版本，只改变执行映射：

| 源规则 | 环境 A | 环境 B | 环境 C |
| --- | --- | --- | --- |
| `R1-output-write` | Sandbox | Sandbox | Sandbox |
| `R2-protect-rollback` | OS Harness | Sandbox | Sandbox + OS Harness |
| `R3-github-report` | Gateway | Gateway | Gateway |
| `R4-deny-sensitive-read` | OS Harness | Sandbox | Sandbox + OS Harness |

能力前提如下，均为目标环境假设，不是已验证的部署组合：

- **环境 A**：Sandbox 承接目录访问边界，OS Harness 承接精确禁删与禁读。
- **环境 B**：Sandbox 及其适配器能够准确落实 R1、R2、R4，并覆盖全部需要保护的操作路径。
- **环境 C**：两端都具备相应能力，选择对 R2、R4 做双重保护。

这张表列出核心规则的承接端，R3 的凭据隔离、受控出口等协作前置条件仍需同时落实。不能因为表中只写 Gateway，就忽略 Sandbox 或其他网络机制的配合。

不能仅根据 Docker、bubblewrap、microVM 的名称选择映射；还要确认实际后端、适配器、保护对象与作用域。例如只在 shell 内启用 Sandbox，不足以承接对 Sandbox 外原生文件工具的禁读要求。microVM 中的本地文件操作也不能直接假定由宿主 OS Harness 覆盖。

```text
源规则：R2-protect-rollback / 回滚包删除保护
  当前环境 A → OS Harness
  当前环境 B → Sandbox（支持精确禁删的后端及适配器）
  当前环境 C → Sandbox + OS Harness（双重保护）
```

任务要求和资源范围不变时，业务规则不用重写；映射改变后仍需重新转译、应用和验证。没有可用承接端时，明确报告缺口，不删除源规则，也不默认为已保护。

## 4. 本次执行映射的 YAML 示意

下面用环境 C 展示建议的数据组织方式。**这是设计示意，不是当前 CLI、PAP 或 Gateway 已支持的配置协议；不能直接下发。** 字段只用于解释职责，不定义新的产品接口。

```yaml
source:
  policyId: build-report-task
  revision: 7

deployment:
  environment: environment-c
  mappingRevision: 1
  scopeRef: build-report-run

rules:
  R1-output-write:
    enforceBy:
      - sandbox
    required: all

  R2-protect-rollback:
    enforceBy:
      - sandbox
      - os-harness
    required: all

  R3-github-report:
    enforceBy:
      - gateway
    required: all

  R4-deny-sensitive-read:
    enforceBy:
      - sandbox
      - os-harness
    required: all

prerequisites:
  - 任务只能取得绑定到本次作用域的 fake token
  - 真实凭据对任务不可见或不可读
  - 上报请求必须经过受控 Gateway，限制旁路
  - 必需执行端在相关操作开始前完成策略应用
```

| 字段 | 示意含义 |
| --- | --- |
| `source` | 三端共同引用的不可变源策略版本 |
| `scopeRef` | 引用受信编排创建的实际任务绑定，不以调用方随意填写的名称作为身份依据 |
| `enforceBy` | 本次选定的承接端；名称需解析到具备对应能力的实际后端 |
| `required: all` | 列出的执行端都必须完成应用；双重保护不能只成功一个就算就绪 |
| `mappingRevision` | 标识映射变化，用于关联派生配置与应用、验证证据 |
| `prerequisites` | 待由部署与运行编排落实的义务，文本列出不等于已实现 |

映射通过规则标识引用 Cedar，没有重新定义 `previous.zip` 路径或 GitHub URL。授权条件只维护在源策略中，映射不能改写这些条件。

### 在策略上如何读出每项要求的执行边界

`enforceBy` 是部署侧的映射，不写进策略正文：正文只说允许什么、禁止什么，写进执行端名称既会随部署变化，也等于让生成模型替部署做决定。为了让边界在同一份文本上可读，`agent-sec-cli intent --format cedar` 在导出的文件头写一段按语句形状推导的 `COVERAGE`，一项要求的一个承接端占一行：

```text
// COVERAGE: who can carry each requirement, from statement shape only:
//   permit -> sandbox + PDP (a permit testing context -> sandbox only);
//   forbid on file.read or file.write -> os-harness (any other forbid -> none).
//   A Scope still has to apply it; a requirement without statements is not listed.
//   base  #1 #2  sandbox, PDP
//   goal  #3     sandbox, PDP
//   R1    #4     os-harness
//   R3    #5     os-harness
```

| 正文里的形状 | 行里的承接端 | 与本文 YAML 的对应 |
| --- | --- | --- |
| `permit`，条件只用 `resource` | `sandbox, PDP` | `enforceBy` 含 sandbox；daemon PDP 也读这一条 |
| `permit`，条件里带 `context` | `sandbox only` | 授权视图会丢掉这条，只剩沙箱执行时有效 |
| `forbid` 作用于 `file.read` / `file.write`、`principal` 留空 | `os-harness` | `enforceBy` 含 os-harness；授权视图丢弃 `forbid` |
| 其他 `forbid` | `none` | 没有执行端能承接，发布后整个 Binding 会失败 |

`#N` 是语句在整份生成物中的序号（基础授权占 `#1`、`#2`），按它回到正文就能找到具体那条规则。同一项要求的多条语句落到不同承接端时各占一行；没有语句的要求（例如禁网只靠不授予）不出现，记在 `unresolved`。

这一段只回答"有没有执行端能表达"：它不读部署环境，也不代表已下发。某次运行实际由谁承担，仍以 Scope 的 Binding 状态为准，与 YAML 的 `enforceBy`、`required: all` 同一层次。

源规则标识需要在同一策略内唯一；保留同一业务要求的标识有助于跨版本追踪，但具体语义必须结合 revision 判断。一项要求若拆成多条语句，还应保留要求到语句的对应关系，不能只按数组位置或可变注释识别。

实际编排需要将前置条件转成可执行配置并取得证据。源策略版本、映射版本、目标作用域及具体后端版本应能够关联；映射未完成、依赖未就绪时，不能释放依赖这些保护的操作。

**当前落地方式（agent-sec-core）**：这份 YAML 没有作为文件实现，各字段拆到已有组件中，用户不需要另外维护映射：

| YAML 字段 | 落在哪里 | 说明 |
| --- | --- | --- |
| `rules` 的键（规则标识） | 源策略每条语句的 `@id`，由意图生成写出 | 一项要求多条语句时写 `R1.1`、`R1.2`，按 `.` 前缀归组；三个消费者都接受 `@id`，它不改变语义 |
| `enforceBy` | 不存储，由各执行端按语句形状推导；`intent propose` 导出时以 `// COVERAGE:` 逐项列出（见上一节） | 生成时不知道部署环境，模型自报的承接端也不可信；写进源策略还会破坏跨环境复用 |
| `source`、`scopeRef`、`required: all` | `scope create` 引用 `policyId` + `revision`；每个执行端的 Binding 状态 | 预览只说明"能表达"，是否已应用以 Binding `READY` / `APPLY_FAILED` 为准 |
| `environment`、`mappingRevision`、`prerequisites` | 未实现 | 当前只有环境 C 一种组合；没有语句的要求（如禁网只靠不授予）不进 COVERAGE，列在 `unresolved` |

## 5. 三端派生结果与来源追踪

下面是环境 C 的语义预览，不是后端原生配置，也不是当前命令输出。完整派生结果还需包含基础启动授权与相关部署约束。

```text
源策略：build-report-task@7
映射：environment-c / mappingRevision=1
作用域引用：build-report-run

Sandbox 执行视图
  R1-output-write
    → 构建目录写入边界
  R2-protect-rollback
    → 精确删除保护
  R4-deny-sensitive-read
    → 敏感文件读取限制

OS Harness 执行视图
  R2-protect-rollback
    → 文件删除检查点保护
  R4-deny-sensitive-read
    → 文件读取检查点保护

Gateway 执行视图
  R3-github-report
    → HTTPS + 主机 + POST + 路径匹配
    → 受管 fake token 替换为真实 token
    → 按配置处理响应中的凭据回显
```

R2 出现两次，但两处都引用 `build-report-task@7 / R2-protect-rollback`。这是一个业务要求、两个执行保护点，不是两套独立策略。

派生不是简单复制或剪切 Cedar：两个后端可以使用不同原生配置，但需要保持对象、操作和作用域语义，并保留来源关系。任何未承接要求或额外阻断合法操作的情况都要显式报告。

逐端记录“已表达、已映射、已应用、已验证”。映射 YAML 只分配责任，不构成真实转译或应用回执。一端成功不能代替另一端成功；组合测试若在前一个执行端已被拒绝，后一个执行端可能根本未收到操作，验证双重保护需在受控环境中获得各端证据。

验收至少覆盖：

| 要求 | 正向与负向证据 |
| --- | --- |
| R1 | 产物写入成功，范围外写入被拒绝 |
| R2 | 删除回滚包被拒绝；业务要求允许的普通写入仍能完成 |
| R3 | 测试上游验证凭据注入正确；错误主机、方法、路径的受管凭据使用被拒绝；任务与网关日志、响应检查无真实值泄露 |
| R4 | 在要求覆盖的 shell 与原生文件工具路径上，敏感文件读取被拒绝；非敏感业务读取仍正常 |
| 配套条件 | Gateway 通道可达、旁路受限、真实凭据不对任务暴露 |

使用受控测试端和测试凭据即可，不需要向真实 Issue 提交评论。四项核心要求不会因为派生为六个执行责任项就变成六项业务覆盖；要求覆盖数与执行端验证数应分别统计。

## 6. 修改、发布与当前实现差异

### 什么变化应该改哪里

| 变化 | 修改位置与处理 |
| --- | --- |
| 更换后端，但业务要求和资源范围不变 | 更新执行映射，重新派生、应用、验证 |
| R2 从单端改为双重保护 | 更新执行映射，分别验证两端 |
| 禁删对象或 GitHub 允许目标改变 | 修改源策略，发布新 revision 后重新派生 |
| 某端不支持规则 | 选择能完整承接的执行端，或报告缺口；不删除源要求 |
| 双重保护的一端应用失败 | 如实报告未完成，不静默降为单端成功 |
| 实际凭据轮换 | 走受信凭据绑定与生命周期流程；若源策略中的凭据引用改变，也需发布新 revision |

发布顺序应是：确认候选 → 固定源版本 → 确认环境映射 → 校验规则组合与能力覆盖 → 生成派生配置 → 在目标作用域应用 → 按要求验证。源策略与映射都应可追踪；仅切换配置文件名不构成版本一致性保证。

### 与仓库实现的差异

以下是本文编写时对工作区源码的静态核对，不代表已安装版本或运行时状态：

| 检查对象 | 已核对的现状 | 本文样稿仍需的适配 |
| --- | --- | --- |
| [两份 schema](../src/agent-sec-core/v2/crates/asc-policy-cedar/schema/seccore.cedarschema)、[HTTP 扩展 schema](../src/agent-sec-core/v2/crates/asc-policy-cedar/schema/seccore-v2.cedarschema) | 两文件仍并存，后者增加 `HttpEndpoint` 和 `network.send` | 统一类型契约与消费者兼容；不是只拼接文件 |
| [意图生成提示](../src/agent-sec-core/v2/crates/asc-intent/prompts/policy-generation.md) | 已按安全要求编号分块，每条语句带 `@id`；导出时按语句形状给出每项要求的承接预览（`COVERAGE`）；仍限制 `permit` 使用 context，除 `@id` 外不带注解 | 支持 HTTP 上下文；预览不等于已应用 |
| [HTTP 凭据转译](../src/agent-sec-core/v2/crates/asc-policy-cedar/src/http.rs) | 识别到凭据注解后要求 schema revision 2，并逐条按凭据规则转译整个集合 | 正确处理混合策略、相关允许与禁止规则及责任交接；不能直接把 R1–R4 全文交给现有转译器 |
| [文件保护转译](../src/agent-sec-core/v2/crates/asc-policy-translator-agentsight/src/cedar.rs) | 跳过 `permit`，只承接文件保护 `forbid`；接受 `@id`，拒绝其他注解 | 不能把注释或标签当路由 |
| [Gateway Plan](../src/agent-sec-core/v2/crates/asc-gateway-plan/src/plan.rs) | 有自己的 Plan 格式和来源信息 | 本文 YAML 不是其协议；跨端映射、依赖和证据关联仍需落实 |
| [本地任务](task.txt)与[留档策略](policies/task.cedar) | 禁网验收；基础授权（全局读取上限、bash 启动）由程序生成，正文按 task 写明的写入范围 `goal` 与所列 R1–R4（禁删、禁网、禁读、改配置先确认）分块，每条语句带 `@id`（`base`、`goal`、`R1`、`R3`、`R4`）；编号来自本地任务，与本文样稿的 R1–R4 不对应 | 完整上报需要另行确认任务授权与网络、凭据部署；不能由本文自动开启 |

本文未修改上述提示、schema、策略或运行代码。Cedar 表达已静态对照类型和既有规则写法，但未将这份目标混合样稿作为当前产品支持的策略发布、转译或联调；YAML 仅为组织示意。

> **Cedar 按“要保护什么”组织；执行映射按“本次由谁保护”组织；派生配置按“具体怎么保护”组织。一个要求只维护一份，允许多个执行端共同落实。**
