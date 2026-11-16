# demo666 分支改动说明（build-report 四步演示）

基线：`f03002fdd feat(sec-core): skip Cedar permits for Sight`。
本次在其上共 7 个 commit，**未 push**。`origin/demo666` 上原有的 `e5b6636f6 chore(chore): add build-report skill task sources`
已并入第 7 个 commit，因此推送需要 force push。本文件随第 7 个 commit 一起提交，
所以表里第 7 个 commit 不写哈希，可用 `git log -1 -- build-report-demo` 查看。

目标：只做四步——生成并发布一份策略 → 建 Scope → 手敲 `cosh` → 输入 4 个 prompt；
生成物不经人工修改直接发布，全程不需要人工点击，4 个 case 都按预期被拦。

## 一览

| # | Commit | 组件 | 一句话 | 主要支撑的 case |
|---|---|---|---|---|
| 1 | `1c8619761` feat(sec-core): derive launch view of task policy | agent-sec-core | 一份裸 `principal` 策略同时给 PDP 用 | 全部（发布即可用） |
| 2 | `35e0e5d63` feat(sec-core): derive sandbox launch baseline | agent-sec-core | 解释器/系统目录读取由 Hook 自动合成 | 全部（命令能启动） |
| 3 | `63ffb87ce` feat(sec-core): request parent dir for deletes | agent-sec-core | 删除按父目录申请成对写权限 | Case 3 |
| 4 | `bde6b7670` feat(sec-core): flag task drafts consumers reject | agent-sec-core | 生成物不经人工修改就能发布 | 第一步 |
| 5 | `324383605` fix(sight): adopt pre-existing descendants on bind | agentsight | 收养 Binding 之前已存在的子进程 | Case 3 / Case 4（cat） |
| 6 | `bef6dfa3b` feat(sec-core): retry rejected task drafts once | agent-sec-core | 任务策略首稿被本地校验拒绝时自动重试一次 | 第一步 |
| 7 | chore(chore): add build-report four-step demo | build-report-demo | build-report skill；任务文本、fixture、README 改为四步；RPM 重建脚本；设计说明与本文件 | 全部 |

四个 case 与 commit 的对应：

| Case | 预期结果 | 依赖的 commit |
|---|---|---|
| 1 跑构建脚本 | 两处写入 `Read-only file system`（Sandbox 只放行申请到的路径） | 1、2、7 |
| 2 改 source-guard.txt | `policy adjusted`（MODIFY 收窄）+ `Read-only file system` | 1、2、4、7 |
| 3 删 previous.zip | `rm: ... Operation not permitted`，文件还在（ActPlane 内核拦） | 1、2、3、4、**5**、7 |
| 4 读 deploy.env | 原生 read 返回 `Permission denied`，或 `cat` 返回 `Operation not permitted` | 1、2、4、5、7 |

第一步（意图服务生成 `task.cedar`）依赖 4 和 6：4 保证生成物能直接发布，6 保证偶发的坏首稿不会让这一步报 `internal`。

---

## 1. `1c8619761` feat(sec-core): derive launch view of task policy

**改了哪里**
- 新增 `src/agent-sec-core/v2/crates/asc-policy-cedar/src/authorization_view.rs`（并在 `lib.rs` 导出）：
  确定性投影，把裸 `principal` 改写为 `principal is SecCore::Subject`，丢掉 `forbid` 和含 `context.` 的 `permit`。
- `asc-pap/src/service.rs` 的 `authorization_policies()`：对非 eligible 的 revision 调用该投影，
  **保持同一个 `policyId + revision`**；投影后什么都不授予的 revision 不进授权集。
- `asc-pap/tests/validation.rs`：新增 `deployment_shape_contributes_a_derived_launch_view`，调整原用例。

**为什么改**
三个消费者对策略形状的要求互斥：
- ActPlane 转译器只收裸 `principal`，显式 principal 报 `UNSUPPORTED_PRINCIPAL_CONSTRAINT`；
- PDP 授权集只收每条都带显式 principal、且不含 `context` 的策略；
- 一份里混写两种头部，PAP 直接以 `mixed bare and constrained principal headers` 拒绝。

所以"一份策略喂三端"在原代码里做不到。投影让 PDP 读同一 revision 的派生视图，Sandbox 与 ActPlane 仍读原文。

**不改会怎样**
裸 `principal` 的统一策略不进授权集，cosh 里每条 shell 命令都拿不到授权（被阻断）；
要跑通只能发布两份策略（一份给 PDP、一份给 ActPlane），Scope 绑的不是 PDP 用的那份，"同一策略"的叙事不成立。

## 2. `35e0e5d63` feat(sec-core): derive sandbox launch baseline

**改了哪里**
- 新增 `asc-pep-runtime/src/permissions/baseline.rs`：从 `LaunchSpec` 合成**零写权限**的 Cedar
  （shell 需要的系统目录、程序所在目录、cwd 的读取，以及进程启动）；
  所有根都先解析成真实路径，软链形式的系统根额外按点授权，保证 loader 与 shebang 能解析。
- `asc-pep-runtime/src/permissions.rs`：新增 `PermissionInput::is_cedar()`。
- `asc-cli/src/sandbox/hook.rs`：`sandbox hook prepare` 在候选为 Cedar 时总是并入基线，
  `--runtime-permissions` 变为可选追加项。
- `asc-pep-runtime/src/runtime.rs`：`permission path lacks an authorized identity` 报错带上具体路径。
- `cosh-extension/hooks/sandbox_authorization.py`：command 模式下不再强制要求
  `AGENT_SEC_COSH_SANDBOX_RUNTIME_PERMISSIONS`，未设置时不传 `--runtime-permissions`；
  配套单测 `test_unset_preset_leaves_the_launch_baseline_to_the_cli`。
- `asc-cli/tests/sandbox_permissions.rs`：`hook_rereads_cedar_for_each_authorization_request` 的写授权
  从"全部资源"收窄为测试目录子树，否则会与基线里 `/bin` 等软链的点授权冲突（`permission alias has a writable ancestor`）。

**为什么改**
意图服务只按命令字面量生成候选，永远不会写 `/usr/bin/bash`、动态加载器、cwd；
而 daemon 要求程序和 cwd 可读才放行启动。这些是 `prepare_launch` 已经算出的事实，应由代码合成，不应靠每台机器手写一份 runtime 预设。

**不改会怎样**
- 必须给 cosh 额外配一个 `AGENT_SEC_COSH_SANDBOX_RUNTIME_PERMISSIONS=<本机手写的 runtime.cedar>`；
  不设时 Hook 抛 `must name an absolute Cedar runtime preset`，命令全部被阻断；
- 手写预设换机器就要重写；在 `/bin`、`/lib` 是软链的机器上写法稍宽就报
  `permission alias has a writable ancestor`，没定位信息很难排查。

## 3. `63ffb87ce` feat(sec-core): request parent dir for deletes

**改了哪里**
`asc-intent/prompts/command-proposal.md` 新增"删除与重命名"一节：删改文件/目录时为**目标所在目录**申请写权限，
目录必须写成 `== dir` 与 `like dir/*` 成对两条，并在 caveats 说明。

**为什么改**
`unlink`/`rename` 改的是目录项，只授权目标文件本身，内核层面就无法完成删除。

**不改会怎样**
Case 3 的 `rm releases/previous.zip` 在沙箱里直接 `Read-only file system`，根本到不了内核——
演示出来的是"Sandbox 拦住了"，而不是"Sandbox 放行、ActPlane 在内核拦住"，Case 3 想证明的能力边界看不到。
只写单条目录规则还会被沙箱以 `point-only or descendants-only directory permissions` 拒绝。

## 4. `bde6b7670` feat(sec-core): flag task drafts consumers reject

**改了哪里**
- `asc-intent/prompts/policy-generation.md`（版本升为 `cedar-policy@3`，`intent_extraction.rs` 与 `v2/README.md` 同步）：
  规定 `[S1]-[S4]` permit / `[H1]-[H2]` forbid 的分区；principal 一律留空；`context` 只出现在 forbid；
  forbid 不带注解；不生成补集 forbid；forbid 只用于 `file.read` / `file.write`；目录成对、精确文件只写 `==`。
- `asc-intent/src/policy_validation.rs`：新增 `launch_view_gaps`（permit 测了 context）、
  `annotated_forbids`（forbid 带注解）、`point_aliases`（精确授权指向本机软链）。
- `asc-intent/src/policy_generator.rs`：`propose_task` 发现前两类问题时带上拒绝原因**重试一次**，
  重试结果合法且干净才替换；软链问题只报告不重试（放宽授权应由审阅者决定）。
  剩余问题以 `LAUNCH VIEW:` / `RUNTIME VIEW:` / `POINT ALIAS:` notes 输出。
- `asc-cli/src/commands/intent/render.rs`：`--format cedar` 导出时把上述 notes 写成文件头注释。
- 新增集成测试 `asc-intent/tests/task_launch_view.rs`。

**为什么改**
原来的生成物能过 Cedar 校验，但发布后跑不通，必须人工修改：
- permit 里写 `context.input.cwd` → 授权视图丢掉这条 → 启动无授权；
- forbid 带 `@id` → `scope create` 后 Binding 报 `UNSUPPORTED_ANNOTATION`（之后转译器改为接受 `@id`，其他注解仍拒绝）；
- `network.use` 上的 forbid → `UNSUPPORTED_ACTION`，整份下发失败；
- 精确授权 `/bin/bash`、`/usr/bin/python3` 落在软链上 → `permission path lacks an authorized identity`。

**不改会怎样**
达不到"生成物不经人工修改直接 `policy create`"的要求；演示第一步就需要手工改 Cedar，且问题要到 Binding 或执行时才暴露。

## 5. `324383605` fix(sight): adopt pre-existing descendants on bind

> 这是 agentsight 组件的改动，已经你批准。

**改了哪里**
- `src/agentsight/crates/ebpf-ifc-engine/src/lib.rs`：新增 `PinnedEngine::adopt_child(parent, child, domain)`，
  按内核 `te_fork` 的语义复制 `ts_proc`、`ts_proc_domains`、`ts_root`，最后写 `cap_task`。
- `src/agentsight/crates/agentsight-enforcer/src/actplane.rs`：新增 `adopt_preexisting_descendants`，
  在 Binding 安装、迁移完成后扫描 root 的子孙进程并收养；每次收养后复查父子关系，不一致就撤销；
  最多扫 4 轮，没有进展提前结束；PID 命名空间不一致时只打 warn 不收养。
  成功时日志：`adopted N pre-existing descendants [pid...]`。
- `src/agentsight/crates/agentsight-enforcer/src/actplane/preexisting_maps.rs`：新增读取 `/proc` 进程树的
  `process_tree_edges` 等函数及单测。
- `src/agentsight/scripts/build-enforcer.sh`：同步 `ACTPLANE_STAGED_BPF_LIB_BLOB`（构建会校验 vendored `lib.rs` 的哈希）。

**为什么改**
交互式 cosh 一启动（约 1 秒内）就 fork 出内部 PTY bash（`bash --rcfile /tmp/cosh-shel…`），
早于 agentsight 发现 cosh 并建 Binding。内核 fork 钩子只把策略继承给 **Binding 之后** fork 的进程，
而 agent 的 Bash 工具命令和手敲命令都在这个 PTY bash 里执行——它不在策略域里。
手敲 `cosh` 一定会走到这个竞态，只有在 sight 侧补上才是根治。

**不改会怎样**
- Case 3：`rm releases/previous.zip` 成功，回滚包被真的删掉；
- Case 4：agent 用 `cat project/deploy.env` 时能读到凭据（只有原生 `read_file` 被拦）；
- 结果随时序漂移：偶尔赢了竞态能拦住，所以"之前跑通过"不可复现。

## 6. `bef6dfa3b` feat(sec-core): retry rejected task drafts once

**改了哪里**
- `asc-intent/src/policy_generator.rs`：新增 `first_task_draft`，`propose_task` 的首稿若因语法、Strict 类型、
  非规范路径或通配路径字面量被本地校验拒绝，就带上拒绝原因**重试一次**（与 `propose_command` 的重试一致）。
  重试后仍是语法/类型错误则报错，仍是路径问题则转为 `needs_clarification`；不支持的策略特性不重试。
  原有 `LAUNCH VIEW` / `RUNTIME VIEW` 重试在通过校验的稿子上照旧进行。
- 新增集成测试 `asc-intent/tests/task_retry.rs`（4 个）。
- `asc-cli/tests/intent.rs`：回放 provider 只解析请求第一行，重试时追加的拒绝原因不影响回放。

**为什么改**
连续 8 次生成里有 1 次首稿没过 Cedar 校验，daemon 记 `reason="cedar_validation"`，
CLI 只看到 `intent daemon rejected request: internal`，第一步失败。

**不改会怎样**
演示第一步偶发失败，只能重跑；对观众来说就是"意图服务报了内部错误"。

## 7. chore(chore): add build-report four-step demo

`build-report-demo/` 下的全部内容都在这个 commit 里（含原 `e5b6636f6` 引入的 skill 与初版脚本），按用途分四部分。

### 7.0 build-report skill 与初版演示（原 `e5b6636f6`）

**改了哪里** `skill/build-report/`（`SKILL.md`、`README.md` 与 `build.sh` / `clean.sh` / `deps.sh` / `report.sh`），
以及 `task.txt`、`policies/task.cedar`、`prepare.sh`、`run-demo.sh` 的初版。

**为什么改** 提供演示要跑的 skill（构建 `project/` 为 `releases/new.zip`、保留 `previous.zip` 回滚、上报 GitHub Issue），以及意图任务文本、目标策略和 fixture。

**不改会怎样** 演示没有可执行的工作负载，也没有 `/srv/br-demo` 的 fixture。下面 7.1 是在这份初版上的改动。

### 7.1 四步演示

**改了哪里**
- `task.txt`：5 行——一句业务说明、一句可写范围（`releases/` 与 `out/`）、三条安全要求（`previous.zip` 禁删、
  禁网、`deploy.env` 禁读），每条一句。读上限与 bash 启动由程序生成的基础授权给出，不写进 task；
  写入范围只照抄 task 写明的位置，成 `goal` 块，因此多次生成结果一致。
- `policies/task.cedar`：与当前生成物同结构的留档（基础授权、goal、R1–R3；意图服务不可用时可直接 `--file` 发布）。
- `prepare.sh`：新增 Case 1 脚本 `scripts/build-with-setup.sh`、演示用 `home/.zshrc`、模拟凭据 `project/deploy.env`。
- `run-demo.sh`：ActPlane 改为绑定统一策略，不再用第二份 `actplane.cedar`。
- `README.md`：开头一张架构图（task.txt → 意图服务 → PAP → Sandbox / PDP / ActPlane → cosh）加一张完整流程图，后者覆盖完整链路（task.txt → 意图服务 → task.cedar → PAP 三个消费者 → Scope → cosh/Binding/收养 → 四个 prompt 各自落到哪个 case）；四步流程、四个 prompt 与预期输出、cosh 的 4 个环境变量、确认 `READY` 与收养日志、审计、清理、已知边界。

**为什么改**
落实"一份策略、一个 revision、四步演示"，并让 fixture 覆盖四个 case 所需的对象。

**不改会怎样**
没有 Case 1/4 的受保护对象；写入范围由模型推导时每次生成结果不同；README 与实际流程不一致，演示时要临场改策略。

### 7.2 组件 RPM 重建脚本

**改了哪里** 新增 `build-report-demo/rpm-cycle.sh`：对 agent-sec-core / agentsight / cosh-ng 执行
停服务并卸载 → `scripts/rpm-build.sh` 构建（flock 防并发）→ 只安装本次产物 → enable 并带超时探活。

**为什么改** 本次 sight 修复需要反复重建安装验证；手工步骤多，且并发构建会触发 rustc FatLTO ICE、误装历史版本包。

**不改会怎样** 不影响功能，只是重建环境要手工操作、容易出错。

### 7.3 文档

**改了哪里** 新增 `sandbox-os-harness-boundaries_zh.md`（一份策略如何对应 Sandbox / OS Harness / Gateway 三个执行面）、
`unified-policy-organization-example_zh.md`（源策略组织、环境映射与派生配置样稿），以及本文件 `demo666-changes_zh.md`。

**为什么改** 前两份是给汇报用的方案说明，都声明是目标设计，不是当前 CLI 行为或验收结果；本文件说明 demo666 上每个 commit 改了什么、为什么改。

**不改会怎样** 不影响演示。

---

## 验证

- 每个 sec-core commit 单独 `cargo clippy --workspace --all-targets --locked -- -D warnings` 通过
  （`1c8619761`、`35e0e5d63`、`63ffb87ce`、`bde6b7670`、`bef6dfa3b`，与 CI 的 `rust-lint` 相同）；`cargo fmt --check` 通过。
- HEAD 上 `cargo test --workspace --no-fail-fast` 只有 `asc-event-log` 的
  `a_rotation_that_cannot_rename_reports_and_still_appends` 失败：它靠 `chmod 0500` 让 rename 失败，root 运行时不生效，与本次改动无关。
- `test_sandbox_command_permissions.py` 29 个通过；`black --check` 通过。
- agentsight-enforcer `--features actplane` lib 测试 158 个通过；`scripts/test-rpm-packaging.sh` 6 个通过；新增代码无 clippy 警告。
- rpm 重建安装后完整跑了 6 轮四步演示：每轮 PTY bash 都被收养（`IN-DOMAIN`）；
  Case 1 两处 `Read-only file system`、Case 2 `policy adjusted`、Case 3 `Operation not permitted`、Case 4 被拒；
  `source-guard.txt` 未变、`previous.zip` 仍在；审计中 unlink / read 两条均 `blocked=true`。
  有一轮 Case 2 截屏为空（文件未被改），把每条等待从 75 秒加到 100 秒后正常，判断是 agent 尚未答完。
- 加入 commit 6 并重装 RPM 后，用 `task.txt` 连续生成 8 次：8 次全部成功（每次 5–15 秒），没有 `LAUNCH VIEW` /
  `RUNTIME VIEW` / `POINT ALIAS` 头。8 份生成物在本地都过了 PAP 校验；对四个 case 的候选，PDP 判定
  （Allow / Modify / Allow / Allow）、Sandbox 有效权限与执行前检查，以及 Sight 转译出的 targets
  （`deploy.env` 禁读、`previous.zip` 禁删）都与 `policies/task.cedar` 完全一致。

## 没有进 commit 的内容

| 项 | 说明 |
|---|---|
| `src/agentsight/Cargo.lock`、`dashboard/package-lock.json`、`dsh-plugin/lib/`、`dsh-plugin/package-lock.json` | agentsight 构建产生的污染，与功能无关，仍留在工作区；可用 `git checkout -- src/agentsight/Cargo.lock src/agentsight/dashboard/package-lock.json` 并删除 `dsh-plugin/lib`、`dsh-plugin/package-lock.json` 还原 |
| `CODE_SCANNER_HOOK_ENABLED=false` | 不是代码改动，是启动 cosh 时的环境变量（已写进 README）；否则 `cat deploy.env` 会弹 code-scanner 审批框需人工点击。该开关只认 `true`/`false` |
| sight 补丁队列中的 `lib.rs`（0013）与 `PATCHED_BPF_LIB_BLOB` | 未重新生成；只更新了 `STAGED` 哈希，本地构建与认证已通过。若要把 commit 5 提交给 sight 上游，需要一起同步 |
| `skillsec.json.rpmsave` | 重装时 rpm 留下的配置备份，未处理 |
| 已知无关失败 | observability 的 PTY 相关测试失败，与本次改动无关 |
