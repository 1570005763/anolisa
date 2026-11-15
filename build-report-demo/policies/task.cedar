// Unified task policy for the build-report workload.
//
// Published once: PAP stores this text as one policyId + revision, and every
// consumer reads that same revision instead of a second policy. The body is
// organized by security requirement (R1-R4 from task.txt), not by consumer:
//
//   Sandbox      projects the rules into bwrap mounts: writes outside R1 are
//                refused by the mount layer (EROFS).
//   Request PDP  derives a launch view of this revision - permits without runtime
//                context - and intersects it with the per-command candidate, so an
//                over-broad candidate becomes MODIFY instead of an approval.
//   OS Harness   lowers the file-protection rules (R2, R4) to kernel protection
//                attached to the cosh process tree through a Scope + Binding.
//
// Each statement carries `@id` naming the requirement it implements (`base`,
// `R1`, `R2.1` ...). The id is a label, not a route: which consumer takes a
// statement follows from its shape, `agent-sec-cli intent propose` previews that
// as `// COVERAGE:`, and only a Scope's Binding shows that a rule was applied.
//
// The bare `principal` header is deliberate. The enforcement translator accepts
// only bare headers, while the PDP only compiles explicit ones; the daemon derives
// that view from this same revision, so neither consumer needs its own file.

// ============================================================
// 基础授权：读取上限与解释器启动
// 不是安全要求，只让命令能够启动。
// ============================================================

// Read ceiling. It deliberately covers the whole filesystem: how many system
// directories (loader caches, locale, /proc) a launch asks for is not
// predictable, so an exhaustive allowlist would cut ordinary commands into
// MODIFY. The actual read restriction in this task is R4.
@id("base")
permit(
  principal,
  action == SecCore::Action::"file.read",
  resource is SecCore::File
)
when {
  resource.path == "/" || resource.path like "/*"
};

// Interpreter entry points. The Hook launches `/bin/bash -c`, so that exact
// string must be granted as well.
@id("base.2")
permit(
  principal,
  action == SecCore::Action::"process.spawn",
  resource is SecCore::Process
)
when {
  resource.program == "bash" || resource.program == "/bin/bash" ||
  resource.program == "/usr/bin/bash" ||
  resource.program == "python3" || resource.program == "/usr/bin/python3"
};

// ============================================================
// R1：构建写入范围
// 只允许写构建产物目录和报告目录，范围外写入一律拒绝。
// ============================================================

@id("R1")
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
// 禁止删除 previous.zip，不额外禁止正常写入。
// ============================================================

// Delete protection also covers renaming and overwriting the protected target,
// so the claim is "ordinary writes stay possible, deletion does not".
@id("R2")
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
// R3：网络与上报
// 本次本地验收禁网：不授予 network.use，由默认拒绝承担。
// ============================================================

// Deliberately no statement: the enforcement translator only lowers file
// actions, and a network forbid would reject the whole revision there.

// ============================================================
// R4：敏感文件读取保护
// 禁止读取任务目录中的模拟凭据文件，包括不经过 shell 的原生文件工具。
// ============================================================

// Read protection is exact-file only: a directory-tree read target is rejected
// by the enforcement backend, so this rule cannot be widened to
// "/srv/br-demo/project/*".
@id("R4")
forbid(
  principal,
  action == SecCore::Action::"file.read",
  resource is SecCore::File
)
when {
  resource.path == "/srv/br-demo/project/deploy.env"
};
