// Unified task policy for the build-report workload.
//
// Published once: PAP stores this text as one policyId + revision, and every
// consumer reads that same revision instead of a second policy. The program
// writes the launch base; the model writes the rest, organized by security
// requirement (the writable scope as `goal`, then R1-R3 from task.txt), not by
// consumer:
//
//   Sandbox      projects the rules into bwrap mounts: writes outside goal are
//                refused by the mount layer (EROFS).
//   Request PDP  derives a launch view of this revision - permits without runtime
//                context - and intersects it with the per-command candidate, so an
//                over-broad candidate becomes MODIFY instead of an approval.
//   OS Harness   lowers the file-protection rules (R1, R3) to kernel protection
//                attached to the cosh process tree through a Scope + Binding.
//
// Each statement carries `@id` naming the requirement it implements (`base`,
// `goal`, `R1`, `R1.1` ...). The id is a label, not a route: which consumer takes a
// statement follows from its shape, `agent-sec-cli intent propose` previews that
// as a `// COVERAGE:` block with one row per requirement and carrier, and only a
// Scope's Binding shows that a rule was applied.
//
// The bare `principal` header is deliberate. The enforcement translator accepts
// only bare headers, while the PDP only compiles explicit ones; the daemon derives
// that view from this same revision, so neither consumer needs its own file.
//
// The block below is the one `agent-sec-cli intent propose --format cedar` prints
// for this draft; `#N` is the number of the statement in this file:
//
// COVERAGE: who can carry each requirement, from statement shape only;
//   a Scope still has to apply it, and a requirement without statements is not listed.
//   base  #1 #2  sandbox, launch authorizer
//   goal  #3     sandbox, launch authorizer
//   R1    #4     runtime protector (authorization view drops forbids)
//   R3    #5     runtime protector (authorization view drops forbids)

// ============================================================
// 基础授权（程序生成，不来自 task）：读取上限与 shell 启动
// 不是安全要求，只让命令能够启动；读取限制与写入范围由下面的要求给出。
// ============================================================

// Read ceiling. It deliberately covers the whole filesystem: how many system
// directories (loader caches, locale, /proc) a launch asks for is not
// predictable, so an exhaustive allowlist would cut ordinary commands into
// MODIFY. The actual read restriction in this task is R3.
@id("base")
permit(
  principal,
  action == SecCore::Action::"file.read",
  resource is SecCore::File
)
when {
  resource.path == "/" || resource.path like "/*"
};

// The Hook launches every command as `/bin/bash -c`, so that exact string must
// be granted; programs a script starts after that are not launches.
@id("base.2")
permit(
  principal,
  action == SecCore::Action::"process.spawn",
  resource is SecCore::Process
)
when {
  resource.program == "bash" || resource.program == "/bin/bash" ||
  resource.program == "/usr/bin/bash"
};

// ============================================================
// goal：只允许写 releases/ 和 out/
// 写入范围限定在 /srv/br-demo/releases 与 /srv/br-demo/out 两个目录
// ============================================================
@id("goal")
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
// R1：保护 releases/previous.zip 不被删除
// 允许范围内禁止对 /srv/br-demo/releases/previous.zip 的删除操作
// ============================================================

// Delete protection also covers renaming and overwriting the protected target,
// so the claim is "ordinary writes stay possible, deletion does not".
@id("R1")
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
// R2：不允许联网
// 不授予 network.use
// ============================================================

// Deliberately no statement: the enforcement translator only lowers file
// actions, and a network forbid would reject the whole revision there.

// ============================================================
// R3：不允许读 project/deploy.env
// 禁止读取 /srv/br-demo/project/deploy.env
// ============================================================

// Read protection is exact-file only: a directory-tree read target is rejected
// by the enforcement backend, so this rule cannot be widened to
// "/srv/br-demo/project/*".
@id("R3")
forbid(
  principal,
  action == SecCore::Action::"file.read",
  resource is SecCore::File
)
when {
  resource.path == "/srv/br-demo/project/deploy.env"
};
