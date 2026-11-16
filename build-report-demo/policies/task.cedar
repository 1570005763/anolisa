// CANDIDATE: not approved; not effective.
// unresolved: []
// COVERAGE: who can carry each requirement, from statement shape only:
//   permit -> sandbox + PDP (a permit testing context -> sandbox only);
//   forbid on file.read or file.write -> os-harness (any other forbid -> none).
//   A Scope still has to apply it; a requirement without statements is not listed.
//   base  #1 #2  sandbox, PDP
//   goal  #3     sandbox, PDP
//   R1    #4     os-harness
//   R3    #5     os-harness
// ============================================================
// 基础授权（程序生成，不来自 task）：读取上限与 shell 启动
// 不是安全要求，只让命令能够启动；读取限制与写入范围由下面的要求给出。
// ============================================================

@id("base")
permit(
  principal,
  action == SecCore::Action::"file.read",
  resource is SecCore::File
)
when {
  resource.path == "/" || resource.path like "/*"
};

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
// 在允许写入范围内，禁止对 previous.zip 的删除操作
// ============================================================
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

// ============================================================
// R3：不允许读 project/deploy.env
// 禁止读取 /srv/br-demo/project/deploy.env
// ============================================================
@id("R3")
forbid(
    principal,
    action == SecCore::Action::"file.read",
    resource is SecCore::File
)
when {
    resource.path == "/srv/br-demo/project/deploy.env"
};
