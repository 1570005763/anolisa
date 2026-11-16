// CANDIDATE: not approved; not effective.
// unresolved: []
// HUMAN GATE: these permits stop for confirmation before taking effect, each on paths another
//   permit already grants, so the gate is friction and not a wider grant:
//   #6 @id("R4") /srv/br-demo/config -- config/ 下是手工维护的构建配置，改动前需要你确认
// COVERAGE: who can carry each requirement, from statement shape only:
//   permit -> sandbox + PDP (a permit testing context -> sandbox only);
//   forbid on file.read or file.write -> os-harness (any other forbid -> none).
//   A Scope still has to apply it; a requirement without statements is not listed.
//   base  #1 #2  sandbox, PDP
//   goal  #3     sandbox, PDP
//   R1    #4     os-harness
//   R3    #5     os-harness
//   R4    #6     sandbox, PDP
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
// goal：只允许写 releases/、out/ 和 config/
// 写入范围限定在 /srv/br-demo/releases、out 与 config 三个目录
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
    resource.path like "/srv/br-demo/out/*" ||
    resource.path == "/srv/br-demo/config" ||
    resource.path like "/srv/br-demo/config/*"
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

// ============================================================
// R4：改 config/ 下的构建配置要人工确认
// config/ 已在 goal 的写入范围内，escalate 只把裁决抬成 STEP_UP，
// 不新增可写路径；没有 goal 那一条，这条件本身就是一次无上限的扩权
// ============================================================
@id("R4")
@advice("{\"verdict\":\"escalate\",\"message\":\"config/ 下是手工维护的构建配置，改动前需要你确认\"}")
permit(
    principal,
    action == SecCore::Action::"file.write",
    resource is SecCore::File
)
when {
    resource.path == "/srv/br-demo/config" ||
    resource.path like "/srv/br-demo/config/*"
};
