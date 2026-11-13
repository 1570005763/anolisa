// Unified task policy for the build-report workload.
//
// Published once: PAP stores this text as one policyId + revision, and every
// consumer reads that same revision instead of a second policy.
//
//   Sandbox      projects the [S*] permits: writes outside the allowed ranges are
//                refused by the mount layer (EROFS).
//   Request PDP  derives a launch view of this revision - permits without runtime
//                context - and intersects it with the per-command candidate, so an
//                over-broad candidate becomes MODIFY instead of an approval.
//   OS Harness   lowers the [H*] forbids to kernel file protection attached to the
//                cosh process tree through a Scope + Binding.
//
// The two sections and the [S*]/[H*] tags state the intended responsibility of each
// rule. They are comments: Cedar ignores them, and neither a section nor a tag is
// evidence that a rule was delivered, loaded or enforced.
//
// The bare `principal` header is deliberate. The enforcement translator accepts
// only bare headers, while the PDP only compiles explicit ones; the daemon derives
// that view from this same revision, so neither consumer needs its own file.

// ============================================================
// Sandbox Policy - resource access boundary
// ============================================================

// [S1] Read ceiling. It deliberately covers the whole filesystem: the candidate is
// generated per command and how many system directories (loader caches, locale,
// /proc) a launch ends up asking for is not predictable, so an exhaustive
// allowlist would cut ordinary commands into MODIFY. The actual read restriction
// in this task is [H2].
permit(
  principal,
  action == SecCore::Action::"file.read",
  resource is SecCore::File
)
when {
  resource.path == "/" || resource.path like "/*"
};

// [S2] The only writable region: build outputs and the local report directory.
// Anything else a candidate asks for is trimmed here before the sandbox starts.
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

// [S3] Interpreter entry points. The Hook launches `/bin/bash -c`, so that exact
// string must be permitted as well; ActPlane has no process-start target yet.
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

// [S4] No rule grants network.use, so both consumers keep the network closed. This
// is deliberate rather than a `forbid`: the enforcement translator only lowers
// file actions, and a network forbid would reject the whole revision there.

// ============================================================
// OS Harness Policy - operation-level protection
// ============================================================

// [H1] The rollback package may be rewritten in place but never deleted. Sandbox
// projection only knows "writable / not writable" per mount, so this delete-only
// rule has no OS-right equivalent and stays with the kernel file protection.
//
// Note: delete protection also covers renaming and overwriting the protected
// target, so the claim is "ordinary writes stay possible, deletion does not".
forbid(
  principal,
  action == SecCore::Action::"file.write",
  resource is SecCore::File
)
when {
  resource.path == "/srv/br-demo/releases/previous.zip" &&
  context.input.operation == SecCore::WriteOperation::"delete"
};

// [H2] The simulated credential file stays unreadable even when the read does not
// go through the shell Hook (the agent's native file tool). Read protection is
// exact-file only: a directory-tree read target is rejected by the enforcement
// backend, so this rule cannot be widened to "/srv/br-demo/project/*".
forbid(
  principal,
  action == SecCore::Action::"file.read",
  resource is SecCore::File
)
when {
  resource.path == "/srv/br-demo/project/deploy.env"
};
