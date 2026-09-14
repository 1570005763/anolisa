# AgentSecCore: Protecting Skill Security

[中文版](../../../zh/agent-security/agent-sec-core/container-demo-card.md)

**Who touched my Skill?** · Hands-on operation card

Staff have prepared and authenticated this environment. Start directly below; ask staff if a window is missing.

| Window | Purpose |
| --- | --- |
| A | Qoder CLI, for the activity prompts |
| B | Control terminal in the Linux demo directory (local, or SSH into ECS), for modification commands |
| C | AgentSight in Chrome, for security events |

At a Windows venue, A and B are WSL terminals already connected to ECS by staff, and C is Windows Chrome. Use these ready windows; do not run modification commands in a new, unconnected PowerShell window.

## 1. Scan and establish a baseline

Send this prompt in A. If a scan command requires approval, verify the target before allowing it. The prompts preserve the wording used in the Chinese activity:

```text
请使用 skill-ledger Skill，对 ledger-demo-target 执行快速扫描认证。目标是当前项目下的 .qoder/skills/ledger-demo-target。只执行快速扫描，不执行深度扫描。
```

Expect the target status to become `pass`.

## 2. Invoke the original Skill

Send in A:

```text
请调用名为 ledger-demo-target 的 Skill，并严格按其说明执行。
```

Expect an actual `Skill` tool call and `LEDGER_DEMO_OK`. Without that tool call, this step has not passed. Enter `/clear` separately and repeat the prompt once; ask staff to investigate if the tool call is still missing.

## 3. Modify, invoke again, and select No

Run in B:

```bash
./demo.sh tamper
```

In A, enter separately:

```text
/clear
```

Repeat step 2. At the `drifted` confirmation, select **No** to cancel. This status means the files changed since signing; the new content has not yet been rescanned.

**No cancels only the current Skill call.** If Qoder CLI requests additional exploration such as Read or Glob, press Esc to cancel, then enter `/clear` before step 4. Do not approve those extra operations.

## 4. Rescan and inspect the risks

Repeat the step 1 prompt in A. Expect `deny` and both findings:

- `prompt-override`: requests overriding prior instructions.
- `prompt-secret-exfiltration`: requests sending the system prompt outside the session.

## 5. Inspect this round's security events

In the prepared Chrome window C, open Security Events. Use the address provided by staff (normally `http://127.0.0.1:17396/#/security`).

1. Open **Security Events**.
2. Select **Last 1h** and **Category = skill_ledger**.
3. Set **Verdict** and **Result** to **All**, and clear **Session ID**.
4. Click **Query** and find this round's `pass → drifted → deny` by time and target path. For new events, select **Last 1h** again before querying to advance the end time.
5. Open a pre-invocation `check` event and inspect **Session ID** and **Tool Call** details. Direct scan events may not include those fields.

In event details, identify **Skill name / target path `ledger-demo-target`** first. `skill-ledger` is the scanning helper; its `pass` does not mean the target recovered. `check` inspects status and `scan` certifies content. The helper usually runs `check → scan → check`, so one scan experience produces multiple records. `Result` describes command execution; `Verdict` is the security conclusion. `scan / succeeded / deny` means scanning completed and found denial findings.

Optional extension: enter `/clear`, invoke the target again, select **No** at the `deny` prompt, and inspect the associated `check / deny` event.

This demo uses the `ask` policy; selecting **No** cancels the invocation. The modification adds only synthetic text. After the experience, ask staff to follow the [reset instructions](container-demo.md#staff).
