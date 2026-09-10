# AgentSecCore: Protecting Skill Security

[中文版](../../../zh/agent-security/agent-sec-core/container-demo-card.md)

**Who touched my Skill?** · Hands-on operation card

Staff should complete setup, Qoder CLI authentication, and rehearsal using the [full guide](container-demo.md) before handing over the terminal. It covers Token configuration, startup, readiness checks, and remote access through Chrome.

| Window | Purpose |
| --- | --- |
| A | Qoder CLI, for the activity prompts |
| B | Linux terminal in the bundle directory, for modification and reset commands |
| C | AgentSight in Chrome, for security events |

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

## 4. Rescan and inspect the risks

Repeat the step 1 prompt in A. Expect `deny` and both findings:

- `prompt-override`: requests overriding prior instructions.
- `prompt-secret-exfiltration`: requests sending the system prompt outside the session.

## 5. Inspect this round's security events

In C, open [AgentSight security events](http://127.0.0.1:17396/#/security).

1. Open **Security Events**.
2. Select **Last 1h** and **Category = skill_ledger**.
3. Set **Verdict** and **Result** to **All**, and clear **Session ID**.
4. Click **Query** and find this round's `pass → drifted → deny` by time and target path. For new events, select **Last 1h** again before querying to advance the end time.
5. Open a pre-invocation `check` event and inspect **Session ID** and **Tool Call** details. Direct scan events may not include those fields.

## Staff: reset

Run in B:

```bash
./demo.sh reset
./demo.sh qoder
```

Reset ends the Qoder CLI session, restores the original Skill, and rescans to `pass`. Historical events and signing keys remain.

At the end of the activity:

```bash
./demo.sh down
```

The `ask` policy requests confirmation on abnormal status; selecting **No** cancels the invocation. The modification command only appends synthetic text. Allow time based on rehearsal, including network delays, model responses, and terminal approvals.
