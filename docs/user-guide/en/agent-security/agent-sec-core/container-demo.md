# AgentSecCore container hands-on demo

[中文版](../../../zh/agent-security/agent-sec-core/container-demo.md)

Run, modify, and rescan a Skill in a prepared Qoder CLI environment, then inspect its security records in AgentSight. The activity theme is **AgentSecCore：护航 Skill 安全** and its slogan is **谁动了我的 Skill？**.

The image runs **Qoder CLI 1.1.48**. `./demo.sh qoder` opens its interactive terminal interface.

## Staff: first-time setup

Use a Linux x86_64 host with Docker installed and running. The image includes the products and scanning dependencies; importing it and scanning locally do not require network access. Qoder CLI authentication and model requests require a working network and valid account. Version 1 supports one demo instance and one participant at a time.

### Install and start with one command (recommended)

Run on a Linux amd64 host with Docker installed, running, and accessible to the current user:

```bash
curl -fsSL https://github.com/1570005763/anolisa/releases/download/agentseccore-demo-20260910.1/install.sh | bash
```

The script downloads the starter, verifies SHA-256, pulls the public image by its fixed digest, starts the container, and runs `doctor`. It installs into `$HOME/agentseccore-demo` by default, with no GitHub login. It checks Docker availability and exits with instructions to install and start Docker if needed.

After installation, run:

```bash
cd "$HOME/agentseccore-demo"
./demo.sh qoder
```

On first use, enter `/login` in Qoder CLI and complete your own account authentication in Chrome. `Authentication: missing` in `doctor` is expected before login. For a remote host, establish the SSH tunnel in step 5 below. If browser callbacks fail, use the Token method in step 2; after saving `demo.env`, run `./demo.sh down` before step 3 so the new configuration takes effect.

Use `bash -s -- /path/to/demo` to choose the installation directory:

```bash
curl -fsSL https://github.com/1570005763/anolisa/releases/download/agentseccore-demo-20260910.1/install.sh | bash -s -- /path/to/demo
```

Rerunning verifies and reuses the same release and existing instance, preserving `demo.env`, authentication, and activity records without resetting the Skill. If the directory contains another release or modified distribution files, the script stops and asks for another directory. Continue below for manual or offline installation.

### 1. Prepare the demo directory and image

Open [this release](https://github.com/1570005763/anolisa/releases/tag/agentseccore-demo-20260910.1) and choose the starter or full offline bundle. Use one method below in an empty directory on the Linux host. Run subsequent shell commands in the directory containing `demo.sh`.

**Option A: pull the image.** The starter includes the launcher, Markdown operation card, and image version information:

```bash
curl -fL -o agentseccore-demo-starter.tar.gz https://github.com/1570005763/anolisa/releases/download/agentseccore-demo-20260910.1/agentseccore-demo-starter-linux-amd64-20260910.1.tar.gz
tar -xzf agentseccore-demo-starter.tar.gz
cd agentseccore-demo
sha256sum --check SHA256SUMS
./demo.sh pull
```

`pull` reads `image.ref`, pulls the public image from `ghcr.io/1570005763/agentseccore-demo` by its fixed digest, and verifies `image.id`. Participants need neither a GitHub account nor `docker login`. Continue to step 2 after pulling.

**Option B: import offline.** Download the full offline bundle from the same release, then run in an empty directory:

```bash
tar -xzf agentseccore-demo-linux-amd64-20260910.1.tar.gz
cd agentseccore-demo
sha256sum --check SHA256SUMS
```

Continue to step 2. The later `up` command verifies and imports the bundled `image.tar.gz`; skip `pull`.

### 2. Configure Qoder CLI authentication (Token recommended)

Open the [Qoder account integrations page](https://qoder.com/account/integrations) in Chrome, sign in with the activity account, and create a Personal Access Token. Create a private configuration file in the Linux terminal:

```bash
umask 077
cp demo.env.example demo.env
chmod 600 demo.env
${EDITOR:-vi} demo.env
```

Replace the value after `=` with the actual token; do not add quotes or `export`:

```dotenv
QODER_PERSONAL_ACCESS_TOKEN=YOUR_TOKEN
```

Save and close the editor. The launcher passes this value into the container for automatic authentication. Keep `demo.env` out of the distribution. PAT authentication suits remote hosts and containers. [Qoder CLI authentication documentation](https://docs.qoder.com/cli/authentication)

### 3. Start the environment and enter Qoder CLI

```bash
./demo.sh up
./demo.sh doctor
./demo.sh qoder
```

`up` waits for healthy services and prints the dashboard address. `doctor` should report reachable services, a ready signing key, and configured authentication. On the first Qoder CLI launch, trust only `/home/demo/agentseccore-lab`.

Enter `/status` separately to inspect account and usage status, then send:

```text
不要调用工具，只回复 READY。
```

This requests only `READY`, without tools. After a successful response, enter `/clear` separately before starting the five steps. `doctor` checks for configuration; a model response establishes that this request works.

### 4. Alternative: sign in inside Qoder CLI

To use browser login, skip step 2, start Qoder CLI, enter `/login`, and follow the browser option. Copy the displayed URL into Chrome if the container cannot open a browser. Return to the terminal to check status. If the remote callback fails, use the Token method. [Qoder CLI authentication troubleshooting](https://docs.qoder.com/cli/troubleshoot-auth)

`QODER_PERSONAL_ACCESS_TOKEN` takes precedence over saved `/login` credentials. To switch, remove that line from `demo.env`, run `./demo.sh down`, `./demo.sh up`, and `./demo.sh qoder`, then `/login`. Do not copy host authentication files into the image.

#### Model API keys and login tokens

`QODER_PERSONAL_ACCESS_TOKEN` authenticates a Qoder account. A model provider's API key authenticates requests to that provider and must not be placed in this field.

Qoder CLI supports BYOK after Qoder account authentication, through `/model` → **Custom** → **Add custom model...**. Follow the wizard to select a provider and model and enter an API key. Availability depends on the account and plan; use the catalog shown in the wizard. The pinned `1.1.48` BYOK configuration and validation flow still requires Qoder authentication; a provider API key alone does not replace it. [Qoder CLI custom models](https://docs.qoder.com/cli/custom-models)

The three accepted demo rounds used native Qoder account authentication. The complete activity with a provider API key has not been tested and is not an accepted alternative configuration yet.

### 5. Open the security events page

Prepare three windows: A runs Qoder CLI; B is a Linux terminal in the extracted bundle directory; C is Chrome at the [AgentSight security events page](http://127.0.0.1:17396/#/security). For a remote container, first open another terminal on the participant's computer and keep this tunnel running. Replace `DEMO_SSH_HOST` with the actual SSH host alias or `user@host`:

```bash
ssh -N -L 17396:127.0.0.1:17396 DEMO_SSH_HOST
```

## Participant: five steps

### 1. Scan and establish a baseline

Enter the following prompt in window A. These prompts retain the wording used for the Chinese activity:

```text
请使用 skill-ledger Skill，对 ledger-demo-target 执行快速扫描认证。目标是当前项目下的 .qoder/skills/ledger-demo-target。只执行快速扫描，不执行深度扫描。
```

This asks the skill-ledger Skill to run only a quick scan of the project-local target. If Qoder CLI requests permission to run the scan command, verify the target directory before allowing it. Expect `pass`. The signed record stores this version's file hashes and scan results; `pass` refers to this scan and verification.

### 2. Invoke the original Skill

Enter this prompt in window A:

```text
请调用名为 ledger-demo-target 的 Skill，并严格按其说明执行。
```

This asks Qoder CLI to invoke the named Skill and follow its instructions. Expect an actual `Skill` tool call followed by `LEDGER_DEMO_OK`. If no `Skill` tool call appears, this step has not passed. Enter `/clear` separately, then send the same request again. If it still does not appear, ask the facilitator to investigate before continuing.

### 3. Modify, invoke again, and decline

In window B, run:

```bash
./demo.sh tamper
```

The command appends a fixed synthetic prompt-injection fixture to the demo Skill; it does not execute the appended instructions. In window A, enter `/clear` separately, then repeat the invocation prompt from step 2.

Expect `drifted` and a confirmation prompt. Select **No** to cancel this invocation. `drifted` establishes that the current files differ from the signed version; the next step assesses the added content.

### 4. Rescan

Repeat the scan prompt from step 1 in window A. Expect `deny` with `prompt-override` and `prompt-secret-exfiltration`. These identify requests to override earlier instructions and send the system prompt outside the session.

### 5. Inspect security events

In window C, open Security Events. Select `Last 1h`, set Category to `skill_ledger`, set Verdict and Result to all values, and clear the Session ID filter. Click Query, then use the time and target path to find this round's `pass → drifted → deny` records. When new events arrive, select `Last 1h` again and click Query to update the query time range.

Open a Qoder CLI pre-invocation `check` event to inspect Session ID and Tool Call correlation. Scan events do not necessarily carry the same invocation fields. Optional extension: `/clear`, invoke the target again, select **No** at the `deny` prompt, and inspect the corresponding `check / deny` event.

## Staff: reset between rounds

In window B, run:

```bash
./demo.sh reset
./demo.sh qoder
```

Reset ends the Qoder CLI session inside this instance, restores the original fixture, and rescans it to `pass`. Signing keys and historical events remain. Identify the next round by time and session; version numbering does not need to restart at `v000001`.

At the end of the activity, run:

```bash
./demo.sh down
```

`down` stops the container and retains instance data. Running `up` again does not automatically restore a modified Skill; use `reset` explicitly when needed.

## Troubleshooting and limits

- **Environment not ready:** run `./demo.sh doctor` and follow the specific Docker, port 17396, service, or plugin error. Preserve existing services and resolve any port collision.
- **Authentication or model request fails:** check `demo.env`, account validity, and network access; after updating credentials, run `./demo.sh down` followed by `./demo.sh up`, then enter Qoder CLI again.
- **The modified Skill is answered directly:** use `/clear` and confirm a new `Skill` tool call occurred instead of a cached answer being repeated.
- **No events for this round:** expand the time range, clear filters, and verify that you opened this instance's page on port 17396.

This demo uses the `ask` policy: an abnormal status requests confirmation, and declining cancels the invocation. It demonstrates local Skill pre-invocation verification and scanning, not equivalent coverage for every Agent action. This rehearsal includes multiple model responses and terminal approvals, and the full flow takes more than three minutes. Plan the activity using the measured timings in the acceptance report and allow time for network and participant delays.

Use the version manifest and verification report shipped with the bundle for exact component versions, image checksums, and test results.
