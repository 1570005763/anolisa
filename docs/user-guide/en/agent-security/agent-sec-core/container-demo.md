# AgentSecCore: Protecting Skill Security

[中文版](../../../zh/agent-security/agent-sec-core/container-demo.md)

**Who touched my Skill?** Staff prepare and rehearse once; participants use ready windows to experience `pass → drifted → deny`. Share only [this entry page](https://github.com/1570005763/anolisa/releases/tag/agentseccore-demo-20260910.1).

## Choose the deployment location

| Container location | Where staff run installation | Prerequisites |
| --- | --- | --- |
| Local Linux | Terminal on that Linux machine | Linux amd64; Docker running and accessible to the current user |
| ECS | Local macOS/Linux terminal; Windows uses WSL | Local Bash, curl, OpenSSH; SSH access to Linux amd64 ECS with Docker available remotely |

Install on local Linux:

```bash
curl -fSL --retry 3 --connect-timeout 15 --max-time 180 \
  https://github.com/1570005763/anolisa/releases/download/agentseccore-demo-20260911.1/install.sh -o install.sh && bash install.sh
```

Connect to ECS from the local machine, replacing `user@ecs-host` with the address or SSH alias:

```bash
curl -fSL --retry 3 --connect-timeout 15 --max-time 180 \
  https://github.com/1570005763/anolisa/releases/download/agentseccore-demo-20260911.1/ecs-demo.sh -o ecs-demo.sh && \
  bash ecs-demo.sh user@ecs-host
```

The scripts verify downloads, reuse or prepare the pinned image, start the container, and check services. The default directory is `~/agentseccore-demo` on the **container host**. Retry the same command after a download or pull failure. The downloaded script stays in the invoking directory for reuse.

| Task | Material |
| --- | --- |
| Staff: login, rehearse, and hand over | [Preparation guide](container-demo.md#staff) |
| Staff: prepare ECS windows or diagnose SSH | [ECS guide](container-demo-ssh.md) |
| Participants: run the five steps | [Markdown operation card](container-demo-card.md) |
| Staff: download the offline bundle | [Current release files](https://github.com/1570005763/anolisa/releases/tag/agentseccore-demo-20260911.1) |

One host runs one instance, used sequentially. Chrome displays security events; ECS needs only the SSH tunnel, without a public AgentSight port. Staff preinstall Docker; these scripts do not install system software. See the [official Docker installation guide](https://docs.docker.com/engine/install/) and your organization's machine management requirements.

<!-- release-entry-end -->

<a id="staff"></a>
## Staff workflow

### 1. Prepare the environment and three windows

Online installation requires GitHub/GHCR access from the container host. Authentication and model calls require Qoder service access and a valid activity account. The Linux amd64 image pins AgentSecCore 0.11.1, AgentSight 0.11.2, and Qoder CLI 1.1.48. This guide is for the dedicated demo container; see the [AgentSecCore guide](QUICKSTART.md) for regular product installation.

On the container host, check `docker --host unix:///var/run/docker.sock info`. If it fails, start Docker or ask the administrator to configure access for the current user, then retry installation. See the [ECS guide](container-demo-ssh.md) for SSH prerequisites and port troubleshooting.

For local deployment, run in A:

```bash
cd "$HOME/agentseccore-demo" && ./demo.sh qoder
```

Run in B:

```bash
cd "$HOME/agentseccore-demo"
```

For ECS, open A and B using the ECS guide; B is already in the remote demo directory. Open the actual printed address in Chrome window C, normally `http://127.0.0.1:17396/#/security`. Keep A connected: exiting Qoder CLI closes its SSH tunnel.

### 2. Authenticate the activity account and rehearse

In A, staff confirm the demo directory and enter `/login`. Use native Qoder CLI authentication. On ECS, prefer **Personal Access Token** and paste a PAT obtained from the activity account into the native prompt. Local deployment can also use browser login. Staff complete account authentication and initial SSH host verification; see the [official Qoder CLI authentication guide](https://docs.qoder.com/cli/authentication).

A PAT is a Qoder account token, not a model provider API key. Native authentication persists in this instance's data volume; the normal workflow needs neither editing `demo.env` nor recreating the container. Keep credentials out of public scripts, operation cards, and screenshots.

Enter `/status` to check the account, then verify an actual model request:

```text
不要调用工具，只回复 READY。
```

`./demo.sh doctor` checks services and credential presence; it does not prove account validity or model availability. After the model request succeeds, enter `/clear` and rehearse the entire [operation card](container-demo-card.md). Hand over only after actual `Skill` calls, confirmation, and corresponding events work. Schedule rounds based on measured rehearsal time.

### 3. Hand over and reset for the next round

Hand over three ready windows: prompts in A, modification commands in B, events in C. Participants use only the operation card; they do not install or log in again.

After each round, staff run in B:

```bash
./demo.sh reset
```

This ends Qoder CLI in A, restores the original Skill, and scans it to `pass`, retaining authentication, signing keys, and history. **Return to A** to reenter: locally run `./demo.sh qoder`; for ECS rerun `bash ecs-demo.sh user@ecs-host` on the client. Keep B as the control terminal; do not launch Qoder CLI in B.

At the end, run `./demo.sh down` in B, then exit the terminals. `down` removes the container and retains account state and history in the volume. Staff remain responsible for the dedicated activity machine and account.

### 4. Offline image and troubleshooting

Download the offline bundle and `SHA256SUMS` from the current release, copy both into one directory on the container host, and run:

```bash
sha256sum --check --ignore-missing SHA256SUMS && \
  tar -xzf agentseccore-demo-linux-amd64-20260911.1.tar.gz -C "$HOME"
cd "$HOME/agentseccore-demo" && ./demo.sh up && ./demo.sh doctor
```

Extract only when the default installation directory does not exist. For an existing current installation, copy only `image.tar.gz` from the verified offline bundle into that directory and run `./demo.sh up`. Both sources use the same controls, including the ECS connector. The offline bundle supplies the image; authentication and model calls still need network.

- **Pull failure**: restore connectivity and retry. An existing correct image needs no GHCR access.
- **File verification failure**: stop using the changed files and investigate. The installer accepts the current release or a known unmodified `20260910.1`; updates retain private configuration, offline image, and data volume, and remove temporary files on success.
- **Expired login**: staff use `/login` again in A. A PAT in an existing `demo.env` takes precedence over native login; remove it from that private file and run `down`, then `up` before switching to native authentication.
- **No Skill invocation**: follow the operation card, `/clear`, and retry once. A direct `Read` does not pass.
- **Missing new events**: reselect `Last 1h` in Chrome, then click `Query`.

This delivery provides neither a BYOK setup flow nor independent concurrent participant instances.
