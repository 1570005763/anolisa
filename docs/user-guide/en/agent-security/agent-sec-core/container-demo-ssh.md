# Connect to the ECS experience from your computer

[中文版](../../../zh/agent-security/agent-sec-core/container-demo-ssh.md)

Run the connection script locally to prepare the experience on ECS, forward the AgentSight page, and enter Qoder CLI. It reuses the published container image; follow the [operation card](container-demo-card.md) for the experience itself.

## Prerequisites

- Use macOS or Linux with Bash, curl, and OpenSSH. Windows users can run the script in WSL; a native PowerShell script is not provided.
- Ensure `ssh user@ecs-host` connects to the target ECS. Configure custom ports, private keys, or jump hosts in your local `~/.ssh/config`; an SSH alias can replace the destination.
- ECS must run Linux amd64 with Docker installed and running, and the SSH user must have Docker access. Initial installation requires ECS access to GitHub and GHCR. Qoder CLI authentication and model requests also require its service network and a valid account.
- Prepare Chrome on your computer. Each ECS runs one experience instance, shared by participants in turn.

## Connect with one command

Run in your **local terminal**, replacing `user@ecs-host` with the destination or SSH alias:

```bash
curl -fsSL --retry 3 --connect-timeout 15 --max-time 60 \
  https://github.com/1570005763/anolisa/releases/download/agentseccore-demo-20260910.1/ecs-demo.sh \
  | bash -s -- user@ecs-host
```

On first use, the script installs the starter bundle in `~/agentseccore-demo` on ECS, verifies files, pulls the pinned image, and starts the container. An existing matching starter installation is verified, started, and checked without downloading the installer or pulling the image again. Reconnecting does not reset the Skill.

In Qoder CLI, confirm the demo directory when prompted and enter `/login` to authenticate your account. SSH host verification, password entry, and Qoder CLI login use their native prompts. If a remote browser login callback fails, configure a Personal Access Token on ECS using the [authentication instructions](container-demo.md). After changing `demo.env`, stop the container and reconnect to apply it.

Open <http://127.0.0.1:17396/#/security> in local Chrome. Keep the Qoder CLI terminal connected. Exiting Qoder CLI closes the SSH tunnel while preserving the remote container, account state, and history.

## Staff commands

For repeated use, save the connection script in your current local directory:

```bash
curl -fsSL --retry 3 --connect-timeout 15 --max-time 60 \
  https://github.com/1570005763/anolisa/releases/download/agentseccore-demo-20260910.1/ecs-demo.sh \
  -o ecs-demo.sh
```

Run all commands below in your **local terminal**. Omitting the action opens Qoder CLI.

| Purpose | Command |
| --- | --- |
| Prepare and check the environment without opening Qoder CLI | `bash ecs-demo.sh user@ecs-host prepare` |
| Open Qoder CLI and the page tunnel | `bash ecs-demo.sh user@ecs-host` |
| Check environment status | `bash ecs-demo.sh user@ecs-host doctor` |
| Modify the demo Skill from a second terminal | `bash ecs-demo.sh user@ecs-host tamper` |
| Reset for the next participant | `bash ecs-demo.sh user@ecs-host reset` |
| Stop the remote container after the event | `bash ecs-demo.sh user@ecs-host down` |

`prepare` supports unattended setup when SSH already has non-interactive authentication and trusted host records. It does not perform Qoder CLI login or model requests. `reset` ends this instance's Qoder CLI session and restores `pass`, also closing the associated tunnel; run the default connection command for the next round. `down` retains instance data.

During the demo, keep the default connection in terminal A, run `tamper` or `reset` in terminal B, and use Chrome as window C. Prompts, approval choices, and expected results for terminal A are in the [operation card](container-demo-card.md).

## Troubleshooting

- **Local port 17396 is occupied:** use another local port, for example `LOCAL_PORT=17397 bash ecs-demo.sh user@ecs-host`, and open `http://127.0.0.1:17397/#/security` in Chrome. ECS still uses 17396.
- **SSH fails or forwarding is denied:** check login with `ssh user@ecs-host`. The SSH service must permit local forwarding. The script uses existing SSH configuration and host verification.
- **Docker is missing or inaccessible:** prepare Docker on ECS and confirm the login user can access the local engine, then run `prepare`. The script does not install Docker.
- **Download fails:** retry when connectivity recovers. A successfully installed matching environment can be reconnected directly; Qoder CLI still requires its service network.
- **Directory version or file verification fails:** the entry supports this `.1` starter bundle in the default directory. It preserves and refuses to execute other files. For custom directories, offline bundles, or older installations, use direct SSH following the [full guide](container-demo.md) and keep installation directories separate.
- **Qoder CLI requires a terminal:** run the default connection command in a local interactive terminal; use `prepare` for automation jobs.

The script forwards the page through SSH to your local loopback address; AgentSight does not need a public port. See the [preparation guide](container-demo.md) for installation, account configuration, and experience boundaries.
