# Staff: connect to the ECS demo from a local machine

[中文版](../../../zh/agent-security/agent-sec-core/container-demo-ssh.md)

Staff prepare three local windows; participants follow the same [operation card](container-demo-card.md). The container, Skills, account state, and history live on ECS. The local machine runs only SSH and Chrome.

## Prerequisites

- Local macOS/Linux with Bash, curl, and OpenSSH; Windows uses WSL, with no native PowerShell support.
- `ssh user@ecs-host` reaches Linux amd64 ECS. Use an existing `~/.ssh/config` alias for custom ports, keys, or jump hosts. Staff verify the initial host identity.
- Docker runs on ECS and is accessible to the SSH user. Online installation uses GitHub/GHCR; authentication and model requests need Qoder connectivity and a valid activity account.
- One ECS runs one instance for sequential participants; no public AgentSight port is required.

## Window A: Qoder CLI and dashboard tunnel

Run in **local terminal A**, replacing `user@ecs-host` with the actual address or SSH alias:

```bash
curl -fSL --retry 3 --connect-timeout 15 --max-time 180 \
  https://github.com/1570005763/anolisa/releases/download/agentseccore-demo-20260911.1/ecs-demo.sh -o ecs-demo.sh && \
  bash ecs-demo.sh user@ecs-host
```

Initial preparation and updates from the known old release are automatic. Missing images are pulled even when installation files already exist; correct images are reused. The script stays in the current local directory. Staff then follow the [preparation guide](container-demo.md#staff) for native `/login`, the model check, and rehearsal.

To reenter the same environment, run in the local directory containing the saved script:

```bash
bash ecs-demo.sh user@ecs-host
```

## Window B: remote control terminal

In **another local terminal B**, in the directory containing the script, run:

```bash
bash ecs-demo.sh user@ecs-host control
```

B is now connected by SSH in `~/agentseccore-demo` on ECS. Participants run `./demo.sh tamper` exactly as shown on the operation card, without translating commands or entering host addresses. Keep B connected; exiting it does not stop the container.

## Window C and the next round

Open the actual address printed by A in local Chrome, normally `http://127.0.0.1:17396/#/security`. Keep A connected. Exiting Qoder CLI, or running `./demo.sh reset` in B, closes A's SSH tunnel. Staff rerun the entry command in **A**; B remains the control terminal.

| Staff task (commands run locally) | Command |
| --- | --- |
| Prepare and check only | `bash ecs-demo.sh user@ecs-host prepare` |
| Check services | `bash ecs-demo.sh user@ecs-host doctor` |
| Reset without a control window | `bash ecs-demo.sh user@ecs-host reset` |
| Stop the container after the activity | `bash ecs-demo.sh user@ecs-host down` |

`prepare` neither authenticates nor requests a model. Unattended use also requires existing noninteractive SSH authentication and trusted host records. The existing `tamper`, `reset`, and `down` actions remain supported. `down` retains the volume.

## Troubleshooting

- **Local port busy**: run `LOCAL_PORT=17397 bash ecs-demo.sh user@ecs-host` and use its corresponding Chrome address. A tunnel failure is reported rather than silently using the wrong port.
- **SSH or forwarding failure**: check native SSH login and the server's local forwarding configuration. Host identity verification remains enabled.
- **Download or pull failure**: restore connectivity and retry, or use the [preparation guide](container-demo.md#staff) to install this release's offline bundle in the default ECS directory, then use the same connector.
- **Directory or file verification failure**: unknown installations, changed files, and symlinks are rejected. Do not disable verification. The connector uses the default directory and does not manage custom paths.
- **Terminal required**: `qoder` and `control` require a real interactive terminal; automation uses `prepare`.

Staff handle account login, handoff, and shutdown. Participants use only the operation card.
