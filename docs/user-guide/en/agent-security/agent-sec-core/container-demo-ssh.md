# Staff: connect to the ECS demo from a local machine

[中文版](../../../zh/agent-security/agent-sec-core/container-demo-ssh.md)

Staff prepare three local windows; participants follow the same [operation card](container-demo-card.md). The container, Skills, account state, and history live on ECS. The local machine runs only SSH and Chrome.

## Prerequisites

- Local macOS/Linux with Bash, curl, and OpenSSH; Windows uses WSL, with no native PowerShell support.
- `ssh user@ecs-host` reaches Linux amd64 ECS. Use an existing `~/.ssh/config` alias for custom ports, keys, or jump hosts. Staff verify the initial host identity.
- Docker runs on ECS and is accessible to the SSH user. Online installation uses GitHub/GHCR; authentication and model requests need Qoder connectivity and a valid activity account.
- One ECS runs one instance for sequential participants; no public AgentSight port is required.

<a id="windows"></a>
## Windows: prepare once before the event

Windows runs SSH in WSL Ubuntu and displays the page in Windows Chrome; Docker and Qoder CLI are not required locally. These instructions target Windows 11, or Windows 10 version 2004 / Build 19041 or later. Staff install, restart, and initialize WSL in advance, following organizational requirements. Skip installation if Ubuntu is already available. See [Microsoft's WSL installation guide](https://learn.microsoft.com/windows/wsl/install).

Run in **Windows PowerShell as administrator**, then restart:

```powershell
wsl --install -d Ubuntu
```

Open Ubuntu from the Start menu and create the WSL local username and password; this is separate from the ECS SSH user. Subsequently select **Ubuntu** in Windows Terminal, or enter `wsl -d Ubuntu` in ordinary PowerShell. All client commands on this page run inside Ubuntu unless explicitly marked PowerShell.

Check tools in **WSL Ubuntu**. Run the installation command below only if curl or ssh is missing:

```bash
command -v bash curl ssh
```

```bash
sudo apt-get update && sudo apt-get install -y curl openssh-client
```

Use the same WSL user in A and B. After opening Ubuntu, enter the fixed client directory:

```bash
mkdir -p "$HOME/agentseccore-client"
cd "$HOME/agentseccore-client"
```

### Configure SSH

Staff obtain the ECS address, SSH username, port, host fingerprint, and dedicated activity credentials through an internal channel. The cloud account manages ECS, SSH credentials connect to it, and the Qoder CLI activity account is authenticated inside the ECS container. Keep actual credentials out of public pages and operation cards. Mac SSH aliases do not automatically transfer to WSL.

```bash
mkdir -p "$HOME/.ssh"
chmod 700 "$HOME/.ssh"
```

For key authentication, copy the staff-provided activity key into WSL. Replace the Windows username and source path below; retain quotes to support spaces:

```bash
install -m 600 "/mnt/c/Users/WINDOWS_USER/Downloads/agentseccore-demo.pem" "$HOME/.ssh/agentseccore-demo"
```

Add this entry to WSL's `~/.ssh/config`, replacing the address, user, and port; edit the existing entry if the alias exists. For password authentication, omit `IdentityFile` and `IdentitiesOnly`; staff enter the password at the SSH prompt.

```sshconfig
Host agentseccore-demo-ecs
    HostName ecs-host
    User demo
    Port 22
    IdentityFile ~/.ssh/agentseccore-demo
    IdentitiesOnly yes
```

```bash
chmod 600 "$HOME/.ssh/config"
ssh agentseccore-demo-ecs 'uname -sm; docker --host unix:///var/run/docker.sock info >/dev/null'
```

On first connection, compare the host fingerprint with the value supplied by staff. Expect `Linux x86_64` and no Docker errors. Keep host identity verification enabled. Substitute `agentseccore-demo-ecs` for `user@ecs-host` below.

<a id="prestage"></a>
## Staff: prepare ECS ahead of time

Use a dedicated Linux amd64 ECS. Before reusing a machine, check its purpose, containers, and data; do not reinstall a shared development machine to obtain a clean environment. Follow organizational procedures and the [official ECS documentation](https://help.aliyun.com/zh/ecs/) for instance creation and networking. An administrator preinstalls Docker Engine and verifies access for the SSH user; see [Docker's installation guide](https://docs.docker.com/engine/install/).

Share the host, usage period, owner, and SSH connection details through an internal channel. The preparation client needs connector download access; ECS needs GitHub/GHCR and Qoder access; the venue network must permit SSH and local forwarding. Download the image ahead of time to avoid large downloads at the venue. A client without GitHub access can use a previously saved copy of this release's `ecs-demo.sh`. See the [preparation guide](container-demo.md#staff) for offline image setup.

Download the connector on the preparation client and prepare services first:

```bash
curl -fSL --retry 3 --connect-timeout 15 --max-time 180 \
  https://github.com/1570005763/anolisa/releases/download/agentseccore-demo-20260910.1/ecs-demo-20260916.1.sh -o ecs-demo.sh && \
  bash ecs-demo.sh user@ecs-host prepare
```

`prepare` neither authenticates nor requests a model. Open A/B/C below and follow the [preparation guide](container-demo.md#staff) for authentication, a real model check, rehearsal, and reset. Exit A normally before leaving the preparation machine to release the single Qoder CLI session; keep the ECS container running. At the venue, connect to the same ECS and reuse authentication in its volume without copying Qoder authentication files.

## Window A: Qoder CLI and dashboard tunnel

On Windows, use `~/agentseccore-client` in WSL Ubuntu. If the connector is already saved, use the reentry command below.

Run in **local terminal A**, replacing `user@ecs-host` with the actual address or SSH alias:

```bash
curl -fSL --retry 3 --connect-timeout 15 --max-time 180 \
  https://github.com/1570005763/anolisa/releases/download/agentseccore-demo-20260910.1/ecs-demo-20260916.1.sh -o ecs-demo.sh && \
  bash ecs-demo.sh user@ecs-host
```

Initial preparation and updates from the known old release are automatic. Missing images are pulled even when installation files already exist; correct images are reused. The script stays in the current local directory. Staff then follow the [preparation guide](container-demo.md#staff) for native `/login`, the model check, and rehearsal.

To reenter the same environment, run in the local directory containing the saved script:

```bash
bash ecs-demo.sh user@ecs-host
```

## Window B: remote control terminal

On Windows, open another WSL Ubuntu window and enter `~/agentseccore-client`. In **another local terminal B**, in the directory containing the script, run:

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

## Windows venue handover and troubleshooting

C uses **Windows Chrome**, without a browser installed in WSL. See [Microsoft's WSL networking guide](https://learn.microsoft.com/windows/wsl/networking#accessing-linux-networking-apps-from-windows-localhost) for Windows localhost access to WSL. Label A / Qoder CLI and B / Control; exiting A returns to local WSL, while B's `./demo.sh` commands run in the ECS directory.

Rehearse the operation card on the actual Windows machine and venue network, checking Chinese prompt pasting, real `Skill` calls, manual No, and new events. Verify reentering A and restoring Chrome access after reset from B. macOS/Linux acceptance does not replace Windows testing. Hand over with A authenticated and waiting for input, B in the ECS demo directory, C able to query events, and the target at `pass`. Ensure only one Qoder CLI session is in use; multiple clients on this instance do not provide independent experiences.

- **PowerShell reports missing bash or syntax errors**: enter WSL Ubuntu first. Run `wsl --list --verbose` in PowerShell to list distributions.
- **B cannot find ecs-demo.sh**: use the same WSL user and enter `~/agentseccore-client`; download the script only once.
- **Key permission error**: use a mode-600 key under WSL's `~/.ssh/`, not a key directly under `/mnt/c/`; the SSH user must match the ECS configuration.
- **Chrome cannot reach the page**: keep A connected and run `curl -I --max-time 5 http://127.0.0.1:17396/` in another local WSL window. If WSL also fails, inspect A's tunnel error; if only Windows fails, check Windows port conflicts, proxies, WSL localhost forwarding, and organizational network policy. Do not expose the service publicly to bypass the failure.

## Troubleshooting

- **Local port busy**: run `LOCAL_PORT=17397 bash ecs-demo.sh user@ecs-host` and use its corresponding Chrome address. A tunnel failure is reported rather than silently using the wrong port.
- **SSH or forwarding failure**: check native SSH login and the server's local forwarding configuration. Host identity verification remains enabled.
- **Download or pull failure**: restore connectivity and retry, or use the [preparation guide](container-demo.md#staff) to install this release's offline bundle in the default ECS directory, then use the same connector.
- **Directory or file verification failure**: unknown installations, changed files, and symlinks are rejected. Do not disable verification. The connector uses the default directory and does not manage custom paths.
- **Terminal required**: `qoder` and `control` require a real interactive terminal; automation uses `prepare`.

Staff handle account login, handoff, and shutdown. Participants use only the operation card.
