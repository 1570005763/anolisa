# AgentSecCore hands-on demo

[中文版](README_zh.md)

Run the Skill safety experience in a dedicated Linux amd64 container. The launcher uses a fixed AgentSecCore, AgentSight, and Qoder CLI image and supports both public GHCR pulls and offline imports.

On a Linux amd64 host with Docker installed and running, download, install, pull the image, and start the environment with one command:

```bash
curl -fsSL https://github.com/1570005763/anolisa/releases/download/agentseccore-demo-20260910.1/install.sh | bash
```

The default directory is `$HOME/agentseccore-demo`. Then run `cd "$HOME/agentseccore-demo" && ./demo.sh qoder` and complete your Qoder CLI account login. See the [English guide](../../docs/user-guide/en/agent-security/agent-sec-core/container-demo.md) for details; [this release](https://github.com/1570005763/anolisa/releases/tag/agentseccore-demo-20260910.1) also provides manual starter and offline bundles.

`demo.sh` starts and manages one instance; `build.sh` records the Linux build recipe, and `check.py` checks syntax, modification behavior, pull identity checks, and optional archived image layers. Published releases import the accepted image without rebuilding it. Keep real credentials out of source and distribution files.

`install.sh` is a release template; packaging pins the starter checksum. Use the generated script from the Release.

For local macOS/Linux access to an ECS host, `ecs-demo.sh SSH_DESTINATION` prepares the remote environment, forwards the dashboard, and opens Qoder CLI. See the [SSH guide](../../docs/user-guide/en/agent-security/agent-sec-core/container-demo-ssh.md) for the one-command entry and staff actions. Run `python3 tools/agentseccore-demo/check-ecs.py` to check the connection wrapper without accessing a host.
