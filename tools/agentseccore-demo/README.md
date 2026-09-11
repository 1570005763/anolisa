# AgentSecCore hands-on demo

[中文版](README_zh.md)

Experience Skill safety in a dedicated Linux amd64 container. Staff prepare and authenticate; participants use one Markdown operation card sequentially. Local Linux deployment and local access to ECS share a fixed image.

Share only the [entry page](https://github.com/1570005763/anolisa/releases/tag/agentseccore-demo-20260910.1), with copyable installation commands and navigation by role and deployment. Details are in the [preparation guide](../../docs/user-guide/en/agent-security/agent-sec-core/container-demo.md), [ECS guide](../../docs/user-guide/en/agent-security/agent-sec-core/container-demo-ssh.md), and [operation card](../../docs/user-guide/en/agent-security/agent-sec-core/container-demo-card.md).

`demo.sh up` reuses, imports, or pulls the pinned image. `ecs-demo.sh SSH_DESTINATION control` opens a control terminal in the remote demo directory. `install.sh` and `ecs-demo.sh` are release templates; use their generated Release assets.

Maintainers run `check.py`, `check-ecs.py`, and `check-release.py`. `package.py` generates bundles, scripts, documentation, and checksums together; `publish.py` rejects replacement with different bytes. The manually triggered workflow reuses the accepted image without rebuilding or pushing it. `build.sh` records the original image recipe. Keep credentials and instance state out of distribution files.
