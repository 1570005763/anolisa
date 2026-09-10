# AgentSecCore hands-on demo

[中文版](README_zh.md)

Run the Skill safety experience in a dedicated Linux amd64 container. The launcher uses a fixed AgentSecCore, AgentSight, and Qoder CLI image and supports both public GHCR pulls and offline imports.

Download the starter or offline bundle from [the release](https://github.com/1570005763/anolisa/releases/tag/agentseccore-demo-20260910), then follow the [English guide](../../docs/user-guide/en/agent-security/agent-sec-core/container-demo.md) or [Chinese guide](../../docs/user-guide/zh/agent-security/agent-sec-core/container-demo.md). Docker must be available on the Linux host. Qoder CLI authentication and model requests need network access and a valid Qoder identity.

`demo.sh` starts and manages one instance; `build.sh` records the Linux build recipe, and `check.py` checks syntax, modification behavior, pull identity checks, and optional archived image layers. Published releases import the accepted image without rebuilding it. Keep real credentials out of source and distribution files.
