# AgentSecCore 容器上手体验

[English](README.md)

通过专用 Linux amd64 容器体验 Skill 安全防护。启动脚本使用固定版本的 AgentSecCore、AgentSight 和 Qoder CLI 镜像，支持从公开 GHCR 拉取或从离线包导入。

从[本版 Release](https://github.com/1570005763/anolisa/releases/tag/agentseccore-demo-20260910)下载轻量启动包或离线包，再按[中文指南](../../docs/user-guide/zh/agent-security/agent-sec-core/container-demo.md)或[英文指南](../../docs/user-guide/en/agent-security/agent-sec-core/container-demo.md)操作。Linux 主机需要可用的 Docker；Qoder CLI 认证和模型请求需要网络及有效的 Qoder 身份认证。

`demo.sh` 启动和管理单个实例；`build.sh` 保存 Linux 构建配方；`check.py` 检查语法、修改行为、镜像身份校验和可选的镜像层审计。发布流程直接导入已验收镜像。真实凭据不得加入源码或交付文件。
