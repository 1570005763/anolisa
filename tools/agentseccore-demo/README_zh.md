# AgentSecCore 容器上手体验

[English](README.md)

通过专用 Linux amd64 容器体验 Skill 安全防护。启动脚本使用固定版本的 AgentSecCore、AgentSight 和 Qoder CLI 镜像，支持从公开 GHCR 拉取或从离线包导入。

在已安装并启动 Docker 的 Linux amd64 主机执行一条命令，自动下载安装、拉取镜像并启动环境：

```bash
curl -fsSL https://github.com/1570005763/anolisa/releases/download/agentseccore-demo-20260910.1/install.sh | bash
```

默认目录为 `$HOME/agentseccore-demo`。完成后执行 `cd "$HOME/agentseccore-demo" && ./demo.sh qoder`，按提示完成 Qoder CLI 账号登录。详细说明见[中文指南](../../docs/user-guide/zh/agent-security/agent-sec-core/container-demo.md)；[本版 Release](https://github.com/1570005763/anolisa/releases/tag/agentseccore-demo-20260910.1)也提供手工启动包和离线包。

`demo.sh` 启动和管理单个实例；`build.sh` 保存 Linux 构建配方；`check.py` 检查语法、修改行为、镜像身份校验和可选的镜像层审计。发布流程直接导入已验收镜像。真实凭据不得加入源码或交付文件。

`install.sh` 是发布模板，打包时写入启动包校验值；请使用 Release 中生成的脚本。
