# AgentSecCore 容器上手体验

[English](README.md)

通过专用 Linux amd64 容器体验 Skill 安全防护。工作人员准备并登录，参与者轮流使用同一张 Markdown 操作卡。支持本机 Linux 部署和从本机连接 ECS，复用固定镜像。

对外只需转发[上手体验入口](https://github.com/1570005763/anolisa/releases/tag/agentseccore-demo-20260910.1)：页面提供可复制的安装命令及按角色、部署方式划分的文档导航。详细操作见[准备指南](../../docs/user-guide/zh/agent-security/agent-sec-core/container-demo.md)、[ECS 指南](../../docs/user-guide/zh/agent-security/agent-sec-core/container-demo-ssh.md)和[操作卡](../../docs/user-guide/zh/agent-security/agent-sec-core/container-demo-card.md)。

`demo.sh up` 自动复用、导入或拉取固定镜像；`ecs-demo.sh SSH_DESTINATION control` 打开已进入远端体验目录的控制终端。`install.sh` 与 `ecs-demo.sh` 是发布模板，请使用 Release 中生成的文件。

维护者运行 `check.py`、`check-ecs.py` 和 `check-release.py`；`package.py` 统一生成包、脚本、文档及校验值，`publish.py` 拒绝覆盖不同内容。发布工作流仅手动触发，直接使用已验收镜像，无需重新构建或推送。`build.sh` 仅保存原镜像构建配方。真实凭据和实例状态不得进入交付文件。
