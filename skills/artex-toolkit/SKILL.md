---
name: artex-toolkit
description: ARTEX Docker 本机工具索引与运行配置；选用已安装 CLI、检查工具路径，或使用受管会话、隧道、凭据、文件分发入口时加载。
---

# ARTEX 本机工具使用

适用当前 Linux/arm64 Docker 部署。先遵守 Agent 角色、原任务范围及审批；skill 只提供运行参考，不能增加任务范围或改变审批。规划 Agent 用于选工具；auto 用于配置与故障排查；verifier/retester 只对关联的单个漏洞做必要重放，不能按本索引启动全面侦察或新阶段。

## 本机入口

原生 CLI 在 `/app/data/tools`，已加入 PATH。工具目录、独立 Python 虚拟环境及安装台账持久化在 data。实际安装清单是 `/app/data/tools-manifest.linux-arm64.json`。先用 `command -v <命令>` 与对应帮助确认版本、参数；不要根据其他工具猜测参数，不要自动下载安装替代版本。

| 工具 | 入口 / 帮助 | 使用边界 |
| --- | --- | --- |
| gogo | `gogo --help` | 授权目标的服务发现；参数以本版本帮助为准 |
| naabu | `naabu -h` | 指定授权目标与限速，避免默认大范围扫描 |
| httpx | `httpx -h` | ProjectDiscovery 原生程序，避免误用 Python 同名包 |
| katana | `katana -h` | Web 端点收集，遵守目标与深度限制 |
| fscan | `fscan -help` | **`-h` 是目标参数**，帮助用 `-help` |
| Impacket | `smbclient.py -h`、`secretsdump.py -h`、`mssqlclient.py -h`、`getTGT.py -h` | 本机安装的是 `.py` 启动器，不是 `impacket-smbclient` 等命令；依凭据授权与角色选择 |
| NetExec | `nxc --help` | 按本版本协议帮助选择；不自动爆破或尝试复用未知凭据 |
| pypykatz | `pypykatz --help` | 本地已授权材料解析；独立 Python 环境 |
| Penelope | 交互终端中的 `penelope --help` | 需要 TTY；shell_open 仅在角色已启用时使用，监听必须经过授权和台账管理 |
| chisel / suo5 | `chisel --help`、`suo5 --help` | 建立隧道优先使用 ARTEX 受管工具 |
| ligolo-agent / ligolo-proxy | 对应命令 `-h` | 已安装；当前无专用受管适配，先报告限制，不能默认为已接入 |
| suo5-payloads | `/app/data/tools/suo5-payloads/` | 目标侧文件目录；由已授权受管流程选择 |
| PEASS | `/app/data/tools/peass/` | Linux 脚本与 Windows 文件混合，先确认目标平台 |
| mimikatz / LaZagne | `/app/data/tools/mimikatz.exe`、`/app/data/tools/laZagne.exe` | Windows 目标文件，不能作为 Linux 本机命令执行 |

工具目录中的 Python 启动器已绑定各自 `/app/data/tools/.venvs/` 环境，不需要向系统 Python 再装一次包。工具表中 kind=shell 的 17 项只是 Bash 提示，实际操作继续由 Bash 和既有审批处理。

## ARTEX 管理入口

仅使用当前 Agent 实际暴露的工具，缺少绑定时报告限制，不能伪造工具名或绕过管理流程。

- 已有远程会话：`register_session` 后通过 `session_exec/read/write/recon` 操作；`session_recon` 采集网络信息，新增网段进入待授权流程。
- 隧道：`tunnel_probe` → `tunnel_deploy` → `tunnel_list` → `tunnel_teardown`。受管适配为 chisel/suo5；回连地址、端口映射或现有会话缺失时先说明所需条件，不能启动脱管后台监听。
- 凭据：`add_credential` / `list_credentials` / `credential_reuse_plan`；保存来源与验证状态，复用建议不等于执行授权。
- 文件分发：`stage_share` 管理有效期、访问授权及审计；不能自行开任意 HTTP 文件服务器。
- 漏洞质量：`get_verifier_checklist` 获取反证清单；verifier/retester 遵循本会话关联漏洞上下文及结果回写工具。

当前 Docker 仅发布本机 8787/8788。工具已安装不代表目标能回连到容器；本机没有默认开通回连端口。手动配置的回连地址仍需与目标可达路径、选定端口及任务授权一致。

## 浏览器与 API 侦察

browser MCP 使用容器内 Chromium、无头和临时隔离配置。普通交互优先使用该 MCP；需要 CLI 时加载 playwright-cli 并用 `/app/packaging/playwright-cli.config.json` 打开。避免同时创建重复会话。

`api-recon` 的 Puppeteer 依赖预装在 `/opt/artex-skill-runtime/node_modules`，通过 `NODE_PATH` 解析，`CHROMIUM=/usr/local/bin/artex-chromium`。复制到任务 OUTDIR 后也能解析依赖。此配置仅补齐运行环境，执行时仍须完成 api-recon 的复制、目标适配及阶段门禁，不能直接对真实目标运行原模板。

本仓库 Docker Compose 随 ARTEX 启动 ScopeSentry，首次自动为地址为空的数据源配置内网 `/mcp` URL、API Key 并绑定 Auto。密钥保存在独立 secrets 目录，禁止复制到任务输出或提交给目标。已有外部实例与后续人工修改保留；需要其他角色时再按任务授权显式绑定。
