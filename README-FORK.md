# ARTEX 二次开发说明

本文仅记录本仓库二次开发新增的功能、配置和部署差异。原项目文档保留在 [README.md](README.md)，保持原样；后续二次开发说明统一维护在本文件。Agent 协作规则见 [AGENTS.md](AGENTS.md)。

## 根据 Base URL 选择模型

「系统 → 大模型配置」的新建／编辑表单在填写 Base URL 后自动获取模型列表；需鉴权的接口填写 API Key 后会重新获取，编辑配置时 Key 留空沿用已保存的 Key。支持 OpenAI、Responses 和 Anthropic 兼容接口，以及无需鉴权的模型列表；可填写根地址、`/v1` 前缀或完整接口地址。留空 Base URL 时使用所选格式的官方地址，需要 API Key。

点击「选择模型」可搜索并选择返回的模型，也可手动输入模型名或刷新列表。修改地址、Key、格式或代理会重新获取，旧请求不会覆盖新列表；失败或空列表不影响手动配置。模型列表经现有后端接口获取，沿用表单代理，不新增配置或数据库迁移。

## ScopeSentry 任务联动（2026-10-31）

原有部署完成了服务、MCP 与角色绑定；本次补上任务运行链路。规划和执行入口自动检索任务已登记的明确域名／单个 IP，按目标显示存量数据缺口，回流范围内资产到「测试资产」，记录来源与真实 MCP 调用。查询最多 16 个目标、回流最多 500 个资产；企业、关键词和宽网段不作为隐式扫描目标，需先登记明确目标。只回流数据，不因此扩大授权范围或直接确认漏洞。

「任务总览 → ScopeSentry 联动」可关闭存量联动、检索并回流、选择模板、授权缺数据时自动补扫，或显式发起一次测绘。新扫描默认不自动授权；只接受已启用模块的固定目标端口／服务测绘模板，空 `default` 模板不能执行。模板选择留空时，仅在已经授权自动补扫或显式请求扫描的路径中查找唯一的 `ARTEX HTTP service mapping (fixed targets)`，读取详情核验后使用；不会因发现默认模板就开启扫描授权，缺失、同名冲突或被修改时停止。模板只接受已核验的 httpx、WebFingerprint、SkipCdn、RustScan、fingerprintx 插件及参数；httpx 必须显式使用下方安全参数，不能依赖会跟随跳转的默认值。不允许目标转换、扩域、爬虫、目录／漏洞流水线。审批结束及每次创建远端项目／扫描前重新核对任务状态、权限、范围约束、模板内容与插件启用状态，审批期间变化则停止。任务内扫描统一经 `scopesentry_scan` 校验，原始 MCP 创建扫描不能绕过该流程；Auto 的独立平台操作不受此任务入口限制。已有 MCP／skill 关闭、解绑和工具配置保留。

文字约束只对可确定的整句主机范围声明自动核验，例如 `仅允许对隔离靶机 http://172.30.243.22 进行测试`：必须与登记范围相交，仅缩小范围，不能授权新主机或扩展子域。禁止操作、路径／端口／速率等限制及无法解析的语句仍阻止新扫描，不忽略或删除约束；文字范围与登记范围冲突时连存量检索也停止。其他操作限制不阻止只读存量检索，但不被视为新扫描授权。

回流事实锚定本地资产，并保存最多 100 条远端记录的 ID、URL、端口、协议、状态码、标题、产品字段及观察时间，不保存响应正文或凭据。后续 Agent／用户登记可以更新资产列表的单一来源标签，但不删除该事实及锚点；追溯 ScopeSentry 来源应同时查看黑板回流事实，不能只依赖最新的列表标签。归档恢复遇到本地资产 ID 冲突时，快照的本地 ID 与锚点一起重映射，远端记录 ID 和测绘字段保持原样。

扫描固定使用已登记的目标，不从项目／资产搜索隐式扩展目标；项目创建和扫描提交均经过任务 Guard、RoE 与现有拦截审批。扫描标识先持久化再提交，重启和重复请求不会为同一范围重复创建扫描；提交结果不明时查询并核对远端，不盲目重试。平台约每分钟跟踪已提交扫描并回流结果，状态与跳过／失败原因在任务总览和会话记录可见。

已完成、暂停或删除的任务不创建新扫描，不会自动复活任务。关闭联动或暂停 ARTEX 不会自动终止已经提交的远端扫描，需要在 ScopeSentry 管理页面处理。任务联动配置与远端标识随数据库持久化、任务归档／恢复保留。更新本机源码部署仍使用现有 `docker compose up -d --build --wait --wait-timeout 900 artex`。

### 固定目标 HTTP 模板与本机隔离靶场

`python3 deploy/scopesentry/configure-http-template.py` 幂等创建 `ARTEX HTTP service mapping (fixed targets)` 并启用内置 httpx，不修改其他插件、既有同名异配置模板或启动扫描。当前管理员密码与初始密码不同时通过 `SCOPESENTRY_ADMIN_PASSWORD` 提供，不重置密码。定义位于 `deploy/scopesentry/templates/artex-http-services.json`；只使用 httpx，显式关闭跟随跳转、截图、TLS 扩展探测、绕过头，并把并发设为 3。已部署 ScopeSentry 的项目创建响应没有 ID 时，联动按精确项目名查回并核对目标，不重复创建。

隔离靶场文件位于 `tests/scopesentry-lab/`，启动使用 `python3 tests/scopesentry-lab/manage.py up`：创建独立 internal 网络 `172.30.243.0/24` 并给现有扫描节点和运行中的 ARTEX 接入，不改变其原网络。靶场目标容器只读、无额外权限、无外网出口；另设固定目标的只读查看网关，宿主端口仅绑定回环，不能作为任意代理。若该网段与已有 Docker 网络冲突，脚本停止，不改网络。

| 场景 | 宿主查看地址 | 容器扫描目标 |
| --- | --- | --- |
| HTTP 管理页（200） | `http://127.0.0.1:18381` | `172.30.243.11` |
| HTTP 鉴权页（401） | `http://127.0.0.1:18382` | `172.30.243.12` |
| 范围外跳转（302） | `http://127.0.0.1:18383` | `172.30.243.13` |
| 自签名 HTTPS | `https://127.0.0.1:18384` | `172.30.243.14` |
| 无监听端口阴性对照 | 不发布端口 | `172.30.243.15` |
| 范围外金丝雀 | 不发布端口，不登记扫描授权 | `172.30.243.99` |
| 青港书店订单访问控制 CTF | `http://127.0.0.1:18385`（只读页面查看） | `172.30.243.21` |

`python3 tests/scopesentry-lab/run-live-tests.py` 使用真实 ScopeSentry MCP、Redis 队列和扫描节点，测试 ARTEX 检索、创建项目／扫描、轮询回流、去重、审批拒绝及暂停／完成边界。ARTEX 侧使用临时独立 PostgreSQL 数据库，不跑 LLM，不改现有任务；测试结束删除该测试数据库，保留靶场与远端测试扫描记录供检查。测试明确断言跳转不命中金丝雀、关闭端口不产生虚假服务，扫描完成但没有服务的目标不被标成需要自动重扫。停止靶场使用 `python3 tests/scopesentry-lab/manage.py down`，只移除本靶场容器与网络；若扫描容器重建，重新运行 `up` 接入靶场网络。自签名证书只用于测试，不要在浏览器安全警告页强行放行。

配置场景模板后，增加 `--automatic-templates` 对另外三个可自动联动模板逐项创建真实扫描：固定目标 HTTP 指纹、单 IP Top1000 TCP／HTTP 清单、单 IP 服务与指纹。它们分别使用仅内部网络可达的 `.31`、`.32`、`.33`，检查远端完成、80 端口服务回流、来源、范围及金丝雀；`.32` 另提供 2222 端口的惰性 SSH banner（无认证、无 shell）用于核验非 HTTP 协议回流。不会执行 `manual` 模板或访问外部目标。

自然任务验证使用独立的青港书店 CTF：模拟客户登录、订单列表和缺少订单归属校验的发票接口，所有账号、订单和 flag 均为靶场数据。`python3 tests/scopesentry-lab/natural-task.py launch` 经正常任务创建入口运行真实 LLM，输入不点名 ScopeSentry、不手动触发扫描、不替任务选择模板或开启自动补扫；结果以实际调用记录为准，不能把工具已发现算作已扫描。运行前执行靶场 `manage.py up` 给 ARTEX 接入网络，使 Bash／浏览器可达靶场；重建 ARTEX 后再次执行 `up`。`status` 查询状态，`stop` 仅暂停这次新建任务；任务 ID 保存在被 Git 忽略的 `tests/scopesentry-lab/local/natural-task.json`，脚本拒绝重复创建。该任务使用当前模型并产生实际模型费用，默认任务期限 600 秒；原有任务不修改。

对照运行可增加 `--configured`：仅在正常任务配置入口选择有效模板并授权缺数据时自动补扫，仍不点名产品、不调用扫描接口。再加 `--default-template` 留空模板，验证授权后自动选择已核验的安全默认模板。`--target 172.30.243.22` 或 `172.30.243.23` 使用独立书店实例，`--run-tag <名称>` 分开保存各轮任务 ID，不覆盖旧记录；首次测绘后该实例已有存量数据，不再是缺数据对照。`verify` 使用相同的 `--configured`、`--run-tag` 只读观察任务完成、远端完成、带测绘字段的来源事实、真实扫描次数、Agent 读取完成状态、三项目标及 FLAG 证据，不刷新联动、不触发扫描或催促模型。超过验证期限只暂停本轮新任务。任务内联动使用 Engine 的实际启动状态，而不是只把数据库 `created` 当成未运行；未启动、暂停、排队和终态仍然不能提交扫描。Agent 运行时指引要求区分登记范围、实际测绘证据和漏洞证据，扫描中避免重复侦察，并行推进独立验证；取得 FLAG 不替代其他交付目标。

### 场景化模板库

`python3 deploy/scopesentry/configure-scenario-templates.py` 按 `deploy/scopesentry/templates/scenario-catalog.json` 幂等创建 13 个场景模板，覆盖 17 个已安装的节点插件；先检查完整插件身份和既有同名模板，再启用所需插件并创建缺失模板。`--dry-run` 只读预检，不改插件状态或模板；不启用服务端定时插件、不修改全局默认参数、不覆盖用户编辑，也不创建扫描。管理员密码仍通过前述方式提供。

| 新模板名称 | 插件组合 | 使用入口 |
| --- | --- | --- |
| `ARTEX HTTP fingerprints (fixed targets)` | httpx + WebFingerprint | ARTEX 自动联动 |
| `ARTEX IP TCP and HTTP inventory (top1000)` | SkipCdn + RustScan + fingerprintx + httpx | ARTEX 自动联动，仅明确单 IP |
| `ARTEX IP services and fingerprints (top1000)` | SkipCdn + RustScan + fingerprintx + httpx + WebFingerprint | ARTEX 自动联动，仅明确单 IP |
| `ARTEX Subdomains passive sources (manual)` | subfinder + Findomain | ScopeSentry 人工授权；会请求外部公开数据源 |
| `ARTEX Subdomains DNS wordlist (manual)` | ksubdomain | ScopeSentry 人工授权；主动 DNS 枚举 |
| `ARTEX Subdomains and takeover signals (manual)` | subfinder + Findomain + SubdomainTakeover | ScopeSentry 人工授权；仅检查接管信号，不注册资源 |
| `ARTEX Web historical URLs (manual)` | httpx + wayback | ScopeSentry 人工授权；历史 URL 不代表当前有效 |
| `ARTEX Web JS and API crawl (manual)` | httpx + katana | ScopeSentry 人工授权；深度 3、并发 3、非无头模式 |
| `ARTEX Web browser crawl (manual)` | httpx + rad | ScopeSentry 人工授权；先检查表单操作与浏览器副作用 |
| `ARTEX Web sensitive data (manual, no verify)` | httpx + katana + sensitive + trufflehog | ScopeSentry 人工授权；关闭凭据验证，不向第三方验证密钥 |
| `ARTEX Web directory discovery (manual)` | httpx + SentryDir | ScopeSentry 人工授权；目录字典并发 3 |
| `ARTEX Web backup discovery (manual)` | httpx + spray | ScopeSentry 人工授权；目录／备份枚举，与 SentryDir 二选一 |
| `ARTEX Web JS monitoring baseline (manual)` | httpx + katana + PageMonitoring | ScopeSentry 人工授权；记录 JS 基线，不创建周期任务 |

加上原有固定目标 HTTP 模板，ARTEX 自动联动有 4 个可用模板；其余 10 个场景模板只在 ScopeSentry 的人工授权流程中使用，不放宽任务内的固定目标／模板检查。PortScan 限 Top1000，不启用 masscan 全端口模板；HTTP 均显式关闭跟随跳转和扩展探测。FOFA／Quake／Hunter、需要专门数据源的企业／APK 插件、空 POC 库下的 nuclei、需要独立代理配置的 xray 不被批量启用。模板配置已读回核对，不代表所有新插件组合都完成了真实扫描验收。

旧 `ARTEX IP TCP inventory (top1000)` 仅包含 RustScan，真实节点会找到端口，但该阶段只向后续流水线传递内存结果；仅追加 fingerprintx 的旧 `inventory and protocols` 也不保存识别出的 HTTP 服务。当前用新名称的 `TCP and HTTP inventory` 同时补上 fingerprintx 协议识别与 httpx 测绘／HTTP 结果存储。旧模板不删除、不覆盖，ARTEX 将缺少 HTTP 存储阶段的模板标为不可用，避免把“任务完成”误认为“资产已回流”。fingerprintx 是主动协议探测，部分协议实现可能试探认证；它不是安全默认模板的一部分，选择含该插件的模板前须核对授权与目标限制。

## 本机 Docker 与 skill／工具配置（2026-10-24）

本机 Docker 已更新为当前工作区代码与运行依赖，应用、数据库均健康。13 个 skill 已按角色绑定：planner/mainagent 使用元决策与侦察参考，worker/pentest 可加载全部 9 类 chains、API 侦察、浏览器及本机工具指南，报告与验证角色使用相应精简配置。17 项已安装工具登记为 Bash 环境提示；受管会话、隧道、凭据和文件分发继续使用专用入口。

浏览器 MCP 改为直接启动预装程序，使用容器内 Chromium；Playwright CLI 配置与锁定的 Puppeteer 依赖固化到镜像。新增 `artex-toolkit` skill 提供路径、平台和调用方式。工具配置批次曾因没有外部实例而停用 ScopeSentry；当前已改为下方的一键联动部署。

本轮修复 skill 关闭后重启又被默认配置启用的问题：单项和批量配置保存明确的关闭状态。原模型、提示词、运行预算、审批、任务与门控材料均保留。原始 README 未修改。

2026-10-25 补齐 skill 加载规则：运行时根据角色、可见技能和实际工具注入场景指引，匹配场景时先调用 `Skill` 再执行，同一会话不重复加载；现有自定义提示词正文保留。规划与转向使用 chains-meta/侦察指南，执行按当前攻击面选择 chains 类别，接口采集、CLI 浏览器、本机工具及 ScopeSentry 分别按场景加载。L4 原文由 Skill 返回的技能目录定位。启动或保存 MCP 绑定时，为已有启用的 ScopeSentry MCP 权限补齐缺失的指南绑定，明确关闭的 skill 不会被恢复；本机对应 Auto、mainagent、worker、pentest、verifier、retester。验证/复测仅查询关联单个漏洞的既有记录，不因此启动批量扫描。新规则从下一次 Agent run 生效。

日常使用、角色配置表、可选回连设置、备份和持久化规则见 [本机 skill 与工具配置说明](docs/agent-tooling.md)；重启、工具装配、竞态回归及部署检查结果见 [工具配置验证报告](docs/testing/agent-tooling-report.md)。下文各迁移报告中的镜像、二进制摘要和测试结果保留为对应批次的历史记录；ScopeSentry 当前状态见下方部署与验证报告。

## 对话与任务会话卡顿修复（2026-10-24）

任务状态刷新和实时消息重放保留未变化的消息对象；消息分组、正文和 Markdown 复用已有渲染。工具／推理详情按需加载，同一会话的重叠请求共用一个请求，缓存最多保留 128 条、合计 200 万字符，切换会话后释放。连续滚动事件只请求一次同页历史，旧任务请求不会更新新任务或改变新会话的滚动位置。

任务 SSE 与分页历史统一只发送摘要及身份、Token、审批等元数据，完整正文仍通过原详情接口读取；前端兼容旧后端的大正文事件。Worker 的合成意图直接显示完整文本。无需新增配置或数据库迁移。

本机 Docker 已切换新版。Chrome 的「React DevTools 1.0.0」（ID `bfndgimipcdaiadjgkaailoahpbinebi`）会在打开对话时扫描并序列化组件，导致长时间阻塞；本机已按用户授权停用，重新启用可能再次卡顿。

## ScopeSentry 随 Docker 一键启动（2026-10-24）

`docker compose up -d artex` 会自动带起 ScopeSentry 管理平台、扫描节点、MongoDB 和 Redis。首次生成数据库密码与专用 API Key，保存在 `.secrets/scopesentry/`；自动接入地址为空的 ScopeSentry 数据源，绑定 Auto 并发现工具。已有外部地址、后续人工关闭／解绑／密钥修改保留。

首次部署或更新源码使用：

```bash
docker compose up -d --build --wait --wait-timeout 900 artex
```

ScopeSentry 管理页面为 `http://127.0.0.1:8082`，初始账号 `ScopeSentry`，初始密码保存在 `.secrets/scopesentry/login/PASSWORD`；登录后修改。扫描节点默认 `artex-local-1`，只启动待命，不自动创建扫描任务。MongoDB／Redis 不发布宿主端口，管理页面仅绑定回环。两个 ScopeSentry 官方镜像固定摘要，本机 ARM 通过 AMD64 模拟运行。

来源固定提交、文件对应、配置、备份和迁移步骤见 [ScopeSentry 联动部署说明](docs/scopesentry-deployment.md)，实际上线与验证结果见 [验证报告](docs/testing/scopesentry-report.md)。旧的 `ScopeSentry-local` 教程目录属于独立部署历史方案，当前无需进入该目录。

继续交付时已复核整套服务健康、扫描节点在线、17 项 MCP 工具和 Auto 绑定；日常可运行 `python3 deploy/scopesentry/verify.py` 进行只读验收。

## 迁移 TODO（已完成）

来源：[panda0x123/artex-ymh](https://github.com/panda0x123/artex-ymh)，固定提交 `48adc7f1d8f62cbc47e658c9a2b47d6f63ca6cb1`。按依赖关系分批迁移；只有实现及验证完成后才勾选，路线图不代表当前能力。

### 第一批：稳定性与小型加固（2026-10-24 已完成）

- [x] LLM 单次调用超时：覆盖 Stream/Complete，默认 600 秒；保留取消、部分输出和当前故障转移语义。
- [x] 宿主睡眠／VM 冻结感知：检测超睡并顺延任务期限，适配期限持久化与重启恢复。
- [x] 意图队列治理：planner 待执行意图上限、取消 open 意图、高优先级意图领取超时提示。
- [x] 外部链接校验：动态外链只允许 HTTP/HTTPS，非法 URL 降级为文本。
- [x] 台账外监听审计：Linux 定期告警非回环、未登记监听；适配实际服务端口和关闭清理。

### 第二批：漏洞质量闭环（2026-10-24 已完成）

- [x] 独立漏洞验证 Agent：新漏洞独立验证会话、三态结论、状态回写和手动重验，与已有复测功能协调。
- [x] 重复漏洞合并及资产补锚：追加证据、合并后重验；完善入口区分，避免不同漏洞误合并。

### 第三批：内网管理子系统（2026-10-24 已完成）

- [x] 远程会话管理及探活：注册、会话台账、工作台、手动探活与启动卫生。
- [x] 受管代理隧道：部署、探测、台账、清理及任务级代理切换。
- [x] 只读网络信息采集与拓扑：接口、路由、邻居、监听结构化落库，展示主机／网段／链路。
- [x] 加密凭据台账：来源血缘、验证状态、脱敏展示及带理由的适用性建议。
- [x] 阶段移交与待授权网段：基于会话创建后续任务，新网段经人工批准再扩范围。
- [x] 受管临时文件分发：到期清理、可选一次下载和审计；使用独立资源授权，保留门控保护。

### 发布链配套

- [x] 更新包签名验证：客户端强制验签、本仓库独立公钥、CI Secret 与发布签名流程已配套；本机发布包验签通过。

已完成的安全、军火库、蜜罐和 chains 迁移见下文。每批同步保存来源、文件对应关系、适配差异及验证记录。

## 第一批稳定性与小型加固

| 二次开发内容 | 当前行为 |
| --- | --- |
| LLM调用超时 | Stream/Complete默认600秒，ARTEX_LLM_CALL_TIMEOUT=0关闭；保留取消和部分输出，调用级超时在安全窗口内可走已启用的pool故障转移 |
| 睡眠／冻结感知 | 定时器超睡至少60秒时补任务总期限并持久化；重启恢复已补期限，拒绝旧代际及终态顺延；已启动的单次运行／调用预算保留各自上限 |
| 意图队列治理 | planner新增open方向原子上限8；取消open方向留痕、mainagent可终止running方向；高优先级逾期提示跨重启只报一次 |
| 动态外链校验 | 资产、更新日志及Markdown链接仅允许HTTP/HTTPS绝对URL，非法链接显示文字 |
| Linux监听审计 | 启动及每5分钟检查当前网络命名空间的非回环、未登记TCP监听，只告警；登记实际端口，关闭时停止巡检 |

第一批上线时，本机Docker应用已更新，原门控、认证和17项工具验证正常。专项及兼容竞态复测45项通过；当时全量竞态回归仍有2项问题，详见 [验证记录](docs/testing/stability-report.md)。配置、迁移文件对应与行为边界见 [第一批搬迁记录](docs/stability-migration.md)。后续批次在当时保留未完成状态，当前状态以上方清单为准。

## 第二批漏洞质量闭环

| 二次开发内容 | 当前行为 |
| --- | --- |
| 独立漏洞验证 | 新证据默认自动验证，独立会话保存 verified／false_positive／inconclusive；详情支持手动重验、历史证据与过期版本 |
| 状态回写保护 | 只回写仍pending且证据版本／人工处置未变化的漏洞；其他处置保留，验证结论与处置状态分开展示 |
| 原复测协调 | 验证与修复复测互斥；原reproduced/fixed/inconclusive保留，过期证据及人工变更不自动回写fixed |
| 重复漏洞合并 | report_finding提供entry、method、parameter，同任务／首资产／严格类别／URL／方法／精确参数条件一致才合并；缺字段则新增 |
| 资产补锚 | 仅匹配本任务唯一exact endpoint／service，拒绝多目标、模糊前缀和跨任务猜测 |
| 合并后重验 | 追加原子证据、去重锚点和意图边、保留ID并提升版本；持久请求避免合并发生在验证中时丢失下一轮 |

详情页「全局自动验证」按钮对应auto/off；关闭清空待验证队列，已有会话继续，重新开启不补历史，手动不受限制。自动最多5个活跃check，默认每轮20步／600秒；LLM或工具缺失保留请求，启动后失败需查看会话并手动重验。原任务删除或缺失时不启动验证。verifier及工具默认播种一次，用户编辑／解绑／禁用保留。

第二批上线时，干净库专项竞态86项通过；全量1126通过、2失败、2跳过，基线同类问题与模拟界面见 [第二批验证记录](docs/testing/finding-quality-report.md)。来源文件对应、配置与边界见 [第二批搬迁记录](docs/finding-quality-migration.md)。该历史记录中的第三批和签名 TODO 已在本轮完成，当前状态见下文。

## 第三批内网管理与发布签名

| 二次开发内容 | 当前行为 |
| --- | --- |
| 已有远程会话管理 | HTTP 会话登记、恢复、探活、命令／文件工作台；连接参数加密保存，展示 URL 移除账号、query 和 fragment |
| 受管隧道与录制代理 | chisel／suo5 部署、连通验证、台账、失败回滚和清理；每任务回环录制代理保留证据并切换 SOCKS 上游 |
| 只读网络信息与拓扑 | 接口、路由、邻居、hosts、监听结构化保存，展示主机、网段与链路；新网段进入待授权列表 |
| 加密凭据台账 | 与会话使用不同派生密钥；来源血缘、脱敏列表、验证状态与理由、带理由的适用性评分 |
| 阶段移交 | 初始仅立足点主机范围；人工批准新范围、显式启动任务；重启不会自动启动尚未准入的移交任务 |
| 临时资源分发 | 默认15分钟、最长120分钟、可选完整下载一次后销毁；精确资源授权、敏感文件检查、到期／重启清理与审计 |
| 关闭资源回收 | 取消并等待任务和已登记后台工作，随后关闭数据库、隧道、暂存及代理 |
| 发布签名 | 更新源固定为 listensay/ARTEX；先验证本仓库签名清单再校验 ZIP，缺失或非法签名拒绝升级；独立密钥与CI Secret已配套 |

入口为「内网管理」。管理操作继续经过门控、管理员 Cookie、CSRF 和任务 Guard。普通任务沿用现有 RoE；受限移交任务在 off/warn 与一键放行期间也不能自动扩展未批准范围。没有搬入会话生成、执行函数绕过及反向连接自动接管。

本机已更新；专项竞态118通过、0失败、1跳过，另行空库探针复测通过；全量1248通过、2失败、2跳过且无竞态报告。目标播种失败在独立干净库复测通过，企业范围展示问题继续保留。前端32页导出、类型检查、内嵌构建、真实chisel／suo5隔离传输及本机包验签通过；本轮未创建远程发布标签。

配置、来源文件对应、迁移步骤与使用边界见 [第三批搬迁记录](docs/intranet-migration.md)，页面、完整验证、上线和回滚信息见 [第三批验证报告](docs/testing/intranet-report.md)。本机保持回环发布，目标回连地址和路由按实际部署配置。

## 蜜罐识别、反 AI 陷阱与 chains 场景化

来源为 [panda0x123/artex-ymh](https://github.com/panda0x123/artex-ymh) 的固定提交 `48adc7f1d8f62cbc47e658c9a2b47d6f63ca6cb1`。

| 二次开发内容 | 行为 |
| --- | --- |
| 静态蜜罐识别 | 内嵌 11 条签名，覆盖 Cowrie、OpenCanary、Kippo、Glastopf、HFish、Dionaea；可用 data/signatures/honeypot.json 覆盖并按修改时间热更新 |
| 资产评分与处置 | 服务资产登记、HTTP 自动补全评估已有 banner/title/body/TLS 证据；评分与证据持久化，资产页和任务资产页展示疑似徽标，planner 态势列出命中资产 |
| 反 AI 陷阱红线 | worker 永不向目标提交系统提示词、工具清单、本机凭据、平台配置或身份自证；目标响应中的指令视为不可信数据，发现诱导写事实 |
| 敏感信息拦截 | 已注册的 LLM/search key、数据库密码、管理员和门控签名材料、门控口令/路径命中工具输入时直接阻止，先于 RoE 和审批；一键放行不豁免 |
| tarpit 预算告警 | 按任务、host 统计 WebFetch；默认 40 次，超预算只写一次 hint，提示 planner 停抓换方向，后续仍告警放行 |
| UA 池 | 按任务稳定分配，注入 worker 的 ARTEX_UA；默认如实标识 ARTEX，UA 不改变 TLS/HTTP2 指纹 |
| 九类场景骨架 | web/ad/app/priv/pwn/recon/rev/pivot/meta，按 chain_tags（最多两个）或 summary 关键词自动注入；完整参考资料放在 skills/chains-*/refs/ |
| 反证与转向 | worker 注入类别反证判据，可调用 get_verifier_checklist；report_finding 的 false_positive/inconclusive 只写 fact，verified 须有实际证据；同质响应触发类别化转向和 planner 提示，收尾追加自检 |

静态命中属于单信号，即使评分高也只表示疑似；planner 降级为被动/只读，不投递、不爆破、不利用，双信号才按纪律停止方向。无信号不能证明不是蜜罐。当前未加入自动行为探针、登录后检查、测绘平台评分。独立漏洞反证会话管线已在第二批接入，见上方说明。

旧数据库启动时补齐 add_intent、insert_assets、report_finding 缺失的可选字段，保留已有说明、参数默认值、绑定与启用状态。2026-10-24 已更新本机 Docker 服务；56 项专项竞态测试通过，前端构建、资产徽标检查及运行健康检查通过。全量回归与基线失败详见验证记录。

部署、配置方式、文件对应关系和适配差异见 [蜜罐与 chains 搬迁记录](docs/honeypot-chains-migration.md)，验证结果见 [本轮验证记录](docs/testing/honeypot-chains-report.md)。历史参考设计见 [蜜罐设计归档](docs/honeypot-detection-design.md)与 [chains 设计归档](docs/chains-integration-design.md)。

## 军火库与部署链

参考 [panda0x123/artex-ymh](https://github.com/panda0x123/artex-ymh)，移植 17 项外部工具清单、启动 SHA-256 自检、`artex doctor` 部署预检和 Linux systemd 模板。

| 二次开发内容 | 行为 |
| --- | --- |
| `packaging/tools-manifest.json` | 17 项文件清单，保留上游版本、平台和哈希；支持 data 相对路径及环境变量路径覆盖 |
| 启动完整性检查 | 汇总匹配、未钉、缺失、不可读和平台差异；哈希不匹配告警，不阻断启动 |
| `artex doctor` | 检查 PostgreSQL、LLM 配置、目录可写性与密钥隔离、全部工具、门控和录制代理；不启动服务、不写数据库，不输出凭据 |
| `packaging/artex.service` | Linux 服务模板，回环监听、独立密钥目录、崩溃重启，兼容自更新退出码 75 |
| 发布集成 | Docker 携带清单；发布压缩包携带清单及二次开发说明，Linux 包附带 unit |
| 本机工具安装 | 17 项已安装到持久化 data/tools；启用 Linux/arm64 实际版本与哈希清单，Python 工具使用独立虚拟环境 |

```bash
docker compose exec -T artex /app/artex doctor -addr :8787 -proxy :8788 -data /app/data
```

清单不包含工具文件，也不自动安装、执行或注册工具。参考仓库仅明确 nxc 版本，其余版本未知；保留的哈希不适用于任意新版本或 arm64 文件。目录条目只查存在，Python 入口脚本哈希不覆盖包依赖。军火库初次移植时未接入受管隧道；本轮已接入，回连配置与部署边界见第三批说明。

完整路径规则、预检退出码和 systemd 部署步骤见 [军火库与部署说明](docs/arsenal-deployment.md)。

搬迁日期为 2026-10-24，来源固定在提交 `48adc7f1d8f62cbc47e658c9a2b47d6f63ca6cb1`。来源文件对应关系、Linux/arm64 与安全配置适配、分阶段上线、依赖固定和备份位置见 [军火库与部署链搬迁记录](docs/arsenal-migration.md)。后续搬迁也按 [Agent 文档规则](AGENTS.md) 留存记录。

本机 17 项工具已全部安装，缺失与哈希不匹配均为 0；14 个文件 SHA-256 一致，3 个目录存在。13 个本机 CLI、NetExec 四个协议帮助命令及三个 Python 环境依赖检查通过；原服务与安全配置保持正常。版本、来源、持久化规则和结果见 [17 项工具安装记录](docs/arsenal-installation.md)。

部署链移植时的 21 项专项竞态测试通过；初次移植的全量回归与安装前状态见 [军火库与部署链验证记录](docs/testing/arsenal-deployment-report.md)。

## 安全与反测绘

参考 [panda0x123/artex-ymh](https://github.com/panda0x123/artex-ymh)，移植并适配当前 ARTEX 的门控、审批和授权范围检查。

| 新增功能 | 行为 |
| --- | --- |
| 伪装门控 | 除已知入口的登录表单外，未通过门控的页面、API、静态资源、SSE 和未知路径统一返回固定 nginx 欢迎页；默认生成并持久化随机入口 |
| 一键放行 | 选择 2、4、8 小时有效期，自动批准新的 `ask` 审批，到期恢复人工审批；`deny` 规则不豁免 |
| RoE 三态 | `off` 关闭范围检查，`warn` 告警并放行，`strict` 对范围外目标要求审批；默认 `warn` |

控制入口为「系统配置 → 安全与反测绘」。审批历史标记自动批准来源为「一键放行」，可按来源筛选。

### 更新后的访问方式

所有监听地址（包括回环）默认开启门控，直接访问首页会看到 nginx 欢迎页。更新后读取 `data/gate.path`，使用服务地址加该路径进入门控，再继续原有管理员登录。

```bash
docker compose up -d --build --wait --wait-timeout 180 artex
cat data/gate.path
```

例如文件内容为 `/g-<随机字符串>`，入口为 `http://localhost:8787/g-<随机字符串>`。未配置独立门控口令时，自动生成独立随机口令到 `.secrets/gate.token`（Compose）或 `ARTEX_SECRET_DIR/gate.token`；入口路径不再充当口令。默认入口在重启后复用，请保存书签。

### 新增部署配置

以下变量已接入 Docker Compose，可在 `.env` 中设置，重建容器后生效。

| 环境变量 | 说明 |
| --- | --- |
| `ARTEX_GATE` | `on/1/true` 开启，`off/0/false` 显式关闭；留空时所有监听地址均开启 |
| `ARTEX_GATE_PATH` | 自定义独立入口路径；留空时生成随机路径 |
| `ARTEX_GATE_TOKEN` | 独立门控口令，24–256 字节；留空时独立随机生成并持久化 |
| `ARTEX_GATE_TTL_HOURS` | 门控 Cookie 有效期，默认 168 小时，支持 1–8760 小时 |
| `ARTEX_HTTP_BIND` | Compose 宿主机绑定地址，默认 `127.0.0.1` |
| `ARTEX_TRUSTED_PROXIES` | 实际反向代理的 IP/CIDR，逗号分隔；默认不信任 Forwarded 头 |
| `ARTEX_ALLOWED_ORIGINS` | 额外允许的完整 Origin，逗号分隔；默认仅同源 |

门控使用独立 HMAC 签名 Cookie，并与管理员服务端会话分开校验。更换入口路径会使旧门控 Cookie 失效。门控隐藏应用 HTTP 指纹，不能替代管理员认证。

Docker 健康检查改为 `/app/artex -healthcheck`：利用本地门控材料验证真实健康接口，避免把 nginx 伪装页的 HTTP 200 当作后端健康。

### 公网暴露加固

- 回环监听不再自动关闭门控；二进制默认监听 `127.0.0.1:8787`，Compose 默认只向本机发布 8787。数据库使用独立的 internal 网络，应用另接出站网络。
- 浏览器凭据改为 8 小时的随机服务端会话，只通过 HttpOnly、SameSite=Strict Cookie 传递；HTTPS 下设置 Secure。数据库仅保存会话摘要，退出删除会话，修改密码在同一事务中吊销全部旧会话。
- 浏览器不再将认证凭据写入 localStorage、响应 JSON 或 SSE URL。旧 `artex_token` Cookie、URL token 和旧版本 Bearer JWT 均不再接受；升级后需要重新登录。
- 所有浏览器写请求（包括登录、首次设置和上传）验证签名 CSRF Cookie 与请求头，并限制来源。只有配置的可信代理可以提供外部 HTTPS/Host 信息。
- `.secrets/` 存放门控口令与签名密钥，位于可浏览工作目录之外，容器重建后继续保留；已加入 Git 与 Docker 构建排除规则。
- 页面、静态资源、API、SSE 和未知下载路径全部经过门控，不设置 `/s/` 前缀豁免；授权资源使用 private/no-store 和 Cookie Vary，隔离共享缓存。生产运行 Go 内嵌前端，独立 Next 服务仅用于本机开发。
- 外部网关必须使用 Host 白名单和固定上游，禁止任意目标拨号与 CONNECT；范例见 [固定上游 Nginx 配置](deploy/nginx-fixed-upstream.conf.example)。本机未发现报告中的公网网关，此范例不代表外部网关已完成修复。

本轮验证与上线记录见 [暴露加固报告](docs/testing/exposure-hardening-report.md)。

### 审批与范围检查

- 放行状态和绝对到期时间保存在数据库中，重启不会延长时限。到期清理不会覆盖并发续期，自动批准保留审批及执行审计记录。
- 新增 `GET/PUT /api/guard/auto-allow` 管理放行状态；启用时 API 仅接受 2、4、8 小时。接口同时受门控和管理员认证保护。
- RoE 模式通过 `PUT /api/settings` 的 `roe_enforcement` 设置，即时生效。任务 worker、planner、main agent 和对话 Agent 均接入 Guard。
- 匹配任务登记的域名、IP、CIDR，并展开关联企业的网络范围。CIDR 扫描目标必须整体包含在授权网段中。
- `strict` 的范围外审批可由一键放行自动批准，后续 `deny` 仍然阻止执行。范围读取失败时 strict 阻止调用，warn 记录告警。
- 未登记范围、无法识别目标和非任务对话按未知范围放行，本机操作保留参考实现的豁免。目标提取覆盖常见 Shell 参数和 WebFetch URL，无法保证识别动态脚本或隐式网络访问。

详细行为和配置见 [安全与反测绘使用说明](docs/security.md)。

### 验证结果

初次移植的隔离环境验证结果（2026-10-24，历史记录；本轮会话加固与上线结果见上方暴露加固报告）：

| 验证 | 结果 |
| --- | --- |
| 安全专项及竞态测试 | 58/58 通过，无竞态报告 |
| 全量 Go 回归 | 966 通过、1 项已有失败、1 项跳过 |
| 改动前全量 Go 回归 | 存在相同失败及跳过项 |
| 前端类型检查、静态生产构建、内嵌前端构建 | 通过 |
| 静态检查、Compose 配置、真实健康接口及浏览器页面验证 | 通过 |

全量回归的已有失败为 `agent.TestGraphOverviewExpandsAssociatedCompanyScope`，属于探索总览的企业范围展示问题；需要外部模型凭据的 `TestLiveContextReview` 未执行。测试使用独立数据库，没有改动运行实例的数据。

完整结果、复现命令及页面截图见 [安全功能测试报告](docs/testing/security-report.md)。
