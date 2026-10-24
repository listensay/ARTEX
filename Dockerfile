# syntax=docker/dockerfile:1
#
# Docker Compose 使用 source 阶段，在 Docker 内构建前端和 Go，无需宿主机安装工具链。
# CI 默认使用最后的 prebuilt 阶段，继续复用 dist/<TARGETARCH>/artex。
#
# 本地手动构建：docker build --target source -t artex:local .
FROM --platform=$BUILDPLATFORM node:22-bookworm-slim AS frontend
WORKDIR /src/web
ENV NEXT_TELEMETRY_DISABLED=1 HUSKY=0
COPY web/package.json web/package-lock.json ./
RUN --mount=type=cache,target=/root/.npm npm ci
COPY web/ ./
RUN npm run build:static

FROM --platform=$BUILDPLATFORM golang:1.26-bookworm AS backend
WORKDIR /src
COPY go.mod go.sum ./
RUN --mount=type=cache,target=/go/pkg/mod go mod download
COPY . .
COPY --from=frontend /src/web/out ./server/webui/dist
ARG TARGETOS
ARG TARGETARCH
RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} \
    go build -tags embedui -trimpath -ldflags="-s -w" -o /out/artex ./cmd/artex

FROM python:3.12-slim-bookworm AS runtime
# 常用工具：ripgrep / curl / vim，加一批 recon 常备件（按需增删）。
# Node 从 NodeSource 装 20.x：bookworm 自带的 apt nodejs 是 18，Playwright 要求 >=20。
RUN apt-get update && apt-get install -y --no-install-recommends \
      ca-certificates ripgrep curl wget vim git jq unzip \
      dnsutils iputils-ping netcat-openbsd inetutils-telnet whois nmap \
    && curl -fsSL https://deb.nodesource.com/setup_20.x | bash - \
    && apt-get install -y --no-install-recommends nodejs \
    && rm -rf /var/lib/apt/lists/*
# 预装 Playwright MCP 与 CLI（全局），运行时不再 npx 联网下载。
# @playwright/mcp：browser MCP 直接调用预装 playwright-mcp，避免运行时 npx 查询包。
# @playwright/cli：提供 playwright-cli，装完顺带 --help 验证可执行。
# 再装 playwright（提供浏览器管理），装完用 --with-deps 预置 chromium 及其系统依赖，
# 这样容器内 MCP/CLI 首次启动即可用，不再联网下载浏览器。
RUN npm install -g @playwright/mcp@latest @playwright/cli@latest playwright@latest \
    && playwright-cli --help \
    && playwright install --with-deps chromium \
    && rm -rf /var/lib/apt/lists/*
# API recon 的依赖放在镜像中，避免 node_modules 污染可浏览的 skill 文件树。
COPY packaging/skill-runtime/package*.json /opt/artex-skill-runtime/
RUN cd /opt/artex-skill-runtime && npm ci --omit=dev --ignore-scripts \
    && ln -sf "$(node -e 'console.log(require("/usr/lib/node_modules/playwright").chromium.executablePath())')" /usr/local/bin/artex-chromium
WORKDIR /app
ENV PATH="/app/data/tools:${PATH}"
ENV NODE_PATH="/opt/artex-skill-runtime/node_modules:/usr/lib/node_modules" \
    CHROMIUM="/usr/local/bin/artex-chromium"
# 守护启动脚本：进程退出后按退出码决定是否重新拉起，页面一键更新靠它完成换装。
# 它同时负责把 SIGTERM 转发给 artex —— docker stop 只把信号发给 PID 1，
# 不转发的话 artex 收不到、做不了优雅关闭，10 秒后被 SIGKILL 硬杀。
COPY start.sh /app/start.sh
RUN chmod +x /app/start.sh
COPY skills/ /app/skills/
COPY packaging/tools-manifest*.json /app/packaging/
COPY packaging/playwright-cli.config.json /app/packaging/playwright-cli.config.json
COPY packaging/agent-tooling.profile.json /app/packaging/agent-tooling.profile.json
# data/（SQLite + jwt.key）持久化点
VOLUME ["/app/data"]
EXPOSE 8787 8788
ENTRYPOINT ["/app/start.sh"]
CMD ["-addr", ":8787", "-proxy", ":8788"]

FROM runtime AS source
COPY --from=backend --chmod=755 /out/artex /app/artex

FROM runtime AS prebuilt
ARG TARGETARCH
COPY --chmod=755 dist/${TARGETARCH}/artex /app/artex
