import { fileURLToPath } from "node:url";

// 静态导出供 Go 内嵌服务使用；所有页面与资源均经过 Go 门控。
// 开发服务只绑定回环，不能作为公网生产入口。
const isExport = process.env.NEXT_EXPORT === "1";
// Vercel demo：整站走 mock，无后端，无需 /api 反代。
const isMock = process.env.NEXT_PUBLIC_MOCK === "1";

/** @type {import('next').NextConfig} */
const nextConfig = {
  // 避免父目录的 lockfile 影响根目录推断及资源路径生成。
  turbopack: { root: fileURLToPath(new URL(".", import.meta.url)) },
  reactCompiler: true,
  // HMR 仅允许本机来源。
  allowedDevOrigins: ["127.0.0.1", "localhost"],
  compiler: {
    removeConsole: process.env.NODE_ENV === "production",
  },
  ...(isExport
    ? {
        // 纯静态导出：无 Node 运行时；图片不经优化；每个路由产出 <route>/index.html。
        output: "export",
        images: { unoptimized: true },
        trailingSlash: true,
      }
    : isMock
      ? {
          // Vercel mock demo：无后端，不需要 /api 反代。
          images: { unoptimized: true },
        }
      : {
          // 开发：把 /api/* 反代到 Go 后端（默认 :8787，可用 AUTOPENTEST_API 覆盖）。
          async rewrites() {
            const backend = process.env.AUTOPENTEST_API ?? "http://localhost:8787";
            return [{ source: "/api/:path*", destination: `${backend}/api/:path*` }];
          },
        }),
};

export default nextConfig;
