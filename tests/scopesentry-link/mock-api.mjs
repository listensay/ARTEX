import { createServer } from "node:http";

createServer((request, response) => {
  response.writeHead(200, { "Content-Type": "application/json" });
  response.end(JSON.stringify(request.url === "/api/auth/status" ? { initialized: true, authenticated: true } : {}));
}).listen(Number(process.env.ARTEX_SS_UI_API_PORT ?? 3036), "127.0.0.1");
