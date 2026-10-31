import { createServer } from "node:http";

// Isolated auth stub for the Next.js development proxy; no real service/data is used.
createServer((request, response) => {
  response.writeHead(200, { "Content-Type": "application/json" });
  response.end(JSON.stringify(request.url === "/api/auth/status" ? { authenticated: true } : {}));
}).listen(Number(process.env.ARTEX_MODEL_TEST_API_PORT ?? 3016), "127.0.0.1");
