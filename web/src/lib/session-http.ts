import { deleteClientCookie } from "@/lib/cookie.client";

// The session credential stays in an HttpOnly cookie. Only the signed CSRF
// value is readable by JavaScript and sent back on state-changing requests.
export function clearLegacyCredentials(): void {
  if (typeof window === "undefined") return;
  try {
    localStorage.removeItem("artex_token");
  } catch {
    /* Cookie sessions work when storage is unavailable. */
  }
  deleteClientCookie("artex_token");
}

function csrfToken(): string | undefined {
  if (typeof document === "undefined") return undefined;
  const cookie = document.cookie.split("; ").find((value) => value.startsWith("artex_csrf="));
  return cookie ? decodeURIComponent(cookie.slice("artex_csrf=".length)) : undefined;
}

let csrfReady: Promise<void> | null = null;

export async function sessionFetch(input: string, init: RequestInit = {}): Promise<Response> {
  clearLegacyCredentials();
  const method = (init.method ?? "GET").toUpperCase();
  const headers = new Headers(init.headers);
  if (!["GET", "HEAD", "OPTIONS"].includes(method)) {
    if (!csrfToken()) {
      csrfReady ??= fetch("/api/auth/status", { credentials: "same-origin", cache: "no-store" })
        .then((response) => {
          if (!response.ok) throw new Error("无法初始化安全会话");
        })
        .finally(() => {
          csrfReady = null;
        });
      await csrfReady;
    }
    const csrf = csrfToken();
    if (!csrf) throw new Error("缺少 CSRF 凭据，请重新加载页面");
    headers.set("X-Artex-CSRF", csrf);
  }
  return fetch(input, { ...init, headers, credentials: "same-origin" });
}
