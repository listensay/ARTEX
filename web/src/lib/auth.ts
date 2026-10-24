import { MOCK } from "@/lib/mock/enabled";
import { clearLegacyCredentials, sessionFetch } from "@/lib/session-http";

export interface CurrentUser {
  id: string;
  name: string;
  username: string;
  email: string;
  avatar: string;
  role: string;
}

export const auth = {
  async checkSession(): Promise<boolean> {
    clearLegacyCredentials();
    if (MOCK) return true;
    const response = await sessionFetch("/api/auth/status", { cache: "no-store" });
    if (!response.ok) throw new Error("无法验证登录状态");
    const status = (await response.json()) as { authenticated: boolean };
    return status.authenticated;
  },
  async logout(): Promise<void> {
    clearLegacyCredentials();
    if (MOCK) return;
    const response = await sessionFetch("/api/auth/logout", { method: "POST" });
    if (!response.ok && response.status !== 401) throw new Error("退出失败，请重试");
  },
  getCurrentUser(): CurrentUser {
    return { id: "1", name: "ARTEX", username: "ARTEX", email: "", avatar: "", role: "operator" };
  },
};
