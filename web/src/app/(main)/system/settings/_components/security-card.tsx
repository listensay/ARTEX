"use client";

import * as React from "react";

import { CopyIcon, ShieldCheckIcon } from "lucide-react";
import { toast } from "sonner";

import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Label } from "@/components/ui/label";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Switch } from "@/components/ui/switch";
import { api } from "@/lib/api";
import type { Settings } from "@/lib/types";

type AutoAllow = Awaited<ReturnType<typeof api.guardAutoAllow>>;
type Mode = NonNullable<Settings["roe_enforcement"]>;

export function SecurityCard() {
  const [settings, setSettings] = React.useState<Settings | null>(null);
  const [autoAllow, setAutoAllow] = React.useState<AutoAllow | null>(null);
  const [hours, setHours] = React.useState("2");
  const [busy, setBusy] = React.useState(false);
  const [error, setError] = React.useState("");
  const [now, setNow] = React.useState(() => Date.now());

  const refresh = React.useCallback(async () => {
    try {
      const [s, state] = await Promise.all([api.settings(), api.guardAutoAllow()]);
      setSettings(s);
      setAutoAllow(state);
      setError("");
    } catch (e) {
      setError((e as Error).message || "加载安全配置失败");
    }
  }, []);

  React.useEffect(() => {
    void refresh();
    const timer = window.setInterval(() => setNow(Date.now()), 1000);
    return () => window.clearInterval(timer);
  }, [refresh]);

  React.useEffect(() => {
    if (busy) return;
    const timer = window.setInterval(() => void refresh(), 10000);
    return () => window.clearInterval(timer);
  }, [busy, refresh]);

  const remaining = autoAllow ? Math.max(0, autoAllow.expires_at - Math.floor(now / 1000)) : 0;
  const enabled = Boolean(autoAllow?.enabled && remaining > 0);
  const disabled = busy || !settings || !autoAllow || Boolean(error);
  let gateStatus = "加载中";
  if (settings) gateStatus = settings.gate_enabled ? "已开启" : "已关闭";
  let allowStatus = "加载中";
  if (autoAllow) {
    allowStatus = "未开启 · 需按审批规则确认调用";
    if (enabled)
      allowStatus = `剩余 ${Math.floor(remaining / 3600)} 小时 ${Math.floor((remaining % 3600) / 60)} 分 ${remaining % 60} 秒 · 到期 ${new Date(autoAllow.expires_at * 1000).toLocaleString("zh-CN")}`;
  }

  async function setMode(value: string | null) {
    if (!value) return;
    setBusy(true);
    try {
      setSettings(await api.setSettings({ roe_enforcement: value as Mode }));
      toast.success("已保存 RoE 范围检查模式，即时生效");
    } catch (e) {
      toast.error(`保存失败：${(e as Error).message}`);
    } finally {
      setBusy(false);
    }
  }

  async function setAuto(enabled: boolean) {
    setBusy(true);
    try {
      setAutoAllow(await api.setGuardAutoAllow(enabled, Number(hours)));
      setNow(Date.now());
      toast.success(enabled ? `已开启 ${hours} 小时审批放行` : "已恢复人工审批");
    } catch (e) {
      toast.error(`保存失败：${(e as Error).message}`);
    } finally {
      setBusy(false);
    }
  }

  async function copyEntrance() {
    try {
      await navigator.clipboard.writeText(new URL(settings?.gate_path || "/", window.location.origin).href);
      toast.success("已复制门控入口");
    } catch {
      toast.error("复制失败，请手动复制入口路径");
    }
  }

  return (
    <Card className="mb-4 break-inside-avoid md:mb-6">
      <CardHeader>
        <CardTitle className="flex items-center gap-2 text-base">
          <ShieldCheckIcon className="size-4" />
          安全与反测绘
        </CardTitle>
        <CardDescription>管理伪装门控、限时审批放行与任务授权范围检查。</CardDescription>
      </CardHeader>
      <CardContent className="space-y-6">
        {error ? (
          <div role="alert" className="space-y-2 text-destructive text-sm">
            <p>{error}</p>
            <Button variant="outline" size="sm" onClick={() => void refresh()}>
              重新加载
            </Button>
          </div>
        ) : null}
        <section className="space-y-2">
          <h3 className="font-medium text-sm">伪装门控 · {gateStatus}</h3>
          <p className="text-muted-foreground text-sm">
            未通过门控时，页面、API 和事件流均返回固定 nginx 欢迎页。进入门控后仍需管理员登录。
          </p>
          {settings?.gate_enabled && settings.gate_path ? (
            <div className="flex items-center gap-2">
              <code className="min-w-0 flex-1 break-all rounded bg-muted px-2 py-1 text-xs">{settings.gate_path}</code>
              <Button size="icon" variant="outline" aria-label="复制门控入口" onClick={() => void copyEntrance()}>
                <CopyIcon className="size-4" />
              </Button>
            </div>
          ) : null}
          <p className="text-muted-foreground text-xs">门控配置通过部署环境变量修改，重启生效。请保存入口地址。</p>
        </section>
        <section className="space-y-3 border-t pt-4">
          <div className="flex items-center justify-between gap-3">
            <Label htmlFor="security-auto-allow">一键放行</Label>
            <Switch
              id="security-auto-allow"
              checked={enabled}
              disabled={disabled}
              onCheckedChange={(v) => void setAuto(v)}
            />
          </div>
          <p className="text-muted-foreground text-sm">
            在指定时限内自动批准 ask 审批，到期恢复人工审批。deny 拒绝规则始终生效，自动批准会记录到审批历史。
          </p>
          <div className="flex items-center gap-2">
            <Label htmlFor="security-allow-hours" className="shrink-0">
              放行时限
            </Label>
            <Select value={hours} disabled={disabled} onValueChange={(v) => v && setHours(v)}>
              <SelectTrigger id="security-allow-hours" className="w-28">
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                {["2", "4", "8"].map((h) => (
                  <SelectItem key={h} value={h}>
                    {h} 小时
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
            {enabled ? (
              <Button size="sm" variant="outline" disabled={disabled} onClick={() => void setAuto(true)}>
                续期
              </Button>
            ) : null}
          </div>
          <p className="text-muted-foreground text-xs" aria-live="off">
            {allowStatus}
          </p>
        </section>
        <section className="space-y-3 border-t pt-4">
          <Label htmlFor="security-roe-mode">RoE 授权范围检查</Label>
          <Select
            value={settings?.roe_enforcement || "warn"}
            disabled={disabled}
            onValueChange={(v) => void setMode(v)}
          >
            <SelectTrigger id="security-roe-mode">
              <SelectValue />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value="off">off · 关闭</SelectItem>
              <SelectItem value="warn">warn · 告警并放行</SelectItem>
              <SelectItem value="strict">strict · 范围外需审批</SelectItem>
            </SelectContent>
          </Select>
          <p className="text-muted-foreground text-sm">
            检查任务已登记的域名、IP 和网段。strict
            模式的范围外调用需审批，一键放行生效时可自动批准。未登记范围、无法识别目标和非任务对话按未知范围放行；本机操作允许执行。
          </p>
        </section>
      </CardContent>
    </Card>
  );
}
