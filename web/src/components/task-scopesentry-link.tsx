"use client";

import * as React from "react";
import Link from "next/link";
import { NetworkIcon, RefreshCwIcon } from "lucide-react";

import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import {
  AlertDialog,
  AlertDialogAction,
  AlertDialogCancel,
  AlertDialogContent,
  AlertDialogDescription,
  AlertDialogFooter,
  AlertDialogHeader,
  AlertDialogTitle,
  AlertDialogTrigger,
} from "@/components/ui/alert-dialog";
import { Label } from "@/components/ui/label";
import { NativeSelect, NativeSelectOption } from "@/components/ui/native-select";
import { Switch } from "@/components/ui/switch";
import { api } from "@/lib/api";
import type { ScopeSentryLink } from "@/lib/types";

const STATE_LABELS: Record<string, string> = {
  pending: "尚未检查",
  skipped: "已跳过",
  ready: "待补充测绘",
  scanning: "远端扫描中",
  imported: "已回流",
  failed: "联动失败",
  blocked: "未获准执行",
};

export function TaskScopeSentryLink({ taskId, running }: { taskId: string; running: boolean }) {
  const [link, setLink] = React.useState<ScopeSentryLink>();
  const [templates, setTemplates] = React.useState<Awaited<ReturnType<typeof api.ssTemplates>>["templates"]>([]);
  const [error, setError] = React.useState("");
  const [templateError, setTemplateError] = React.useState("");
  const [busy, setBusy] = React.useState(false);

  React.useEffect(() => {
    let current = true;
    const load = async () => {
      try {
        const value = await api.taskScopeSentry(taskId);
        if (current) {
          setLink(value);
          setError("");
        }
      } catch (e) {
        if (current) setError(e instanceof Error ? e.message : "无法读取联动状态");
      }
    };
    void load();
    void api
      .ssTemplates()
      .then((value) => {
        if (current) setTemplates(value.templates);
      })
      .catch((e) => {
        if (current) setTemplateError(e instanceof Error ? e.message : "模板暂时不可读");
      });
    const timer = setInterval(load, 5000);
    return () => {
      current = false;
      clearInterval(timer);
    };
  }, [taskId]);

  async function action(body: Parameters<typeof api.taskScopeSentryAction>[1]) {
    if (busy) return;
    setBusy(true);
    setError("");
    try {
      setLink(await api.taskScopeSentryAction(taskId, body));
    } catch (e) {
      setError(e instanceof Error ? e.message : "操作失败，请重试");
    } finally {
      setBusy(false);
    }
  }

  const defaultReady = templates.filter((item) => item.default && item.usable).length === 1;
  const templateReady = link?.template_id
    ? templates.some((item) => item.id === link.template_id && item.usable)
    : defaultReady;
  const scanDisabled = busy || !running || !link?.enabled || !templateReady || link?.state === "scanning";
  const explicitOnly = templates.find((item) => item.id === link?.template_id)?.automatic === false;

  return (
    <Card aria-labelledby="scopesentry-link-title">
      <CardHeader>
        <div className="flex flex-wrap items-center justify-between gap-3">
          <CardTitle id="scopesentry-link-title" className="flex items-center gap-2 text-base">
            <NetworkIcon className="size-4 text-primary" /> ScopeSentry 联动
          </CardTitle>
          <Badge variant="secondary">
            {link
              ? link.scan_state === "paused"
                ? "远端已暂停"
                : (STATE_LABELS[link.state] ?? link.state)
              : "正在读取"}
          </Badge>
        </div>
        <CardDescription>先复用存量资产，再按授权补充测绘。平台负责范围校验、扫描跟踪与结果回流。</CardDescription>
      </CardHeader>
      <CardContent className="grid min-w-0 gap-4">
        <div aria-live="polite" className="grid gap-1 text-sm">
          <p className="break-words">{link?.summary ?? "正在读取任务联动状态…"}</p>
          {link && (
            <p className="text-muted-foreground text-xs">
              已回流 {link.imported} 个资产 ·{" "}
              {link.checked_at ? `最近检查 ${new Date(link.checked_at * 1000).toLocaleString()}` : "尚无检查记录"}
            </p>
          )}
          {link?.targets?.length ? <p className="break-all font-mono text-xs">{link.targets.join(" · ")}</p> : null}
          {link?.missing_targets?.length ? (
            <p className="break-all text-xs">尚无存量数据的目标：{link.missing_targets.join("、")}</p>
          ) : null}
          {link?.scan_name ? (
            <p className="break-all text-xs">
              远端扫描：{link.scan_name}（{link.scan_state || "已提交"}）
            </p>
          ) : null}
          {error && (
            <p role="alert" className="text-destructive">
              {error}。可刷新重试；不会因此重复提交扫描。
            </p>
          )}
        </div>
        <div className="flex items-center justify-between gap-4">
          <Label htmlFor="scopesentry-link-enabled">自动检索与回流存量资产</Label>
          <Switch
            id="scopesentry-link-enabled"
            checked={link?.enabled ?? false}
            disabled={!link || busy}
            onCheckedChange={(enabled) => void action({ action: "config", enabled, template_id: link?.template_id })}
          />
        </div>
        <div className="grid gap-2 sm:grid-cols-[minmax(0,1fr)_auto] sm:items-end">
          <div className="grid min-w-0 gap-1.5">
            <Label htmlFor="scopesentry-link-template">扫描模板</Label>
            <NativeSelect
              id="scopesentry-link-template"
              className="w-full"
              value={link?.template_id ?? ""}
              disabled={!link || busy}
              onChange={(e) => {
                const selected = templates.find((item) => item.id === e.target.value);
                void action({
                  action: "config",
                  template_id: e.target.value,
                  ...(selected?.automatic === false ? { auto_scan: false } : {}),
                });
              }}
            >
              <NativeSelectOption value="">
                {defaultReady ? "安全默认 · HTTP 服务测绘" : "请先配置或选择有效模板"}
              </NativeSelectOption>
              {templates.map((item) => (
                <NativeSelectOption key={item.id} value={item.id} disabled={!item.usable}>
                  {item.name}
                  {!item.usable ? " · 暂不可用" : item.automatic === false ? " · 显式发起" : ""}
                </NativeSelectOption>
              ))}
            </NativeSelect>
          </div>
          <Button variant="outline" disabled={busy || !link} onClick={() => void action({ action: "refresh" })}>
            <RefreshCwIcon className={busy ? "animate-spin" : ""} /> {busy ? "处理中…" : "检索并回流"}
          </Button>
        </div>
        <p className="text-muted-foreground text-xs">
          留空只使用已核验的安全默认 HTTP
          模板，不自动开启扫描授权。其他已核验模板可显式发起，按实际操作与授权范围检查。后台联动不阻止本地侦察或验证。
        </p>
        <div className="grid gap-1.5">
          <Label htmlFor="scopesentry-link-coverage">存量数据覆盖要求</Label>
          <NativeSelect
            id="scopesentry-link-coverage"
            value={link?.coverage_mode ?? ""}
            disabled={!link || busy}
            onChange={(e) =>
              void action({
                action: "config",
                coverage_mode: e.target.value as NonNullable<ScopeSentryLink["coverage_mode"]>,
              })
            }
          >
            <NativeSelectOption value="">按所选模板判断</NativeSelectOption>
            <NativeSelectOption value="http">HTTP 服务</NativeSelectOption>
            <NativeSelectOption value="services">端口与服务清单</NativeSelectOption>
            <NativeSelectOption value="subdomains">子域名测绘</NativeSelectOption>
            <NativeSelectOption value="urls">URL／目录采集</NativeSelectOption>
          </NativeSelect>
          <p className="text-xs text-muted-foreground">
            默认只复用 24 小时内的数据；时间未知或仅有一条服务记录不代表清单完整。
          </p>
        </div>
        {templateError && (
          <p role="alert" className="text-destructive text-xs">
            模板读取失败：{templateError}。请检查数据源后重新打开此页。
          </p>
        )}
        {!templateError && templates.length > 0 && !templates.some((item) => item.usable) && (
          <p className="text-muted-foreground text-xs">
            现有模板为空或包含扩域／漏洞流水线，请先在 ScopeSentry 配置固定目标的端口／服务测绘模板。空 default
            模板不能执行扫描。
          </p>
        )}
        <div className="flex flex-wrap items-center justify-between gap-3 border-t pt-3">
          <label className="flex items-center gap-2 text-sm" htmlFor="scopesentry-link-auto-scan">
            <Switch
              id="scopesentry-link-auto-scan"
              checked={link?.auto_scan ?? false}
              disabled={busy || !link || !templateReady || explicitOnly}
              onCheckedChange={(enabled) =>
                void action({ action: "config", auto_scan: enabled, template_id: link?.template_id })
              }
            />
            {explicitOnly ? "所选模板需要显式发起，不执行自动补扫" : "授权数据缺失、过期或覆盖不足时自动补扫"}
          </label>
          <AlertDialog>
            <AlertDialogTrigger asChild>
              <Button disabled={scanDisabled}>发起一次测绘</Button>
            </AlertDialogTrigger>
            <AlertDialogContent>
              <AlertDialogHeader>
                <AlertDialogTitle>对本任务登记范围发起测绘？</AlertDialogTitle>
                <AlertDialogDescription>
                  仅使用所选模板扫描明确登记的目标。新扫描仍经过任务 Guard
                  和审批；按模板实际操作检查约束，扩域／根域爬取需明确授权相应范围。已提交扫描不会因 ARTEX
                  暂停而自动终止，需要在 ScopeSentry 管理页处理。
                </AlertDialogDescription>
              </AlertDialogHeader>
              <AlertDialogFooter>
                <AlertDialogCancel>取消</AlertDialogCancel>
                <AlertDialogAction onClick={() => void action({ action: "scan" })}>确认发起</AlertDialogAction>
              </AlertDialogFooter>
            </AlertDialogContent>
          </AlertDialog>
        </div>
        <p className="text-muted-foreground text-xs">
          新扫描默认不自动授权；只在任务运行中创建，不复活已完成任务。回流数据不等同于已验证漏洞。
          <Link className="underline underline-offset-4" href="/function/sync">
            查看数据源与资产同步
          </Link>
        </p>
      </CardContent>
    </Card>
  );
}
