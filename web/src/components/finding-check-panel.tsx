"use client";

import * as React from "react";

import Link from "next/link";

import { toast } from "sonner";

import { Markdown } from "@/components/markdown";
import { Alert, AlertDescription } from "@/components/ui/alert";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { api } from "@/lib/api";
import type { FindingCheck } from "@/lib/types";

const labels = { pending: "等待启动", running: "验证中", completed: "已完成", failed: "验证失败", stopped: "已停止" };
const verdicts = { verified: "确认真实", false_positive: "误报", inconclusive: "无法确认" };
const active = (item: FindingCheck) => item.status === "pending" || item.status === "running";

export function FindingCheckPanel({
  findingId,
  readOnly = false,
  onCompleted,
}: {
  findingId: string;
  readOnly?: boolean;
  onCompleted?: () => void;
}) {
  const [items, setItems] = React.useState<FindingCheck[]>([]);
  const [version, setVersion] = React.useState(0);
  const [loaded, setLoaded] = React.useState(false);
  const [error, setError] = React.useState("");
  const [busy, setBusy] = React.useState(false);
  const [mode, setMode] = React.useState<"auto" | "off" | null>(null);
  const previous = React.useRef<FindingCheck[]>([]);
  const requestSeq = React.useRef(0);
  const load = React.useCallback(async () => {
    const seq = ++requestSeq.current;
    try {
      const data = await api.findingChecks(findingId);
      if (seq !== requestSeq.current) return;
      const finished = previous.current.some(
        (item) => active(item) && data.checks.some((row) => row.id === item.id && !active(row)),
      );
      previous.current = data.checks;
      setItems(data.checks);
      setVersion(data.evidence_version);
      setLoaded(true);
      setError("");
      if (finished) onCompleted?.();
    } catch (e) {
      if (seq === requestSeq.current) setError((e as Error).message);
    }
  }, [findingId, onCompleted]);
  React.useEffect(() => {
    void load();
    let disposed = false;
    api
      .findingVerifyMode()
      .then((data) => {
        if (!disposed) setMode(data.mode);
      })
      .catch((e) => {
        if (!disposed) toast.error((e as Error).message);
      });
    return () => {
      disposed = true;
      requestSeq.current++;
    };
  }, [load]);
  // Poll also while idle: a delayed automatic dispatch may start after this page opened.
  React.useEffect(() => {
    const timer = setInterval(() => void load(), 5000);
    return () => clearInterval(timer);
  }, [load]);
  async function start() {
    setBusy(true);
    try {
      const data = await api.startFindingCheck(findingId);
      toast.success(data.created ? "已发起独立验证" : "该漏洞正在验证");
      await load();
    } catch (e) {
      toast.error((e as Error).message);
    } finally {
      setBusy(false);
    }
  }
  async function changeMode() {
    if (mode === null) return;
    setBusy(true);
    try {
      const data = await api.setFindingVerifyMode(mode === "auto" ? "off" : "auto");
      setMode(data.mode);
      toast.success(data.mode === "off" ? "已关闭自动验证，当前会话继续完成" : "已开启自动验证");
    } catch (e) {
      toast.error((e as Error).message);
    } finally {
      setBusy(false);
    }
  }
  const running = items.find(active);
  const modeLabel = mode === null ? "加载中" : { auto: "开启", off: "关闭" }[mode];
  return (
    <Card>
      <CardHeader>
        <CardTitle>独立漏洞验证</CardTitle>
        <CardDescription>先尝试证伪，再确认真实。新增证据使历史结论过期；人工处置不会被自动结论覆盖。</CardDescription>
        <div className="flex flex-wrap gap-2">
          {running?.conversation_id != null ? (
            <Button asChild variant="outline" size="sm">
              <Link href={`/chat?c=${running.conversation_id}`}>查看验证会话</Link>
            </Button>
          ) : null}
          {!readOnly ? (
            <Button size="sm" disabled={!loaded || !!error || busy || !!running} onClick={() => void start()}>
              手动重验
            </Button>
          ) : null}
          {!readOnly ? (
            <Button variant="outline" size="sm" disabled={mode === null || busy} onClick={() => void changeMode()}>
              全局自动验证：{modeLabel}
            </Button>
          ) : null}
        </div>
        <p className="text-muted-foreground text-xs">
          关闭自动验证会清空待验证队列；重新开启仅处理后续证据，已有会话继续。修复后复测使用下方原复测入口。
        </p>
      </CardHeader>
      <CardContent className="flex flex-col gap-3">
        {error ? (
          <Alert variant="destructive">
            <AlertDescription>
              {error}
              <Button variant="outline" size="sm" onClick={() => void load()}>
                重试
              </Button>
            </AlertDescription>
          </Alert>
        ) : null}
        {!loaded && !error ? <p className="text-muted-foreground text-sm">加载验证记录…</p> : null}
        {loaded && !items.length ? (
          <p className="text-muted-foreground text-sm">暂无独立验证记录；可手动发起。</p>
        ) : null}
        {items.map((item) => (
          <div key={item.id} className="flex min-w-0 flex-col gap-2 rounded-lg border p-3">
            <div className="flex flex-wrap items-center gap-2">
              <Badge variant={item.status === "completed" && item.verdict === "verified" ? "destructive" : "secondary"}>
                {item.status === "completed" && item.verdict ? verdicts[item.verdict] : labels[item.status]}
              </Badge>
              <Badge variant="outline">
                证据 v{item.evidence_version}
                {item.evidence_version !== version ? " · 已过期" : ""}
              </Badge>
              <span className="text-muted-foreground text-xs">
                #{item.id} · {new Date(item.created_at).toLocaleString("zh-CN")}
              </span>
              {item.conversation_id != null ? (
                <Button asChild variant="ghost" size="sm">
                  <Link href={`/chat?c=${item.conversation_id}`}>查看会话</Link>
                </Button>
              ) : (
                <span className="text-muted-foreground text-xs">会话已删除</span>
              )}
            </div>
            {item.status === "completed" ? (
              <>
                <p className="whitespace-pre-wrap break-words text-sm">{item.summary}</p>
                <p className="text-muted-foreground text-xs">
                  {item.applied ? "结论完成时已回写状态" : "保留历史结论，未回写处置状态"}
                </p>
              </>
            ) : null}
            {item.error ? (
              <p className="whitespace-pre-wrap break-words text-destructive text-sm">{item.error}</p>
            ) : null}
            {item.evidence ? (
              <details className="min-w-0">
                <summary className="cursor-pointer text-sm">本次验证证据</summary>
                <div className="mt-3 overflow-x-auto">
                  <Markdown text={item.evidence} />
                </div>
              </details>
            ) : null}
          </div>
        ))}
      </CardContent>
    </Card>
  );
}
