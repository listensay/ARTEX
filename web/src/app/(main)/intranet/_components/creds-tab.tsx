"use client";

import * as React from "react";

import { CheckCircle2Icon, Loader2Icon, MinusCircleIcon } from "lucide-react";

import { Badge } from "@/components/ui/badge";
import { Card } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Button } from "@/components/ui/button";
import { api } from "@/lib/api";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import type { Credential } from "@/lib/types";

import { fmtTime } from "./format";

// 凭据台账：密钥只做脱敏展示。后端提供 task_id 字段时出现任务过滤框。
export function CredsTab({ credentials, loading, onChanged }: { credentials: Credential[]; loading: boolean; onChanged: () => void }) {
  const [taskFilter, setTaskFilter] = React.useState("");
  const [editing, setEditing] = React.useState<Credential | null>(null);
  const [reason, setReason] = React.useState("");
  const [verified, setVerified] = React.useState(false);
  const [busy, setBusy] = React.useState(false);
  const [error, setError] = React.useState("");
  async function save() {
    if (!editing || !reason.trim()) return;
    setBusy(true); setError("");
    try { await api.verifyCredential(String(editing.id), verified, reason.trim()); setEditing(null); onChanged(); }
    catch (e) { setError(String(e)); }
    finally { setBusy(false); }
  }

  // 后端 task_id 是 JSON number(0 = 未关联),不是字符串。
  const hasTaskField = credentials.some((c) => typeof c.task_id === "number" && c.task_id > 0);
  const q = taskFilter.trim();
  const visible = q ? credentials.filter((c) => String(c.task_id ?? "").includes(q)) : credentials;

  return (
    <>
      {editing && <div className="flex flex-wrap items-center gap-2 pb-3">
        <span className="text-sm">凭据 #{editing.id}</span>
        <label className="text-sm"><input type="checkbox" checked={verified} onChange={e => setVerified(e.target.checked)} />已验证</label>
        <Input className="w-80" aria-label="验证理由" placeholder="验证证据或撤销理由" value={reason} onChange={e => setReason(e.target.value)} />
        <Button size="sm" disabled={busy || !reason.trim()} onClick={save}>保存验证状态</Button>
        <Button size="sm" variant="outline" disabled={busy} onClick={() => setEditing(null)}>取消</Button>
      </div>}
      {error && <p className="pb-2 text-sm text-destructive" role="alert">{error}</p>}
      {hasTaskField && (
        <div className="flex items-center gap-2 px-1 pb-2">
          <Input
            placeholder="按任务 ID 过滤..."
            className="h-8 w-56"
            value={taskFilter}
            onChange={(e) => setTaskFilter(e.target.value)}
          />
          {q && (
            <span className="text-xs text-muted-foreground tabular-nums">
              {visible.length} / {credentials.length}
            </span>
          )}
        </div>
      )}
      <Card className="flex min-h-0 flex-1 flex-col overflow-hidden py-0">
        <div className="min-h-0 flex-1 overflow-auto">
          <Table>
            <TableHeader className="sticky top-0 z-10 bg-card">
              <TableRow>
                <TableHead className="w-[70px]">ID</TableHead>
                <TableHead className="w-[110px]">类型</TableHead>
                <TableHead>用户名</TableHead>
                <TableHead className="w-[140px]">域</TableHead>
                <TableHead>密钥（脱敏）</TableHead>
                <TableHead className="w-[160px]">来源</TableHead>
                <TableHead className="w-[80px]">已验证</TableHead>
                <TableHead>验证理由</TableHead>
                <TableHead>操作</TableHead>
                <TableHead className="w-[140px]">时间</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {loading && visible.length === 0 ? (
                <TableRow>
                  <TableCell colSpan={10} className="py-12 text-center">
                    <Loader2Icon className="mx-auto h-5 w-5 animate-spin text-muted-foreground" />
                  </TableCell>
                </TableRow>
              ) : visible.length === 0 ? (
                <TableRow>
                  <TableCell colSpan={10} className="py-12 text-center text-sm text-muted-foreground">
                    {q ? "该任务下暂无凭据" : "暂无凭据"}
                  </TableCell>
                </TableRow>
              ) : (
                visible.map((c) => (
                  <TableRow key={c.id}>
                    <TableCell className="font-mono text-xs text-muted-foreground">#{c.id}</TableCell>
                    <TableCell>
                      <Badge variant="secondary" className="font-mono text-xs">
                        {c.cred_type || "-"}
                      </Badge>
                    </TableCell>
                    <TableCell className="max-w-0">
                      <span className="block truncate font-mono text-xs" title={c.username}>
                        {c.username || "—"}
                      </span>
                    </TableCell>
                    <TableCell className="max-w-0">
                      <span className="block truncate font-mono text-xs" title={c.domain}>
                        {c.domain || "—"}
                      </span>
                    </TableCell>
                    <TableCell className="max-w-0">
                      <code className="block truncate font-mono text-xs" title={c.secret_masked}>
                        {c.secret_masked || "—"}
                      </code>
                    </TableCell>
                    <TableCell className="max-w-0">
                      <span className="block truncate text-xs text-muted-foreground" title={c.source}>
                        {c.source || "—"}
                      </span>
                    </TableCell>
                    <TableCell>
                      {c.verified ? (
                        <CheckCircle2Icon className="size-4 text-emerald-500" aria-label="已验证" />
                      ) : (
                        <MinusCircleIcon className="size-4 text-muted-foreground" aria-label="未验证" />
                      )}
                    </TableCell>
                    <TableCell className="text-xs">{c.verification_reason || "—"}</TableCell>
                    <TableCell><Button size="sm" variant="outline" onClick={() => {setEditing(c);setReason(c.verification_reason || "");setVerified(c.verified);setError("");}}>记录验证</Button></TableCell>
                    <TableCell className="text-xs text-muted-foreground tabular-nums">
                      {fmtTime(c.created_at)}
                    </TableCell>
                  </TableRow>
                ))
              )}
            </TableBody>
          </Table>
        </div>
      </Card>
    </>
  );
}
