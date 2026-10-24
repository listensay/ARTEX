"use client";
import * as React from "react";
import { api } from "@/lib/api";
import type { PendingScopeRow,StageEntry } from "@/lib/types";
import { Button } from "@/components/ui/button";
import { Card,CardContent } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { ExternalLink } from "@/components/external-link";

export function ManagedActions({taskId,onChange}:{taskId?:string;onChange:()=>void}){
 const [pending,setPending]=React.useState<PendingScopeRow[]>([]);
 const [entries,setEntries]=React.useState<StageEntry[]>([]);
 const [message,setMessage]=React.useState("");const [busy,setBusy]=React.useState(false);
 const [url,setURL]=React.useState("");const [password,setPassword]=React.useState("");const [lang,setLang]=React.useState("auto");
 const [sessionId,setSessionId]=React.useState("");const [adapter,setAdapter]=React.useState("chisel");const [kind,setKind]=React.useState("socks");const [target,setTarget]=React.useState("");
 const [path,setPath]=React.useState("");const [oneShot,setOneShot]=React.useState(true);
 const [username,setUsername]=React.useState("");const [secret,setSecret]=React.useState("");const [source,setSource]=React.useState("");
 const refresh=React.useCallback(()=>{if(taskId)api.pendingScopes(taskId).then(setPending).catch(e=>setMessage(String(e)));else setPending([]);api.stageEntries().then(setEntries).catch(e=>setMessage(String(e)));},[taskId]);
 React.useEffect(refresh,[refresh]);
 async function run(fn:()=>Promise<unknown>){setBusy(true);setMessage("");try{const result=await fn();setMessage(JSON.stringify(result));refresh();onChange();}catch(e){setMessage(String(e));}finally{setBusy(false);}}
 return <Card className="mb-4"><CardContent className="space-y-4 pt-4">
 <p className="text-sm text-muted-foreground">选择任务后登记已有远程会话、管理隧道和文件。新网段须人工批准，移交任务创建后等待启动。</p>
 <details><summary className="cursor-pointer text-sm font-medium">会话登记与网络采集</summary><div className="mt-3 flex flex-wrap gap-2">
 <Input className="w-72" aria-label="会话 URL" placeholder="已有会话 HTTP/HTTPS URL" value={url} onChange={e=>setURL(e.target.value)}/>
 <Input className="w-36" aria-label="协议" placeholder="auto/phpcmd/jsp" value={lang} onChange={e=>setLang(e.target.value)}/>
 <Input className="w-36" type="password" aria-label="连接字段或密钥" placeholder="连接字段或密钥" value={password} onChange={e=>setPassword(e.target.value)}/>
 <Button disabled={busy||!taskId||!url} onClick={()=>run(async()=>{const r=await api.registerSession({task_id:Number(taskId),url,lang,password});setPassword("");return r;})}>登记</Button>
 <Input className="w-28" aria-label="会话 ID" placeholder="会话 ID" value={sessionId} onChange={e=>setSessionId(e.target.value)}/>
 <Button disabled={busy||!sessionId} onClick={()=>run(()=>api.reconSession(sessionId))}>只读网络采集</Button></div></details>
 <details><summary className="cursor-pointer text-sm font-medium">受管隧道部署</summary><div className="mt-3 flex flex-wrap gap-2">
 <select aria-label="适配器" value={adapter} onChange={e=>setAdapter(e.target.value)}><option>chisel</option><option>suo5</option></select>
 <select aria-label="隧道类型" value={kind} onChange={e=>setKind(e.target.value)}><option>socks</option><option>portfwd</option></select>
 <Input className="w-64" placeholder="portfwd 目标 host:port" value={target} onChange={e=>setTarget(e.target.value)}/>
 <Button disabled={busy||!taskId||!sessionId} onClick={()=>run(()=>api.deployTunnel({task_id:Number(taskId),session_id:Number(sessionId),kind,adapter,target}))}>部署并验证</Button></div></details>
 <details><summary className="cursor-pointer text-sm font-medium">凭据登记</summary><div className="mt-3 flex flex-wrap gap-2">
 <Input className="w-36" placeholder="用户名" value={username} onChange={e=>setUsername(e.target.value)}/>
 <Input className="w-44" type="password" placeholder="凭据内容" value={secret} onChange={e=>setSecret(e.target.value)}/>
 <Input className="w-64" placeholder="来源主机与证据" value={source} onChange={e=>setSource(e.target.value)}/>
 <Button disabled={busy||!taskId||!secret||!source} onClick={()=>run(async()=>{const r=await api.addCredential({task_id:Number(taskId),username,secret,source,cred_type:"password"});setSecret("");return r;})}>加密登记</Button></div></details>
 <details><summary className="cursor-pointer text-sm font-medium">待授权网段（{pending.filter(p=>p.status==="pending").length}）</summary><div className="space-y-2 mt-3">{!taskId&&<p>请先选择任务。</p>}{pending.map(p=><div key={p.id} className="flex items-center gap-3 text-sm"><span>{p.value} · {p.status} · 发现 {p.hits} 次</span>{p.status==="pending"&&<><Button size="sm" disabled={busy} onClick={()=>run(()=>api.decidePendingScope(p.id,"approve"))}>批准范围</Button><Button size="sm" variant="outline" disabled={busy} onClick={()=>run(()=>api.decidePendingScope(p.id,"dismiss"))}>拒绝</Button></>}</div>)}</div></details>
 <details><summary className="cursor-pointer text-sm font-medium">临时文件分发</summary><div className="flex gap-2 mt-3"><Input placeholder="当前任务工作目录或已安装工具的文件路径" value={path} onChange={e=>setPath(e.target.value)}/><label className="shrink-0 text-sm"><input type="checkbox" checked={oneShot} onChange={e=>setOneShot(e.target.checked)}/>一次下载</label><Button disabled={busy||!taskId||!path} onClick={()=>run(()=>api.createStage({task_id:taskId,path,one_shot:oneShot,ttl_minutes:15}))}>暂存</Button></div><div className="space-y-2 mt-3">{entries.filter(e=>!taskId||e.task_id===taskId).map(e=><div key={e.token} className="flex gap-3 text-sm"><ExternalLink href={e.url}>{e.name}</ExternalLink><span>{e.size} B · 到期 {new Date(e.expires_at).toLocaleTimeString()}</span><Button size="sm" variant="outline" disabled={busy} onClick={()=>run(()=>api.deleteStage(e.token))}>销毁</Button></div>)}</div></details>
 {message&&<pre className="max-h-48 overflow-auto whitespace-pre-wrap text-xs" role="status">{message}</pre>}
 </CardContent></Card>;
}
