async (page) => {
  const ts = '2026-10-24T12:00:00Z';
  const worker = Array.from({ length: 200 }, (_, i) => ({
    seq: 1001 + i, intent_id: '2415', worker: 'work#2', ts,
    kind: i % 3 === 0 ? 'thinking' : i % 3 === 1 ? 'tool_use' : 'tool_result',
    tool: i % 3 === 0 ? undefined : 'Bash', tool_use_id: `tool-${Math.floor(i / 3)}`,
    summary: i % 3 === 0 ? '分析执行结果' : `Bash ${1001 + i} fixture-command`,
  }));
  const main = [
    { seq: 501, worker: 'mainagent', main_seg: 0, ts, kind: 'user', summary: '主会话问题摘要' },
    { seq: 502, worker: 'mainagent', main_seg: 0, ts, kind: 'result', summary: '主会话回答摘要' },
  ];
  let release;
  const released = new Promise(resolve => { release = resolve; });
  const requests = [];
  await page.unrouteAll({ behavior: 'ignoreErrors' });
  await page.route('**/api/**', async route => {
    const url = new URL(route.request().url());
    requests.push(url.pathname + url.search);
    let data = {};
    if (url.pathname === '/api/auth/status') data = { initialized: true, authenticated: true };
    else if (url.pathname === '/api/tasks/15') data = { id: '15', name: '会话性能验证', title: '会话性能验证', status: 'running', created_at: ts, updated_at: ts };
    else if (url.pathname === '/api/exploration/intents') data = { items: [{ id: '2415', type: 'intent', state: 'done', priority: 1, origin: 'fixture', ts, payload: JSON.stringify({ summary: '性能回归 Worker' }) }], has_more: false };
    else if (url.pathname === '/api/exploration/main-sessions') data = { sessions: [{ seq: 0, created_at: ts }], current: 0 };
    else if (url.pathname === '/api/exploration/activity/history') {
      const isWorker = url.searchParams.get('session') === 'intent:2415';
      const older = Number(url.searchParams.get('before')) > 0;
      const items = isWorker ? older ? [{ seq: 800, intent_id: '2415', worker: 'work#2', ts, kind: 'round', summary: '较早历史验证' }] : worker : main;
      data = { items, snapshot_cursor: 1200, has_more: isWorker && !older };
    } else if (url.pathname === '/api/exploration/activity/stream') {
      await released;
      const events = [
        { seq: 1201, intent_id: '2415', worker: 'work#2', ts, kind: 'tool_result', tool: 'Bash', tool_use_id: 'tool-66', summary: '实时工具结果摘要', detail: '旧后端大正文'.repeat(200000) },
        { seq: 1202, intent_id: '2415', worker: 'work#2', ts, kind: 'result', summary: '实时回答摘要', detail: '旧后端内联回答' },
      ];
      return route.fulfill({ contentType: 'text/event-stream', body: events.map(a => `id: ${a.seq}\ndata: ${JSON.stringify(a)}\n\n`).join('') });
    } else if (/\/exploration\/activity\/\d+$/.test(url.pathname)) {
      const seq = Number(url.pathname.split('/').pop());
      const detail = seq === 1200 ? JSON.stringify({ command: 'fixture-command' }) : seq === 1201 ? '实时输出完整正文' : seq === 1202 ? '# 实时回答完整正文' : seq === 501 ? '主会话问题完整正文' : seq === 502 ? '# 主会话回答完整正文' : '历史详情正文';
      data = { detail };
    } else if (url.pathname === '/api/exploration/tokens') data = { total: { input_tokens: 0, output_tokens: 0, cache_read_tokens: 0, cache_write_tokens: 0 }, sessions: [], workers: [] };
    else if (url.pathname.endsWith('/chat/status')) data = { running: false };
    else if (url.pathname.endsWith('/intent-assets')) data = { assets: [] };
    else if (url.pathname.includes('/intercept/')) data = { items: [] };
    else if (url.pathname.endsWith('/side-questions')) data = { items: [], snapshot: null, next_cursor: 0 };
    else if (url.pathname.endsWith('/llm/resolution')) data = { planner: {}, mainagent: {}, worker: {} };
    else if (['/api/llm/profiles', '/api/agents', '/api/tasks'].includes(url.pathname)) data = [];
    else if (url.pathname === '/api/health') data = { version: 'fixture' };
    return route.fulfill({ contentType: 'application/json', body: JSON.stringify(data) });
  });
  await page.goto('http://127.0.0.1:8091/function/tasks/detail/?id=15');
  await page.getByText('主会话回答完整正文', { exact: true }).waitFor();
  await page.getByRole('button', { name: /#2415 性能回归 Worker/ }).click();
  const tool = page.getByRole('button', { name: /1200 fixture-command/ });
  await tool.click();
  await page.getByText('【命令】', { exact: false }).waitFor();
  const beforeOlder = requests.filter(p => p.includes('/activity/history') && Number(new URL(p, 'http://fixture').searchParams.get('before')) > 0).length;
  const beforeNegative = requests.filter(p => p.includes('/activity/-1')).length;
  release();
  await page.getByText('实时输出完整正文', { exact: false }).waitFor();
  await page.getByText('实时回答完整正文', { exact: true }).waitFor();
  const cdp = await page.context().newCDPSession(page);
  await cdp.send('Performance.enable');
  const before = Object.fromEntries((await cdp.send('Performance.getMetrics')).metrics.map(m => [m.name, m.value]));
  await page.waitForTimeout(6500);
  const after = Object.fromEntries((await cdp.send('Performance.getMetrics')).metrics.map(m => [m.name, m.value]));
  const detailCounts = Object.fromEntries([1200,1201,1202].map(seq => [seq, requests.filter(p => p.includes(`/activity/${seq}?`)).length]));
  if (Object.values(detailCounts).some(n => n !== 1)) throw new Error(`重复详情请求: ${JSON.stringify(detailCounts)}`);
  if (beforeOlder || beforeNegative) throw new Error(`打开会话触发了提前历史加载或合成消息详情请求: ${JSON.stringify({ beforeOlder, beforeNegative, requests })}`);
  const viewport = page.locator('[data-slot="scroll-area-viewport"]').filter({ has: tool });
  await viewport.evaluate(el => { el.scrollTop = 0; el.dispatchEvent(new Event('scroll')); });
  await page.getByText('较早历史验证', { exact: true }).waitFor();
  const olderRequests = requests.filter(p => p.includes('/activity/history') && p.includes('before=1001')).length;
  if (olderRequests !== 1) throw new Error(`历史分页请求次数 ${olderRequests}`);
  await page.getByRole('button', { name: /主 Agent · 会话 #1/ }).click();
  await page.getByText('主会话回答完整正文', { exact: true }).waitFor();
  if (await page.getByText('实时回答完整正文', { exact: true }).count()) throw new Error('会话切换留下旧回答');
  return { detailCounts, beforeOlder, beforeNegative, olderRequests, switchedWithoutStaleBody: true, heapMB: after.JSHeapUsedSize / 1048576, scriptMs: (after.ScriptDuration - before.ScriptDuration) * 1000, taskMs: (after.TaskDuration - before.TaskDuration) * 1000, layoutCount: after.LayoutCount - before.LayoutCount };
}
