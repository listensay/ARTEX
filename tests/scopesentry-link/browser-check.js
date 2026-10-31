async (page) => {
  const dir = "__QA_DIR__";
  const origin = new URL(page.url()).origin;
  const templateId = "111111111111111111111111";
  const task = { id: "99", name: "联动界面测试", description: "隔离数据，不访问真实目标", goal: "验证查询、授权与状态展示", status: "running", paused: false, coverage_enabled: true, created_at: Math.floor(Date.now() / 1000) };
  let link = { task_id: 99, enabled: true, auto_scan: false, template_id: "", state: "ready", summary: "未找到存量数据，可以选择模板后补充测绘", targets: ["example.test"], missing_targets: ["example.test"], checked_at: Math.floor(Date.now() / 1000), imported: 0, scan_name: "", scan_state: "" };
  let scans = 0;
  let lastConfig;
  let defaultAvailable = false;
  await page.context().addCookies([{ name: "artex_csrf", value: "isolated-ui-csrf", url: origin }]);
  await page.route("**/api/**", async (route) => {
    const request = route.request();
    const path = new URL(request.url()).pathname;
    if (path.includes("/activity/stream")) {
      await route.fulfill({ contentType: "text/event-stream", body: ": isolated test stream\n\n" });
      return;
    }
    let response = { profiles: [], agents: [], tasks: [], assets: [], intents: [], findings: [], goals: [], constraints: [], scope: [], models: [], types: [], total: 0, tested: 0 };
    if (path === "/api/auth/status") response = { initialized: true, authenticated: true };
    if (path === "/api/tasks/99") response = task;
    if (path === "/api/stats") response = { ...response, active_task: task, engine_mode: "exploring", asset_counts: {}, tokens: {} };
    if (["/api/exploration/intents", "/api/exploration/findings", "/api/exploration/frontier"].includes(path)) response = [];
    if (path === "/api/sync/scopesentry/templates") response = { templates: [{ id: templateId, name: "HTTP 服务测绘", usable: true, default: defaultAvailable, reason: "" }, { id: "222222222222222222222222", name: "default", usable: false, reason: "模板未配置模块" }] };
    if (path === "/api/tasks/99/scopesentry") {
      if (request.method() === "POST") {
        const args = request.postDataJSON();
        if (args.action === "config") { lastConfig = args; link = { ...link, ...args }; }
        if (args.action === "refresh") link = { ...link, state: "imported", imported: 4, missing_targets: [], summary: "已回流 4 个范围内资产，来源尚未独立验证" };
        if (args.action === "scan") { scans++; link = { ...link, state: "scanning", scan_name: "artex-99-fixture", scan_state: "running", summary: "已提交扫描，平台持续跟踪并回流结果" }; }
      }
      response = link;
    }
    await route.fulfill({ json: response });
  });
  await page.setViewportSize({ width: 1280, height: 900 });
  await page.goto(`${origin}/function/tasks/detail?id=99`);
  await page.getByRole("tab", { name: "总览", exact: true }).click();
  await page.getByText("ScopeSentry 联动", { exact: true }).waitFor();
  const area = page.locator('[aria-labelledby="scopesentry-link-title"]');
  await area.getByText("未找到存量数据，可以选择模板后补充测绘").waitFor();
  if (!(await page.getByRole("button", { name: "发起一次测绘", exact: true }).isDisabled())) throw new Error("Scan allowed without a template");
  await page.getByLabel("端口／服务测绘模板", { exact: true }).selectOption(templateId);
  await page.waitForFunction((id) => document.querySelector("#scopesentry-link-template")?.value === id, templateId);
  await page.getByLabel("授权缺少存量数据时自动补扫", { exact: true }).click();
  await page.waitForFunction(() => document.querySelector("#scopesentry-link-auto-scan")?.getAttribute("aria-checked") === "true");
  if (!lastConfig?.auto_scan || lastConfig.template_id !== templateId) throw new Error("Authorization/configuration was not preserved");
  await page.getByRole("button", { name: "检索并回流", exact: true }).click();
  await page.getByText("已回流 4 个范围内资产，来源尚未独立验证", { exact: true }).waitFor();
  await page.getByRole("button", { name: "发起一次测绘", exact: true }).click();
  await page.getByRole("button", { name: "取消", exact: true }).click();
  if (scans !== 0) throw new Error("Cancel submitted a scan");
  await page.getByRole("button", { name: "发起一次测绘", exact: true }).click();
  await page.getByRole("button", { name: "确认发起", exact: true }).click();
  await page.getByText("已提交扫描，平台持续跟踪并回流结果", { exact: true }).waitFor();
  if (scans !== 1 || !(await page.getByRole("button", { name: "发起一次测绘", exact: true }).isDisabled())) throw new Error("Duplicate scan was not prevented");
  // A validated default enables configuration, not scan authority or an automatic POST.
  defaultAvailable = true;
  link = { ...link, template_id: "", state: "ready", auto_scan: false, scan_name: "", scan_state: "", summary: "尚未授权自动扫描" };
  await page.goto(`${origin}/function/tasks/detail?id=99`);
  await page.getByRole("tab", { name: "总览", exact: true }).click();
  await page.waitForFunction(() => document.querySelector('#scopesentry-link-template option[value=""]')?.textContent === "安全默认 · HTTP 服务测绘");
  await page.getByText("尚未授权自动扫描", { exact: true }).waitFor();
  if (scans !== 1 || await page.getByLabel("授权缺少存量数据时自动补扫", { exact: true }).isChecked()) throw new Error("Default selection silently authorized a scan");
  await page.getByLabel("授权缺少存量数据时自动补扫", { exact: true }).click();
  await page.waitForFunction(() => document.querySelector("#scopesentry-link-auto-scan")?.getAttribute("aria-checked") === "true");
  if (!lastConfig?.auto_scan || lastConfig.template_id !== "" || scans !== 1) throw new Error("Blank-template opt-in issued a manual scan or lost configuration");
  await area.scrollIntoViewIfNeeded();
  await page.screenshot({ path: `${dir}/desktop.png` });
  await page.setViewportSize({ width: 390, height: 844 });
  await area.scrollIntoViewIfNeeded();
  if (await page.evaluate(() => document.documentElement.scrollWidth > innerWidth + 1)) throw new Error("Mobile page overflows horizontally");
  await page.screenshot({ path: `${dir}/mobile.png` });
  return { scans, templateId, desktop: `${dir}/desktop.png`, mobile: `${dir}/mobile.png` };
}
