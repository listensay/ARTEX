async (page) => {
  const origin = new URL(page.url()).origin;
  const calls = [];
  let saved;
  let failNextNetworkRequest = true;
  const check = (condition, message) => {
    if (!condition) throw new Error(message);
  };
  const wait = (ms) => new Promise((resolve) => setTimeout(resolve, ms));
  const waitForCalls = async (count) => {
    for (let i = 0; i < 100 && calls.length < count; i++) await wait(50);
    check(calls.length === count, `Expected ${count} requests, received ${calls.length}`);
  };
  const waitForStatus = async (text) => {
    await page.waitForFunction((value) => document.querySelector("#p-model-status")?.textContent.includes(value), text);
  };
  const longModel = `long-model-${"segment-".repeat(30)}`;
  await page.unrouteAll({ behavior: "wait" });
  await page.context().addCookies([{ name: "artex_csrf", value: "test-csrf", url: origin }]);
  await page.route("**/api/**", async (route) => {
    const request = route.request();
    const path = new URL(request.url()).pathname;
    let response = {};
    if (path === "/api/auth/status") response = { authenticated: true };
    if (path === "/api/llm/pool") response = { enabled: false, chain: [] };
    if (path === "/api/llm/profiles" && request.method() === "GET") {
      response = {
        profiles: [{ id: "7", name: "Stored profile", format: "openai", model: "stored-model", base_url: "https://saved.example/v1", api_key_hint: "stored-key" }],
      };
    }
    if (path === "/api/llm/profiles" && request.method() === "POST") {
      saved = request.postDataJSON();
      response = { id: 8 };
    }
    if (path === "/api/llm/models") {
      const body = request.postDataJSON();
      calls.push(body);
      if (body.base_url.includes("slow")) {
        await wait(1800);
        response = { ok: true, models: ["stale-model"] };
      } else if (body.base_url.includes("long-error")) {
        response = { ok: false, error: `Request failed https://gateway.example/${"a".repeat(700)}` };
      } else if (body.base_url.includes("error")) {
        response = { ok: false, error: "API returned 401" };
      } else if (body.base_url.includes("offline") && failNextNetworkRequest) {
        failNextNetworkRequest = false;
        return route.abort("failed");
      } else if (body.base_url.includes("empty")) {
        response = { ok: true, models: [] };
      } else if (body.base_url.includes("long")) {
        response = { ok: true, models: [longModel] };
      } else if (body.base_url.includes("many")) {
        response = { ok: true, models: Array.from({ length: 1000 }, (_, i) => `model-${String(i).padStart(4, "0")}`) };
      } else {
        response = { ok: true, models: ["zeta-model", "gpt-test", "claude-test", "gpt-test", " "] };
      }
    }
    try {
      await route.fulfill({ json: response });
    } catch (error) {
      if (!request.postData()?.includes("slow")) throw error;
    }
  });
  await page.setViewportSize({ width: 1280, height: 900 });
  await page.goto(`${origin}/system/llm`);
  await page.getByRole("button", { name: "新建", exact: true }).click();
  await page.getByLabel("名称", { exact: true }).fill("Browser test profile");
  await page.getByLabel("模型", { exact: true }).fill("manual-model");

  // Rapid endpoint/key edits share one debounced request, without stealing input focus.
  await page.getByLabel("Base URL（可选）").fill("https://gateway.example/");
  await page.getByLabel("Base URL（可选）").fill("https://gateway.example/v1");
  await page.getByLabel("API Key", { exact: true }).fill("key-a");
  await waitForStatus("已获取 3 个模型");
  check(calls.length === 1, "Typing was not debounced");
  check(calls[0].base_url === "https://gateway.example/v1" && calls[0].api_key === "key-a", "Wrong endpoint/key");
  check(await page.getByLabel("模型", { exact: true }).inputValue() === "manual-model", "Auto-fetch overwrote the model");
  check(await page.evaluate(() => document.activeElement?.id) === "p-api-key", "Auto-fetch stole focus");

  // Cached options are searchable and keyboard-selectable, with no second fetch.
  await page.getByRole("button", { name: "选择模型", exact: true }).click();
  await page.getByRole("combobox", { name: "搜索模型" }).fill("gpt");
  await page.getByRole("combobox", { name: "搜索模型" }).press("ArrowDown");
  await page.getByRole("combobox", { name: "搜索模型" }).press("Enter");
  check(await page.getByLabel("模型", { exact: true }).inputValue() === "gpt-test", "Keyboard selection failed");
  check(calls.length === 1, "Opening cached options refetched");
  await page.getByRole("button", { name: "刷新模型列表", exact: true }).click();
  await waitForCalls(2);
  await waitForStatus("已获取 3 个模型");

  await page.getByLabel("API Key", { exact: true }).fill("key-b");
  await waitForCalls(3);
  await waitForStatus("已获取 3 个模型");
  check(calls[2].api_key === "key-b", "Updated key not used");
  await page.locator('[data-slot="sheet-content"]').getByRole("combobox").first().click();
  await page.getByRole("option", { name: "OpenAI (Responses API)", exact: true }).click();
  await waitForCalls(4);
  await waitForStatus("已获取 3 个模型");
  check(calls[3].provider === "openai-responses", "Format change did not reload");
  await page.getByLabel("代理（可选）").fill("http://proxy.example:8080");
  await waitForCalls(5);
  await waitForStatus("已获取 3 个模型");
  check(calls[4].proxy === "http://proxy.example:8080", "Proxy change did not reload");

  // An in-flight response from a replaced endpoint must not resurrect stale options.
  await page.getByLabel("Base URL（可选）").fill("https://slow.example/v1");
  await waitForCalls(6);
  await page.getByLabel("Base URL（可选）").fill("https://fast.example/v1");
  await waitForCalls(7);
  await waitForStatus("已获取 3 个模型");
  await wait(2000);
  await page.getByRole("button", { name: "选择模型", exact: true }).click();
  check(await page.getByRole("option", { name: "stale-model" }).count() === 0, "Stale response replaced current options");
  await page.getByRole("combobox", { name: "搜索模型" }).fill("no-match");
  await page.getByText("没有匹配的模型，可关闭列表后手动输入。", { exact: true }).waitFor();
  await page.keyboard.press("Escape");

  await page.getByLabel("Base URL（可选）").fill("https://error.example/v1");
  await waitForCalls(8);
  await waitForStatus("获取失败");
  check(await page.getByRole("button", { name: "选择模型", exact: true }).isDisabled(), "Error left stale options enabled");
  await page.getByLabel("模型", { exact: true }).fill("manual-after-error");
  await page.getByLabel("Base URL（可选）").fill("https://empty.example/v1");
  await waitForCalls(9);
  await waitForStatus("接口未返回可用模型");
  check(await page.getByLabel("模型", { exact: true }).inputValue() === "manual-after-error", "Empty list cleared manual model");

  await page.getByLabel("Base URL（可选）").fill("ftp://invalid.example");
  await waitForStatus("请填写有效的");
  await wait(800);
  check(calls.length === 9, "Invalid URL sent a request");

  // Closing during the debounce cancels it; a new form has no prior key/model/list.
  await page.getByLabel("Base URL（可选）").fill("https://cancel.example/v1");
  await page.getByRole("button", { name: "Close", exact: true }).click();
  await wait(800);
  check(calls.length === 9, "Closing did not cancel scheduled fetch");
  await page.getByRole("button", { name: "新建", exact: true }).click();
  check(await page.getByLabel("API Key", { exact: true }).inputValue() === "", "New form retained key");
  check(await page.getByLabel("模型", { exact: true }).inputValue() === "", "New form retained model");

  // Base URL alone can request public lists; long IDs fit both mobile form and popover.
  await page.setViewportSize({ width: 375, height: 812 });
  await page.getByLabel("Base URL（可选）").fill("https://long.example/v1");
  await waitForCalls(10);
  await waitForStatus("已获取 1 个模型");
  check(calls[9].api_key === "", "Public-list lookup required a key");
  await page.getByRole("button", { name: "选择模型", exact: true }).click();
  const popup = page.locator('[data-slot="popover-content"]');
  const bounds = await popup.boundingBox();
  check(bounds.x >= 0 && bounds.x + bounds.width <= 375, "Mobile popup overflows viewport");
  check(await popup.evaluate((el) => el.scrollWidth <= el.clientWidth), "Long model overflows popup");
  await page.getByRole("option", { name: longModel }).click();
  check(await page.getByLabel("模型", { exact: true }).inputValue() === longModel, "Long model selection failed");
  check(await page.locator('[data-slot="sheet-content"]').evaluate((el) => el.scrollWidth <= el.clientWidth), "Mobile sheet overflows");
  await page.getByLabel("名称", { exact: true }).fill("Saved browser model");
  await page.locator('[data-slot="sheet-content"]').getByRole("button", { name: "新建", exact: true }).click();
  await page.getByRole("button", { name: "新建", exact: true }).waitFor();
  check(saved.model === longModel && saved.base_url === "https://long.example/v1", "Selected model was not saved");

  // Editing retains a manually configured ID while reusing the saved key via profile_id.
  await page.setViewportSize({ width: 1280, height: 900 });
  await page.getByRole("button", { name: /Stored profile/ }).click();
  await waitForCalls(11);
  await waitForStatus("已获取 3 个模型");
  check(calls[10].profile_id === 7 && calls[10].api_key === "", "Stored key fallback not requested");
  check(await page.getByLabel("模型", { exact: true }).inputValue() === "stored-model", "Editing replaced existing model");
  await page.getByRole("button", { name: "Close", exact: true }).click();
  await page.getByRole("button", { name: /Stored profile/ }).click();
  await waitForCalls(12);
  await waitForStatus("已获取 3 个模型");

  // A stored key also permits discovery at the provider's default URL.
  await page.getByLabel("Base URL（可选）").fill("");
  await waitForCalls(13);
  await waitForStatus("已获取 3 个模型");
  check(calls[12].base_url === "" && calls[12].profile_id === 7, "Default URL lost stored key fallback");

  // Unbroken upstream error text must not push the model controls off a small screen.
  await page.setViewportSize({ width: 375, height: 812 });
  await page.getByLabel("Base URL（可选）").fill("https://long-error.example/v1");
  await waitForCalls(14);
  await waitForStatus("获取失败");
  check(await page.locator('[data-slot="sheet-content"]').evaluate((el) => el.scrollWidth <= el.clientWidth), "Long error overflows sheet");
  const modelStatus = page.locator("#p-model-status");
  check(await modelStatus.evaluate((el) => el.scrollWidth <= el.clientWidth), "Long error text does not wrap");
  const refreshBounds = await page.getByRole("button", { name: "刷新模型列表", exact: true }).boundingBox();
  check(refreshBounds.x >= 0 && refreshBounds.x + refreshBounds.width <= 375, "Error pushed refresh outside viewport");

  // A failed transport can be retried without changing the form or its model.
  await page.getByLabel("Base URL（可选）").fill("https://offline.example/v1");
  await waitForCalls(15);
  await waitForStatus("获取失败");
  await page.getByRole("button", { name: "刷新模型列表", exact: true }).click();
  await waitForCalls(16);
  await waitForStatus("已获取 3 个模型");
  check(await page.getByLabel("模型", { exact: true }).inputValue() === "stored-model", "Network retry replaced model");

  // The nested modal retains scrolling and search even for a large gateway catalog.
  await page.getByLabel("Base URL（可选）").fill("https://many.example/v1");
  await waitForCalls(17);
  await waitForStatus("已获取 1000 个模型");
  await page.getByRole("button", { name: "选择模型", exact: true }).click();
  await page.getByRole("option", { name: "model-0000", exact: true }).hover();
  await page.mouse.wheel(0, 600);
  await page.waitForFunction(() => document.querySelector('[data-slot="command-list"]')?.scrollTop > 0);
  await page.getByRole("combobox", { name: "搜索模型" }).fill("model-0999");
  await page.getByRole("option", { name: "model-0999", exact: true }).click();
  check(await page.getByLabel("模型", { exact: true }).inputValue() === "model-0999", "Large-list selection failed");
  await page.getByRole("button", { name: "Close", exact: true }).click();
  return "PASS: debounce, search/keyboard selection, refresh, key/format/proxy changes, stale cancellation, errors, empty/public lists, mobile overflow, save, stored/default-key editing, network retry, and large-list scrolling";
}
