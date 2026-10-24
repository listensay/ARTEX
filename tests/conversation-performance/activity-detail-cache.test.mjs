import assert from "node:assert/strict";
import test from "node:test";
import { createActivityDetailCache } from "../../web/src/lib/activity-detail-cache.ts";

test("overlapping renders share one request and cache the completed body", async () => {
  let calls = 0;
  const load = createActivityDetailCache(async (seq) => {
    calls++;
    return `detail-${seq}`;
  });
  const first = load(42);
  assert.equal(load(42), first);
  assert.deepEqual(await Promise.all([first, load(42)]), ["detail-42", "detail-42"]);
  assert.equal(await load(42), "detail-42");
  assert.equal(calls, 1);
});

test("failed requests can retry and another transcript has its own cache", async () => {
  let calls = 0;
  const load = createActivityDetailCache(async () => {
    if (++calls === 1) throw new Error("offline");
    return "recovered";
  });
  await assert.rejects(load(1), /offline/);
  assert.equal(await load(1), "recovered");
  assert.equal(await createActivityDetailCache(async () => "other task")(1), "other task");
});

test("completed bodies are bounded and recent access preserves an entry", async () => {
  const calls = [];
  const load = createActivityDetailCache(async (seq) => {
    calls.push(seq);
    return String(seq);
  }, 2);
  await load(1);
  await load(2);
  await load(1);
  await load(3);
  await load(1);
  await load(2);
  assert.deepEqual(calls, [1, 2, 3, 2]);
});

test("large outputs cannot exceed the character budget or evict useful small bodies", async () => {
  const calls = [];
  const load = createActivityDetailCache(
    async (seq) => {
      calls.push(seq);
      return seq === 3 ? "x".repeat(20) : "x".repeat(6);
    },
    128,
    10,
  );
  await load(1);
  await load(2);
  await load(3);
  await load(2);
  await load(3);
  await load(1);
  assert.deepEqual(calls, [1, 2, 3, 3, 1]);
});
