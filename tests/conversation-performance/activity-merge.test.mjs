import assert from "node:assert/strict";
import test from "node:test";
import { mergeActivities } from "../../web/src/lib/activity-merge.ts";

test("replay keeps unchanged row references and returns the same list", () => {
  const rows = [
    { seq: 1, kind: "text", worker: "mainagent", summary: "summary", ts: "2026-10-24T12:00:00Z" },
    { seq: 2, kind: "result", worker: "mainagent", summary: "summary", ts: "2026-10-24T12:00:00Z", metadata: { llm_transition: { mode: "automatic" } } },
  ];
  assert.equal(mergeActivities(rows, structuredClone(rows)), rows);
  const changed = mergeActivities(rows, [{ ...rows[1], summary: "updated" }]);
  assert.equal(changed[0], rows[0]);
  assert.equal(changed[1].summary, "updated");
});
