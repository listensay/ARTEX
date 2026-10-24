import { test } from "node:test";
import assert from "node:assert/strict";
import { safeHref } from "./safe-href.ts";
test("external links reject dangerous and ambiguous URLs", () => {
  for (const value of [null, {}, "", "/tasks", "//example.org", "javascript:alert(1)", "JaVaScRiPt:alert(1)", "data:text/html,x", "file:///tmp/x", "java\nscript:alert(1)", " https://example.org", "https://example.org\u0000", "https://a\\@b", "https://u:p@example.org", "http://", "http://[x]"]) assert.equal(safeHref(value), undefined, String(value));
});
test("external links return the validated canonical HTTP URL", () => {
  assert.equal(safeHref("HTTPS://EXAMPLE.ORG/a?q=1#b"), "https://example.org/a?q=1#b");
  assert.equal(safeHref("http://127.0.0.1:8787/a%20b"), "http://127.0.0.1:8787/a%20b");
  assert.equal(safeHref("https://[::1]/"), "https://[::1]/");
});
