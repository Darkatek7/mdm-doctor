import { describe, it } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";

describe("browser privacy contract", () => {
  it("does not use persistent browser storage or a service worker", () => {
    const source = ["App.tsx", "api.ts", "main.tsx"].map(name => readFileSync(new URL(name, import.meta.url), "utf8")).join("\n");
    for (const forbidden of ["local" + "Storage", "session" + "Storage", "indexed" + "DB", "caches.open", "serviceWorker.register"]) {
      assert.equal(source.includes(forbidden), false, `found ${forbidden}`);
    }
  });

  it("does not put the job handle in browser URLs", () => {
    const source = readFileSync(new URL("api.ts", import.meta.url), "utf8");
    assert.match(source, /headers\.set\(JOB_HEADER, handle\)/);
    assert.doesNotMatch(source, /URLSearchParams|history\.pushState|location\.hash/);
  });

  it("requires a per-preview reveal before requesting original evidence", () => {
    const source = readFileSync(new URL("App.tsx", import.meta.url), "utf8");
    assert.match(source, /reveal\?"original":"redacted"/);
    assert.doesNotMatch(source, /reveal\?"original":redaction/);
  });
});
