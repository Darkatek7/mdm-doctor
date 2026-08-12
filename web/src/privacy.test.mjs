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

  it("shows expiry only after analysis and derives elapsed time from job creation", () => {
    const source = readFileSync(new URL("App.tsx", import.meta.url), "utf8");
    assert.match(source, /phase==="ready"\?current\.job\.expires_at:undefined/);
    assert.match(source, /Time elapsed/);
    assert.match(source, /Date\.parse\(slot\.job\.created_at\)/);
  });

  it("loads the configured identifier default without browser persistence", () => {
    const source = readFileSync(new URL("App.tsx", import.meta.url), "utf8");
    assert.match(source, /default_identifiers_visible\?"original":"redacted"/);
    assert.match(source, /ApplicationPage/);
    assert.match(source, /severity:\["critical","error","warning"\]/);
  });

  it("keeps applications out of the policies and enrollment query", () => {
    const source = readFileSync(new URL("App.tsx", import.meta.url), "utf8");
    assert.match(source, /POLICY_ENTITY_TYPES=\["policy","package","profile","network profile","certificate","enrollment","identity"\]/);
    assert.match(source, /entity_type:POLICY_ENTITY_TYPES/);
    assert.doesNotMatch(source, /POLICY_ENTITY_TYPES=\[[^\]]*"application"/);
  });

  it("prioritizes attempted applications and current policy evidence", () => {
    const source = readFileSync(new URL("App.tsx", import.meta.url), "utf8");
    assert.match(source, /query\/applications[\s\S]*attempted:true/);
    assert.match(source, /query\/entities[\s\S]*current:true/);
    assert.match(source, /label="Execution" values=\{\["attempted","inventory_only"\]\}/);
    assert.match(source, /label="Scope" values=\{\["current","historical"\]\}/);
  });
});
