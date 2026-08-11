import { readFileSync } from "node:fs";

const lock = JSON.parse(readFileSync(new URL("../web/package-lock.json", import.meta.url), "utf8"));
const allowed = new Set(["Apache-2.0", "BSD-2-Clause", "BSD-3-Clause", "ISC", "MIT", "Unicode-3.0", "Zlib"]);
const failures = [];
for (const [path, pkg] of Object.entries(lock.packages ?? {})) {
  if (!path || !pkg.license) continue;
  const choices = String(pkg.license).replace(/[()]/g, "").split(/\s+(?:OR|AND)\s+/);
  if (!choices.some(value => allowed.has(value))) failures.push(`${path}: ${pkg.license}`);
}
if (failures.length) {
  process.stderr.write(`Disallowed or unknown frontend licenses:\n${failures.join("\n")}\n`);
  process.exit(1);
}
process.stdout.write("Frontend license policy passed.\n");
