// The adapter is pure like the core: no network, processes, environment, file system or eval. It may
// import the core and nothing else; the HTTP server and storage belong to the guardian package.
import { execFileSync } from "node:child_process";
import { readdirSync, readFileSync, statSync } from "node:fs";
import { join, relative } from "node:path";
import { describe, expect, it } from "vitest";

const pkg = join(import.meta.dirname, "..");
function files(dir: string): string[] {
  return readdirSync(dir).flatMap((f) => {
    const p = join(dir, f);
    return statSync(p).isDirectory() ? files(p) : /\.(ts|js|mjs)$/.test(f) ? [p] : [];
  });
}
const sources = files(join(pkg, "src")).map((p) => ({ file: relative(pkg, p), text: readFileSync(p, "utf8") }));
const call = (name: string) => new RegExp(`(?<!['"])\\b${name}\\s*\\(`);

describe("the ACS adapter is pure", () => {
  it("covers the generated validators", () => expect(sources.map((s) => s.file)).toContain("src/generated/validators.js"));
  it("has no network, processes, environment, file system or eval", () => {
    for (const { file, text } of sources) {
      expect(text, file).not.toMatch(/["']node:[a-z_]+["']|child_process|\bprocess\.(env|argv|exit)\b/);
      expect(text, file).not.toMatch(/\bXMLHttpRequest\b|\bWebSocket\b|\bEventSource\b|navigator\.sendBeacon/);
      for (const f of ["fetch", "eval", "require"]) expect(text, file).not.toMatch(call(f));
      expect(text, file).not.toMatch(/(?<!['"])\bnew Function\b|\bimport\s*\(/);
    }
  });
  it("imports only its own files and the core", () => {
    for (const { file, text } of sources) {
      for (const m of text.matchAll(/^\s*(?:import|export)\b[^"']*?from\s+["']([^"']+)["']/gm)) {
        expect(m[1], `${file} imports ${m[1]}`).toMatch(/^(\.\.?\/|@verkflode\/vaom-guardian-core$)/);
      }
    }
  });
  it("depends on the core only", () => {
    const p = JSON.parse(readFileSync(join(pkg, "package.json"), "utf8"));
    expect(Object.keys(p.dependencies ?? {})).toEqual(["@verkflode/vaom-guardian-core"]);
  });
  it("loads under Node's type stripping alone", () => {
    const out = execFileSync(process.execPath, ["--disable-warning=MODULE_TYPELESS_PACKAGE_JSON", "--input-type=module", "-e", `const m = await import(${JSON.stringify(join(pkg, "src", "index.ts"))}); console.log(typeof m.AcsEndpoint)`], { encoding: "utf8", cwd: pkg });
    expect(out.trim()).toBe("function");
  }, 60_000);
});
