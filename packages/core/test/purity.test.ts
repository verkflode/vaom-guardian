// The core's purity claims, as tests that fail the build: no network, no processes, no environment,
// no eval, no runtime dependencies. The core runs where enforcement decisions are made, and in the
// browser (the Delegation Lab), so its bar is the strictest in the project.
import { execFileSync } from "node:child_process";
import { readdirSync, readFileSync, statSync } from "node:fs";
import { join, relative } from "node:path";
import { describe, expect, it } from "vitest";

const pkg = join(import.meta.dirname, "..");
const root = join(pkg, "..", "..");

function files(dir: string): string[] {
  return readdirSync(dir).flatMap((f) => {
    const p = join(dir, f);
    return statSync(p).isDirectory() ? files(p) : /\.(ts|js|mjs)$/.test(f) ? [p] : [];
  });
}
const sources = files(join(pkg, "src")).map((p) => ({ file: relative(pkg, p), text: readFileSync(p, "utf8") }));

// A match directly after a quote is a string literal, not a call: the generated validators carry Ajv's
// codegen metadata such as 'require("ajv/dist/runtime/equal").default', which never executes.
const call = (name: string) => new RegExp(`(?<!['"])\\b${name}\\s*\\(`);

describe("the core is pure", () => {
  it("covers the generated validators too", () => {
    expect(sources.map((s) => s.file)).toContain("src/generated/validators.js");
  });

  it("has no network access", () => {
    for (const { file, text } of sources) {
      expect(text, file).not.toMatch(/node:(net|tls|dns|http|https|dgram)\b/);
      expect(text, file).not.toMatch(/\bXMLHttpRequest\b|\bWebSocket\b|\bEventSource\b|navigator\.sendBeacon/);
      expect(text, file).not.toMatch(call("fetch"));
    }
  });

  it("spawns no processes and reads no environment", () => {
    for (const { file, text } of sources) {
      expect(text, file).not.toMatch(/child_process|node:worker_threads|\bprocess\.(env|argv|exit)\b/);
    }
  });

  it("never evaluates code", () => {
    for (const { file, text } of sources) {
      expect(text, file).not.toMatch(call("eval"));
      expect(text, file).not.toMatch(/(?<!['"])\bnew Function\b/);
      expect(text, file).not.toMatch(call("require"));
      expect(text, file).not.toMatch(/\bimport\s*\(/);
    }
  });

  it("touches no file system or Node built-in at all", () => {
    for (const { file, text } of sources) expect(text, file).not.toMatch(/from\s+["']node:|["']node:[a-z_]+["']/);
  });

  it("imports only its own files", () => {
    for (const { file, text } of sources) {
      for (const m of text.matchAll(/^\s*(?:import|export)\b[^"']*?from\s+["']([^"']+)["']/gm)) {
        expect(m[1], `${file} imports ${m[1]}`).toMatch(/^\.\.?\//);
      }
    }
  });

  it("has zero runtime dependencies", () => {
    const p = JSON.parse(readFileSync(join(pkg, "package.json"), "utf8"));
    expect(Object.keys(p.dependencies ?? {})).toEqual([]);
    expect(Object.keys(p.peerDependencies ?? {})).toEqual([]);
  });
});

describe("the core loads under Node's own TypeScript support", () => {
  it("imports with type stripping alone, no bundler or compiler in between", () => {
    const entry = join(pkg, "src", "index.ts");
    const out = execFileSync(process.execPath, ["--disable-warning=MODULE_TYPELESS_PACKAGE_JSON", "--input-type=module", "-e", `const m = await import(${JSON.stringify(entry)}); console.log(typeof m.decide)`], { encoding: "utf8" });
    expect(out.trim()).toBe("function");
  }, 60_000);
});

describe("the generated validators match the schemas", () => {
  it("regenerating changes nothing", () => {
    const out = execFileSync(process.execPath, [join(root, "scripts", "gen-validators.mjs"), "--check"], { encoding: "utf8" });
    expect(out).toContain("up to date");
  }, 60_000);
});
