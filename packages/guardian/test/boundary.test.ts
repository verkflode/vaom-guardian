// The Guardian process listens; it never calls out. No outbound network, no processes, no eval, and
// only the Node built-ins it needs: a scan of its own sources, so a change that adds any fails the build.
import { readdirSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";

const src = join(import.meta.dirname, "..", "src");
const sources = readdirSync(src).filter((f) => f.endsWith(".ts")).map((f) => ({ file: f, text: readFileSync(join(src, f), "utf8") }));
const ALLOWED = new Set(["node:crypto", "node:fs", "node:http", "node:path", "node:util", "@verkflode/vaom-guardian-core", "@verkflode/vaom-guardian-acs"]);

describe("the Guardian process", () => {
  it("imports only what it needs", () => {
    for (const { file, text } of sources) {
      for (const m of text.matchAll(/^\s*(?:import|export)\b[^"']*?from\s+["']([^"']+)["']/gm)) {
        if (m[1]!.startsWith("./")) continue;
        expect(ALLOWED.has(m[1]!), `${file} imports ${m[1]}`).toBe(true);
      }
    }
  });
  it("makes no outbound connections, spawns nothing, evaluates nothing", () => {
    for (const { file, text } of sources) {
      if (file === "page.ts") continue; // browser script, checked below
      expect(text, file).not.toMatch(/\bfetch\s*\(|\brequest\s*\(|\bget\s*\(\s*["'`]http|\.connect\s*\(|child_process|(?<!\.)\bexec(File)?(Sync)?\s*\(|\bspawn\s*\(/);
      expect(text, file).not.toMatch(/(?<!['"])\beval\s*\(|new Function\b|\bimport\s*\(/);
    }
  });
  it("the page script talks to its own origin only (CSP connect-src 'self' enforces it too)", () => {
    const page = sources.find((s) => s.file === "page.ts")!.text;
    const calls = [...page.matchAll(/fetch\(([^,)]+)/g)].map((m) => m[1]!.trim());
    expect(calls.length).toBeGreaterThan(0);
    for (const c of calls) expect(c, c).toMatch(/^(path|"\/)/);
    expect(page).not.toMatch(/https?:\/\/(?!localhost)/);
    expect(page).not.toMatch(/innerHTML|outerHTML|insertAdjacentHTML|document\.write/);
  });
  it("binds to the loopback interface only", () => {
    const cli = sources.find((s) => s.file === "cli.ts")!.text;
    expect(cli).toMatch(/listen\(config\.port, "127\.0\.0\.1"/);
  });
});
