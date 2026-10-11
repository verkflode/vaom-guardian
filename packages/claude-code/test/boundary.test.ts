// The shim talks to the Guardian on 127.0.0.1 and to nothing else: no other hosts, no processes, no eval,
// and only the Node built-ins it needs. A scan of its own sources, so a change that adds any fails the build.
import { readdirSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";

const src = join(import.meta.dirname, "..", "src");
const sources = readdirSync(src).filter((f) => f.endsWith(".ts")).map((f) => ({ file: f, text: readFileSync(join(src, f), "utf8") }));
const ALLOWED = new Set(["node:crypto", "node:fs", "node:http", "node:os", "node:path", "node:util", "@verkflode/vaom-guardian-acs", "@verkflode/vaom-guardian-server"]);

describe("the Claude Code shim", () => {
  it("imports only what it needs", () => {
    for (const { file, text } of sources) {
      for (const m of text.matchAll(/^\s*(?:import|export)\b[^"']*?from\s+["']([^"']+)["']/gm)) {
        if (m[1]!.startsWith("./")) continue;
        expect(ALLOWED.has(m[1]!), `${file} imports ${m[1]}`).toBe(true);
      }
    }
  });
  it("spawns nothing and evaluates nothing", () => {
    for (const { file, text } of sources) {
      expect(text, file).not.toMatch(/child_process|(?<!\.)\bexec(File)?(Sync)?\s*\(|\bspawn\s*\(|\bfetch\s*\(|\.connect\s*\(/);
      expect(text, file).not.toMatch(/(?<!['"])\beval\s*\(|new Function\b|\bimport\s*\(/);
    }
  });
  it("makes one kind of outbound request: to 127.0.0.1, without connection reuse", () => {
    const calls = sources.flatMap(({ file, text }) => [...text.matchAll(/\brequest\(\{([^}]*)/g)].map((m) => ({ file, opts: m[1]! })));
    expect(calls).toHaveLength(1);
    expect(calls[0]!.opts).toMatch(/^\s*host: "127\.0\.0\.1", port,/);
    expect(calls[0]!.opts).toMatch(/agent: false/);
  });
});
