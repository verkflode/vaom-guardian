// Every schema and example must be JSON without duplicate object keys. JSON.parse keeps the last value
// silently, so a duplicated key can hide an edit that went wrong; this scans the text itself.
import { readdirSync, readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";

const dir = (p) => fileURLToPath(new URL(p, import.meta.url));
const files = [...readdirSync(dir("..")).filter((f) => f.endsWith(".json")).map((f) => dir(`../${f}`)), ...readdirSync(dir("../examples")).filter((f) => f.endsWith(".json")).map((f) => dir(`../examples/${f}`))];

function duplicates(text) {
  const found = [], stack = [];
  let i = 0;
  const str = () => { let s = ""; i++; while (text[i] !== '"') { if (text[i] === "\\") { s += text[i] + text[i + 1]; i += 2; } else s += text[i++]; } i++; return s; };
  while (i < text.length) {
    const c = text[i];
    if (c === "{") { stack.push({ keys: new Set(), expectKey: true }); i++; }
    else if (c === "[") { stack.push(null); i++; }
    else if (c === "}" || c === "]") { stack.pop(); i++; }
    else if (c === ",") { const top = stack[stack.length - 1]; if (top) top.expectKey = true; i++; }
    else if (c === '"') {
      const top = stack[stack.length - 1], s = str();
      if (top && top.expectKey) { if (top.keys.has(s)) found.push(s); top.keys.add(s); top.expectKey = false; }
    } else i++;
  }
  return found;
}

let bad = 0;
for (const f of files) {
  const d = duplicates(readFileSync(f, "utf8"));
  if (d.length) { bad++; console.log(`DUPLICATE KEYS ${f.split("/schema/")[1]}: ${d.join(", ")}`); }
}
console.log(`${files.length} JSON files, ${bad} with duplicate keys`);
process.exit(bad ? 1 : 0);
